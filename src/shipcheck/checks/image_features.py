"""``image-features`` check.

Detects insecure entries in ``IMAGE_FEATURES`` configured in
``conf/local.conf`` / ``conf/auto.conf`` and surfaces them with a
calibrated severity drawn from a hardcoded table. Maps to CRA Annex I
Part I §b (secure-by-default configuration) and §j (limit attack
surfaces).

Per ``specs/image-features/spec.md``:

- The severity table is hardcoded and not user-tunable in this release.
- Each literal ``IMAGE_FEATURES`` entry that matches the table produces
  its own finding so users see exactly which entries their build
  configured. ``debug-tweaks`` plus an explicit ``allow-root-login``
  yields two distinct findings.
- The check returns ``PASS`` when ``IMAGE_FEATURES`` is unset or when
  it contains only entries outside the table. Absence of hardening
  features never FAILs this check -- the philosophy is "auditor, not
  architect".
"""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING

from shipcheck.models import BaseCheck, CheckResult, Finding, determine_status

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger(__name__)

# CRA catalog IDs covered by this check, applied as the
# ``CheckResult.cra_mapping`` regardless of which entry (if any) was
# matched. Per-finding ``cra_mapping`` may be narrower; see
# ``_FEATURE_TABLE`` below.
CRA_MAPPING: list[str] = ["I.P1.b", "I.P1.j"]

_CONF_FILES = ("conf/local.conf", "conf/auto.conf")

# Hardcoded severity table from ``specs/image-features/spec.md``. The
# value is ``(severity, cra_mapping, remediation)``. Per the spec's
# "cra_mapping per finding" requirement, the four high entries cite
# both §b (secure-by-default violation) and §j (attack-surface gap);
# the lower-severity entries (dev/dbg packages) cite only §j because
# they are pure attack-surface concerns, not secure-default violations.
_HIGH_CRA = ["I.P1.b", "I.P1.j"]
_LOWER_CRA = ["I.P1.j"]

_REMEDIATION_DEBUG_TWEAKS = (
    "Remove 'debug-tweaks' from IMAGE_FEATURES before shipping. It "
    "enables passwordless root, allows empty passwords, and unlocks "
    "root login over getty -- all shipping-blocking defaults for a "
    "production image."
)
_REMEDIATION_PASSWORD = (
    "Remove this feature from IMAGE_FEATURES. It allows authentication "
    "without a real password, which is unsafe for any image that leaves "
    "the development bench."
)
_REMEDIATION_ROOT_LOGIN = (
    "Remove 'allow-root-login' from IMAGE_FEATURES. Root login over "
    "getty is unsafe for production images."
)
_REMEDIATION_TOOLS_DEBUG = (
    "Remove 'tools-debug' from IMAGE_FEATURES for production builds. "
    "It pulls in gdb / strace and other on-target debug tooling."
)
_REMEDIATION_DBG_PKGS = (
    "Remove 'dbg-pkgs' from IMAGE_FEATURES for production builds. It "
    "installs the -dbg variant of every package, inflating image size "
    "and exposing debug symbols."
)
_REMEDIATION_ECLIPSE_DEBUG = (
    "Remove 'eclipse-debug' from IMAGE_FEATURES. It pulls in remote "
    "debug agents that have no place on a production image."
)
_REMEDIATION_DEV_PKGS = (
    "Consider removing 'dev-pkgs' from IMAGE_FEATURES for production "
    "builds. Development headers and static libraries are not needed "
    "on a shipping image and increase the attack surface."
)

# (severity, cra_mapping, remediation, message-suffix)
_FEATURE_TABLE: dict[str, tuple[str, list[str], str, str]] = {
    "debug-tweaks": (
        "high",
        _HIGH_CRA,
        _REMEDIATION_DEBUG_TWEAKS,
        "enables passwordless root and other shipping-blocking defaults",
    ),
    "allow-empty-password": (
        "high",
        _HIGH_CRA,
        _REMEDIATION_PASSWORD,
        "allows accounts with empty passwords",
    ),
    "empty-root-password": (
        "high",
        _HIGH_CRA,
        _REMEDIATION_PASSWORD,
        "leaves the root account with an empty password",
    ),
    "allow-root-login": (
        "high",
        _HIGH_CRA,
        _REMEDIATION_ROOT_LOGIN,
        "permits root login over getty",
    ),
    "tools-debug": (
        "medium",
        _LOWER_CRA,
        _REMEDIATION_TOOLS_DEBUG,
        "installs on-target debug tooling (gdb, strace)",
    ),
    "dbg-pkgs": (
        "medium",
        _LOWER_CRA,
        _REMEDIATION_DBG_PKGS,
        "installs -dbg variants of every package",
    ),
    "eclipse-debug": (
        "medium",
        _LOWER_CRA,
        _REMEDIATION_ECLIPSE_DEBUG,
        "installs remote debug agents (TCF / GDB server)",
    ),
    "dev-pkgs": (
        "low",
        _LOWER_CRA,
        _REMEDIATION_DEV_PKGS,
        "installs development headers and static libraries",
    ),
}


def _read_config_files(build_dir: Path) -> list[tuple[Path, str]]:
    """Read ``conf/local.conf`` and ``conf/auto.conf`` if present."""
    configs: list[tuple[Path, str]] = []
    for name in _CONF_FILES:
        path = build_dir / name
        if not path.is_file():
            continue
        try:
            configs.append((path, path.read_text()))
        except (OSError, UnicodeDecodeError):
            logger.debug("Could not read %s", path)
    return configs


def _parse_variable(content: str, var_name: str) -> list[str]:
    """Extract all values assigned to ``var_name`` across a conf file.

    Mirrors the parser used by the UEFI detector
    (``shipcheck.checks.code_integrity.uefi._parse_variable``):
    handles plain assignment, ``+=``, ``?=``, ``??=``, ``:append``,
    and multi-line values joined with ``\\``. Values are split on
    whitespace so a single ``IMAGE_FEATURES = "a b c"`` returns three
    entries.
    """
    values: list[str] = []
    normalized = re.sub(r"\\\n\s*", " ", content)
    pattern = rf'^[ \t]*{re.escape(var_name)}\s*(?:\?\??=|\+?=)\s*"([^"]*)"'
    for match in re.finditer(pattern, normalized, re.MULTILINE):
        values.extend(match.group(1).split())
    append_pattern = rf'^[ \t]*{re.escape(var_name)}:append\s*=\s*"([^"]*)"'
    for match in re.finditer(append_pattern, normalized, re.MULTILINE):
        values.extend(match.group(1).split())
    return values


def _collect_image_features(configs: list[tuple[Path, str]]) -> list[str]:
    """Return all ``IMAGE_FEATURES`` entries across the provided conf files.

    Order is preserved across files (``local.conf`` first, then
    ``auto.conf``) and within a file. The aggregator deduplicates so
    each literal entry produces exactly one finding even when the user
    appends the same feature in multiple places.
    """
    entries: list[str] = []
    for _path, content in configs:
        entries.extend(_parse_variable(content, "IMAGE_FEATURES"))
    return entries


class ImageFeaturesCheck(BaseCheck):
    """Detect insecure entries in ``IMAGE_FEATURES``.

    Each literal entry that matches the hardcoded severity table
    produces one ``Finding``. The check returns ``PASS`` when no entry
    matches; absence of hardening features never causes a FAIL.
    """

    id = "image-features"
    name = "Image Features"
    framework = ["CRA"]
    severity = "critical"
    cra_mapping = list(CRA_MAPPING)

    def run(self, build_dir: Path, config: dict) -> CheckResult:  # noqa: ARG002
        configs = _read_config_files(build_dir)
        entries = _collect_image_features(configs)

        findings: list[Finding] = []
        seen: set[str] = set()
        for entry in entries:
            if entry in seen:
                continue
            seen.add(entry)
            row = _FEATURE_TABLE.get(entry)
            if row is None:
                continue
            severity, cra, remediation, suffix = row
            findings.append(
                Finding(
                    message=f"IMAGE_FEATURES contains '{entry}': {suffix}",
                    severity=severity,
                    remediation=remediation,
                    cra_mapping=list(cra),
                )
            )

        status = determine_status(findings)

        if findings:
            noun = "entry" if len(findings) == 1 else "entries"
            summary = f"{len(findings)} insecure IMAGE_FEATURES {noun} detected"
        elif not configs:
            summary = "No IMAGE_FEATURES value found (no conf/local.conf or conf/auto.conf)"
        elif not entries:
            summary = "No IMAGE_FEATURES value found in conf/local.conf or conf/auto.conf"
        else:
            summary = "IMAGE_FEATURES contains no entries from the insecure-feature table"

        return CheckResult(
            check_id=self.id,
            check_name=self.name,
            status=status,
            score=0,
            max_score=0,
            findings=findings,
            summary=summary,
            cra_mapping=list(CRA_MAPPING),
        )


__all__ = ["CRA_MAPPING", "ImageFeaturesCheck"]

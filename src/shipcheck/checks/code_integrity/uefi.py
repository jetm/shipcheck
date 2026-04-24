"""UEFI Secure Boot mechanism detector.

Ports the UEFI-side of the retired ``secureboot.py`` check into the
``code-integrity`` package as a single ``detect`` function returning a
``MechanismResult``. The aggregator in ``CodeIntegrityCheck.run``
(task 1.7) consumes this alongside the FIT, dm-verity, and IMA/EVM
detectors.

Signals (in order):

1. ``IMAGE_CLASSES`` in ``conf/local.conf`` / ``conf/auto.conf``
   contains one of the known signing classes (``uefi-sign``,
   ``sbsign``, ``image-uefi-sign``, ``secureboot``). Presence of a
   signing class is what flips ``present`` to ``True``.
2. Key-variable extraction from ``SECURE_BOOT_SIGNING_KEY``,
   ``SECURE_BOOT_DB_KEY``, ``UEFI_SIGN_KEY``. Missing files or
   missing variables become misconfiguration findings.
3. Test/development key flagging via the default pattern set
   (``test``, ``development``, ``sample``, ``example``, ``debug``,
   plus ``ovmf`` / ``edk2`` test artifacts) and any extra patterns
   the user supplied via ``known_test_keys``.
4. EFI-artifact discovery under ``tmp/deploy/images/`` -- ``.efi``
   files without a signing class produce a high-severity finding so
   the aggregator can surface the inconsistency.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import TYPE_CHECKING

from shipcheck.checks.code_integrity import MechanismResult
from shipcheck.models import Finding

if TYPE_CHECKING:
    from collections.abc import Mapping

logger = logging.getLogger(__name__)

_SIGNING_CLASSES = {"uefi-sign", "sbsign", "image-uefi-sign", "secureboot"}

_KEY_VARIABLES = ("SECURE_BOOT_SIGNING_KEY", "SECURE_BOOT_DB_KEY", "UEFI_SIGN_KEY")

_DEFAULT_TEST_KEY_PATTERNS = frozenset({"test", "development", "sample", "example", "debug"})

_OVMF_TEST_PATTERNS = frozenset({"ovmf", "edk2"})

_CONF_FILES = ("conf/local.conf", "conf/auto.conf")

_UEFI_CRA_MAPPING = ["I.P1.c", "I.P1.d", "I.P1.f"]

_REMEDIATION_MISSING_KEY = "Set {var} in conf/local.conf to point to a valid signing key file."

_REMEDIATION_TEST_KEY = (
    "Replace development/test keys with production keys before shipping. "
    "Test keys are publicly known and provide no security."
)

_REMEDIATION_MISCONFIGURATION = (
    "EFI artifacts found without signing configuration. "
    "Either sign them via IMAGE_CLASSES or remove the unsigned binaries."
)

_REMEDIATION_NO_KEY_VAR = (
    "Signing class configured but no SECURE_BOOT_SIGNING_KEY / "
    "SECURE_BOOT_DB_KEY / UEFI_SIGN_KEY assignment was found in conf/."
)


def _read_config_files(build_dir: Path) -> list[tuple[Path, str]]:
    """Read ``conf/local.conf`` and ``conf/auto.conf`` if present.

    Returns a list of ``(path, content)`` tuples. Files that fail to
    decode as text are skipped with a debug log; the detector's
    surrounding logic treats missing/unreadable conf files as "no
    UEFI signal".
    """
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

    Handles plain assignment, ``+=``, ``?=``, ``??=``, ``:append``,
    and multi-line values joined with ``\\``. Values are split on
    whitespace so a single ``IMAGE_CLASSES = "a b c"`` returns three
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


def _detect_signing_classes(configs: list[tuple[Path, str]]) -> list[str]:
    """Return matched signing-class names from ``IMAGE_CLASSES``."""
    found: list[str] = []
    for _path, content in configs:
        for cls in _parse_variable(content, "IMAGE_CLASSES"):
            if cls in _SIGNING_CLASSES:
                found.append(cls)
    return found


def _extract_key_paths(configs: list[tuple[Path, str]]) -> dict[str, str]:
    """Extract last-assignment value for each known key variable."""
    keys: dict[str, str] = {}
    for _path, content in configs:
        for var in _KEY_VARIABLES:
            values = _parse_variable(content, var)
            if values:
                keys[var] = values[-1]
    return keys


def _validate_key_files(key_paths: dict[str, str], build_dir: Path) -> list[Finding]:
    """Emit findings for key variables whose target file is missing."""
    findings: list[Finding] = []
    for var, raw_path in key_paths.items():
        path = Path(raw_path)
        if not path.is_absolute():
            path = build_dir / path
        if path.is_file():
            continue
        findings.append(
            Finding(
                message=f"Key file not found: {var} = {raw_path}",
                severity="high",
                remediation=_REMEDIATION_MISSING_KEY.format(var=var),
                cra_mapping=list(_UEFI_CRA_MAPPING),
            )
        )
    return findings


def _flag_test_keys(
    key_paths: dict[str, str],
    build_dir: Path,
    extra_patterns: list[str],
) -> list[Finding]:
    """Emit findings for keys whose path matches a test/dev pattern."""
    findings: list[Finding] = []
    patterns = _DEFAULT_TEST_KEY_PATTERNS | {p.lower() for p in extra_patterns}

    for var, raw_path in key_paths.items():
        path = Path(raw_path)
        if not path.is_absolute():
            path = build_dir / path

        name_lower = path.name.lower()
        stem_lower = path.stem.lower()
        path_str_lower = str(path).lower()

        flagged = any(p in name_lower or p in stem_lower for p in patterns)

        if not flagged:
            try:
                rel = path.relative_to(build_dir)
            except ValueError:
                rel = path
            for part in rel.parts[:-1]:
                part_lower = part.lower()
                if any(p in part_lower for p in patterns):
                    flagged = True
                    break

        if not flagged:
            flagged = any(ovmf in path_str_lower for ovmf in _OVMF_TEST_PATTERNS)

        if flagged:
            findings.append(
                Finding(
                    message=f"Test/development key detected: {var} = {raw_path}",
                    severity="high",
                    remediation=_REMEDIATION_TEST_KEY,
                    cra_mapping=list(_UEFI_CRA_MAPPING),
                )
            )
    return findings


def _find_efi_artifacts(build_dir: Path) -> list[Path]:
    """Return ``.efi`` files under ``tmp/deploy/images/`` (recursive)."""
    images_dir = build_dir / "tmp" / "deploy" / "images"
    if not images_dir.is_dir():
        return []
    return sorted(images_dir.rglob("*.efi"))


def detect(build_dir: Path, config: Mapping[str, object] | None = None) -> MechanismResult:
    """Detect UEFI Secure Boot configuration.

    Args:
        build_dir: Path to the Yocto build directory.
        config: Optional mapping carrying ``known_test_keys`` (a list
            of extra substrings that should be treated as test/dev key
            indicators). Accepts either the raw ``CodeIntegrityConfig``
            dict or any compatible mapping.

    Returns:
        A ``MechanismResult`` with ``present=True`` when a signing
        class is configured. ``misconfigurations`` carries findings
        about missing/test keys and unsigned EFI artifacts. The
        ``evidence`` list names the matched class, configured key
        variables, and discovered EFI artifacts.
    """
    cfg = config or {}
    raw_known = cfg.get("known_test_keys", []) if isinstance(cfg, dict) else []
    known_test_keys: list[str] = list(raw_known) if isinstance(raw_known, list) else []

    configs = _read_config_files(build_dir)
    signing_classes = _detect_signing_classes(configs)
    key_paths = _extract_key_paths(configs)
    efi_artifacts = _find_efi_artifacts(build_dir)

    present = bool(signing_classes)
    evidence: list[str] = []
    misconfigurations: list[Finding] = []

    if present:
        evidence.append(f"IMAGE_CLASSES: {', '.join(sorted(set(signing_classes)))}")

        if key_paths:
            for var, raw_path in key_paths.items():
                evidence.append(f"{var} = {raw_path}")
            misconfigurations.extend(_validate_key_files(key_paths, build_dir))
            misconfigurations.extend(_flag_test_keys(key_paths, build_dir, known_test_keys))
        else:
            misconfigurations.append(
                Finding(
                    message="Signing class configured but no key variables found",
                    severity="high",
                    remediation=_REMEDIATION_NO_KEY_VAR,
                    cra_mapping=list(_UEFI_CRA_MAPPING),
                )
            )

        if efi_artifacts:
            evidence.append(f"{len(efi_artifacts)} EFI artifact(s) under tmp/deploy/images/")
    elif efi_artifacts:
        # No signing class but EFI artifacts exist -- emit a finding
        # so the aggregator can surface the inconsistency. The detector
        # itself still reports ``present=False`` because UEFI Secure
        # Boot is not configured.
        misconfigurations.append(
            Finding(
                message=(
                    f"EFI artifacts found ({len(efi_artifacts)} .efi files) "
                    "but no UEFI signing class configured"
                ),
                severity="high",
                remediation=_REMEDIATION_MISCONFIGURATION,
                cra_mapping=list(_UEFI_CRA_MAPPING),
            )
        )

    return MechanismResult(
        present=present,
        confidence="high" if present else "low",
        evidence=evidence,
        misconfigurations=misconfigurations,
    )


__all__ = ["detect"]

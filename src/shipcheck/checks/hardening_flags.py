"""``hardening-flags`` check.

Detects compile-time hardening evidence at *global build-config scope*
in a Yocto build via two signals:

- **Signal A** -- inclusion of ``security_flags.inc`` (any file whose
  basename matches ``security_flags.inc``) via ``require`` or
  ``include`` directives in ``conf/local.conf``, ``conf/auto.conf``,
  or any ``conf/distro/*.conf`` reachable from those files. Detection
  follows ``require`` chains one level deep.
- **Signal B** -- ``TUNE_CCARGS`` and ``SELECTED_OPTIMIZATION``
  parsing for the four hardening flag classes:

  - ``-D_FORTIFY_SOURCE=2`` / ``-D_FORTIFY_SOURCE=3`` (FORTIFY_SOURCE)
  - ``-fstack-protector-strong``                       (stack-protector)
  - ``-fPIE``                                          (PIE)
  - ``-Wl,-z,relro`` *and* ``-Wl,-z,now`` together     (RELRO+now)

Per-recipe override syntax (``TUNE_CCARGS:append:pn-foo``,
``SELECTED_OPTIMIZATION:pn-bar``) is **not** considered here per
``specs/hardening-flags/spec.md`` Requirement: Global build-config
scope only. Per-recipe coverage is deferred to a follow-on change.

Maps to CRA Annex I Part II §c (no known exploitable vulnerabilities)
and §j (limit attack surfaces). Status semantics (PASS / WARN / FAIL
across the two signals) and per-finding ``cra_mapping`` wiring belong
to task 3.2.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from shipcheck.models import BaseCheck, CheckResult, CheckStatus, Finding

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger(__name__)

# CRA catalog IDs covered by this check, applied as the
# ``CheckResult.cra_mapping`` regardless of which signal (if any)
# fires. Per-finding ``cra_mapping`` is a non-empty subset wired up by
# task 3.2.
CRA_MAPPING: list[str] = ["I.P2.c", "I.P2.j"]

_TOP_LEVEL_CONF_FILES = ("local.conf", "auto.conf")
"""Conf files read directly under ``build_dir/conf/``.

These are the entry points for both signals: signal A scans for
``require`` / ``include`` lines naming ``security_flags.inc``, and
signal B scans for global ``TUNE_CCARGS`` / ``SELECTED_OPTIMIZATION``
assignments.
"""

_SECURITY_FLAGS_BASENAME = "security_flags.inc"

_DIRECTIVE_PATTERN = re.compile(
    r"^[ \t]*(?:require|include)[ \t]+(\S+)\s*$",
    re.MULTILINE,
)
"""Match ``require <path>`` or ``include <path>`` lines.

Bitbake's parser treats the two as functionally equivalent for our
purposes: ``require`` errors if the file is missing, ``include``
silently skips. Both surface as evidence that the build *intends* to
pull in the named file. The pattern is multiline-anchored to avoid
matching commented variants.
"""

_FORTIFY_TOKENS = ("-D_FORTIFY_SOURCE=2", "-D_FORTIFY_SOURCE=3")
_STACK_PROTECTOR_TOKEN = "-fstack-protector-strong"
_PIE_TOKEN = "-fPIE"
_RELRO_TOKEN = "-Wl,-z,relro"
_NOW_TOKEN = "-Wl,-z,now"


@dataclass
class SignalAResult:
    """Outcome of signal-A detection.

    Attributes:
        present: True if any reachable conf file requires or includes
            ``security_flags.inc``.
        including_files: The conf files that named the include. Order
            preserved (entry-point conf files first, then any distro
            conf followed via the require chain).
    """

    present: bool = False
    including_files: list[Path] = field(default_factory=list)


@dataclass
class SignalBResult:
    """Outcome of signal-B detection.

    Each flag class is reported independently per the spec's
    "report each flag as present or absent independently" requirement.

    Attributes:
        fortify_source: True if ``-D_FORTIFY_SOURCE=2`` or ``=3`` is
            present in any global ``TUNE_CCARGS`` /
            ``SELECTED_OPTIMIZATION`` assignment.
        stack_protector: True if ``-fstack-protector-strong`` is
            present.
        pie: True if ``-fPIE`` is present.
        relro_now: True if *both* ``-Wl,-z,relro`` and ``-Wl,-z,now``
            are present (they form a single defensive class -- RELRO
            without ``now`` leaves the GOT writable after relocation).
    """

    fortify_source: bool = False
    stack_protector: bool = False
    pie: bool = False
    relro_now: bool = False

    @property
    def any_present(self) -> bool:
        """True when at least one flag class is detected."""
        return self.fortify_source or self.stack_protector or self.pie or self.relro_now


def _read_text(path: Path) -> str | None:
    """Return file text or ``None`` if unreadable."""
    try:
        return path.read_text()
    except (OSError, UnicodeDecodeError):
        logger.debug("Could not read %s", path)
        return None


def _read_top_level_confs(build_dir: Path) -> list[tuple[Path, str]]:
    """Read ``conf/local.conf`` and ``conf/auto.conf`` if present."""
    out: list[tuple[Path, str]] = []
    for name in _TOP_LEVEL_CONF_FILES:
        path = build_dir / "conf" / name
        if not path.is_file():
            continue
        content = _read_text(path)
        if content is None:
            continue
        out.append((path, content))
    return out


def _parse_global_variable(content: str, var_name: str) -> list[str]:
    """Extract values assigned to ``var_name`` at *global* scope only.

    Recognises plain assignment, ``+=``, ``?=``, ``??=``, ``:append =``
    (the colon-form append on the bare variable), and multi-line
    values joined with ``\\``. Per-recipe overrides such as
    ``TUNE_CCARGS:append:pn-foo`` or ``SELECTED_OPTIMIZATION:pn-bar``
    are deliberately *not* matched -- the spec scopes signal B to the
    global build configuration only.

    Values are split on whitespace so a single
    ``TUNE_CCARGS = "-fPIE -Wl,-z,relro"`` returns two entries.
    """
    values: list[str] = []
    normalized = re.sub(r"\\\n\s*", " ", content)

    # Plain / ?= / ??= / += assignment with no override suffix.
    plain = rf'^[ \t]*{re.escape(var_name)}\s*(?:\?\??=|\+?=)\s*"([^"]*)"'
    for match in re.finditer(plain, normalized, re.MULTILINE):
        values.extend(match.group(1).split())

    # ``VAR:append = "..."`` -- a global append on the bare variable
    # (no ``:pn-foo`` recipe scope). The negative lookahead rejects
    # any further ``:`` segment that would indicate a per-recipe
    # override or override-style chain.
    bare_append = rf'^[ \t]*{re.escape(var_name)}:append(?![:\w])\s*=\s*"([^"]*)"'
    for match in re.finditer(bare_append, normalized, re.MULTILINE):
        values.extend(match.group(1).split())

    return values


def _find_security_flags_directives(content: str) -> bool:
    """True if any ``require`` / ``include`` line names ``security_flags.inc``.

    Match is by basename so a vendored copy under a non-standard
    layer prefix still counts -- the spec says any file whose
    basename matches ``security_flags.inc`` qualifies.
    """
    for match in _DIRECTIVE_PATTERN.finditer(content):
        target = match.group(1)
        # Strip trailing comments / whitespace defensively.
        target = target.split("#", 1)[0].strip()
        if not target:
            continue
        # Compare on basename only; bitbake variables like
        # ``${LAYERDIR}/security_flags.inc`` resolve at build time and
        # we cannot expand them without a parser, but the basename is
        # a reliable structural cue.
        basename = target.rsplit("/", 1)[-1]
        if basename == _SECURITY_FLAGS_BASENAME:
            return True
    return False


def _resolve_distro_confs(
    build_dir: Path,
    top_confs: list[tuple[Path, str]],
) -> list[tuple[Path, str]]:
    """Return ``conf/distro/*.conf`` files reachable from ``DISTRO``.

    Implements one level of require-chain depth: read ``DISTRO`` from
    the top-level confs and look up ``conf/distro/<distro>.conf``
    inside the build directory. Distro confs that live in external
    layers cannot be resolved without a layer index -- the spec
    explicitly limits chasing to one level deep, so we only follow
    the in-build path.
    """
    distros: list[str] = []
    for _path, content in top_confs:
        distros.extend(_parse_global_variable(content, "DISTRO"))
    out: list[tuple[Path, str]] = []
    seen: set[Path] = set()
    for distro in distros:
        candidate = build_dir / "conf" / "distro" / f"{distro}.conf"
        if candidate in seen or not candidate.is_file():
            continue
        seen.add(candidate)
        content = _read_text(candidate)
        if content is None:
            continue
        out.append((candidate, content))
    return out


def detect_signal_a(build_dir: Path) -> SignalAResult:
    """Detect ``security_flags.inc`` inclusion (signal A).

    Searches ``conf/local.conf``, ``conf/auto.conf``, and any
    ``conf/distro/<distro>.conf`` reachable in one require-chain hop
    from the top-level confs. Returns a populated
    :class:`SignalAResult` -- ``present`` flips to ``True`` on the
    first match and ``including_files`` collects every file that
    named the include.
    """
    result = SignalAResult()
    top_confs = _read_top_level_confs(build_dir)

    for path, content in top_confs:
        if _find_security_flags_directives(content):
            result.present = True
            result.including_files.append(path)

    for path, content in _resolve_distro_confs(build_dir, top_confs):
        if _find_security_flags_directives(content):
            result.present = True
            result.including_files.append(path)

    return result


def detect_signal_b(build_dir: Path) -> SignalBResult:
    """Parse ``TUNE_CCARGS`` / ``SELECTED_OPTIMIZATION`` (signal B).

    Reads ``conf/local.conf`` and ``conf/auto.conf`` and inspects
    *global* assignments only. Each of the four flag classes is
    reported independently: FORTIFY_SOURCE, stack-protector, PIE, and
    RELRO+now (the last requires *both* ``-Wl,-z,relro`` and
    ``-Wl,-z,now``).
    """
    top_confs = _read_top_level_confs(build_dir)

    tokens: list[str] = []
    for _path, content in top_confs:
        tokens.extend(_parse_global_variable(content, "TUNE_CCARGS"))
        tokens.extend(_parse_global_variable(content, "SELECTED_OPTIMIZATION"))

    token_set = set(tokens)

    return SignalBResult(
        fortify_source=any(t in token_set for t in _FORTIFY_TOKENS),
        stack_protector=_STACK_PROTECTOR_TOKEN in token_set,
        pie=_PIE_TOKEN in token_set,
        relro_now=_RELRO_TOKEN in token_set and _NOW_TOKEN in token_set,
    )


class HardeningFlagsCheck(BaseCheck):
    """Detect compile-time hardening evidence at global build-config scope.

    Composes signal A (``security_flags.inc`` inclusion) and signal B
    (``TUNE_CCARGS`` / ``SELECTED_OPTIMIZATION`` parsing) and surfaces
    per-class detection in the result. Status semantics (PASS / WARN /
    FAIL) and per-finding ``cra_mapping`` wiring are layered on by
    task 3.2 -- this scaffold returns a minimal informational result
    so the registry, CLI plumbing, and dossier renderers can pick up
    the new check without a follow-up rewrite.
    """

    id = "hardening-flags"
    name = "Hardening Flags"
    framework = ["CRA"]
    severity = "critical"
    cra_mapping = list(CRA_MAPPING)

    def run(self, build_dir: Path, config: dict) -> CheckResult:  # noqa: ARG002
        signal_a = detect_signal_a(build_dir)
        signal_b = detect_signal_b(build_dir)

        # Status wiring lives in task 3.2; for now classify by whether
        # *any* hardening evidence was observed so the result is not
        # silently misleading.
        findings: list[Finding] = []
        any_evidence = signal_a.present or signal_b.any_present
        status = CheckStatus.PASS if any_evidence else CheckStatus.SKIP

        if any_evidence:
            summary_parts: list[str] = []
            if signal_a.present:
                count = len(signal_a.including_files)
                summary_parts.append(f"security_flags.inc included via {count} file(s)")
            if signal_b.any_present:
                detected = [
                    name
                    for name, flag in (
                        ("FORTIFY_SOURCE", signal_b.fortify_source),
                        ("stack-protector", signal_b.stack_protector),
                        ("PIE", signal_b.pie),
                        ("RELRO+now", signal_b.relro_now),
                    )
                    if flag
                ]
                summary_parts.append(f"hardening flags: {', '.join(detected)}")
            summary = "; ".join(summary_parts)
        else:
            summary = "No compile-time hardening evidence detected"

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


__all__ = [
    "CRA_MAPPING",
    "HardeningFlagsCheck",
    "SignalAResult",
    "SignalBResult",
    "detect_signal_a",
    "detect_signal_b",
]

"""IMA/EVM mechanism detector.

New detector (no source file to port from) that implements the
"IMA/EVM detection signal hierarchy" from design.md. Unlike the UEFI,
FIT, and dm-verity detectors, IMA/EVM is rare in default Yocto builds
and configured via a mix of kernel config, package install, and boot
arguments -- so the detector inspects four loosely coupled signals and
assigns confidence by which combination is observed.

Signals (in order of strength):

1. Kernel ``.config`` symbols under
   ``tmp/work/.../linux-yocto*/.config``: ``CONFIG_IMA=y``,
   ``CONFIG_IMA_APPRAISE=y``, ``CONFIG_EVM=y``. ``=m`` (module) values
   also count as enabled. Two or more matched symbols → high
   confidence; a single matched symbol → medium.
2. License-manifest entry ``ima-evm-utils`` in
   ``tmp/deploy/licenses/*/license.manifest``. Combined with any
   kernel-config signal → high; alone → medium.
3. ``IMAGE_INSTALL`` reference to ``ima-evm-utils`` or
   ``ima-policy-*`` in ``conf/local.conf`` / ``conf/auto.conf``. Low
   confidence when no other signal is present.
4. Boot-arg evidence (``ima_policy=`` token in
   ``tmp/deploy/images/*/bootargs`` or any bootloader config file in
   that directory). Best-effort supplementary signal: raises
   confidence one tier when combined with another signal but does not
   stand alone.

The detector emits no misconfigurations -- absence is surfaced by the
aggregator (task 1.7) as a top-level finding when every mechanism
reports ``present=False``.
"""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING

from shipcheck.checks.code_integrity import MechanismResult

if TYPE_CHECKING:
    from collections.abc import Mapping
    from pathlib import Path

logger = logging.getLogger(__name__)

_KERNEL_WORK_GLOB = "tmp/work/*/linux-yocto*/*/.config"
_LICENSE_MANIFEST_GLOB = "tmp/deploy/licenses/*/license.manifest"
_IMAGES_DIR = ("tmp", "deploy", "images")
_CONF_FILES = ("conf/local.conf", "conf/auto.conf")

_IMA_KERNEL_SYMBOLS = ("CONFIG_IMA", "CONFIG_IMA_APPRAISE", "CONFIG_EVM")
_IMA_PACKAGE = "ima-evm-utils"
_IMA_POLICY_PATTERN = re.compile(r"\bima-policy-[A-Za-z0-9_.+-]+")
_BOOT_ARG_PATTERN = re.compile(r"\bima_policy=")

_CONFIDENCE_RANK = {"low": 0, "medium": 1, "high": 2}
_CONFIDENCE_BY_RANK = {0: "low", 1: "medium", 2: "high"}


def _read_text(path: Path) -> str | None:
    """Return file contents as text, or ``None`` if unreadable."""
    try:
        return path.read_text()
    except (OSError, UnicodeDecodeError):
        logger.debug("Failed to read %s", path)
        return None


def _detect_kernel_symbols(build_dir: Path) -> list[str]:
    """Return matched IMA/EVM kernel-config symbol names.

    Scans every ``.config`` under ``tmp/work/*/linux-yocto*/*/`` (the
    Yocto kernel build's work directory) and returns the list of
    ``CONFIG_IMA*`` / ``CONFIG_EVM`` symbols set to a non-disabled
    value. ``=y`` and ``=m`` count as enabled; ``=n``,
    ``# CONFIG_FOO is not set``, and unset symbols do not.
    """
    matched: set[str] = set()
    enable_pattern = re.compile(
        r"^[ \t]*(" + "|".join(_IMA_KERNEL_SYMBOLS) + r")[ \t]*=[ \t]*([ymYM])\b",
        re.MULTILINE,
    )
    for cfg in build_dir.glob(_KERNEL_WORK_GLOB):
        if not cfg.is_file():
            continue
        text = _read_text(cfg)
        if text is None:
            continue
        for match in enable_pattern.finditer(text):
            matched.add(match.group(1))
    # Preserve a stable, documented order in evidence.
    return [sym for sym in _IMA_KERNEL_SYMBOLS if sym in matched]


def _detect_license_manifest_package(build_dir: Path) -> bool:
    """Return True when ``ima-evm-utils`` appears in any license.manifest."""
    pattern = re.compile(rf"^[ \t]*PACKAGE NAME:\s*{re.escape(_IMA_PACKAGE)}\b", re.MULTILINE)
    for manifest in build_dir.glob(_LICENSE_MANIFEST_GLOB):
        if not manifest.is_file():
            continue
        text = _read_text(manifest)
        if text is None:
            continue
        if pattern.search(text):
            return True
    return False


def _detect_image_install(build_dir: Path) -> bool:
    """Return True when IMAGE_INSTALL references ima-evm-utils / ima-policy-*."""
    for conf_name in _CONF_FILES:
        path = build_dir / conf_name
        if not path.is_file():
            continue
        text = _read_text(path)
        if text is None:
            continue
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if line.startswith("#") or "IMAGE_INSTALL" not in line:
                continue
            if _IMA_PACKAGE in line or _IMA_POLICY_PATTERN.search(line):
                return True
    return False


def _detect_boot_arg(build_dir: Path) -> bool:
    """Return True when an ``ima_policy=`` token is found in any boot-arg file."""
    images_dir = build_dir.joinpath(*_IMAGES_DIR)
    if not images_dir.is_dir():
        return False
    for path in images_dir.rglob("bootargs*"):
        if not path.is_file():
            continue
        text = _read_text(path)
        if text is None:
            continue
        if _BOOT_ARG_PATTERN.search(text):
            return True
    return False


def _bump(confidence: str) -> str:
    """Raise a confidence tier by one, capped at ``"high"``."""
    return _CONFIDENCE_BY_RANK[min(2, _CONFIDENCE_RANK[confidence] + 1)]


def detect(build_dir: Path, config: Mapping[str, object] | None = None) -> MechanismResult:
    """Detect IMA/EVM configuration via the four-signal hierarchy.

    Args:
        build_dir: Path to the Yocto build directory.
        config: Optional mapping. Reserved for future expansion; the
            IMA/EVM detector currently does not read any keys
            (``expect_ima`` lives on ``CodeIntegrityConfig`` and is
            consumed by the aggregator, not this detector).

    Returns:
        A ``MechanismResult``. ``present=True`` when at least one
        non-boot-arg signal is observed (a boot-arg alone never flips
        ``present``). ``confidence`` follows the design.md hierarchy:
        2+ kernel symbols → high; license manifest + kernel symbol →
        high; single kernel symbol or license manifest alone → medium;
        IMAGE_INSTALL alone → low. A boot-arg signal raises confidence
        one tier when combined with any other signal. ``evidence``
        lists the matched symbols, packages, and config keys.
        ``misconfigurations`` is always empty: the IMA/EVM detector
        does not emit per-mechanism findings; absence is the
        aggregator's job.
    """
    _ = config  # reserved for future use; expect_ima belongs to the aggregator

    kernel_symbols = _detect_kernel_symbols(build_dir)
    has_license_pkg = _detect_license_manifest_package(build_dir)
    has_image_install = _detect_image_install(build_dir)
    has_boot_arg = _detect_boot_arg(build_dir)

    primary_signals = bool(kernel_symbols) or has_license_pkg or has_image_install
    if not primary_signals:
        return MechanismResult(
            present=False,
            confidence="low",
            evidence=[],
            misconfigurations=[],
        )

    if len(kernel_symbols) >= 2 or (kernel_symbols and has_license_pkg):
        confidence = "high"
    elif kernel_symbols or has_license_pkg:
        confidence = "medium"
    else:
        # Only IMAGE_INSTALL reference seen.
        confidence = "low"

    if has_boot_arg:
        confidence = _bump(confidence)

    evidence: list[str] = []
    for sym in kernel_symbols:
        evidence.append(f"{sym} in kernel .config")
    if has_license_pkg:
        evidence.append(f"{_IMA_PACKAGE} in license.manifest")
    if has_image_install:
        evidence.append(f"IMAGE_INSTALL references {_IMA_PACKAGE} / ima-policy-*")
    if has_boot_arg:
        evidence.append("ima_policy= boot argument")

    return MechanismResult(
        present=True,
        confidence=confidence,
        evidence=evidence,
        misconfigurations=[],
    )


__all__ = ["detect"]

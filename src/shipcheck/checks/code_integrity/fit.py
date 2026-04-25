"""Signed FIT image mechanism detector.

Ports the FIT-related logic from the retired ``image_signing.py`` check
into the ``code-integrity`` package as a single ``detect`` function
returning a ``MechanismResult``. The aggregator in
``CodeIntegrityCheck.run`` (task 1.7) consumes this alongside the UEFI,
dm-verity, and IMA/EVM detectors.

Signals (in order):

1. Signed FIT artifact under ``tmp/deploy/images/`` -- a ``.itb`` or
   ``.fit`` file whose first four bytes are FDT magic
   (``0xD00DFEED``) and whose body contains the literal byte string
   ``signature``. This is the strongest signal and yields
   ``confidence="high"``.
2. Unsigned FIT artifact -- a ``.itb`` / ``.fit`` file with FDT magic
   but no ``signature`` node. ``present`` stays ``False`` (no
   integrity mechanism actually configured) but a high-severity
   misconfiguration finding surfaces so the aggregator can report it.
3. ``UBOOT_SIGN_ENABLE`` declared in ``conf/local.conf`` /
   ``conf/auto.conf``. Indicates the build is configured to sign FIT
   images even when no signed artifact has been produced yet (e.g.
   pre-build inspection). Yields ``confidence="medium"``.
"""

from __future__ import annotations

import logging
import struct
from typing import TYPE_CHECKING

from shipcheck.checks.code_integrity import MechanismResult
from shipcheck.models import Finding

if TYPE_CHECKING:
    from collections.abc import Mapping
    from pathlib import Path

logger = logging.getLogger(__name__)

_IMAGES_SUBDIR = ("tmp", "deploy", "images")
_CONF_FILES = ("conf/local.conf", "conf/auto.conf")
_FDT_MAGIC = 0xD00DFEED
_FIT_EXTENSIONS = (".itb", ".fit")

_FIT_CRA_MAPPING = ["I.P1.f"]

_REMEDIATION_UNSIGNED_FIT = (
    "Sign FIT images with a private key using mkimage -F -k <keydir> -r <image>."
)


def _find_fit_files(images_dir: Path) -> list[Path]:
    """Recursively find ``.itb`` and ``.fit`` files under ``images_dir``."""
    files: list[Path] = []
    if not images_dir.is_dir():
        return files
    for ext in _FIT_EXTENSIONS:
        files.extend(images_dir.rglob(f"*{ext}"))
    return sorted(files)


def _read_header_and_body(path: Path) -> tuple[int | None, bytes]:
    """Return ``(magic, body)`` from a FIT file, or ``(None, b"")`` on error.

    ``magic`` is ``None`` when the file is shorter than four bytes or
    cannot be read; callers treat that the same as "not a FIT image".
    """
    try:
        with path.open("rb") as f:
            header = f.read(4)
            if len(header) < 4:
                return None, b""
            magic = struct.unpack(">I", header)[0]
            body = f.read()
    except OSError:
        logger.debug("Failed to read FIT image: %s", path)
        return None, b""
    return magic, body


def _is_signed_fit(path: Path) -> bool:
    """Check if a FIT image has FDT magic and contains a signature node."""
    magic, body = _read_header_and_body(path)
    if magic != _FDT_MAGIC:
        return False
    return b"signature" in body


def _has_fdt_magic(path: Path) -> bool:
    """Check if a file starts with FDT magic bytes."""
    magic, _body = _read_header_and_body(path)
    return magic == _FDT_MAGIC


def _detect_uboot_sign_enable(build_dir: Path) -> bool:
    """Check conf files for ``UBOOT_SIGN_ENABLE`` indicating FIT signing."""
    for conf_name in _CONF_FILES:
        conf_path = build_dir / conf_name
        if not conf_path.is_file():
            continue
        try:
            text = conf_path.read_text()
        except (OSError, UnicodeDecodeError):
            logger.debug("Failed to read config: %s", conf_path)
            continue
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if "UBOOT_SIGN_ENABLE" in stripped:
                return True
    return False


def detect(build_dir: Path, config: Mapping[str, object] | None = None) -> MechanismResult:
    """Detect signed FIT image configuration.

    Args:
        build_dir: Path to the Yocto build directory.
        config: Optional mapping. Reserved for future expansion; the FIT
            detector currently does not read any keys.

    Returns:
        A ``MechanismResult``. ``present=True`` when a signed FIT
        artifact is on disk or ``UBOOT_SIGN_ENABLE`` is declared in the
        build configuration. ``misconfigurations`` carries findings for
        FIT artifacts that have FDT magic but lack a signature node.
        ``evidence`` lists the signed artifacts and/or the matched
        config key.
    """
    _ = config  # reserved for future use; currently no FIT-specific keys
    images_dir = build_dir.joinpath(*_IMAGES_SUBDIR)
    fit_files = _find_fit_files(images_dir)

    signed = [p for p in fit_files if _is_signed_fit(p)]
    unsigned = [p for p in fit_files if _has_fdt_magic(p) and not _is_signed_fit(p)]

    config_signal = _detect_uboot_sign_enable(build_dir)

    evidence: list[str] = []
    misconfigurations: list[Finding] = []

    if signed:
        for path in signed:
            evidence.append(str(path))

    if unsigned:
        names = ", ".join(p.name for p in unsigned)
        misconfigurations.append(
            Finding(
                message=f"Unsigned FIT image(s) found: {names}",
                severity="high",
                remediation=_REMEDIATION_UNSIGNED_FIT,
                cra_mapping=list(_FIT_CRA_MAPPING),
            )
        )

    if signed:
        present = True
        confidence = "high"
        if config_signal:
            evidence.append("UBOOT_SIGN_ENABLE in conf/")
    elif config_signal:
        present = True
        confidence = "medium"
        evidence.append("UBOOT_SIGN_ENABLE in conf/")
    else:
        present = False
        confidence = "low"

    return MechanismResult(
        present=present,
        confidence=confidence,
        evidence=evidence,
        misconfigurations=misconfigurations,
    )


__all__ = ["detect"]

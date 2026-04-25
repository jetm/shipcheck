"""dm-verity mechanism detector.

Ports the dm-verity logic from the retired ``image_signing.py`` check
into the ``code-integrity`` package as a single ``detect`` function
returning a ``MechanismResult``. The aggregator in
``CodeIntegrityCheck.run`` (task 1.7) consumes this alongside the UEFI,
FIT, and IMA/EVM detectors.

Signals:

1. ``DM_VERITY_IMAGE`` or ``DM_VERITY_IMAGE_TYPE`` declared in
   ``conf/local.conf`` / ``conf/auto.conf``. Indicates the build is
   configured to produce a dm-verity-protected rootfs.
2. ``.verity`` or ``.hashtree`` files under ``tmp/deploy/images/``.
   These are the verity hash-tree artifacts produced by a successful
   build.

Either signal alone is sufficient to mark the mechanism present;
together they reinforce each other in the ``evidence`` list.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from shipcheck.checks.code_integrity import MechanismResult

if TYPE_CHECKING:
    from collections.abc import Mapping
    from pathlib import Path

logger = logging.getLogger(__name__)

_IMAGES_SUBDIR = ("tmp", "deploy", "images")
_CONF_FILES = ("conf/local.conf", "conf/auto.conf")
_VERITY_EXTENSIONS = (".verity", ".hashtree")
_VERITY_INDICATORS = ("DM_VERITY_IMAGE", "DM_VERITY_IMAGE_TYPE")


def _detect_verity_config(build_dir: Path) -> list[str]:
    """Return matched ``DM_VERITY_*`` indicator names from conf files.

    Reads ``conf/local.conf`` and ``conf/auto.conf`` and returns the
    names of any non-commented lines mentioning ``DM_VERITY_IMAGE`` or
    ``DM_VERITY_IMAGE_TYPE``. The original ``image_signing.py`` logic
    used substring matching against stripped non-comment lines; the port
    preserves that behavior so existing builds continue to be detected
    identically.
    """
    matched: list[str] = []
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
            for indicator in _VERITY_INDICATORS:
                if indicator in stripped and indicator not in matched:
                    matched.append(indicator)
    return matched


def _find_verity_files(images_dir: Path) -> list[Path]:
    """Find ``.verity`` or ``.hashtree`` files under ``images_dir``."""
    files: list[Path] = []
    if not images_dir.is_dir():
        return files
    for ext in _VERITY_EXTENSIONS:
        files.extend(images_dir.rglob(f"*{ext}"))
    return sorted(files)


def detect(build_dir: Path, config: Mapping[str, object] | None = None) -> MechanismResult:
    """Detect dm-verity configuration.

    Args:
        build_dir: Path to the Yocto build directory.
        config: Optional mapping. Reserved for future expansion; the
            dm-verity detector currently does not read any keys.

    Returns:
        A ``MechanismResult``. ``present=True`` when either a verity
        config variable is set or a ``.verity`` / ``.hashtree`` artifact
        is on disk. ``evidence`` lists the matched config indicators and
        artifact paths. ``misconfigurations`` is always empty: the spec
        defines mechanism-absence as a top-level finding emitted by the
        aggregator, and a "configured but missing artifact" state is
        ambiguous between pre-build inspection and a build issue.
    """
    _ = config  # reserved for future use; currently no verity-specific keys
    images_dir = build_dir.joinpath(*_IMAGES_SUBDIR)

    config_indicators = _detect_verity_config(build_dir)
    verity_files = _find_verity_files(images_dir)

    evidence: list[str] = []
    for indicator in config_indicators:
        evidence.append(f"{indicator} in conf/")
    for path in verity_files:
        evidence.append(str(path))

    present = bool(config_indicators or verity_files)

    return MechanismResult(
        present=present,
        confidence="high" if present else "low",
        evidence=evidence,
        misconfigurations=[],
    )


__all__ = ["detect"]

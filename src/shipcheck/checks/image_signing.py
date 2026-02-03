"""Image Signing check - FIT image signatures and dm-verity detection."""

from __future__ import annotations

import logging
import struct
from typing import TYPE_CHECKING

from shipcheck.models import BaseCheck, CheckResult, CheckStatus, Finding, determine_status

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger(__name__)

IMAGES_SUBDIR = "tmp/deploy/images"
CONF_FILES = ("conf/local.conf", "conf/auto.conf")
FDT_MAGIC = 0xD00DFEED
FIT_EXTENSIONS = (".itb", ".fit")
VERITY_EXTENSIONS = (".verity", ".hashtree")


def _find_fit_files(images_dir: Path) -> list[Path]:
    """Recursively find .itb and .fit files under the images directory."""
    files: list[Path] = []
    if not images_dir.is_dir():
        return files
    for ext in FIT_EXTENSIONS:
        files.extend(images_dir.rglob(f"*{ext}"))
    return sorted(files)


def _is_signed_fit(path: Path) -> bool:
    """Check if a FIT image has FDT magic and contains a signature node."""
    try:
        with path.open("rb") as f:
            header = f.read(4)
            if len(header) < 4:
                return False
            magic = struct.unpack(">I", header)[0]
            if magic != FDT_MAGIC:
                return False
            f.seek(0)
            content = f.read()
            return b"signature" in content
    except OSError:
        logger.debug("Failed to read FIT image: %s", path)
        return False


def _has_fdt_magic(path: Path) -> bool:
    """Check if a file starts with FDT magic bytes."""
    try:
        with path.open("rb") as f:
            header = f.read(4)
            if len(header) < 4:
                return False
            return struct.unpack(">I", header)[0] == FDT_MAGIC
    except OSError:
        return False


def _detect_fit_config(build_dir: Path) -> bool:
    """Check conf files for UBOOT_SIGN_ENABLE indicating FIT signing."""
    for conf_name in CONF_FILES:
        conf_path = build_dir / conf_name
        if not conf_path.is_file():
            continue
        try:
            text = conf_path.read_text()
            for line in text.splitlines():
                stripped = line.strip()
                if stripped.startswith("#"):
                    continue
                if "UBOOT_SIGN_ENABLE" in stripped:
                    return True
        except OSError:
            logger.debug("Failed to read config: %s", conf_path)
    return False


def _detect_verity_config(build_dir: Path) -> bool:
    """Check conf files for dm-verity configuration variables."""
    verity_indicators = ("DM_VERITY_IMAGE", "DM_VERITY_IMAGE_TYPE")
    for conf_name in CONF_FILES:
        conf_path = build_dir / conf_name
        if not conf_path.is_file():
            continue
        try:
            text = conf_path.read_text()
            for line in text.splitlines():
                stripped = line.strip()
                if stripped.startswith("#"):
                    continue
                if any(indicator in stripped for indicator in verity_indicators):
                    return True
        except OSError:
            logger.debug("Failed to read config: %s", conf_path)
    return False


def _find_verity_files(images_dir: Path) -> list[Path]:
    """Find .verity or .hashtree files under the images directory."""
    files: list[Path] = []
    if not images_dir.is_dir():
        return files
    for ext in VERITY_EXTENSIONS:
        files.extend(images_dir.rglob(f"*{ext}"))
    return sorted(files)


class ImageSigningCheck(BaseCheck):
    """Detect FIT image signatures and dm-verity configuration."""

    id = "image-signing"
    name = "Image Signing"
    framework = ["CRA"]
    severity = "critical"

    def run(self, build_dir: Path, config: dict) -> CheckResult:
        expect_fit: bool = config.get("expect_fit", True)
        expect_verity: bool = config.get("expect_verity", True)
        max_score = 50

        if not expect_fit and not expect_verity:
            return CheckResult(
                check_id=self.id,
                check_name=self.name,
                status=CheckStatus.SKIP,
                score=0,
                max_score=max_score,
                findings=[],
                summary="Image signing checks skipped (neither FIT nor verity expected)",
            )

        findings: list[Finding] = []
        images_dir = build_dir / IMAGES_SUBDIR

        # Determine point allocation based on what's expected
        if expect_fit and expect_verity:
            fit_points = 25
            verity_points = 25
        elif expect_fit:
            fit_points = 50
            verity_points = 0
        else:
            fit_points = 0
            verity_points = 50

        score = 0

        # FIT image detection
        if expect_fit:
            fit_files = _find_fit_files(images_dir)
            fit_config = _detect_fit_config(build_dir)
            if fit_files:
                signed = [f for f in fit_files if _is_signed_fit(f)]
                unsigned = [f for f in fit_files if _has_fdt_magic(f) and not _is_signed_fit(f)]
                if signed:
                    score += fit_points
                elif unsigned:
                    names = ", ".join(f.name for f in unsigned)
                    findings.append(
                        Finding(
                            message=f"Unsigned FIT image(s) found: {names}",
                            severity="high",
                            remediation=(
                                "Sign FIT images with a private key using"
                                " mkimage -F -k <keydir> -r <image>"
                            ),
                        )
                    )
            elif fit_config:
                score += fit_points
            else:
                findings.append(
                    Finding(
                        message="No FIT image files (.itb, .fit) found in deploy directory",
                        severity="medium",
                    )
                )

        # dm-verity detection
        if expect_verity:
            verity_config = _detect_verity_config(build_dir)
            verity_files = _find_verity_files(images_dir)
            if verity_config or verity_files:
                score += verity_points
            else:
                findings.append(
                    Finding(
                        message="No dm-verity configuration or hash files found",
                        severity="medium",
                    )
                )

        status = determine_status(findings)
        parts = []
        if expect_fit:
            parts.append("FIT")
        if expect_verity:
            parts.append("verity")
        checked = " and ".join(parts)
        summary = f"Image signing: checked {checked}, score {score}/{max_score}"

        return CheckResult(
            check_id=self.id,
            check_name=self.name,
            status=status,
            score=score,
            max_score=max_score,
            findings=findings,
            summary=summary,
        )

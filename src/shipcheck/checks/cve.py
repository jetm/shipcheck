"""CVE vulnerability check."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from shipcheck.models import BaseCheck, CheckResult, CheckStatus, Finding

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger(__name__)

IMAGES_SUBDIR = "tmp/deploy/images"

_REMEDIATION_NO_OUTPUT = (
    "No CVE scan output found. Add `inherit cve-check` to your image recipe "
    "or run sbom-cve-check against your SPDX SBOM."
)

_CVE_GLOB_PATTERNS = (
    "*.sbom-cve-check.yocto.json",
    "*.rootfs.json",
    "*/cve_check_summary*.json",
)


def _discover_cve_output(build_dir: Path) -> Path | None:
    """Search for CVE scan output in priority order, return first match.

    Lookup order:
        1. tmp/deploy/images/*.sbom-cve-check.yocto.json
        2. tmp/deploy/images/*.rootfs.json
        3. tmp/deploy/images/*/cve_check_summary*.json
    """
    images_dir = build_dir / IMAGES_SUBDIR
    if not images_dir.is_dir():
        return None

    for pattern in _CVE_GLOB_PATTERNS:
        matches = sorted(images_dir.glob(pattern))
        if matches:
            return matches[0]

    return None


class CVECheck(BaseCheck):
    """Assess CVE tracking from Yocto cve-check/sbom-cve-check/vex.bbclass output."""

    id = "cve-tracking"
    name = "CVE Tracking"
    framework = ["CRA"]
    severity = "critical"

    def run(self, build_dir: Path, config: dict) -> CheckResult:
        cve_file = _discover_cve_output(build_dir)

        if cve_file is None:
            return CheckResult(
                check_id=self.id,
                check_name=self.name,
                status=CheckStatus.FAIL,
                score=0,
                max_score=50,
                findings=[
                    Finding(
                        message="No CVE scan output found in build directory.",
                        severity="critical",
                        remediation=_REMEDIATION_NO_OUTPUT,
                    )
                ],
                summary="No CVE scan output found",
            )

        # Parsing, severity classification, suppression, and scoring
        # are implemented in tasks 3.3-3.6.
        return CheckResult(
            check_id=self.id,
            check_name=self.name,
            status=CheckStatus.PASS,
            score=50,
            max_score=50,
            findings=[],
            summary=f"CVE scan output found: {cve_file.name}",
        )

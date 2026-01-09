"""CVE vulnerability check."""

from __future__ import annotations

from typing import TYPE_CHECKING

from shipcheck.models import BaseCheck, CheckResult, CheckStatus

if TYPE_CHECKING:
    from pathlib import Path


class CVECheck(BaseCheck):
    """Assess CVE tracking from Yocto cve-check/sbom-cve-check/vex.bbclass output."""

    id = "cve-tracking"
    name = "CVE Tracking"
    framework = ["CRA"]
    severity = "critical"

    def run(self, build_dir: Path, config: dict) -> CheckResult:
        return CheckResult(
            check_id=self.id,
            check_name=self.name,
            status=CheckStatus.PASS,
            score=0,
            max_score=50,
            findings=[],
            summary="Not implemented",
        )

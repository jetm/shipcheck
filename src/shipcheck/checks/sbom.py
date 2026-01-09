"""SBOM (Software Bill of Materials) check."""

from __future__ import annotations

from typing import TYPE_CHECKING

from shipcheck.models import BaseCheck, CheckResult, CheckStatus

if TYPE_CHECKING:
    from pathlib import Path


class SBOMCheck(BaseCheck):
    """Validate SPDX 2.3 SBOM documents against BSI TR-03183-2 field requirements."""

    id = "sbom-generation"
    name = "SBOM Generation"
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

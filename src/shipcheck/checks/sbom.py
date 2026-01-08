"""SBOM (Software Bill of Materials) check."""

from __future__ import annotations

from typing import Any

from shipcheck.models import BaseCheck, CheckResult, CheckStatus


class SBOMCheck(BaseCheck):
    """Verify that a valid SBOM is attached to or can be generated for an image."""

    name = "sbom"

    def run(self, image: str, **kwargs: Any) -> CheckResult:
        return CheckResult(
            check_name=self.name,
            status=CheckStatus.SKIP,
            message="Not implemented",
        )

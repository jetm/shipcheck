"""CVE vulnerability check."""

from __future__ import annotations

from typing import Any

from shipcheck.models import BaseCheck, CheckResult, CheckStatus


class CVECheck(BaseCheck):
    """Scan an image for known CVE vulnerabilities."""

    name = "cve"

    def run(self, image: str, **kwargs: Any) -> CheckResult:
        return CheckResult(
            check_name=self.name,
            status=CheckStatus.SKIP,
            message="Not implemented",
        )

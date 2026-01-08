"""Registry metadata check."""

from __future__ import annotations

from typing import Any

from shipcheck.models import BaseCheck, CheckResult, CheckStatus


class RegistryCheck(BaseCheck):
    """Check registry metadata: provenance, signatures, and image age."""

    name = "registry"

    def run(self, image: str, **kwargs: Any) -> CheckResult:
        return CheckResult(
            check_name=self.name,
            status=CheckStatus.SKIP,
            message="Not implemented",
        )

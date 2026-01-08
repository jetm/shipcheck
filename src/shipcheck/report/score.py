"""Supply chain score calculator."""

from __future__ import annotations

from shipcheck.models import CheckResult, CheckStatus


def calculate(results: list[CheckResult]) -> int:
    """Calculate a 0-100 supply chain score from check results.

    Returns 100 for a fully passing scan, deducting points per failure severity.
    Returns 0 when no results are provided.
    """
    if not results:
        return 0

    active = [r for r in results if r.status != CheckStatus.SKIP]
    if not active:
        return 100

    passing = sum(1 for r in active if r.status == CheckStatus.PASS)
    return round(passing / len(active) * 100)

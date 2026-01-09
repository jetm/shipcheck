"""Readiness score computation for compliance reports."""

from __future__ import annotations

import importlib.metadata
from datetime import UTC, datetime

from shipcheck.models import CheckResult, CheckStatus, ReportData

CRA_VERSION = "2024/2847"
BSI_TR_VERSION = "TR-03183-2 v2.1.0"


def compute_score(checks: list[CheckResult]) -> tuple[int, int]:
    """Sum check scores and compute the maximum total.

    Returns:
        (total_score, max_total_score) tuple.
    """
    total = sum(c.score for c in checks)
    max_total = sum(c.max_score for c in checks)
    return total, max_total


def determine_overall_status(checks: list[CheckResult]) -> CheckStatus:
    """Determine overall status from all check results.

    Rules:
        - Empty list -> PASS
        - Any FAIL -> FAIL
        - Any WARN (no FAIL) -> WARN
        - All SKIP -> SKIP
        - All PASS (ignoring SKIP) -> PASS
    """
    if not checks:
        return CheckStatus.PASS

    statuses = {c.status for c in checks}

    if CheckStatus.FAIL in statuses:
        return CheckStatus.FAIL
    if CheckStatus.WARN in statuses:
        return CheckStatus.WARN
    if statuses == {CheckStatus.SKIP}:
        return CheckStatus.SKIP
    return CheckStatus.PASS


def _get_version() -> str:
    """Get shipcheck version from package metadata."""
    try:
        return importlib.metadata.version("shipcheck")
    except importlib.metadata.PackageNotFoundError:
        return "unknown"


def build_report_data(checks: list[CheckResult], *, build_dir: str) -> ReportData:
    """Assemble a ReportData object from check results.

    Computes total score, max total, timestamp, and fills in
    CRA framework metadata.
    """
    total, max_total = compute_score(checks)
    return ReportData(
        checks=checks,
        total_score=total,
        max_total_score=max_total,
        framework="CRA",
        framework_version=CRA_VERSION,
        bsi_tr_version=BSI_TR_VERSION,
        build_dir=build_dir,
        timestamp=datetime.now(UTC).isoformat(),
        shipcheck_version=_get_version(),
    )

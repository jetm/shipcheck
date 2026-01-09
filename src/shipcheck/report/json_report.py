"""JSON report renderer."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from shipcheck.models import CheckResult, Finding, ReportData


def _serialize_finding(finding: Finding) -> dict[str, Any]:
    return {
        "message": finding.message,
        "severity": finding.severity,
        "remediation": finding.remediation,
        "details": finding.details,
    }


def _serialize_check(check: CheckResult) -> dict[str, Any]:
    return {
        "check_id": check.check_id,
        "check_name": check.check_name,
        "status": check.status.value,
        "score": check.score,
        "max_score": check.max_score,
        "summary": check.summary,
        "findings": [_serialize_finding(f) for f in check.findings],
    }


def _collect_suppressed(report: ReportData) -> list[dict[str, Any]]:
    """Collect suppressed CVEs from CVE check results.

    The CVE check stores suppressed CVE data in CheckResult when
    suppression is implemented (task 3.5). Until then, returns
    an empty list.
    """
    for check in report.checks:
        if check.check_id == "cve-tracking":
            suppressed = getattr(check, "suppressed", None)
            if isinstance(suppressed, list):
                return suppressed
    return []


def render(report: ReportData) -> str:
    """Render a report as a JSON string.

    The output includes all ReportData metadata fields, per-check
    results with findings, the readiness score, and suppressed CVEs.
    """
    data: dict[str, Any] = {
        "framework": report.framework,
        "framework_version": report.framework_version,
        "bsi_tr_version": report.bsi_tr_version,
        "build_dir": report.build_dir,
        "timestamp": report.timestamp,
        "shipcheck_version": report.shipcheck_version,
        "readiness_score": {
            "score": report.total_score,
            "max_score": report.max_total_score,
        },
        "checks": [_serialize_check(c) for c in report.checks],
        "suppressed": _collect_suppressed(report),
    }
    return json.dumps(data, indent=2)

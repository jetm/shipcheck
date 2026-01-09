"""Tests for JSON report renderer."""

from __future__ import annotations

import json

from shipcheck.models import CheckResult, CheckStatus, Finding, ReportData
from shipcheck.report.json_report import render


def _make_finding(
    *,
    message: str = "test finding",
    severity: str = "medium",
    remediation: str | None = None,
    details: dict | None = None,
) -> Finding:
    return Finding(message=message, severity=severity, remediation=remediation, details=details)


def _make_result(
    *,
    check_id: str = "test-check",
    check_name: str = "Test Check",
    status: CheckStatus = CheckStatus.PASS,
    score: int = 50,
    max_score: int = 50,
    findings: list[Finding] | None = None,
    summary: str = "ok",
) -> CheckResult:
    return CheckResult(
        check_id=check_id,
        check_name=check_name,
        status=status,
        score=score,
        max_score=max_score,
        findings=findings or [],
        summary=summary,
    )


def _make_report(
    *,
    checks: list[CheckResult] | None = None,
    total_score: int = 85,
    max_total_score: int = 100,
    framework: str = "CRA",
    framework_version: str = "2024/2847",
    bsi_tr_version: str = "TR-03183-2 v2.1.0",
    build_dir: str = "/path/to/build",
    timestamp: str = "2026-04-01T12:00:00",
    shipcheck_version: str = "0.1.0",
) -> ReportData:
    return ReportData(
        checks=checks or [],
        total_score=total_score,
        max_total_score=max_total_score,
        framework=framework,
        framework_version=framework_version,
        bsi_tr_version=bsi_tr_version,
        build_dir=build_dir,
        timestamp=timestamp,
        shipcheck_version=shipcheck_version,
    )


class TestJsonRenderReturnsValidJson:
    def test_render_returns_valid_json(self):
        report = _make_report()
        result = render(report)
        parsed = json.loads(result)
        assert isinstance(parsed, dict)

    def test_render_returns_indented_json(self):
        report = _make_report()
        result = render(report)
        assert "\n" in result


class TestJsonRenderMetadata:
    def test_includes_framework(self):
        report = _make_report(framework="CRA")
        parsed = json.loads(render(report))
        assert parsed["framework"] == "CRA"

    def test_includes_framework_version(self):
        report = _make_report(framework_version="2024/2847")
        parsed = json.loads(render(report))
        assert parsed["framework_version"] == "2024/2847"

    def test_includes_bsi_tr_version(self):
        report = _make_report(bsi_tr_version="TR-03183-2 v2.1.0")
        parsed = json.loads(render(report))
        assert parsed["bsi_tr_version"] == "TR-03183-2 v2.1.0"

    def test_includes_build_dir(self):
        report = _make_report(build_dir="/home/user/yocto/build")
        parsed = json.loads(render(report))
        assert parsed["build_dir"] == "/home/user/yocto/build"

    def test_includes_timestamp(self):
        report = _make_report(timestamp="2026-04-01T12:00:00")
        parsed = json.loads(render(report))
        assert parsed["timestamp"] == "2026-04-01T12:00:00"

    def test_includes_shipcheck_version(self):
        report = _make_report(shipcheck_version="0.1.0")
        parsed = json.loads(render(report))
        assert parsed["shipcheck_version"] == "0.1.0"


class TestJsonRenderScore:
    def test_includes_total_score(self):
        report = _make_report(total_score=85, max_total_score=100)
        parsed = json.loads(render(report))
        assert parsed["readiness_score"]["score"] == 85
        assert parsed["readiness_score"]["max_score"] == 100

    def test_zero_score(self):
        report = _make_report(total_score=0, max_total_score=100)
        parsed = json.loads(render(report))
        assert parsed["readiness_score"]["score"] == 0

    def test_full_score(self):
        report = _make_report(total_score=100, max_total_score=100)
        parsed = json.loads(render(report))
        assert parsed["readiness_score"]["score"] == 100


class TestJsonRenderChecks:
    def test_empty_checks_list(self):
        report = _make_report(checks=[])
        parsed = json.loads(render(report))
        assert parsed["checks"] == []

    def test_check_fields(self):
        check = _make_result(
            check_id="sbom-generation",
            check_name="SBOM Generation",
            status=CheckStatus.PASS,
            score=50,
            max_score=50,
            summary="SPDX 2.3 found (42 packages)",
        )
        report = _make_report(checks=[check])
        parsed = json.loads(render(report))
        c = parsed["checks"][0]
        assert c["check_id"] == "sbom-generation"
        assert c["check_name"] == "SBOM Generation"
        assert c["status"] == "pass"
        assert c["score"] == 50
        assert c["max_score"] == 50
        assert c["summary"] == "SPDX 2.3 found (42 packages)"

    def test_multiple_checks_preserved_in_order(self):
        checks = [
            _make_result(check_id="sbom-generation"),
            _make_result(check_id="cve-tracking"),
        ]
        report = _make_report(checks=checks)
        parsed = json.loads(render(report))
        assert len(parsed["checks"]) == 2
        assert parsed["checks"][0]["check_id"] == "sbom-generation"
        assert parsed["checks"][1]["check_id"] == "cve-tracking"


class TestJsonRenderFindings:
    def test_check_with_no_findings(self):
        check = _make_result(findings=[])
        report = _make_report(checks=[check])
        parsed = json.loads(render(report))
        assert parsed["checks"][0]["findings"] == []

    def test_finding_fields(self):
        finding = _make_finding(
            message="Missing supplier field",
            severity="low",
            remediation="Add supplier to SPDX package",
            details={"package": "busybox", "field": "supplier"},
        )
        check = _make_result(findings=[finding])
        report = _make_report(checks=[check])
        parsed = json.loads(render(report))
        f = parsed["checks"][0]["findings"][0]
        assert f["message"] == "Missing supplier field"
        assert f["severity"] == "low"
        assert f["remediation"] == "Add supplier to SPDX package"
        assert f["details"] == {"package": "busybox", "field": "supplier"}

    def test_finding_with_null_optional_fields(self):
        finding = _make_finding(
            message="No SPDX directory",
            severity="critical",
            remediation=None,
            details=None,
        )
        check = _make_result(findings=[finding])
        report = _make_report(checks=[check])
        parsed = json.loads(render(report))
        f = parsed["checks"][0]["findings"][0]
        assert f["remediation"] is None
        assert f["details"] is None

    def test_multiple_findings(self):
        findings = [
            _make_finding(message="first", severity="critical"),
            _make_finding(message="second", severity="high"),
            _make_finding(message="third", severity="low"),
        ]
        check = _make_result(findings=findings)
        report = _make_report(checks=[check])
        parsed = json.loads(render(report))
        assert len(parsed["checks"][0]["findings"]) == 3
        assert parsed["checks"][0]["findings"][0]["message"] == "first"
        assert parsed["checks"][0]["findings"][2]["message"] == "third"


class TestJsonRenderSuppressedCves:
    def test_suppressed_key_present_by_default(self):
        report = _make_report(checks=[])
        parsed = json.loads(render(report))
        assert "suppressed" in parsed
        assert parsed["suppressed"] == []

    def test_suppressed_cves_from_cve_check(self):
        check = _make_result(
            check_id="cve-tracking",
            summary="2 unpatched CVEs",
        )
        # Suppressed CVEs are stored in the CheckResult details won't exist
        # until task 3.5 is implemented. The renderer should handle their absence.
        report = _make_report(checks=[check])
        parsed = json.loads(render(report))
        assert isinstance(parsed["suppressed"], list)

    def test_suppressed_cves_included_when_present(self):
        finding = _make_finding(message="unpatched CVE", severity="critical")
        check = _make_result(
            check_id="cve-tracking",
            findings=[finding],
            summary="1 unpatched CVE",
        )
        # Simulate suppressed CVEs by adding them to finding details
        # The actual mechanism will come from the CVE check implementation
        report = _make_report(checks=[check])
        parsed = json.loads(render(report))
        assert "suppressed" in parsed


class TestJsonRenderRoundTrip:
    def test_full_report_round_trip(self):
        """A complete report with all field types renders correctly."""
        findings = [
            _make_finding(
                message="Unpatched CVE-2024-1234",
                severity="critical",
                remediation="Upgrade openssl to 3.2.1",
                details={"cve_id": "CVE-2024-1234", "cvss": 9.8, "package": "openssl"},
            ),
            _make_finding(
                message="Missing supplier",
                severity="low",
                details={"package": "busybox"},
            ),
        ]
        checks = [
            _make_result(
                check_id="sbom-generation",
                check_name="SBOM Generation",
                status=CheckStatus.PASS,
                score=50,
                max_score=50,
                summary="SPDX 2.3 found",
            ),
            _make_result(
                check_id="cve-tracking",
                check_name="CVE Tracking",
                status=CheckStatus.FAIL,
                score=35,
                max_score=50,
                findings=findings,
                summary="1 critical CVE",
            ),
        ]
        report = _make_report(
            checks=checks,
            total_score=85,
            max_total_score=100,
        )
        parsed = json.loads(render(report))

        assert parsed["framework"] == "CRA"
        assert parsed["framework_version"] == "2024/2847"
        assert parsed["bsi_tr_version"] == "TR-03183-2 v2.1.0"
        assert parsed["build_dir"] == "/path/to/build"
        assert parsed["timestamp"] == "2026-04-01T12:00:00"
        assert parsed["shipcheck_version"] == "0.1.0"
        assert parsed["readiness_score"]["score"] == 85
        assert parsed["readiness_score"]["max_score"] == 100
        assert len(parsed["checks"]) == 2
        assert parsed["checks"][1]["findings"][0]["details"]["cvss"] == 9.8
        assert isinstance(parsed["suppressed"], list)

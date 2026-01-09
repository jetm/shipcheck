"""Tests for the Rich terminal renderer."""

from __future__ import annotations

from io import StringIO

from rich.console import Console

from shipcheck.models import CheckResult, CheckStatus, Finding, ReportData


def _make_report(**overrides) -> ReportData:
    defaults = {
        "checks": [],
        "total_score": 0,
        "max_total_score": 100,
        "framework": "CRA",
        "framework_version": "2024/2847",
        "bsi_tr_version": "TR-03183-2 v2.1.0",
        "build_dir": "./build",
        "timestamp": "2026-04-01T12:00:00Z",
        "shipcheck_version": "0.1.0",
    }
    defaults.update(overrides)
    return ReportData(**defaults)


def _capture_output(report: ReportData) -> str:
    """Render to a string buffer and return the text."""
    from shipcheck.report.terminal import render

    buf = StringIO()
    console = Console(file=buf, width=100, no_color=True, highlight=False)
    render(report, console=console)
    return buf.getvalue()


class TestTerminalHeader:
    def test_header_shows_version(self):
        report = _make_report(shipcheck_version="0.1.0")
        output = _capture_output(report)
        assert "shipcheck v0.1.0" in output

    def test_header_shows_subtitle(self):
        report = _make_report()
        output = _capture_output(report)
        assert "Embedded Linux Compliance Auditor" in output

    def test_shows_build_dir(self):
        report = _make_report(build_dir="/path/to/build")
        output = _capture_output(report)
        assert "Checking /path/to/build" in output


class TestCheckStatusDisplay:
    def test_pass_status_shown(self):
        check = CheckResult(
            check_id="sbom-generation",
            check_name="SBOM generation",
            status=CheckStatus.PASS,
            score=50,
            max_score=50,
            findings=[],
            summary="SPDX 2.3 found (42 packages)",
        )
        report = _make_report(checks=[check], total_score=50)
        output = _capture_output(report)
        assert "PASS" in output
        assert "SBOM generation" in output
        assert "SPDX 2.3 found (42 packages)" in output

    def test_fail_status_shown(self):
        check = CheckResult(
            check_id="cve-tracking",
            check_name="CVE tracking",
            status=CheckStatus.FAIL,
            score=0,
            max_score=50,
            findings=[
                Finding(
                    message="No CVE scan output found",
                    severity="critical",
                    remediation="Add `inherit cve-check` to your image recipe",
                ),
            ],
            summary="cve-check class not enabled",
        )
        report = _make_report(checks=[check], total_score=0)
        output = _capture_output(report)
        assert "FAIL" in output
        assert "CVE tracking" in output

    def test_warn_status_shown(self):
        check = CheckResult(
            check_id="sbom-generation",
            check_name="SBOM generation",
            status=CheckStatus.WARN,
            score=40,
            max_score=50,
            findings=[
                Finding(message="Package foo missing checksum", severity="low"),
            ],
            summary="SPDX 2.3 found, minor issues",
        )
        report = _make_report(checks=[check], total_score=40)
        output = _capture_output(report)
        assert "WARN" in output

    def test_skip_status_shown(self):
        check = CheckResult(
            check_id="sbom-generation",
            check_name="SBOM generation",
            status=CheckStatus.SKIP,
            score=0,
            max_score=50,
            findings=[],
            summary="Skipped",
        )
        report = _make_report(checks=[check], total_score=0)
        output = _capture_output(report)
        assert "SKIP" in output


class TestFindingsDisplay:
    def test_finding_message_shown(self):
        check = CheckResult(
            check_id="cve-tracking",
            check_name="CVE tracking",
            status=CheckStatus.FAIL,
            score=0,
            max_score=50,
            findings=[
                Finding(
                    message="No CVE scan output found",
                    severity="critical",
                    remediation="Add `inherit cve-check` to your image recipe",
                ),
            ],
            summary="cve-check class not enabled",
        )
        report = _make_report(checks=[check])
        output = _capture_output(report)
        assert "No CVE scan output found" in output

    def test_finding_severity_shown(self):
        check = CheckResult(
            check_id="cve-tracking",
            check_name="CVE tracking",
            status=CheckStatus.FAIL,
            score=0,
            max_score=50,
            findings=[
                Finding(message="CVE-2024-1234 unpatched", severity="critical"),
            ],
            summary="1 critical CVE",
        )
        report = _make_report(checks=[check])
        output = _capture_output(report)
        assert "critical" in output.lower()

    def test_remediation_shown_when_present(self):
        check = CheckResult(
            check_id="cve-tracking",
            check_name="CVE tracking",
            status=CheckStatus.FAIL,
            score=0,
            max_score=50,
            findings=[
                Finding(
                    message="No CVE scan output found",
                    severity="critical",
                    remediation="Add `inherit cve-check` to your image recipe",
                ),
            ],
            summary="cve-check class not enabled",
        )
        report = _make_report(checks=[check])
        output = _capture_output(report)
        assert "inherit cve-check" in output

    def test_no_remediation_when_absent(self):
        check = CheckResult(
            check_id="sbom-generation",
            check_name="SBOM generation",
            status=CheckStatus.WARN,
            score=45,
            max_score=50,
            findings=[
                Finding(message="Package foo missing checksum", severity="low"),
            ],
            summary="Minor issues",
        )
        report = _make_report(checks=[check])
        output = _capture_output(report)
        assert "Fix:" not in output or "Package foo missing checksum" in output

    def test_multiple_findings_all_shown(self):
        check = CheckResult(
            check_id="cve-tracking",
            check_name="CVE tracking",
            status=CheckStatus.FAIL,
            score=5,
            max_score=50,
            findings=[
                Finding(message="CVE-2024-1111 unpatched", severity="critical"),
                Finding(message="CVE-2024-2222 unpatched", severity="high"),
                Finding(message="CVE-2024-3333 unpatched", severity="medium"),
            ],
            summary="3 unpatched CVEs",
        )
        report = _make_report(checks=[check])
        output = _capture_output(report)
        assert "CVE-2024-1111" in output
        assert "CVE-2024-2222" in output
        assert "CVE-2024-3333" in output


class TestReadinessScore:
    def test_score_shown(self):
        report = _make_report(total_score=45, max_total_score=100)
        output = _capture_output(report)
        assert "45" in output
        assert "100" in output

    def test_perfect_score(self):
        report = _make_report(total_score=100, max_total_score=100)
        output = _capture_output(report)
        assert "100" in output

    def test_zero_score(self):
        report = _make_report(total_score=0, max_total_score=100)
        output = _capture_output(report)
        assert "0" in output
        assert "100" in output


class TestEmptyReport:
    def test_no_checks_still_renders(self):
        report = _make_report(checks=[])
        output = _capture_output(report)
        assert "shipcheck" in output.lower()
        assert "0" in output

    def test_check_with_no_findings(self):
        check = CheckResult(
            check_id="sbom-generation",
            check_name="SBOM generation",
            status=CheckStatus.PASS,
            score=50,
            max_score=50,
            findings=[],
            summary="All good",
        )
        report = _make_report(checks=[check], total_score=50)
        output = _capture_output(report)
        assert "PASS" in output
        assert "All good" in output


class TestMultipleChecks:
    def test_two_checks_both_shown(self):
        sbom = CheckResult(
            check_id="sbom-generation",
            check_name="SBOM generation",
            status=CheckStatus.PASS,
            score=50,
            max_score=50,
            findings=[],
            summary="SPDX 2.3 found (42 packages)",
        )
        cve = CheckResult(
            check_id="cve-tracking",
            check_name="CVE tracking",
            status=CheckStatus.FAIL,
            score=0,
            max_score=50,
            findings=[
                Finding(
                    message="No CVE scan output found",
                    severity="critical",
                    remediation="Add `inherit cve-check` to your image recipe",
                ),
            ],
            summary="cve-check class not enabled",
        )
        report = _make_report(checks=[sbom, cve], total_score=50)
        output = _capture_output(report)
        assert "SBOM generation" in output
        assert "CVE tracking" in output
        assert "PASS" in output
        assert "FAIL" in output

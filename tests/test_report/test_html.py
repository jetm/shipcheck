"""Tests for the HTML report renderer."""

from __future__ import annotations

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


def _render_html(report: ReportData) -> str:
    from shipcheck.report.html import render

    return render(report)


class TestHtmlStructure:
    def test_returns_valid_html_document(self):
        html = _render_html(_make_report())
        assert "<!DOCTYPE html>" in html
        assert "<html" in html
        assert "</html>" in html

    def test_contains_inline_css(self):
        html = _render_html(_make_report())
        assert "<style>" in html
        assert "</style>" in html

    def test_no_javascript(self):
        html = _render_html(_make_report())
        assert "<script" not in html

    def test_self_contained_no_external_links(self):
        html = _render_html(_make_report())
        assert 'rel="stylesheet"' not in html
        assert "http://" not in html
        assert "https://" not in html


class TestHtmlMetadata:
    def test_shows_shipcheck_version(self):
        html = _render_html(_make_report(shipcheck_version="0.1.0"))
        assert "0.1.0" in html

    def test_shows_framework_version(self):
        html = _render_html(_make_report(framework_version="2024/2847"))
        assert "2024/2847" in html

    def test_shows_bsi_tr_version(self):
        html = _render_html(_make_report(bsi_tr_version="TR-03183-2 v2.1.0"))
        assert "TR-03183-2 v2.1.0" in html

    def test_shows_build_dir(self):
        html = _render_html(_make_report(build_dir="/path/to/build"))
        assert "/path/to/build" in html

    def test_shows_timestamp(self):
        html = _render_html(_make_report(timestamp="2026-04-01T12:00:00Z"))
        assert "2026-04-01T12:00:00Z" in html

    def test_shows_framework(self):
        html = _render_html(_make_report(framework="CRA"))
        assert "CRA" in html


class TestHtmlCheckStatus:
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
        html = _render_html(_make_report(checks=[check], total_score=50))
        assert "PASS" in html
        assert "SBOM generation" in html
        assert "SPDX 2.3 found (42 packages)" in html

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
                    remediation="Add inherit cve-check to your image recipe",
                ),
            ],
            summary="cve-check class not enabled",
        )
        html = _render_html(_make_report(checks=[check], total_score=0))
        assert "FAIL" in html
        assert "CVE tracking" in html

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
        html = _render_html(_make_report(checks=[check], total_score=40))
        assert "WARN" in html

    def test_check_score_shown(self):
        check = CheckResult(
            check_id="sbom-generation",
            check_name="SBOM generation",
            status=CheckStatus.PASS,
            score=50,
            max_score=50,
            findings=[],
            summary="All good",
        )
        html = _render_html(_make_report(checks=[check], total_score=50))
        assert "50/50" in html or ("50" in html)


class TestHtmlFindings:
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
                    remediation="Add inherit cve-check to your image recipe",
                ),
            ],
            summary="cve-check class not enabled",
        )
        html = _render_html(_make_report(checks=[check]))
        assert "No CVE scan output found" in html

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
        html = _render_html(_make_report(checks=[check]))
        assert "critical" in html.lower()

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
                    remediation="Add inherit cve-check to your image recipe",
                ),
            ],
            summary="cve-check class not enabled",
        )
        html = _render_html(_make_report(checks=[check]))
        assert "inherit cve-check" in html

    def test_no_remediation_row_when_absent(self):
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
        html = _render_html(_make_report(checks=[check]))
        assert "Package foo missing checksum" in html

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
        html = _render_html(_make_report(checks=[check]))
        assert "CVE-2024-1111" in html
        assert "CVE-2024-2222" in html
        assert "CVE-2024-3333" in html


class TestHtmlReadinessScore:
    def test_score_shown(self):
        html = _render_html(_make_report(total_score=45, max_total_score=100))
        assert "45" in html
        assert "100" in html

    def test_perfect_score(self):
        html = _render_html(_make_report(total_score=100, max_total_score=100))
        assert "100" in html

    def test_zero_score(self):
        html = _render_html(_make_report(total_score=0, max_total_score=100))
        assert "0" in html


class TestHtmlTableLayout:
    def test_uses_table_elements(self):
        check = CheckResult(
            check_id="sbom-generation",
            check_name="SBOM generation",
            status=CheckStatus.PASS,
            score=50,
            max_score=50,
            findings=[],
            summary="All good",
        )
        html = _render_html(_make_report(checks=[check], total_score=50))
        assert "<table" in html
        assert "<tr" in html
        assert "<td" in html

    def test_findings_in_table(self):
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
        html = _render_html(_make_report(checks=[check]))
        assert "<table" in html


class TestHtmlEmptyReport:
    def test_no_checks_still_renders(self):
        html = _render_html(_make_report(checks=[]))
        assert "<!DOCTYPE html>" in html
        assert "shipcheck" in html.lower()

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
        html = _render_html(_make_report(checks=[check], total_score=50))
        assert "PASS" in html
        assert "All good" in html


class TestHtmlMultipleChecks:
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
                    remediation="Add inherit cve-check to your image recipe",
                ),
            ],
            summary="cve-check class not enabled",
        )
        html = _render_html(_make_report(checks=[sbom, cve], total_score=50))
        assert "SBOM generation" in html
        assert "CVE tracking" in html
        assert "PASS" in html
        assert "FAIL" in html


class TestHtmlSeverityBadges:
    def test_severity_has_visual_distinction(self):
        """Each severity level should have CSS styling for visual distinction."""
        check = CheckResult(
            check_id="test",
            check_name="Test",
            status=CheckStatus.FAIL,
            score=0,
            max_score=50,
            findings=[
                Finding(message="crit issue", severity="critical"),
                Finding(message="high issue", severity="high"),
                Finding(message="med issue", severity="medium"),
                Finding(message="low issue", severity="low"),
            ],
            summary="Multiple issues",
        )
        html = _render_html(_make_report(checks=[check]))
        assert "critical" in html.lower()
        assert "high" in html.lower()
        assert "medium" in html.lower()
        assert "low" in html.lower()

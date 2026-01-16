"""Tests for the Jinja2 markdown renderer."""

from __future__ import annotations

from shipcheck.models import CheckResult, CheckStatus, Finding, ReportData
from shipcheck.report.markdown import render


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


class TestMarkdownHeader:
    def test_title_present(self):
        output = render(_make_report())
        assert "# shipcheck Compliance Report" in output

    def test_version_in_header(self):
        output = render(_make_report(shipcheck_version="0.1.0"))
        assert "0.1.0" in output

    def test_build_dir_shown(self):
        output = render(_make_report(build_dir="/path/to/build"))
        assert "/path/to/build" in output

    def test_timestamp_shown(self):
        output = render(_make_report(timestamp="2026-04-01T12:00:00Z"))
        assert "2026-04-01T12:00:00Z" in output


class TestCRAMetadata:
    def test_framework_shown(self):
        output = render(_make_report(framework="CRA"))
        assert "CRA" in output

    def test_framework_version_shown(self):
        output = render(_make_report(framework_version="2024/2847"))
        assert "2024/2847" in output

    def test_bsi_tr_version_shown(self):
        output = render(_make_report(bsi_tr_version="TR-03183-2 v2.1.0"))
        assert "TR-03183-2 v2.1.0" in output


class TestCheckResults:
    def test_pass_check_shown(self):
        check = CheckResult(
            check_id="sbom-generation",
            check_name="SBOM generation",
            status=CheckStatus.PASS,
            score=50,
            max_score=50,
            findings=[],
            summary="SPDX 2.3 found (42 packages)",
        )
        output = render(_make_report(checks=[check], total_score=50))
        assert "SBOM generation" in output
        assert "PASS" in output
        assert "50/50" in output

    def test_fail_check_shown(self):
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
        output = render(_make_report(checks=[check], total_score=0))
        assert "CVE tracking" in output
        assert "FAIL" in output

    def test_warn_check_shown(self):
        check = CheckResult(
            check_id="sbom-generation",
            check_name="SBOM generation",
            status=CheckStatus.WARN,
            score=40,
            max_score=50,
            findings=[
                Finding(message="Package foo missing checksum", severity="low"),
            ],
            summary="Minor issues",
        )
        output = render(_make_report(checks=[check], total_score=40))
        assert "WARN" in output

    def test_check_summary_shown(self):
        check = CheckResult(
            check_id="sbom-generation",
            check_name="SBOM generation",
            status=CheckStatus.PASS,
            score=50,
            max_score=50,
            findings=[],
            summary="SPDX 2.3 found (42 packages)",
        )
        output = render(_make_report(checks=[check], total_score=50))
        assert "SPDX 2.3 found (42 packages)" in output


class TestFindings:
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
                    remediation="Add `inherit cve-check`",
                ),
            ],
            summary="Critical issues",
        )
        output = render(_make_report(checks=[check]))
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
        output = render(_make_report(checks=[check]))
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
            summary="Critical issues",
        )
        output = render(_make_report(checks=[check]))
        assert "inherit cve-check" in output

    def test_no_remediation_line_when_absent(self):
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
        output = render(_make_report(checks=[check]))
        assert "Package foo missing checksum" in output
        assert "Remediation" not in output.split("Package foo missing checksum")[1].split("\n")[0]

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
        output = render(_make_report(checks=[check]))
        assert "CVE-2024-1111" in output
        assert "CVE-2024-2222" in output
        assert "CVE-2024-3333" in output


class TestReadinessScore:
    def test_score_shown(self):
        output = render(_make_report(total_score=45, max_total_score=100))
        assert "45" in output
        assert "100" in output

    def test_score_section_heading(self):
        output = render(_make_report(total_score=45, max_total_score=100))
        assert "## Readiness Score" in output

    def test_perfect_score(self):
        output = render(_make_report(total_score=100, max_total_score=100))
        assert "100/100" in output

    def test_zero_score(self):
        output = render(_make_report(total_score=0, max_total_score=100))
        assert "0/100" in output


class TestEmptyReport:
    def test_no_checks_still_renders(self):
        output = render(_make_report(checks=[]))
        assert "# shipcheck Compliance Report" in output
        assert "0/100" in output

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
        output = render(_make_report(checks=[check], total_score=50))
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
        output = render(_make_report(checks=[sbom, cve], total_score=50))
        assert "SBOM generation" in output
        assert "CVE tracking" in output
        assert "PASS" in output
        assert "FAIL" in output


class TestMarkdownStructure:
    def test_valid_markdown_headings(self):
        check = CheckResult(
            check_id="sbom-generation",
            check_name="SBOM generation",
            status=CheckStatus.PASS,
            score=50,
            max_score=50,
            findings=[],
            summary="All good",
        )
        output = render(_make_report(checks=[check], total_score=50))
        lines = output.strip().split("\n")
        heading_lines = [line for line in lines if line.startswith("#")]
        assert any("shipcheck" in h.lower() for h in heading_lines)
        assert any("readiness" in h.lower() for h in heading_lines)

    def test_returns_string(self):
        output = render(_make_report())
        assert isinstance(output, str)
        assert len(output) > 0

    def test_ends_with_newline(self):
        output = render(_make_report())
        assert output.endswith("\n")

"""Tests for readiness score computation."""

from __future__ import annotations

from shipcheck.models import CheckResult, CheckStatus, Finding, ReportData
from shipcheck.report.score import build_report_data, compute_score, determine_overall_status


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


# --- compute_score ---


class TestComputeScore:
    def test_both_checks_full_score(self):
        checks = [
            _make_result(check_id="sbom-generation", score=50, max_score=50),
            _make_result(check_id="cve-tracking", score=50, max_score=50),
        ]
        total, max_total = compute_score(checks)
        assert total == 100
        assert max_total == 100

    def test_one_check_fails(self):
        checks = [
            _make_result(check_id="sbom-generation", score=45, max_score=50),
            _make_result(check_id="cve-tracking", score=0, max_score=50),
        ]
        total, max_total = compute_score(checks)
        assert total == 45
        assert max_total == 100

    def test_partial_scores(self):
        checks = [
            _make_result(score=30, max_score=50),
            _make_result(score=20, max_score=50),
        ]
        total, max_total = compute_score(checks)
        assert total == 50
        assert max_total == 100

    def test_single_check(self):
        checks = [_make_result(score=35, max_score=50)]
        total, max_total = compute_score(checks)
        assert total == 35
        assert max_total == 50

    def test_empty_results(self):
        total, max_total = compute_score([])
        assert total == 0
        assert max_total == 0

    def test_all_zero_scores(self):
        checks = [
            _make_result(score=0, max_score=50),
            _make_result(score=0, max_score=50),
        ]
        total, max_total = compute_score(checks)
        assert total == 0
        assert max_total == 100


# --- determine_overall_status ---


class TestDetermineOverallStatus:
    def test_all_pass(self):
        checks = [
            _make_result(status=CheckStatus.PASS),
            _make_result(status=CheckStatus.PASS),
        ]
        assert determine_overall_status(checks) == CheckStatus.PASS

    def test_any_fail_means_fail(self):
        checks = [
            _make_result(status=CheckStatus.PASS),
            _make_result(status=CheckStatus.FAIL),
        ]
        assert determine_overall_status(checks) == CheckStatus.FAIL

    def test_warn_without_fail(self):
        checks = [
            _make_result(status=CheckStatus.PASS),
            _make_result(status=CheckStatus.WARN),
        ]
        assert determine_overall_status(checks) == CheckStatus.WARN

    def test_fail_takes_precedence_over_warn(self):
        checks = [
            _make_result(status=CheckStatus.WARN),
            _make_result(status=CheckStatus.FAIL),
        ]
        assert determine_overall_status(checks) == CheckStatus.FAIL

    def test_all_skip_returns_skip(self):
        checks = [
            _make_result(status=CheckStatus.SKIP),
            _make_result(status=CheckStatus.SKIP),
        ]
        assert determine_overall_status(checks) == CheckStatus.SKIP

    def test_skip_ignored_when_others_present(self):
        checks = [
            _make_result(status=CheckStatus.SKIP),
            _make_result(status=CheckStatus.PASS),
        ]
        assert determine_overall_status(checks) == CheckStatus.PASS

    def test_empty_results(self):
        assert determine_overall_status([]) == CheckStatus.PASS

    def test_single_warn(self):
        checks = [_make_result(status=CheckStatus.WARN)]
        assert determine_overall_status(checks) == CheckStatus.WARN


# --- build_report_data ---


class TestBuildReportData:
    def test_assembles_report_data(self):
        checks = [
            _make_result(check_id="sbom-generation", score=50, max_score=50),
            _make_result(check_id="cve-tracking", score=35, max_score=50),
        ]
        report = build_report_data(checks, build_dir="/path/to/build")
        assert isinstance(report, ReportData)
        assert report.total_score == 85
        assert report.max_total_score == 100
        assert report.build_dir == "/path/to/build"
        assert report.framework == "CRA"
        assert report.framework_version == "2024/2847"
        assert report.bsi_tr_version == "TR-03183-2 v2.1.0"
        assert report.checks is checks
        assert report.timestamp  # non-empty ISO 8601
        assert report.shipcheck_version  # non-empty version string

    def test_empty_checks(self):
        report = build_report_data([], build_dir="/build")
        assert report.total_score == 0
        assert report.max_total_score == 0
        assert report.checks == []

    def test_timestamp_is_iso8601(self):
        from datetime import datetime

        report = build_report_data([], build_dir="/build")
        # Should parse without error
        datetime.fromisoformat(report.timestamp)

    def test_version_from_package(self):
        report = build_report_data([], build_dir="/build")
        # Version should be a non-empty string (from importlib.metadata or fallback)
        assert isinstance(report.shipcheck_version, str)
        assert len(report.shipcheck_version) > 0

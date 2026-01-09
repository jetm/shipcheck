"""Tests for shipcheck data models."""

from __future__ import annotations

from pathlib import Path

import pytest

from shipcheck.models import BaseCheck, CheckResult, CheckStatus, Finding, ReportData


class TestCheckStatus:
    """CheckStatus enum values and string behavior."""

    def test_pass_value(self):
        assert CheckStatus.PASS == "pass"

    def test_fail_value(self):
        assert CheckStatus.FAIL == "fail"

    def test_warn_value(self):
        assert CheckStatus.WARN == "warn"

    def test_skip_value(self):
        assert CheckStatus.SKIP == "skip"

    def test_is_str_enum(self):
        assert isinstance(CheckStatus.PASS, str)

    def test_exactly_four_members(self):
        assert len(CheckStatus) == 4

    def test_no_error_member(self):
        with pytest.raises(KeyError):
            CheckStatus["ERROR"]


class TestFinding:
    """Finding dataclass fields and defaults."""

    def test_required_fields(self):
        f = Finding(message="broken", severity="high")
        assert f.message == "broken"
        assert f.severity == "high"

    def test_optional_remediation_defaults_none(self):
        f = Finding(message="x", severity="low")
        assert f.remediation is None

    def test_optional_details_defaults_none(self):
        f = Finding(message="x", severity="low")
        assert f.details is None

    def test_remediation_set(self):
        f = Finding(message="x", severity="critical", remediation="fix it")
        assert f.remediation == "fix it"

    def test_details_set(self):
        f = Finding(message="x", severity="low", details={"cve": "CVE-2024-1234"})
        assert f.details == {"cve": "CVE-2024-1234"}

    def test_no_title_field(self):
        assert not hasattr(Finding, "title")

    def test_no_reference_field(self):
        assert not hasattr(Finding, "reference")


class TestCheckResult:
    """CheckResult dataclass fields and defaults."""

    def test_all_fields(self):
        r = CheckResult(
            check_id="sbom-generation",
            check_name="SBOM Generation",
            status=CheckStatus.PASS,
            score=50,
            max_score=50,
            findings=[],
            summary="All good",
        )
        assert r.check_id == "sbom-generation"
        assert r.check_name == "SBOM Generation"
        assert r.status == CheckStatus.PASS
        assert r.score == 50
        assert r.max_score == 50
        assert r.findings == []
        assert r.summary == "All good"

    def test_findings_contains_finding_objects(self):
        f = Finding(message="bad", severity="high")
        r = CheckResult(
            check_id="cve",
            check_name="CVE",
            status=CheckStatus.FAIL,
            score=0,
            max_score=50,
            findings=[f],
            summary="fail",
        )
        assert len(r.findings) == 1
        assert r.findings[0].severity == "high"


class TestCheckStatusDetermination:
    """CheckStatus rules: PASS=no findings, FAIL=any critical/high, WARN=only medium/low."""

    def test_pass_no_findings(self):
        r = CheckResult(
            check_id="t",
            check_name="T",
            status=CheckStatus.PASS,
            score=50,
            max_score=50,
            findings=[],
            summary="ok",
        )
        assert r.status == CheckStatus.PASS

    def test_fail_with_critical_finding(self):
        r = CheckResult(
            check_id="t",
            check_name="T",
            status=CheckStatus.FAIL,
            score=0,
            max_score=50,
            findings=[Finding(message="x", severity="critical")],
            summary="bad",
        )
        assert r.status == CheckStatus.FAIL

    def test_fail_with_high_finding(self):
        r = CheckResult(
            check_id="t",
            check_name="T",
            status=CheckStatus.FAIL,
            score=0,
            max_score=50,
            findings=[Finding(message="x", severity="high")],
            summary="bad",
        )
        assert r.status == CheckStatus.FAIL

    def test_warn_only_medium_findings(self):
        r = CheckResult(
            check_id="t",
            check_name="T",
            status=CheckStatus.WARN,
            score=40,
            max_score=50,
            findings=[Finding(message="x", severity="medium")],
            summary="ok-ish",
        )
        assert r.status == CheckStatus.WARN

    def test_warn_only_low_findings(self):
        r = CheckResult(
            check_id="t",
            check_name="T",
            status=CheckStatus.WARN,
            score=48,
            max_score=50,
            findings=[Finding(message="x", severity="low")],
            summary="ok-ish",
        )
        assert r.status == CheckStatus.WARN


class TestDetermineStatus:
    """Test the determine_status helper that computes status from findings."""

    def test_no_findings_returns_pass(self):
        from shipcheck.models import determine_status

        assert determine_status([]) == CheckStatus.PASS

    def test_critical_returns_fail(self):
        from shipcheck.models import determine_status

        findings = [Finding(message="x", severity="critical")]
        assert determine_status(findings) == CheckStatus.FAIL

    def test_high_returns_fail(self):
        from shipcheck.models import determine_status

        findings = [Finding(message="x", severity="high")]
        assert determine_status(findings) == CheckStatus.FAIL

    def test_medium_returns_warn(self):
        from shipcheck.models import determine_status

        findings = [Finding(message="x", severity="medium")]
        assert determine_status(findings) == CheckStatus.WARN

    def test_low_returns_warn(self):
        from shipcheck.models import determine_status

        findings = [Finding(message="x", severity="low")]
        assert determine_status(findings) == CheckStatus.WARN

    def test_mixed_high_and_low_returns_fail(self):
        from shipcheck.models import determine_status

        findings = [
            Finding(message="x", severity="low"),
            Finding(message="y", severity="high"),
        ]
        assert determine_status(findings) == CheckStatus.FAIL

    def test_mixed_medium_and_low_returns_warn(self):
        from shipcheck.models import determine_status

        findings = [
            Finding(message="x", severity="low"),
            Finding(message="y", severity="medium"),
        ]
        assert determine_status(findings) == CheckStatus.WARN


class TestReportData:
    """ReportData dataclass fields."""

    def test_all_fields(self):
        rd = ReportData(
            checks=[],
            total_score=0,
            max_total_score=100,
            framework="CRA",
            framework_version="2024/2847",
            bsi_tr_version="TR-03183-2 v2.1.0",
            build_dir="/path/to/build",
            timestamp="2026-04-01T12:00:00Z",
            shipcheck_version="0.1.0",
        )
        assert rd.checks == []
        assert rd.total_score == 0
        assert rd.max_total_score == 100
        assert rd.framework == "CRA"
        assert rd.framework_version == "2024/2847"
        assert rd.bsi_tr_version == "TR-03183-2 v2.1.0"
        assert rd.build_dir == "/path/to/build"
        assert rd.timestamp == "2026-04-01T12:00:00Z"
        assert rd.shipcheck_version == "0.1.0"

    def test_checks_contain_check_results(self):
        cr = CheckResult(
            check_id="sbom-generation",
            check_name="SBOM Generation",
            status=CheckStatus.PASS,
            score=50,
            max_score=50,
            findings=[],
            summary="ok",
        )
        rd = ReportData(
            checks=[cr],
            total_score=50,
            max_total_score=100,
            framework="CRA",
            framework_version="2024/2847",
            bsi_tr_version="TR-03183-2 v2.1.0",
            build_dir="./build",
            timestamp="2026-04-01T12:00:00Z",
            shipcheck_version="0.1.0",
        )
        assert len(rd.checks) == 1
        assert rd.checks[0].check_id == "sbom-generation"

    def test_no_results_field(self):
        """Old scaffold used 'results', spec uses 'checks'."""
        assert not hasattr(ReportData, "results")

    def test_no_overall_status_property(self):
        """Old scaffold had overall_status property; new spec does not."""
        rd = ReportData(
            checks=[],
            total_score=0,
            max_total_score=100,
            framework="CRA",
            framework_version="2024/2847",
            bsi_tr_version="TR-03183-2 v2.1.0",
            build_dir="./build",
            timestamp="2026-04-01T12:00:00Z",
            shipcheck_version="0.1.0",
        )
        assert not hasattr(rd, "overall_status")


class TestBaseCheck:
    """BaseCheck ABC: attributes and abstract run method."""

    def test_cannot_instantiate_directly(self):
        with pytest.raises(TypeError):
            BaseCheck()

    def test_concrete_subclass_has_required_attributes(self):
        class MyCheck(BaseCheck):
            id = "my-check"
            name = "My Check"
            framework = ["CRA"]
            severity = "high"

            def run(self, build_dir: Path, config: dict) -> CheckResult:
                return CheckResult(
                    check_id=self.id,
                    check_name=self.name,
                    status=CheckStatus.PASS,
                    score=50,
                    max_score=50,
                    findings=[],
                    summary="ok",
                )

        check = MyCheck()
        assert check.id == "my-check"
        assert check.name == "My Check"
        assert check.framework == ["CRA"]
        assert check.severity == "high"

    def test_run_returns_check_result(self):
        class MyCheck(BaseCheck):
            id = "test"
            name = "Test"
            framework = ["CRA"]
            severity = "low"

            def run(self, build_dir: Path, config: dict) -> CheckResult:
                return CheckResult(
                    check_id=self.id,
                    check_name=self.name,
                    status=CheckStatus.PASS,
                    score=50,
                    max_score=50,
                    findings=[],
                    summary="passed",
                )

        result = MyCheck().run(Path("/build"), {})
        assert isinstance(result, CheckResult)
        assert result.check_id == "test"
        assert result.status == CheckStatus.PASS

    def test_run_signature_takes_path_and_dict(self):
        """run() accepts (build_dir: Path, config: dict)."""
        import inspect

        sig = inspect.signature(BaseCheck.run)
        params = list(sig.parameters.keys())
        assert params == ["self", "build_dir", "config"]

    def test_subclass_without_run_raises(self):
        with pytest.raises(TypeError):

            class BadCheck(BaseCheck):
                id = "bad"
                name = "Bad"
                framework = []
                severity = "low"

            BadCheck()

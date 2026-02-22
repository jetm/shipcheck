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

    def test_error_value(self):
        assert CheckStatus.ERROR == "error"

    def test_is_str_enum(self):
        assert isinstance(CheckStatus.PASS, str)

    def test_exactly_five_members(self):
        assert len(CheckStatus) == 5


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


class TestFindingCraMapping:
    """Finding.cra_mapping field (added for v0.3 CRA evidence layer)."""

    def test_cra_mapping_defaults_to_empty_list(self):
        f = Finding(message="x", severity="low")
        assert f.cra_mapping == []

    def test_cra_mapping_accepts_single_id(self):
        f = Finding(message="x", severity="low", cra_mapping=["I.P2.1"])
        assert f.cra_mapping == ["I.P2.1"]

    def test_cra_mapping_accepts_multiple_ids(self):
        f = Finding(
            message="x",
            severity="high",
            cra_mapping=["I.P1.d", "I.P1.f", "VII.2.b"],
        )
        assert f.cra_mapping == ["I.P1.d", "I.P1.f", "VII.2.b"]

    def test_cra_mapping_is_list_type(self):
        f = Finding(message="x", severity="low")
        assert isinstance(f.cra_mapping, list)

    def test_cra_mapping_default_is_independent_per_instance(self):
        """default_factory=list must not share the same list across instances."""
        f1 = Finding(message="a", severity="low")
        f2 = Finding(message="b", severity="low")
        f1.cra_mapping.append("I.P2.1")
        assert f2.cra_mapping == []


class TestFindingSources:
    """Finding.sources field (added for reconciliation per design Decision 8)."""

    def test_sources_defaults_to_empty_list(self):
        f = Finding(message="x", severity="low")
        assert f.sources == []

    def test_sources_accepts_single_source(self):
        f = Finding(message="x", severity="low", sources=["cve-scan"])
        assert f.sources == ["cve-scan"]

    def test_sources_accepts_multiple_sources(self):
        f = Finding(
            message="x",
            severity="high",
            sources=["cve-scan", "yocto-cve-check"],
        )
        assert f.sources == ["cve-scan", "yocto-cve-check"]

    def test_sources_is_list_type(self):
        f = Finding(message="x", severity="low")
        assert isinstance(f.sources, list)

    def test_sources_default_is_independent_per_instance(self):
        """default_factory=list must not share the same list across instances."""
        f1 = Finding(message="a", severity="low")
        f2 = Finding(message="b", severity="low")
        f1.sources.append("cve-scan")
        assert f2.sources == []


class TestCheckResultCraMapping:
    """CheckResult.cra_mapping field (added for v0.3 CRA evidence layer)."""

    def test_cra_mapping_defaults_to_empty_list(self):
        r = CheckResult(
            check_id="sbom",
            check_name="SBOM",
            status=CheckStatus.PASS,
            score=50,
            max_score=50,
            findings=[],
            summary="ok",
        )
        assert r.cra_mapping == []

    def test_cra_mapping_accepts_single_id(self):
        r = CheckResult(
            check_id="sbom",
            check_name="SBOM",
            status=CheckStatus.PASS,
            score=50,
            max_score=50,
            findings=[],
            summary="ok",
            cra_mapping=["I.P2.1"],
        )
        assert r.cra_mapping == ["I.P2.1"]

    def test_cra_mapping_accepts_multiple_ids(self):
        r = CheckResult(
            check_id="sbom",
            check_name="SBOM",
            status=CheckStatus.PASS,
            score=50,
            max_score=50,
            findings=[],
            summary="ok",
            cra_mapping=["I.P2.1", "VII.2.b"],
        )
        assert r.cra_mapping == ["I.P2.1", "VII.2.b"]

    def test_cra_mapping_is_list_type(self):
        r = CheckResult(
            check_id="sbom",
            check_name="SBOM",
            status=CheckStatus.PASS,
            score=50,
            max_score=50,
            findings=[],
            summary="ok",
        )
        assert isinstance(r.cra_mapping, list)

    def test_cra_mapping_default_is_independent_per_instance(self):
        r1 = CheckResult(
            check_id="a",
            check_name="A",
            status=CheckStatus.PASS,
            score=0,
            max_score=50,
            findings=[],
            summary="",
        )
        r2 = CheckResult(
            check_id="b",
            check_name="B",
            status=CheckStatus.PASS,
            score=0,
            max_score=50,
            findings=[],
            summary="",
        )
        r1.cra_mapping.append("I.P2.1")
        assert r2.cra_mapping == []


class TestRoundTripSerialization:
    """asdict/reconstruction preserves cra_mapping and sources."""

    def test_finding_asdict_contains_cra_mapping(self):
        from dataclasses import asdict

        f = Finding(
            message="x",
            severity="high",
            cra_mapping=["I.P1.d", "I.P1.f"],
        )
        d = asdict(f)
        assert d["cra_mapping"] == ["I.P1.d", "I.P1.f"]

    def test_finding_asdict_contains_sources(self):
        from dataclasses import asdict

        f = Finding(
            message="x",
            severity="high",
            sources=["cve-scan", "yocto-cve-check"],
        )
        d = asdict(f)
        assert d["sources"] == ["cve-scan", "yocto-cve-check"]

    def test_finding_round_trip_preserves_cra_mapping_and_sources(self):
        from dataclasses import asdict

        original = Finding(
            message="CVE-2024-1234 affects openssl",
            severity="high",
            remediation="Upgrade to 3.0.12",
            details={"cve": "CVE-2024-1234", "package": "openssl"},
            cra_mapping=["I.P2.2", "I.P2.3"],
            sources=["cve-scan", "yocto-cve-check"],
        )
        d = asdict(original)
        reconstructed = Finding(**d)
        assert reconstructed == original
        assert reconstructed.cra_mapping == ["I.P2.2", "I.P2.3"]
        assert reconstructed.sources == ["cve-scan", "yocto-cve-check"]

    def test_check_result_asdict_contains_cra_mapping(self):
        from dataclasses import asdict

        r = CheckResult(
            check_id="sbom",
            check_name="SBOM",
            status=CheckStatus.PASS,
            score=50,
            max_score=50,
            findings=[],
            summary="ok",
            cra_mapping=["I.P2.1", "VII.2.b"],
        )
        d = asdict(r)
        assert d["cra_mapping"] == ["I.P2.1", "VII.2.b"]

    def test_check_result_round_trip_preserves_cra_mapping(self):
        from dataclasses import asdict

        finding = Finding(
            message="missing SBOM",
            severity="high",
            cra_mapping=["I.P2.1"],
            sources=["sbom"],
        )
        original = CheckResult(
            check_id="sbom",
            check_name="SBOM",
            status=CheckStatus.FAIL,
            score=0,
            max_score=50,
            findings=[finding],
            summary="no SBOM found",
            cra_mapping=["I.P2.1", "VII.2.b"],
        )
        d = asdict(original)
        # Rebuild nested Finding objects from their dicts.
        d["findings"] = [Finding(**fd) for fd in d["findings"]]
        reconstructed = CheckResult(**d)
        assert reconstructed == original
        assert reconstructed.cra_mapping == ["I.P2.1", "VII.2.b"]
        assert reconstructed.findings[0].cra_mapping == ["I.P2.1"]
        assert reconstructed.findings[0].sources == ["sbom"]

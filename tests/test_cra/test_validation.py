"""Tests for CRA mapping validation against the requirement catalog.

These tests pin the contract "Unknown mapping IDs are rejected" from
specs/cra-requirement-mapping/spec.md. Every CRA mapping emitted by a
check must resolve to a known catalog ID; otherwise the scan pipeline
must refuse to render a report that cites a phantom requirement.
"""

from __future__ import annotations

import pytest

from shipcheck.cra.loader import validate_cra_mappings
from shipcheck.models import CheckResult, CheckStatus, Finding, ReportData


def _report_with_findings(findings: list[Finding], result_mapping: list[str]) -> ReportData:
    """Build a minimal ReportData wrapping the supplied findings."""
    result = CheckResult(
        check_id="test-check",
        check_name="Test Check",
        status=CheckStatus.WARN,
        score=0,
        max_score=50,
        findings=findings,
        summary="synthetic result for validation tests",
        cra_mapping=result_mapping,
    )
    return ReportData(
        checks=[result],
        total_score=0,
        max_total_score=50,
        framework="CRA",
        framework_version="2024/2847",
        bsi_tr_version="TR-03183-2 v2.1.0",
        build_dir="/tmp/fake-build",
        timestamp="2026-04-16T00:00:00Z",
        shipcheck_version="0.0.3",
    )


class TestValidateCraMappingsRejectsUnknownIds:
    """`validate_cra_mappings` raises ValueError on phantom catalog IDs."""

    def test_bogus_mapping_raises_value_error(self):
        finding = Finding(
            message="SBOM missing top-level component list",
            severity="high",
            cra_mapping=["BOGUS.X.1"],
        )
        report = _report_with_findings([finding], result_mapping=["I.P2.1"])

        with pytest.raises(ValueError):
            validate_cra_mappings(report)

    def test_error_message_names_invalid_id(self):
        finding = Finding(
            message="SBOM missing top-level component list",
            severity="high",
            cra_mapping=["BOGUS.X.1"],
        )
        report = _report_with_findings([finding], result_mapping=["I.P2.1"])

        with pytest.raises(ValueError) as exc_info:
            validate_cra_mappings(report)

        assert "BOGUS.X.1" in str(exc_info.value)

    def test_error_message_names_finding_title(self):
        finding = Finding(
            message="SBOM missing top-level component list",
            severity="high",
            cra_mapping=["BOGUS.X.1"],
        )
        report = _report_with_findings([finding], result_mapping=["I.P2.1"])

        with pytest.raises(ValueError) as exc_info:
            validate_cra_mappings(report)

        assert "SBOM missing top-level component list" in str(exc_info.value)

    def test_rejects_when_only_one_of_many_mappings_is_invalid(self):
        finding = Finding(
            message="CVE triage incomplete",
            severity="medium",
            cra_mapping=["I.P2.2", "NOT.A.REAL.ID"],
        )
        report = _report_with_findings([finding], result_mapping=["I.P2.2", "I.P2.3"])

        with pytest.raises(ValueError) as exc_info:
            validate_cra_mappings(report)

        message = str(exc_info.value)
        assert "NOT.A.REAL.ID" in message
        assert "CVE triage incomplete" in message


class TestValidateCraMappingsAcceptsValidIds:
    """`validate_cra_mappings` returns None when every mapping is in the catalog."""

    def test_valid_annex_i_part_1_id_passes(self):
        finding = Finding(
            message="Secure boot keys not embedded",
            severity="high",
            cra_mapping=["I.P1.d"],
        )
        report = _report_with_findings([finding], result_mapping=["I.P1.d", "I.P1.f"])

        # Should not raise.
        validate_cra_mappings(report)

    def test_valid_annex_i_part_2_id_passes(self):
        finding = Finding(
            message="SBOM missing top-level component list",
            severity="high",
            cra_mapping=["I.P2.1"],
        )
        report = _report_with_findings([finding], result_mapping=["I.P2.1", "VII.2"])

        # Should not raise.
        validate_cra_mappings(report)

    def test_multiple_valid_mappings_on_one_finding_pass(self):
        finding = Finding(
            message="CVE triage incomplete",
            severity="medium",
            cra_mapping=["I.P2.2", "I.P2.3"],
        )
        report = _report_with_findings([finding], result_mapping=["I.P2.2", "I.P2.3"])

        # Should not raise.
        validate_cra_mappings(report)

    def test_empty_mapping_list_passes(self):
        """A finding with no CRA mapping is not invalid; it is unmapped.

        Validation only rejects *unknown* IDs. Missing mappings surface as
        gaps in the evidence renderer, not as validation errors.
        """
        finding = Finding(
            message="informational note",
            severity="low",
            cra_mapping=[],
        )
        report = _report_with_findings([finding], result_mapping=[])

        # Should not raise.
        validate_cra_mappings(report)

    def test_empty_report_passes(self):
        report = _report_with_findings([], result_mapping=[])

        # Should not raise.
        validate_cra_mappings(report)

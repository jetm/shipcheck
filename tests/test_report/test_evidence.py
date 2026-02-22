"""Tests for the CRA evidence report renderer.

Task 3.1 of devspec change ``shipcheck-v03-cra-evidence``. Asserts the
pivot-by-requirement contract of :mod:`shipcheck.report.evidence`:

* every catalog requirement with at least one mapped finding appears as
  its own section,
* a finding whose ``cra_mapping`` lists multiple requirements appears
  under each of them,
* the Gaps section enumerates every catalog requirement that has no
  mapping and renders its verbatim regulation text with a "no evidence"
  annotation,
* when every requirement is covered, the Gaps section collapses to a
  single reassuring sentence, and
* rendering 10k synthetic findings completes in under 5 seconds
  (``time.perf_counter``-timed; ``pytest-timeout`` acts as a safety net).

The import target ``shipcheck.report.evidence.render`` is deliberately
absent until task 3.2 - the whole module should fail with
``ImportError`` at collection time, which is the valid RED for TDD.
"""

from __future__ import annotations

import time

import pytest

from shipcheck.cra.loader import load_catalog
from shipcheck.models import CheckResult, CheckStatus, Finding, ReportData
from shipcheck.report.evidence import render


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
        "shipcheck_version": "0.3.0",
    }
    defaults.update(overrides)
    return ReportData(**defaults)


def _check_with(findings: list[Finding], cra_mapping: list[str]) -> CheckResult:
    return CheckResult(
        check_id="demo-check",
        check_name="Demo check",
        status=CheckStatus.PASS if not findings else CheckStatus.WARN,
        score=50,
        max_score=50,
        findings=findings,
        summary="synthetic",
        cra_mapping=cra_mapping,
    )


class TestPerRequirementSections:
    def test_section_exists_for_each_mapped_requirement(self):
        findings = [
            Finding(
                message="SBOM present",
                severity="low",
                cra_mapping=["I.P2.1"],
            ),
            Finding(
                message="Secure boot keys enrolled",
                severity="low",
                cra_mapping=["I.P1.d"],
            ),
        ]
        check = _check_with(findings, cra_mapping=["I.P2.1", "I.P1.d"])
        output = render(_make_report(checks=[check]))

        assert "I.P2.1" in output
        assert "I.P1.d" in output

    def test_unmapped_requirement_does_not_appear_as_section(self):
        findings = [
            Finding(
                message="SBOM present",
                severity="low",
                cra_mapping=["I.P2.1"],
            ),
        ]
        check = _check_with(findings, cra_mapping=["I.P2.1"])
        output = render(_make_report(checks=[check]))

        head, _, _ = output.partition("Gaps")
        assert "I.P1.a" not in head
        assert "VII.8" not in head

    def test_finding_message_appears_under_its_section(self):
        findings = [
            Finding(
                message="Package openssl scanned for CVEs",
                severity="low",
                cra_mapping=["I.P2.2"],
            ),
        ]
        check = _check_with(findings, cra_mapping=["I.P2.2"])
        output = render(_make_report(checks=[check]))

        before_gaps, _, _ = output.partition("Gaps")
        assert "Package openssl scanned for CVEs" in before_gaps


class TestMultiMappingFinding:
    def test_finding_with_two_mappings_appears_under_both_sections(self):
        finding = Finding(
            message="Image signing enforced at boot",
            severity="low",
            cra_mapping=["I.P1.d", "I.P1.f"],
        )
        check = _check_with([finding], cra_mapping=["I.P1.d", "I.P1.f"])
        output = render(_make_report(checks=[check]))

        before_gaps, _, _ = output.partition("Gaps")
        assert before_gaps.count("Image signing enforced at boot") == 2


class TestGapsSection:
    def test_gaps_lists_every_unmapped_requirement(self):
        finding = Finding(
            message="SBOM present",
            severity="low",
            cra_mapping=["I.P2.1"],
        )
        check = _check_with([finding], cra_mapping=["I.P2.1"])
        output = render(_make_report(checks=[check]))

        _, _, gaps_section = output.partition("Gaps")
        catalog = load_catalog()
        unmapped_ids = [rid for rid in catalog.requirements if rid != "I.P2.1"]

        assert unmapped_ids, "fixture must leave at least one requirement unmapped"
        for rid in unmapped_ids:
            assert rid in gaps_section, f"missing gap entry for {rid}"

    def test_gaps_includes_verbatim_text_and_no_evidence_annotation(self):
        finding = Finding(
            message="SBOM present",
            severity="low",
            cra_mapping=["I.P2.1"],
        )
        check = _check_with([finding], cra_mapping=["I.P2.1"])
        output = render(_make_report(checks=[check]))

        _, _, gaps_section = output.partition("Gaps")
        catalog = load_catalog()
        sample = catalog.requirements["I.P1.a"]

        assert sample.text in gaps_section
        assert "no evidence" in gaps_section.lower()

    def test_gaps_collapses_when_every_requirement_has_a_mapping(self):
        catalog = load_catalog()
        all_ids = list(catalog.requirements.keys())
        findings = [
            Finding(
                message=f"synthetic evidence for {rid}",
                severity="low",
                cra_mapping=[rid],
            )
            for rid in all_ids
        ]
        check = _check_with(findings, cra_mapping=all_ids)
        output = render(_make_report(checks=[check]))

        assert "All CRA requirements have at least one evidence mapping" in output


@pytest.mark.timeout(15)
class TestRenderPerformance:
    def test_renders_10k_findings_under_5s(self):
        catalog = load_catalog()
        all_ids = list(catalog.requirements.keys())
        assert all_ids, "catalog must expose at least one requirement"

        findings: list[Finding] = []
        for i in range(10_000):
            mapping_id = all_ids[i % len(all_ids)]
            findings.append(
                Finding(
                    message=f"synthetic finding {i}",
                    severity="low",
                    cra_mapping=[mapping_id],
                )
            )
        check = _check_with(findings, cra_mapping=all_ids)
        report = _make_report(checks=[check])

        start = time.perf_counter()
        output = render(report)
        elapsed = time.perf_counter() - start

        assert isinstance(output, str) and output
        assert elapsed < 5.0, f"render took {elapsed:.2f}s (expected < 5s)"

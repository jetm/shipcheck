"""Tests for the Annex VII technical documentation generator.

Task 8.1 of devspec change ``shipcheck-v03-cra-evidence``. Asserts the
contract of :func:`shipcheck.docs_generator.annex_vii.generate_annex_vii`:

* the generator writes a markdown file containing the eight top-level
  Annex VII items (1-8) in order, each headed ``## Item N - <title>``,
* items with no narrative render an ``N/A - <reason>`` body rather than
  being omitted entirely,
* the generator injects a prominent
  ``DRAFT - FOR MANUFACTURER REVIEW`` header at the top of the file,
* the §2 (Item 2) SBOM subsection contains a markdown table with
  columns ``check``, ``finding title``, ``severity``, ``cra_mapping``,
  ``timestamp`` populated from SBOM findings whose ``cra_mapping``
  includes ``"I.P2.1"`` or ``"VII.2"``. The catalog uses ``VII.2`` (not
  ``VII.2.b``) per the devspec amendment log, so that is the identifier
  the test asserts against,
* the §3 (Item 3) cybersecurity risk-assessment section lists the
  Annex I Part I requirements alongside their mapped findings, and
* overwriting an existing output file emits a warning log record.

The import target ``shipcheck.docs_generator.annex_vii`` is deliberately
absent until task 8.2 - the whole module should fail with
``ImportError`` at collection time, which is the valid RED for TDD.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

import pytest

from shipcheck.cra.loader import load_catalog
from shipcheck.docs_generator.annex_vii import generate_annex_vii
from shipcheck.models import CheckResult, CheckStatus, Finding, ReportData
from shipcheck.product import ProductConfig, load_product_config

FIXTURE_PRODUCT = Path("tests/fixtures/product/complete.yaml")


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


def _sbom_check(findings: list[Finding]) -> CheckResult:
    return CheckResult(
        check_id="sbom-scan",
        check_name="SBOM validation",
        status=CheckStatus.PASS if not findings else CheckStatus.WARN,
        score=50,
        max_score=50,
        findings=findings,
        summary="synthetic SBOM check",
        cra_mapping=["I.P2.1", "VII.2"],
    )


def _code_integrity_check(findings: list[Finding]) -> CheckResult:
    return CheckResult(
        check_id="code-integrity",
        check_name="Code Integrity",
        status=CheckStatus.PASS if not findings else CheckStatus.FAIL,
        score=50,
        max_score=50,
        findings=findings,
        summary="synthetic code integrity check",
        cra_mapping=["I.P1.c", "I.P1.d", "I.P1.f", "I.P1.k"],
    )


@pytest.fixture
def product() -> ProductConfig:
    return load_product_config(FIXTURE_PRODUCT)


@pytest.fixture
def out_path(tmp_path: Path) -> Path:
    return tmp_path / "technical-documentation.md"


@pytest.fixture
def empty_report() -> ReportData:
    return _make_report()


class TestEightTopLevelSectionsInOrder:
    def test_all_eight_items_present(
        self,
        product: ProductConfig,
        out_path: Path,
        empty_report: ReportData,
    ) -> None:
        generate_annex_vii(empty_report, product, out_path)
        text = out_path.read_text(encoding="utf-8")

        for n in range(1, 9):
            assert re.search(rf"^## Item {n}\b", text, re.MULTILINE), (
                f"expected '## Item {n}' heading in output"
            )

    def test_items_appear_in_ascending_order(
        self,
        product: ProductConfig,
        out_path: Path,
        empty_report: ReportData,
    ) -> None:
        generate_annex_vii(empty_report, product, out_path)
        text = out_path.read_text(encoding="utf-8")

        positions = []
        for n in range(1, 9):
            match = re.search(rf"^## Item {n}\b", text, re.MULTILINE)
            assert match is not None, f"missing heading for item {n}"
            positions.append(match.start())

        assert positions == sorted(positions), (
            f"Annex VII items not in order: positions={positions}"
        )

    def test_headings_carry_catalog_titles(
        self,
        product: ProductConfig,
        out_path: Path,
        empty_report: ReportData,
    ) -> None:
        generate_annex_vii(empty_report, product, out_path)
        text = out_path.read_text(encoding="utf-8")

        catalog = load_catalog()
        for n in range(1, 9):
            req = catalog.requirements[f"VII.{n}"]
            # Heading format: "## Item N - <title>" (em dash or hyphen both fine,
            # but tasks.md specifies the plain hyphen form, so assert that).
            assert f"## Item {n} - {req.title}" in text, (
                f"expected heading '## Item {n} - {req.title}'"
            )


class TestDraftHeader:
    def test_draft_header_present(
        self,
        product: ProductConfig,
        out_path: Path,
        empty_report: ReportData,
    ) -> None:
        generate_annex_vii(empty_report, product, out_path)
        text = out_path.read_text(encoding="utf-8")
        assert "DRAFT - FOR MANUFACTURER REVIEW" in text

    def test_draft_header_appears_before_first_item(
        self,
        product: ProductConfig,
        out_path: Path,
        empty_report: ReportData,
    ) -> None:
        generate_annex_vii(empty_report, product, out_path)
        text = out_path.read_text(encoding="utf-8")

        draft_pos = text.find("DRAFT - FOR MANUFACTURER REVIEW")
        first_item = re.search(r"^## Item 1\b", text, re.MULTILINE)
        assert draft_pos != -1, "DRAFT header missing"
        assert first_item is not None, "Item 1 heading missing"
        assert draft_pos < first_item.start(), "DRAFT header must appear before '## Item 1'"


class TestMissingNarrativeRendersNA:
    def test_missing_narrative_still_has_section(
        self,
        product: ProductConfig,
        out_path: Path,
        empty_report: ReportData,
    ) -> None:
        # With an empty report (no findings, no narrative input), items
        # that rely on scan evidence (e.g. §6 test reports, §7 DoC copy)
        # cannot be satisfied. The generator must still render a section
        # with an "N/A - <reason>" body rather than silently omitting it.
        generate_annex_vii(empty_report, product, out_path)
        text = out_path.read_text(encoding="utf-8")

        # At least one item must render the explicit N/A annotation.
        assert re.search(r"N/A\s*-\s*\S+", text), (
            "expected 'N/A - <reason>' body for at least one empty item; "
            "missing narratives must not silently drop sections"
        )

    def test_na_body_follows_its_own_heading(
        self,
        product: ProductConfig,
        out_path: Path,
        empty_report: ReportData,
    ) -> None:
        generate_annex_vii(empty_report, product, out_path)
        text = out_path.read_text(encoding="utf-8")

        # Partition the document into per-item chunks and assert that any
        # chunk containing "N/A -" is still anchored by its own Item heading.
        chunks = re.split(r"(?m)^## Item \d+\b", text)
        # chunks[0] is the preamble; subsequent chunks are item bodies.
        assert len(chunks) >= 9, "expected at least 8 item bodies plus preamble"
        na_chunks = [c for c in chunks[1:] if re.search(r"N/A\s*-\s*\S+", c)]
        assert na_chunks, "no item body contained an N/A - <reason> annotation"


class TestItem2SbomTable:
    def test_sbom_table_has_required_columns(
        self,
        product: ProductConfig,
        out_path: Path,
    ) -> None:
        finding = Finding(
            message="SPDX document present",
            severity="low",
            cra_mapping=["I.P2.1", "VII.2"],
        )
        report = _make_report(checks=[_sbom_check([finding])])

        generate_annex_vii(report, product, out_path)
        text = out_path.read_text(encoding="utf-8")

        # Scope to the Item 2 section so we don't accidentally match a
        # table that lives under another item.
        item2 = _section(text, 2)
        for column in ("check", "finding title", "severity", "cra_mapping", "timestamp"):
            assert column in item2.lower(), (
                f"Item 2 section missing column header '{column}'. Got:\n{item2}"
            )

        # Markdown table row separator ensures a table was actually rendered.
        assert re.search(r"\|\s*-{3,}\s*\|", item2), (
            "Item 2 section has no markdown table separator row"
        )

    def test_sbom_table_populated_from_matching_findings(
        self,
        product: ProductConfig,
        out_path: Path,
    ) -> None:
        matching_a = Finding(
            message="SPDX document present",
            severity="low",
            cra_mapping=["I.P2.1"],
        )
        matching_b = Finding(
            message="SBOM satisfies Annex VII.2",
            severity="medium",
            cra_mapping=["VII.2"],
        )
        # Finding whose mapping hits neither I.P2.1 nor VII.2 - should be
        # excluded from the §2 SBOM table.
        unrelated = Finding(
            message="Secure boot keys enrolled",
            severity="low",
            cra_mapping=["I.P1.d"],
        )

        report = _make_report(
            checks=[
                _sbom_check([matching_a, matching_b]),
                _code_integrity_check([unrelated]),
            ],
        )

        generate_annex_vii(report, product, out_path)
        text = out_path.read_text(encoding="utf-8")
        item2 = _section(text, 2)

        assert "SPDX document present" in item2
        assert "SBOM satisfies Annex VII.2" in item2
        assert "Secure boot keys enrolled" not in item2, (
            "§2 SBOM table must only list findings mapped to I.P2.1 or VII.2"
        )

    def test_sbom_table_row_includes_timestamp(
        self,
        product: ProductConfig,
        out_path: Path,
    ) -> None:
        finding = Finding(
            message="SPDX document present",
            severity="low",
            cra_mapping=["I.P2.1"],
        )
        report = _make_report(
            checks=[_sbom_check([finding])],
            timestamp="2026-04-01T12:00:00Z",
        )

        generate_annex_vii(report, product, out_path)
        text = out_path.read_text(encoding="utf-8")
        item2 = _section(text, 2)

        assert "2026-04-01T12:00:00Z" in item2, (
            "Item 2 SBOM table must include the report timestamp"
        )


class TestItem3RiskAssessment:
    def test_risk_assessment_lists_all_part_i_requirements(
        self,
        product: ProductConfig,
        out_path: Path,
        empty_report: ReportData,
    ) -> None:
        generate_annex_vii(empty_report, product, out_path)
        text = out_path.read_text(encoding="utf-8")
        item3 = _section(text, 3)

        catalog = load_catalog()
        part_i_ids = [
            rid for rid, req in catalog.requirements.items() if req.annex == "I" and req.part == "1"
        ]
        assert len(part_i_ids) == 13, (
            f"catalog must expose 13 Annex I Part I requirements, got {len(part_i_ids)}"
        )
        for rid in part_i_ids:
            assert rid in item3, f"Item 3 risk assessment missing Annex I Part I requirement {rid}"

    def test_risk_assessment_includes_mapped_findings(
        self,
        product: ProductConfig,
        out_path: Path,
    ) -> None:
        finding = Finding(
            message="Image signing enforced at boot",
            severity="low",
            cra_mapping=["I.P1.d", "I.P1.f"],
        )
        report = _make_report(checks=[_code_integrity_check([finding])])

        generate_annex_vii(report, product, out_path)
        text = out_path.read_text(encoding="utf-8")
        item3 = _section(text, 3)

        assert "Image signing enforced at boot" in item3, (
            "Item 3 section must cite findings mapped to Annex I Part I"
        )


class TestOverwriteWarning:
    def test_overwrite_logs_warning(
        self,
        product: ProductConfig,
        out_path: Path,
        empty_report: ReportData,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        out_path.write_text("pre-existing content", encoding="utf-8")

        with caplog.at_level(logging.WARNING):
            generate_annex_vii(empty_report, product, out_path)

        warnings = [r for r in caplog.records if r.levelno >= logging.WARNING]
        assert warnings, "overwriting an existing output file must emit a WARNING log record"
        assert any(str(out_path) in r.getMessage() for r in warnings), (
            "warning must reference the output file path"
        )

    def test_first_write_emits_no_warning(
        self,
        product: ProductConfig,
        out_path: Path,
        empty_report: ReportData,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        assert not out_path.exists()

        with caplog.at_level(logging.WARNING):
            generate_annex_vii(empty_report, product, out_path)

        warnings = [r for r in caplog.records if r.levelno >= logging.WARNING]
        assert not warnings, (
            f"writing to a fresh path must not warn, got: {[r.getMessage() for r in warnings]}"
        )


def _section(text: str, item: int) -> str:
    """Return the body of ``## Item <item>`` up to the next ``## Item`` heading."""
    pattern = rf"(?ms)^## Item {item}\b.*?(?=^## Item \d+\b|\Z)"
    match = re.search(pattern, text)
    assert match is not None, f"could not locate section for Item {item} in output:\n{text!r}"
    return match.group(0)

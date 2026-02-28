"""Annex VII technical documentation generator.

Produces a markdown draft of the technical documentation required by
Annex VII of Regulation (EU) 2024/2847. The generator walks the CRA
catalog so every Annex VII item (1 through 8) gets its own section in
order, injects a prominent ``DRAFT - FOR MANUFACTURER REVIEW`` header,
and renders two evidence-driven subsections:

* §2 (Item 2) "Design, development, production and vulnerability
  handling" contains a markdown table of SBOM-related findings whose
  ``cra_mapping`` cites either ``I.P2.1`` (Annex I Part II §1 SBOM
  requirement) or ``VII.2`` (the Annex VII catalog ID for this item -
  see the devspec amendment log for why ``VII.2.b`` is not used).
* §3 (Item 3) "Cybersecurity risk assessment" enumerates every Annex I
  Part I requirement (I.P1.a through I.P1.m) and lists the findings
  mapped against each.

Narrative-only sections render ``N/A - <reason>`` bodies rather than
being silently omitted, so downstream reviewers never lose track of an
Annex VII item. Unknown product fields surface as
``[TO BE FILLED BY MANUFACTURER: <field>]`` placeholders inside the
template.

This module is intentionally pure ``report -> filesystem`` - CLI wiring
is added later in task 10.6.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from jinja2 import Environment, FileSystemLoader

from shipcheck.cra.loader import load_catalog

if TYPE_CHECKING:
    from collections.abc import Mapping

    from shipcheck.cra.loader import CraRequirement
    from shipcheck.models import ReportData
    from shipcheck.product import ProductConfig

_TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"
_TEMPLATE_NAME = "annex_vii.md.j2"

# Requirement IDs that qualify a finding for the §2 SBOM table.
_SBOM_MAPPING_IDS = frozenset({"I.P2.1", "VII.2"})

_logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class _FindingEntry:
    """Flattened view of a finding for template rendering.

    The template works with plain attribute access rather than dict
    lookups, so the entry carries the check-level context alongside the
    finding's own fields.
    """

    check_id: str
    message: str
    severity: str
    cra_mapping: str
    timestamp: str


@dataclass(frozen=True)
class _CheckSummary:
    """Compact per-check row used in the §6 conformity-test-report table."""

    check_id: str
    check_name: str
    status: str
    score: int
    max_score: int
    finding_count: int
    cra_mapping: str


def _build_findings_index(report: ReportData) -> dict[str, list[_FindingEntry]]:
    """Group findings by CRA requirement id in a single O(n) pass.

    A finding with multiple ``cra_mapping`` entries is appended to each
    requirement's bucket so §3's Annex I Part I walk surfaces every
    relevant finding, regardless of how many requirements it evidences.
    """
    index: dict[str, list[_FindingEntry]] = {}
    for result in report.checks:
        for finding in result.findings:
            if not finding.cra_mapping:
                continue
            entry = _FindingEntry(
                check_id=result.check_id,
                message=finding.message,
                severity=finding.severity,
                cra_mapping=", ".join(finding.cra_mapping),
                timestamp=report.timestamp,
            )
            for rid in finding.cra_mapping:
                index.setdefault(rid, []).append(entry)
    return index


def _collect_sbom_findings(report: ReportData) -> list[_FindingEntry]:
    """Return findings whose ``cra_mapping`` cites I.P2.1 or VII.2.

    Each finding appears at most once in the returned list, even if it
    is mapped to both qualifying requirements. Ordering follows the
    input check/finding order to keep output deterministic for tests.
    """
    collected: list[_FindingEntry] = []
    for result in report.checks:
        for finding in result.findings:
            if not finding.cra_mapping:
                continue
            if not any(rid in _SBOM_MAPPING_IDS for rid in finding.cra_mapping):
                continue
            collected.append(
                _FindingEntry(
                    check_id=result.check_id,
                    message=finding.message,
                    severity=finding.severity,
                    cra_mapping=", ".join(finding.cra_mapping),
                    timestamp=report.timestamp,
                )
            )
    return collected


def _summarise_checks(report: ReportData) -> list[_CheckSummary]:
    """Build the §6 per-check conformity summary rows."""
    return [
        _CheckSummary(
            check_id=result.check_id,
            check_name=result.check_name,
            status=str(result.status.value if hasattr(result.status, "value") else result.status),
            score=result.score,
            max_score=result.max_score,
            finding_count=len(result.findings),
            cra_mapping=", ".join(result.cra_mapping) if result.cra_mapping else "-",
        )
        for result in report.checks
    ]


def _annex_vii_items(
    requirements: Mapping[str, CraRequirement],
) -> dict[int, CraRequirement]:
    """Return an ``{item_number: CraRequirement}`` map for Annex VII 1-8.

    Item numbers are exposed as integers so the template can index with
    the natural ``items[1]`` .. ``items[8]`` syntax; the catalog stores
    the item under the string key ``"1"``..``"8"`` inside Annex VII.
    """
    items: dict[int, CraRequirement] = {}
    for req in requirements.values():
        if req.annex != "VII":
            continue
        try:
            number = int(req.item)
        except ValueError:
            continue
        items[number] = req
    return items


def _part_i_requirements(
    requirements: Mapping[str, CraRequirement],
) -> list[CraRequirement]:
    """Return Annex I Part I requirements in catalog order (I.P1.a..m)."""
    return [req for req in requirements.values() if req.annex == "I" and req.part == "1"]


def generate_annex_vii(
    report: ReportData,
    product: ProductConfig,
    out_path: Path,
) -> None:
    """Render the Annex VII technical documentation draft.

    Args:
        report: Aggregated scan report whose findings provide the
            evidence cited in the SBOM table (§2) and risk assessment
            (§3) sections.
        product: Declarative product metadata used to fill
            identification fields, manufacturer details, support period
            end date and CVD contact points.
        out_path: Destination markdown file. If the file already exists,
            a ``WARNING`` log record is emitted before overwriting so a
            caller running under ``caplog`` can observe the clobber.

    The function always writes the full 8-item Annex VII structure even
    when the report is empty: items with no evidence render
    ``N/A - <reason>`` bodies rather than being omitted, matching the
    ship-gate "all 8 Annex VII items present or explicitly marked N/A
    with reason".
    """
    catalog = load_catalog()

    items = _annex_vii_items(catalog.requirements)
    missing = [n for n in range(1, 9) if n not in items]
    if missing:
        raise RuntimeError(
            f"CRA catalog is missing Annex VII item(s) {missing}; "
            "cannot render technical documentation"
        )

    findings_by_requirement = _build_findings_index(report)
    sbom_findings = _collect_sbom_findings(report)
    part_i_requirements = _part_i_requirements(catalog.requirements)
    check_summaries = _summarise_checks(report)

    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        keep_trailing_newline=True,
        trim_blocks=True,
        lstrip_blocks=True,
        autoescape=False,  # markdown output, not HTML
    )
    template = env.get_template(_TEMPLATE_NAME)
    rendered = template.render(
        report=report,
        product=product,
        items=items,
        part_i_requirements=part_i_requirements,
        findings_by_requirement=findings_by_requirement,
        sbom_findings=sbom_findings,
        check_summaries=check_summaries,
    )

    if out_path.exists():
        _logger.warning("overwriting %s", out_path)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(rendered, encoding="utf-8")

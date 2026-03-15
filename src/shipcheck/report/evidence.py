"""CRA evidence report renderer.

Pivots the report data from per-check organisation to per-requirement
organisation: each CRA Annex item that has at least one mapped finding
gets its own section citing the verbatim regulation text and the
findings that evidence it, followed by a Gaps section enumerating the
requirements for which no evidence was collected.

Design Decision 9 (design.md) makes this a first-class renderer rather
than a post-processor on top of the markdown renderer: pivoting by
requirement needs structured access to each finding's ``cra_mapping``
metadata, which is only available on the ``ReportData`` object itself.

Design risk "Performance of evidence render on large builds" mandates a
single O(n) pass to build the findings-by-mapping index. The benchmark
in ``tests/test_report/test_evidence.py`` caps render time at 5 seconds
for 10k findings.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from jinja2 import Environment, FileSystemLoader

from shipcheck.cra.loader import load_catalog

if TYPE_CHECKING:
    from shipcheck.models import ReportData

_TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"


@dataclass(frozen=True)
class _FindingEntry:
    """A finding flattened with its owning check's identifier.

    Used by the Jinja template to render a finding alongside the check
    that produced it, without the template needing to traverse the
    ``CheckResult`` -> ``Finding`` hierarchy itself.
    """

    check_id: str
    message: str
    severity: str


def _build_index(report: ReportData) -> dict[str, list[_FindingEntry]]:
    """Group findings by CRA requirement id in a single O(n) pass.

    A finding whose ``cra_mapping`` lists multiple requirement IDs is
    appended once per requirement, so multi-mapping findings naturally
    surface in each relevant section.
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
            )
            for requirement_id in finding.cra_mapping:
                index.setdefault(requirement_id, []).append(entry)
    return index


def render(report: ReportData) -> str:
    """Render the CRA evidence report as a Markdown string.

    Organises output by CRA requirement rather than by check. Every
    catalog requirement with at least one mapped finding gets a section
    citing the verbatim regulation text and its findings. Requirements
    without mapped findings are listed in the trailing Gaps section; if
    every requirement is covered, the Gaps section collapses to a single
    reassuring sentence.

    Args:
        report: Fully assembled report data to pivot.

    Returns:
        Rendered markdown document as a string.
    """
    catalog = load_catalog()
    findings_by_requirement = _build_index(report)

    mapped_requirements = [
        catalog.requirements[rid] for rid in catalog.requirements if rid in findings_by_requirement
    ]
    unmapped_requirements = [
        catalog.requirements[rid]
        for rid in catalog.requirements
        if rid not in findings_by_requirement
    ]

    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        keep_trailing_newline=True,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    template = env.get_template("evidence.md.j2")
    return template.render(
        report=report,
        mapped_requirements=mapped_requirements,
        unmapped_requirements=unmapped_requirements,
        findings_by_requirement=findings_by_requirement,
    )

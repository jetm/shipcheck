"""Markdown report renderer using Jinja2."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from jinja2 import Environment, FileSystemLoader

if TYPE_CHECKING:
    from shipcheck.models import ReportData

_TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"


def render(report: ReportData) -> str:
    """Render a compliance report as a Markdown string.

    Args:
        report: Aggregated report data to render.

    Returns:
        Rendered markdown string.
    """
    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        keep_trailing_newline=True,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    template = env.get_template("report.md.j2")
    return template.render(report=report)

"""HTML report renderer using Jinja2 template."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from jinja2 import Environment, FileSystemLoader

if TYPE_CHECKING:
    from shipcheck.models import ReportData

_TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"


def render(report: ReportData) -> str:
    """Render a report as a self-contained HTML string.

    Uses the Jinja2 template at templates/report.html.j2 to produce a single
    HTML file with inline CSS and no JavaScript.

    Args:
        report: Aggregated report data to render.

    Returns:
        Complete HTML document as a string.
    """
    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=True,
    )
    template = env.get_template("report.html.j2")
    return template.render(report=report)

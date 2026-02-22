"""Report rendering backends.

Each submodule exposes a ``render(report: ReportData) -> str`` function
producing a rendered representation of a compliance scan. Renderers are
registered here so callers can import them via
``from shipcheck.report import evidence, html, json_report, markdown, terminal``.
The ``evidence`` renderer pivots by CRA requirement; CLI format choices
are wired up in task 10.2.
"""

from shipcheck.report import evidence, html, json_report, markdown, terminal

__all__ = ["evidence", "html", "json_report", "markdown", "terminal"]

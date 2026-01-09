"""Terminal (Rich) report renderer."""

from __future__ import annotations

from typing import TYPE_CHECKING

from rich.console import Console
from rich.text import Text

if TYPE_CHECKING:
    from shipcheck.models import ReportData

from shipcheck.models import CheckStatus

_STATUS_STYLES: dict[str, tuple[str, str]] = {
    CheckStatus.PASS: ("PASS", "bold green"),
    CheckStatus.FAIL: ("FAIL", "bold red"),
    CheckStatus.WARN: ("WARN", "bold yellow"),
    CheckStatus.SKIP: ("SKIP", "bold dim"),
}

_SEVERITY_STYLES: dict[str, str] = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "dim",
}


def render(report: ReportData, *, console: Console | None = None) -> None:
    """Render a compliance report to the terminal using Rich.

    Args:
        report: Aggregated report data to display.
        console: Optional Rich console for output redirection (testing).
    """
    if console is None:
        console = Console()

    console.print()
    console.print(
        f"shipcheck v{report.shipcheck_version} — Embedded Linux Compliance Auditor",
        style="bold",
    )
    console.print()
    console.print(f"Checking {report.build_dir}...")
    console.print()

    for check in report.checks:
        label, style = _STATUS_STYLES.get(check.status, ("????", "bold"))
        status_text = Text(f"  {label}  ", style=style)
        line = Text()
        line.append_text(status_text)
        line.append(f"{check.check_name}", style="bold")
        line.append(f"  {check.summary}")
        console.print(line)

        for finding in check.findings:
            sev_style = _SEVERITY_STYLES.get(finding.severity, "")
            sev_label = Text(f"[{finding.severity}]", style=sev_style)
            finding_line = Text("          ")
            finding_line.append_text(sev_label)
            finding_line.append(f" {finding.message}")
            console.print(finding_line)

            if finding.remediation:
                console.print(f"          Fix: {finding.remediation}")

    console.print()
    console.print(f"Readiness score: {report.total_score}/{report.max_total_score}", style="bold")

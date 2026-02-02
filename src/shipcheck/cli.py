"""CLI entry points for shipcheck."""

from __future__ import annotations

from dataclasses import asdict
from pathlib import Path

import typer
from rich.console import Console

from shipcheck.checks.registry import get_default_registry
from shipcheck.config import load_config
from shipcheck.report import html, json_report, markdown, terminal
from shipcheck.report.score import build_report_data

app = typer.Typer(
    name="shipcheck",
    help="Embedded Linux compliance auditor — CRA, Secure Boot, SBOM, CVE tracking",
    no_args_is_help=True,
)

_VALID_FORMATS = {"markdown", "json", "html"}
_FORMAT_EXT = {"markdown": "md", "json": "json", "html": "html"}

_SEVERITY_ORDER = ["critical", "high", "medium", "low"]


def _build_check_config(config) -> dict:
    """Build a dict keyed by check ID from the ShipcheckConfig for the registry."""
    return {
        "sbom-generation": asdict(config.sbom),
        "cve-tracking": asdict(config.cve),
        "secure-boot": asdict(config.secure_boot),
        "image-signing": asdict(config.image_signing),
    }


def _should_fail(results, fail_on: str | None) -> bool:
    """Return True if any finding meets or exceeds the fail_on severity threshold."""
    if fail_on is None:
        return False

    threshold_idx = _SEVERITY_ORDER.index(fail_on)
    failing_severities = set(_SEVERITY_ORDER[: threshold_idx + 1])

    for result in results:
        for finding in result.findings:
            if finding.severity in failing_severities:
                return True
    return False


def _render_file_report(report_data, fmt: str) -> str:
    """Render a file report and return the content string."""
    if fmt == "json":
        return json_report.render(report_data)
    if fmt == "html":
        return html.render(report_data)
    return markdown.render(report_data)


@app.command()
def check(
    build_dir: Path = typer.Option(
        ...,
        "--build-dir",
        help="Path to the Yocto build directory.",
    ),
    format: str = typer.Option(
        "markdown",
        "--format",
        help="Output format (markdown, json, html).",
    ),
    checks: str | None = typer.Option(
        None,
        "--checks",
        help="Comma-separated list of checks to run.",
    ),
    fail_on: str | None = typer.Option(
        None,
        "--fail-on",
        help="Exit non-zero if findings at this severity or above (critical, high, medium, low).",
    ),
) -> None:
    """Run compliance checks against a Yocto build directory."""
    config = load_config(Path(".shipcheck.yaml"))

    check_ids = [c.strip() for c in checks.split(",")] if checks else None
    config.apply_cli_overrides(
        build_dir=str(build_dir),
        format=format,
        checks=check_ids,
        fail_on=fail_on,
    )

    fmt = config.report.format
    if fmt not in _VALID_FORMATS:
        valid = ", ".join(sorted(_VALID_FORMATS))
        typer.echo(f"Error: invalid format '{fmt}'. Choose from: {valid}", err=True)
        raise typer.Exit(code=1)

    registry = get_default_registry()
    check_config = _build_check_config(config)

    try:
        results = registry.run_checks(
            build_dir=config.build_dir,
            config=check_config,
            check_ids=config.checks,
        )
    except ValueError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    report_data = build_report_data(results, build_dir=str(config.build_dir))

    console = Console()
    terminal.render(report_data, console=console)

    content = _render_file_report(report_data, fmt)
    ext = _FORMAT_EXT[fmt]
    output_name = f"{config.report.output}.{ext}"
    Path(output_name).write_text(content)
    console.print(f"\nFull report saved to: {output_name}")

    if _should_fail(results, config.report.fail_on):
        raise typer.Exit(code=1)


@app.command()
def init() -> None:
    """Initialize a shipcheck configuration file in the current directory."""
    config_path = Path(".shipcheck.yaml")
    if config_path.exists():
        typer.echo("Configuration file already exists: .shipcheck.yaml")
        return

    scaffold = """\
# shipcheck configuration
# See https://github.com/tiamarin/shipcheck for documentation.

# Path to the Yocto build directory
# build_dir: ./build

# Compliance framework (only CRA supported in v0.1)
# framework: CRA

# List of check IDs to run (default: all)
# checks:
#   - sbom-generation
#   - cve-tracking
#   - secure-boot
#   - image-signing

# SBOM check configuration
# sbom:
#   required_fields:
#     - name
#     - version
#     - supplier
#     - license
#     - checksum

# CVE check configuration
# cve:
#   suppress:
#     - CVE-2023-1234

# Secure Boot check configuration
# secure_boot:
#   known_test_keys: []

# Image Signing check configuration
# image_signing:
#   expect_fit: true
#   expect_verity: true

# Report output options
# report:
#   format: markdown        # markdown | json | html
#   output: shipcheck-report
#   fail_on: null            # null | critical | high | medium | low
"""
    config_path.write_text(scaffold)
    typer.echo("Created .shipcheck.yaml")


@app.command()
def version() -> None:
    """Show shipcheck version."""
    from shipcheck import __version__

    typer.echo(f"shipcheck {__version__}")


def main() -> None:
    """Invoke the CLI app."""
    app()

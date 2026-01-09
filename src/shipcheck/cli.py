"""CLI entry points for shipcheck."""

from pathlib import Path
from typing import Optional

import typer

app = typer.Typer(
    name="shipcheck",
    help="Embedded Linux compliance auditor — CRA, Secure Boot, SBOM, CVE tracking",
    no_args_is_help=True,
)


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
    checks: Optional[str] = typer.Option(
        None,
        "--checks",
        help="Comma-separated list of checks to run.",
    ),
    fail_on: Optional[str] = typer.Option(
        None,
        "--fail-on",
        help="Exit non-zero if findings at this severity or above (critical, high, medium, low).",
    ),
) -> None:
    """Run compliance checks against a Yocto build directory."""
    typer.echo("Not implemented")


@app.command()
def init() -> None:
    """Initialize a shipcheck configuration file in the current directory."""
    typer.echo("Not implemented")


@app.command()
def version() -> None:
    """Show shipcheck version."""
    from shipcheck import __version__

    typer.echo(f"shipcheck {__version__}")


def main() -> None:
    """Invoke the CLI app."""
    app()

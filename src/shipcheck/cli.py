"""CLI entry points for shipcheck."""

import typer

app = typer.Typer(
    name="shipcheck",
    help="Docker image supply chain checker.",
    no_args_is_help=True,
)


@app.command()
def check(
    image: str = typer.Argument(..., help="Image reference to check (e.g. nginx:latest)"),
) -> None:
    """Run supply chain checks against a container image."""
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

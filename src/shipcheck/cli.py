"""CLI entry points for shipcheck."""

from __future__ import annotations

from dataclasses import asdict, replace
from pathlib import Path

import typer
from rich.console import Console

from shipcheck.checks.registry import get_default_registry
from shipcheck.config import load_config
from shipcheck.report import evidence, html, json_report, markdown, terminal
from shipcheck.report.score import build_report_data

app = typer.Typer(
    name="shipcheck",
    help="Embedded Linux compliance auditor — CRA, Secure Boot, SBOM, CVE tracking",
    no_args_is_help=True,
)

# Nested `doc` sub-app. Groups paperwork generators that consume a
# product.yaml and emit a single regulator-facing document. Today it
# only hosts `declaration` (Annex V / Annex VI Declaration of
# Conformity); future CRA paperwork (e.g. a stand-alone vulnerability
# disclosure policy template) slots under the same group without
# cluttering the top-level CLI surface.
doc_app = typer.Typer(
    name="doc",
    help="Generate regulator-facing CRA paperwork (Declaration of Conformity, ...).",
    no_args_is_help=True,
)
app.add_typer(doc_app, name="doc")

_VALID_FORMATS = {"markdown", "json", "html", "evidence"}
_FORMAT_EXT = {"markdown": "md", "json": "json", "html": "html", "evidence": "md"}

_SEVERITY_ORDER = ["critical", "high", "medium", "low"]

# Check IDs whose findings populate the dossier's cve-report.md.
_CVE_CHECK_IDS = {"cve-tracking", "yocto-cve-check"}


def _build_check_config(config) -> dict:
    """Build a dict keyed by check ID from the ShipcheckConfig for the registry."""
    cfg: dict = {
        "sbom-generation": asdict(config.sbom),
        "cve-tracking": asdict(config.cve),
        "secure-boot": asdict(config.secure_boot),
        "image-signing": asdict(config.image_signing),
        "license-audit": asdict(config.license_audit),
        "yocto-cve-check": asdict(config.yocto_cve),
        # vuln-reporting needs the product_config_path to locate product.yaml;
        # it is a top-level ShipcheckConfig field, not a nested dataclass, so
        # inject it explicitly here alongside the (currently empty) per-check
        # VulnReportingConfig.
        "vuln-reporting": {
            **asdict(config.vuln_reporting),
            "product_config_path": config.product_config_path,
        },
    }
    return cfg


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
    if fmt == "evidence":
        return evidence.render(report_data)
    return markdown.render(report_data)


def _prepare_out_dir(out_dir: Path) -> None:
    """Validate/create the dossier output directory.

    If the path exists and is a regular file, error out with a message
    containing "not a directory" so callers can reliably match on that
    substring. If the path does not exist, create it (and parents).
    """
    if out_dir.exists() and not out_dir.is_dir():
        typer.echo(
            f"Error: {out_dir} is not a directory (cannot write dossier)",
            err=True,
        )
        raise typer.Exit(code=1)
    out_dir.mkdir(parents=True, exist_ok=True)


def _cve_scoped_report(report_data):
    """Return a shallow copy of report_data filtered to CVE check results.

    Keeps totals/build_dir/timestamp intact so the rendered markdown still
    reads like a complete shipcheck report, just scoped to cve-tracking and
    yocto-cve-check.
    """
    cve_checks = [c for c in report_data.checks if c.check_id in _CVE_CHECK_IDS]
    return replace(report_data, checks=cve_checks)


def _write_dossier(
    report_data,
    out_dir: Path,
    *,
    product_config_path: str | None,
) -> list[Path]:
    """Emit the multi-file dossier under `out_dir` and return the written paths."""
    written: list[Path] = []

    evidence_md = out_dir / "evidence-report.md"
    evidence_md.write_text(evidence.render(report_data))
    written.append(evidence_md)

    cve_md = out_dir / "cve-report.md"
    cve_md.write_text(markdown.render(_cve_scoped_report(report_data)))
    written.append(cve_md)

    scan_json = out_dir / "scan.json"
    scan_json.write_text(json_report.render(report_data))
    written.append(scan_json)

    ran_license_audit = any(c.check_id == "license-audit" for c in report_data.checks)
    if ran_license_audit:
        license_checks = [c for c in report_data.checks if c.check_id == "license-audit"]
        license_report = replace(report_data, checks=license_checks)
        license_md = out_dir / "license-audit.md"
        license_md.write_text(markdown.render(license_report))
        written.append(license_md)

    if product_config_path:
        product_path = Path(product_config_path)
        if product_path.exists():
            try:
                from shipcheck.product import load_product_config

                product = load_product_config(product_path)
            except Exception as exc:  # noqa: BLE001 - surface all load failures cleanly
                typer.echo(
                    f"Warning: could not load product config {product_path}: {exc}",
                    err=True,
                )
            else:
                from shipcheck.docs_generator.annex_vii import generate_annex_vii
                from shipcheck.docs_generator.declaration import generate_declaration

                tech_doc = out_dir / "technical-documentation.md"
                generate_annex_vii(report_data, product, tech_doc)
                written.append(tech_doc)

                doc = out_dir / "declaration-of-conformity.md"
                generate_declaration(product, doc)
                written.append(doc)

    return written


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
        help="Output format (markdown, json, html, evidence).",
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
    out: Path | None = typer.Option(
        None,
        "--out",
        help=(
            "Write a multi-file dossier to DIR (requires --format evidence). "
            "Creates the directory if missing."
        ),
    ),
    product_config: Path | None = typer.Option(
        None,
        "--product-config",
        help=(
            "Path to product.yaml (overrides `product_config_path` from "
            ".shipcheck.yaml). Enables Annex VII and Declaration of Conformity "
            "emission when combined with --out."
        ),
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

    if product_config is not None:
        config.product_config_path = str(product_config)

    fmt = config.report.format
    if fmt not in _VALID_FORMATS:
        valid = ", ".join(sorted(_VALID_FORMATS))
        typer.echo(f"Error: invalid format '{fmt}'. Choose from: {valid}", err=True)
        raise typer.Exit(code=1)

    if out is not None and fmt != "evidence":
        typer.echo(
            "Error: --out requires --format evidence (multi-file dossier emit)",
            err=True,
        )
        raise typer.Exit(code=1)

    if out is not None:
        _prepare_out_dir(out)

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

    if out is not None:
        written = _write_dossier(
            report_data,
            out,
            product_config_path=config.product_config_path,
        )
        console.print(f"\nDossier written to: {out} ({len(written)} files)")
    else:
        content = _render_file_report(report_data, fmt)
        if fmt == "evidence":
            # Evidence pivot prints to stdout so CI pipelines can capture it;
            # file/dossier emission only engages when `--out DIR` is provided.
            typer.echo(content)
        else:
            ext = _FORMAT_EXT[fmt]
            output_name = f"{config.report.output}.{ext}"
            Path(output_name).write_text(content)
            console.print(f"\nFull report saved to: {output_name}")

    if _should_fail(results, config.report.fail_on):
        raise typer.Exit(code=1)


@app.command()
def dossier(
    since: str | None = typer.Option(
        None,
        "--since",
        help="ISO-8601 lower bound (inclusive) on scan timestamp (e.g. 2026-01-01).",
    ),
    build_dir: str | None = typer.Option(
        None,
        "--build-dir",
        help="Restrict the dossier to scans recorded against this build directory.",
    ),
    format: str = typer.Option(
        "markdown",
        "--format",
        help="Output format (markdown).",
    ),
    out: Path | None = typer.Option(
        None,
        "--out",
        help="Write the dossier to FILE instead of stdout.",
    ),
) -> None:
    """Produce a multi-scan compliance dossier from the local history store.

    Reads scan history from the SQLite store configured under
    ``history.path`` in ``.shipcheck.yaml`` (default ``.shipcheck/history.db``)
    and renders a dossier proving sustained compliance activity per
    CRA Annex I Part II §3. When ``history.enabled: false``, the command
    prints a disabled notice and exits 0 rather than crashing.
    """
    from shipcheck.history.dossier import build_dossier
    from shipcheck.history.store import HistoryStore, HistoryStoreError

    if format != "markdown":
        typer.echo(
            f"Error: invalid format '{format}'. Only 'markdown' is supported.",
            err=True,
        )
        raise typer.Exit(code=1)

    config = load_config(Path(".shipcheck.yaml"))

    if not config.history.enabled:
        typer.echo("history persistence disabled in .shipcheck.yaml")
        return

    try:
        store = HistoryStore(config.history.path)
    except HistoryStoreError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    dossier_data = build_dossier(store, since=since, build_dir=build_dir)
    rendered = str(dossier_data)

    if out is not None:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(rendered)
    else:
        typer.echo(rendered)


@app.command()
def docs(
    build_dir: Path = typer.Option(
        ...,
        "--build-dir",
        help="Path to the Yocto build directory.",
    ),
    product_config: Path = typer.Option(
        ...,
        "--product-config",
        help="Path to product.yaml describing product identity and CVD policy.",
    ),
    out: Path = typer.Option(
        ...,
        "--out",
        help="Destination markdown file for the Annex VII technical documentation draft.",
    ),
    checks: str | None = typer.Option(
        None,
        "--checks",
        help="Comma-separated list of checks to run (default: all enabled).",
    ),
) -> None:
    """Generate the Annex VII technical documentation draft.

    Runs the enabled checks against ``--build-dir`` to assemble a
    ``ReportData`` (same path as ``shipcheck check``), loads the product
    metadata from ``--product-config``, and writes the Annex VII markdown
    draft to ``--out``. The file is overwritten if it already exists.
    Missing/invalid ``product.yaml`` fields exit non-zero with a message
    naming the offending field.
    """
    from shipcheck.docs_generator.annex_vii import generate_annex_vii
    from shipcheck.product import ProductConfigError, load_product_config

    if not build_dir.exists():
        typer.echo(f"Error: build dir not found: {build_dir}", err=True)
        raise typer.Exit(code=1)

    if not product_config.exists():
        typer.echo(
            f"Error: product config not found: {product_config}",
            err=True,
        )
        raise typer.Exit(code=1)

    try:
        product = load_product_config(product_config)
    except ProductConfigError as exc:
        typer.echo(f"Error: invalid product config: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    config = load_config(Path(".shipcheck.yaml"))
    check_ids = [c.strip() for c in checks.split(",")] if checks else None
    config.apply_cli_overrides(
        build_dir=str(build_dir),
        checks=check_ids,
    )
    config.product_config_path = str(product_config)

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

    generate_annex_vii(report_data, product, out)
    typer.echo(f"Wrote Annex VII technical documentation draft to {out}")


@doc_app.command("declaration")
def doc_declaration(
    product_config: Path = typer.Option(
        ...,
        "--product-config",
        help="Path to product.yaml describing product identity and manufacturer details.",
    ),
    out: Path = typer.Option(
        ...,
        "--out",
        help="Destination markdown file for the Declaration of Conformity.",
    ),
    simplified: bool = typer.Option(
        False,
        "--simplified",
        help="Emit the Annex VI simplified Declaration of Conformity instead of Annex V.",
    ),
) -> None:
    """Generate an EU Declaration of Conformity (Annex V full or Annex VI simplified).

    Loads product identity from ``--product-config`` and renders the
    Declaration of Conformity required by Article 28 and Annex V of
    Regulation (EU) 2024/2847 (Cyber Resilience Act). Pass
    ``--simplified`` to emit the Annex VI short-form declaration
    referencing the full DoC by URL.
    """
    from shipcheck.docs_generator.declaration import generate_declaration
    from shipcheck.product import ProductConfigError, load_product_config

    if not product_config.exists():
        typer.echo(
            f"Error: product config not found: {product_config}",
            err=True,
        )
        raise typer.Exit(code=1)

    try:
        product = load_product_config(product_config)
    except ProductConfigError as exc:
        typer.echo(f"Error: invalid product config: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    generate_declaration(product, out, simplified=simplified)

    form = "Annex VI simplified" if simplified else "Annex V full"
    typer.echo(f"Wrote {form} Declaration of Conformity to {out}")


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

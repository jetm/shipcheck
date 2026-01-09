"""Configuration loading and validation for shipcheck."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

DEFAULT_CONFIG_NAME = ".shipcheck.yaml"

DEFAULT_SBOM_REQUIRED_FIELDS = [
    "name",
    "version",
    "supplier",
    "license",
    "checksum",
]


@dataclass
class SbomConfig:
    """SBOM check configuration."""

    required_fields: list[str] = field(default_factory=lambda: list(DEFAULT_SBOM_REQUIRED_FIELDS))


@dataclass
class CveConfig:
    """CVE check configuration."""

    suppress: list[str] = field(default_factory=list)


@dataclass
class ReportConfig:
    """Report output configuration."""

    format: str = "markdown"
    output: str = "shipcheck-report"
    fail_on: str | None = None


@dataclass
class ShipcheckConfig:
    """Top-level configuration object."""

    build_dir: Path | None = None
    framework: str = "CRA"
    checks: list[str] | None = None
    sbom: SbomConfig = field(default_factory=SbomConfig)
    cve: CveConfig = field(default_factory=CveConfig)
    report: ReportConfig = field(default_factory=ReportConfig)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ShipcheckConfig:
        """Build a config from a raw dict (e.g. parsed YAML)."""
        raw_build_dir = data.get("build_dir")
        build_dir = Path(raw_build_dir) if raw_build_dir is not None else None

        sbom_data = data.get("sbom", {})
        sbom = SbomConfig(
            required_fields=sbom_data.get("required_fields", list(DEFAULT_SBOM_REQUIRED_FIELDS)),
        )

        cve_data = data.get("cve", {})
        cve = CveConfig(
            suppress=cve_data.get("suppress", []),
        )

        report_data = data.get("report", {})
        report = ReportConfig(
            format=report_data.get("format", "markdown"),
            output=report_data.get("output", "shipcheck-report"),
            fail_on=report_data.get("fail_on"),
        )

        return cls(
            build_dir=build_dir,
            framework=data.get("framework", "CRA"),
            checks=data.get("checks"),
            sbom=sbom,
            cve=cve,
            report=report,
        )

    @classmethod
    def default(cls) -> ShipcheckConfig:
        """Return a default config."""
        return cls()

    def apply_cli_overrides(
        self,
        *,
        build_dir: str | None = None,
        format: str | None = None,
        checks: list[str] | None = None,
        fail_on: str | None = None,
    ) -> None:
        """Apply CLI flag overrides to this config. None values are ignored."""
        if build_dir is not None:
            self.build_dir = Path(build_dir)
        if format is not None:
            self.report.format = format
        if checks is not None:
            self.checks = checks
        if fail_on is not None:
            self.report.fail_on = fail_on


def load_config(path: Path) -> ShipcheckConfig:
    """Load configuration from a YAML file.

    If the file does not exist, returns default configuration.
    Raises yaml.YAMLError for invalid YAML syntax.
    """
    if not path.exists():
        return ShipcheckConfig.default()

    with path.open() as fh:
        data = yaml.safe_load(fh) or {}

    return ShipcheckConfig.from_dict(data)

"""Configuration loading and validation for shipcheck."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

DEFAULT_CONFIG_NAME = ".shipcheck.yaml"


@dataclass
class ChecksConfig:
    """Per-check enablement flags."""

    sbom: bool = True
    cve: bool = True
    registry: bool = True


@dataclass
class ShipcheckConfig:
    """Top-level configuration object."""

    checks: ChecksConfig = field(default_factory=ChecksConfig)
    fail_on_critical: bool = True
    output_format: str = "terminal"

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ShipcheckConfig":
        """Build a config from a raw dict (e.g. parsed YAML)."""
        checks_data = data.get("checks", {})
        checks = ChecksConfig(
            sbom=checks_data.get("sbom", True),
            cve=checks_data.get("cve", True),
            registry=checks_data.get("registry", True),
        )
        return cls(
            checks=checks,
            fail_on_critical=data.get("fail_on_critical", True),
            output_format=data.get("output_format", "terminal"),
        )

    @classmethod
    def load(cls, path: Path) -> "ShipcheckConfig":
        """Load config from a YAML file."""
        with path.open() as fh:
            data = yaml.safe_load(fh) or {}
        return cls.from_dict(data)

    @classmethod
    def default(cls) -> "ShipcheckConfig":
        """Return a default config."""
        return cls()

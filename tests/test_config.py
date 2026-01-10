"""Tests for configuration loading and validation."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from shipcheck.config import ShipcheckConfig, load_config

FIXTURES = Path(__file__).parent / "fixtures" / "config"


class TestLoadConfig:
    """Tests for load_config function."""

    def test_load_full_config(self):
        config = load_config(FIXTURES / "full-config.yaml")

        assert config.build_dir == Path("./build")
        assert config.framework == "CRA"
        assert config.checks == ["sbom-generation", "cve-tracking"]
        assert config.sbom.required_fields == [
            "name",
            "version",
            "supplier",
            "license",
            "checksum",
        ]
        assert config.cve.suppress == ["CVE-2023-1234", "CVE-2024-5678"]
        assert config.report.format == "json"
        assert config.report.output == "my-report"
        assert config.report.fail_on == "high"

    def test_load_minimal_config(self):
        config = load_config(FIXTURES / "minimal-config.yaml")

        assert config.build_dir == Path("./build")
        assert config.framework == "CRA"
        assert config.checks is None
        assert config.sbom.required_fields == [
            "name",
            "version",
            "supplier",
            "license",
            "checksum",
        ]
        assert config.cve.suppress == []
        assert config.report.format == "markdown"
        assert config.report.output == "shipcheck-report"
        assert config.report.fail_on is None

    def test_load_invalid_yaml_raises_error(self):
        with pytest.raises(yaml.YAMLError):
            load_config(FIXTURES / "invalid-config.yaml")

    def test_load_missing_file_returns_defaults(self):
        config = load_config(Path("/nonexistent/.shipcheck.yaml"))

        assert config.build_dir is None
        assert config.framework == "CRA"
        assert config.checks is None
        assert config.report.format == "markdown"


class TestShipcheckConfigFromDict:
    """Tests for ShipcheckConfig.from_dict."""

    def test_empty_dict_produces_defaults(self):
        config = ShipcheckConfig.from_dict({})

        assert config.build_dir is None
        assert config.framework == "CRA"
        assert config.checks is None
        assert config.sbom.required_fields == [
            "name",
            "version",
            "supplier",
            "license",
            "checksum",
        ]
        assert config.cve.suppress == []
        assert config.report.format == "markdown"
        assert config.report.output == "shipcheck-report"
        assert config.report.fail_on is None

    def test_partial_dict_fills_defaults(self):
        config = ShipcheckConfig.from_dict(
            {
                "build_dir": "./other",
                "cve": {"suppress": ["CVE-2024-9999"]},
            }
        )

        assert config.build_dir == Path("./other")
        assert config.cve.suppress == ["CVE-2024-9999"]
        assert config.sbom.required_fields == [
            "name",
            "version",
            "supplier",
            "license",
            "checksum",
        ]
        assert config.report.format == "markdown"

    def test_full_dict_overrides_all(self):
        config = ShipcheckConfig.from_dict(
            {
                "build_dir": "/abs/path",
                "framework": "CRA",
                "checks": ["cve-tracking"],
                "sbom": {"required_fields": ["name", "version"]},
                "cve": {"suppress": ["CVE-2023-1111"]},
                "report": {
                    "format": "html",
                    "output": "custom-name",
                    "fail_on": "critical",
                },
            }
        )

        assert config.build_dir == Path("/abs/path")
        assert config.checks == ["cve-tracking"]
        assert config.sbom.required_fields == ["name", "version"]
        assert config.cve.suppress == ["CVE-2023-1111"]
        assert config.report.format == "html"
        assert config.report.output == "custom-name"
        assert config.report.fail_on == "critical"


class TestCliOverride:
    """Tests for CLI override support."""

    def test_override_build_dir(self):
        config = ShipcheckConfig.from_dict({"build_dir": "./build"})
        config.apply_cli_overrides(build_dir="./other")
        assert config.build_dir == Path("./other")

    def test_override_format(self):
        config = ShipcheckConfig.from_dict({})
        config.apply_cli_overrides(format="json")
        assert config.report.format == "json"

    def test_override_checks(self):
        config = ShipcheckConfig.from_dict({})
        config.apply_cli_overrides(checks=["sbom-generation"])
        assert config.checks == ["sbom-generation"]

    def test_override_fail_on(self):
        config = ShipcheckConfig.from_dict({})
        config.apply_cli_overrides(fail_on="critical")
        assert config.report.fail_on == "critical"

    def test_none_overrides_are_ignored(self):
        config = ShipcheckConfig.from_dict(
            {
                "build_dir": "./build",
                "report": {"format": "html", "fail_on": "high"},
            }
        )
        config.apply_cli_overrides(build_dir=None, format=None, checks=None, fail_on=None)
        assert config.build_dir == Path("./build")
        assert config.report.format == "html"
        assert config.report.fail_on == "high"

    def test_cli_override_takes_precedence_over_config(self):
        config = ShipcheckConfig.from_dict(
            {
                "build_dir": "./build",
                "report": {"format": "html", "fail_on": "low"},
            }
        )
        config.apply_cli_overrides(build_dir="./other", format="json", fail_on="critical")
        assert config.build_dir == Path("./other")
        assert config.report.format == "json"
        assert config.report.fail_on == "critical"


class TestDefaultConfig:
    """Tests for ShipcheckConfig.default."""

    def test_default_returns_sensible_defaults(self):
        config = ShipcheckConfig.default()

        assert config.build_dir is None
        assert config.framework == "CRA"
        assert config.checks is None
        assert config.sbom.required_fields == [
            "name",
            "version",
            "supplier",
            "license",
            "checksum",
        ]
        assert config.cve.suppress == []
        assert config.report.format == "markdown"
        assert config.report.output == "shipcheck-report"
        assert config.report.fail_on is None

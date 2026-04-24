"""Tests for configuration loading and validation."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from shipcheck.config import CodeIntegrityConfig, ShipcheckConfig, load_config

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


class TestCodeIntegrityConfigDefaults:
    """Tests for CodeIntegrityConfig default values."""

    def test_default_known_test_keys_is_empty_list(self):
        config = CodeIntegrityConfig()

        assert config.known_test_keys == []

    def test_default_expect_fit_is_true(self):
        config = CodeIntegrityConfig()

        assert config.expect_fit is True

    def test_default_expect_verity_is_true(self):
        config = CodeIntegrityConfig()

        assert config.expect_verity is True

    def test_default_expect_ima_is_false(self):
        config = CodeIntegrityConfig()

        assert config.expect_ima is False

    def test_default_instances_are_independent(self):
        config_a = CodeIntegrityConfig()
        config_b = CodeIntegrityConfig()

        config_a.known_test_keys.append("test-key-pattern")

        assert config_b.known_test_keys == []

    def test_custom_known_test_keys(self):
        config = CodeIntegrityConfig(known_test_keys=["*test*", "dev-key-*"])

        assert config.known_test_keys == ["*test*", "dev-key-*"]

    def test_custom_expect_fit_false(self):
        config = CodeIntegrityConfig(expect_fit=False)

        assert config.expect_fit is False
        assert config.expect_verity is True
        assert config.expect_ima is False

    def test_custom_expect_verity_false(self):
        config = CodeIntegrityConfig(expect_verity=False)

        assert config.expect_fit is True
        assert config.expect_verity is False
        assert config.expect_ima is False

    def test_custom_expect_ima_true(self):
        config = CodeIntegrityConfig(expect_ima=True)

        assert config.expect_fit is True
        assert config.expect_verity is True
        assert config.expect_ima is True

    def test_all_three_flags_disabled(self):
        config = CodeIntegrityConfig(expect_fit=False, expect_verity=False, expect_ima=False)

        assert config.expect_fit is False
        assert config.expect_verity is False
        assert config.expect_ima is False


class TestShipcheckConfigCodeIntegritySection:
    """Tests for ShipcheckConfig parsing of code_integrity section."""

    def test_missing_code_integrity_section_uses_defaults(self):
        config = ShipcheckConfig.from_dict({})

        assert config.code_integrity.known_test_keys == []
        assert config.code_integrity.expect_fit is True
        assert config.code_integrity.expect_verity is True
        assert config.code_integrity.expect_ima is False

    def test_code_integrity_empty_section_uses_defaults(self):
        config = ShipcheckConfig.from_dict({"code_integrity": {}})

        assert config.code_integrity.known_test_keys == []
        assert config.code_integrity.expect_fit is True
        assert config.code_integrity.expect_verity is True
        assert config.code_integrity.expect_ima is False

    def test_code_integrity_custom_known_test_keys(self):
        config = ShipcheckConfig.from_dict(
            {
                "code_integrity": {
                    "known_test_keys": ["*development*", "ovmf-test-pk"],
                },
            }
        )

        assert config.code_integrity.known_test_keys == ["*development*", "ovmf-test-pk"]

    def test_code_integrity_expect_fit_false(self):
        config = ShipcheckConfig.from_dict(
            {"code_integrity": {"expect_fit": False}},
        )

        assert config.code_integrity.expect_fit is False
        assert config.code_integrity.expect_verity is True
        assert config.code_integrity.expect_ima is False

    def test_code_integrity_expect_verity_false(self):
        config = ShipcheckConfig.from_dict(
            {"code_integrity": {"expect_verity": False}},
        )

        assert config.code_integrity.expect_fit is True
        assert config.code_integrity.expect_verity is False

    def test_code_integrity_expect_ima_true(self):
        config = ShipcheckConfig.from_dict(
            {"code_integrity": {"expect_ima": True}},
        )

        assert config.code_integrity.expect_fit is True
        assert config.code_integrity.expect_verity is True
        assert config.code_integrity.expect_ima is True

    def test_code_integrity_full_section(self):
        config = ShipcheckConfig.from_dict(
            {
                "code_integrity": {
                    "known_test_keys": ["*test*"],
                    "expect_fit": False,
                    "expect_verity": False,
                    "expect_ima": True,
                },
            }
        )

        assert config.code_integrity.known_test_keys == ["*test*"]
        assert config.code_integrity.expect_fit is False
        assert config.code_integrity.expect_verity is False
        assert config.code_integrity.expect_ima is True

    def test_load_code_integrity_config_fixture(self):
        config = load_config(FIXTURES / "code-integrity-config.yaml")

        assert isinstance(config.code_integrity, CodeIntegrityConfig)
        assert config.code_integrity.known_test_keys == [
            "vendor-test-key",
            "ci-signing-key",
        ]
        assert config.code_integrity.expect_fit is True
        assert config.code_integrity.expect_verity is True
        assert config.code_integrity.expect_ima is False

    def test_secure_boot_key_silently_rejected(self):
        config = ShipcheckConfig.from_dict(
            {"secure_boot": {"known_test_keys": ["legacy-key"]}},
        )

        # The retired secure_boot key must not flow into code_integrity.
        assert config.code_integrity.known_test_keys == []
        assert not hasattr(config, "secure_boot")

    def test_image_signing_key_silently_rejected(self):
        config = ShipcheckConfig.from_dict(
            {"image_signing": {"expect_fit": False, "expect_verity": False}},
        )

        # The retired image_signing key must not flow into code_integrity.
        assert config.code_integrity.expect_fit is True
        assert config.code_integrity.expect_verity is True
        assert not hasattr(config, "image_signing")

    def test_default_config_includes_code_integrity(self):
        config = ShipcheckConfig.default()

        assert isinstance(config.code_integrity, CodeIntegrityConfig)
        assert config.code_integrity.known_test_keys == []
        assert config.code_integrity.expect_fit is True
        assert config.code_integrity.expect_verity is True
        assert config.code_integrity.expect_ima is False

    def test_code_integrity_coexists_with_existing_sections(self):
        config = ShipcheckConfig.from_dict(
            {
                "build_dir": "./build",
                "cve": {"suppress": ["CVE-2025-0001"]},
                "code_integrity": {
                    "known_test_keys": ["dev-*"],
                    "expect_fit": False,
                },
            }
        )

        assert config.build_dir == Path("./build")
        assert config.cve.suppress == ["CVE-2025-0001"]
        assert config.code_integrity.known_test_keys == ["dev-*"]
        assert config.code_integrity.expect_fit is False
        assert config.code_integrity.expect_verity is True
        assert config.code_integrity.expect_ima is False


DEFAULT_SBOM_REQUIRED_FIELDS_FOR_TEST = [
    "name",
    "version",
    "supplier",
    "license",
    "checksum",
]


class TestLicenseAuditConfigSection:
    """Tests for new ShipcheckConfig parsing of license_audit section."""

    def test_missing_license_audit_section_uses_defaults(self):
        config = ShipcheckConfig.from_dict({})

        assert config.license_audit is not None
        assert config.license_audit.allowlist == []
        assert config.license_audit.denylist == []
        assert config.license_audit.expected_licenses == []

    def test_license_audit_empty_section_uses_defaults(self):
        config = ShipcheckConfig.from_dict({"license_audit": {}})

        assert config.license_audit.allowlist == []
        assert config.license_audit.denylist == []
        assert config.license_audit.expected_licenses == []

    def test_license_audit_custom_values(self):
        config = ShipcheckConfig.from_dict(
            {
                "license_audit": {
                    "allowlist": ["MIT", "Apache-2.0"],
                    "denylist": ["AGPL-3.0-only"],
                    "expected_licenses": ["MIT", "BSD-3-Clause"],
                }
            }
        )

        assert config.license_audit.allowlist == ["MIT", "Apache-2.0"]
        assert config.license_audit.denylist == ["AGPL-3.0-only"]
        assert config.license_audit.expected_licenses == ["MIT", "BSD-3-Clause"]

    def test_license_audit_unknown_keys_do_not_crash(self):
        config = ShipcheckConfig.from_dict(
            {
                "license_audit": {
                    "allowlist": ["MIT"],
                    "future_field": "ignored",
                }
            }
        )

        assert config.license_audit.allowlist == ["MIT"]


class TestYoctoCveConfigSection:
    """Tests for new ShipcheckConfig parsing of yocto_cve section."""

    def test_missing_yocto_cve_section_uses_defaults(self):
        config = ShipcheckConfig.from_dict({})

        assert config.yocto_cve is not None
        assert config.yocto_cve.treat_ignored_as_patched is False
        assert config.yocto_cve.summary_path is None

    def test_yocto_cve_empty_section_uses_defaults(self):
        config = ShipcheckConfig.from_dict({"yocto_cve": {}})

        assert config.yocto_cve.treat_ignored_as_patched is False
        assert config.yocto_cve.summary_path is None

    @pytest.mark.parametrize("value", [True, False])
    def test_yocto_cve_treat_ignored_as_patched_boolean(self, value):
        config = ShipcheckConfig.from_dict({"yocto_cve": {"treat_ignored_as_patched": value}})

        assert config.yocto_cve.treat_ignored_as_patched is value

    def test_yocto_cve_summary_path_custom(self):
        config = ShipcheckConfig.from_dict(
            {"yocto_cve": {"summary_path": "tmp/log/cve/cve-summary.json"}}
        )

        assert config.yocto_cve.summary_path == "tmp/log/cve/cve-summary.json"

    def test_yocto_cve_unknown_keys_do_not_crash(self):
        config = ShipcheckConfig.from_dict(
            {
                "yocto_cve": {
                    "treat_ignored_as_patched": True,
                    "future_key": 42,
                }
            }
        )

        assert config.yocto_cve.treat_ignored_as_patched is True


class TestHistoryConfigSection:
    """Tests for new ShipcheckConfig parsing of history_config section."""

    def test_missing_history_config_section_uses_defaults(self):
        config = ShipcheckConfig.from_dict({})

        assert config.history is not None
        assert config.history.enabled is True
        assert config.history.path == ".shipcheck/history.db"

    def test_history_config_empty_section_uses_defaults(self):
        config = ShipcheckConfig.from_dict({"history": {}})

        assert config.history.enabled is True
        assert config.history.path == ".shipcheck/history.db"

    @pytest.mark.parametrize("enabled", [True, False])
    def test_history_config_enabled_boolean(self, enabled):
        config = ShipcheckConfig.from_dict({"history": {"enabled": enabled}})

        assert config.history.enabled is enabled

    def test_history_config_custom_path(self):
        config = ShipcheckConfig.from_dict({"history": {"path": "/var/lib/shipcheck/history.db"}})

        assert config.history.path == "/var/lib/shipcheck/history.db"

    def test_history_config_full_section(self):
        config = ShipcheckConfig.from_dict(
            {"history": {"enabled": False, "path": "custom/path.db"}}
        )

        assert config.history.enabled is False
        assert config.history.path == "custom/path.db"

    def test_history_config_unknown_keys_do_not_crash(self):
        config = ShipcheckConfig.from_dict({"history": {"enabled": True, "retention_days": 365}})

        assert config.history.enabled is True


class TestVulnReportingConfigSection:
    """Tests for new ShipcheckConfig parsing of vuln_reporting section."""

    def test_missing_vuln_reporting_section_uses_defaults(self):
        config = ShipcheckConfig.from_dict({})

        assert config.vuln_reporting is not None

    def test_vuln_reporting_empty_section_uses_defaults(self):
        config = ShipcheckConfig.from_dict({"vuln_reporting": {}})

        assert config.vuln_reporting is not None

    def test_vuln_reporting_unknown_keys_do_not_crash(self):
        config = ShipcheckConfig.from_dict({"vuln_reporting": {"future_key": "ignored"}})

        assert config.vuln_reporting is not None


class TestProductConfigPathField:
    """Tests for new top-level product_config_path field."""

    def test_missing_product_config_path_uses_default(self):
        config = ShipcheckConfig.from_dict({})

        assert config.product_config_path == "product.yaml"

    def test_product_config_path_custom(self):
        config = ShipcheckConfig.from_dict({"product_config_path": "configs/my-product.yaml"})

        assert config.product_config_path == "configs/my-product.yaml"

    def test_default_includes_product_config_path(self):
        config = ShipcheckConfig.default()

        assert config.product_config_path == "product.yaml"


class TestNewConfigSectionsIntegration:
    """Integration tests for new_config_sections coexisting with existing ones."""

    def test_new_config_sections_coexist_with_defaults(self):
        config = ShipcheckConfig.from_dict({})

        assert config.license_audit is not None
        assert config.yocto_cve is not None
        assert config.history is not None
        assert config.vuln_reporting is not None
        assert config.product_config_path == "product.yaml"
        assert config.sbom.required_fields == DEFAULT_SBOM_REQUIRED_FIELDS_FOR_TEST

    def test_new_config_sections_custom_values(self):
        config = ShipcheckConfig.from_dict(
            {
                "build_dir": "./build",
                "license_audit": {"denylist": ["AGPL-3.0-only"]},
                "yocto_cve": {
                    "treat_ignored_as_patched": True,
                    "summary_path": "custom.json",
                },
                "history": {"enabled": False, "path": "/tmp/history.db"},
                "vuln_reporting": {},
                "product_config_path": "my-product.yaml",
            }
        )

        assert config.build_dir == Path("./build")
        assert config.license_audit.denylist == ["AGPL-3.0-only"]
        assert config.yocto_cve.treat_ignored_as_patched is True
        assert config.yocto_cve.summary_path == "custom.json"
        assert config.history.enabled is False
        assert config.history.path == "/tmp/history.db"
        assert config.product_config_path == "my-product.yaml"

    def test_new_config_sections_in_default(self):
        config = ShipcheckConfig.default()

        assert config.license_audit is not None
        assert config.yocto_cve is not None
        assert config.history is not None
        assert config.vuln_reporting is not None
        assert config.product_config_path == "product.yaml"

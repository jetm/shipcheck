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
class CodeIntegrityConfig:
    """Code integrity check configuration.

    Replaces the retired ``SecureBootConfig`` and ``ImageSigningConfig``
    dataclasses. Carries the union of fields the merged ``code-integrity``
    check needs across its four mechanism detectors (UEFI Secure Boot,
    signed FIT, dm-verity, IMA/EVM).
    """

    known_test_keys: list[str] = field(default_factory=list)
    expect_fit: bool = True
    expect_verity: bool = True
    expect_ima: bool = False


@dataclass
class LicenseAuditConfig:
    """License audit check configuration."""

    allowlist: list[str] = field(default_factory=list)
    denylist: list[str] = field(default_factory=list)
    expected_licenses: list[str] = field(default_factory=list)


@dataclass
class YoctoCVEConfig:
    """Yocto cve-check.bbclass integration configuration."""

    treat_ignored_as_patched: bool = False
    summary_path: str | None = None


@dataclass
class HistoryConfig:
    """Scan history store configuration."""

    enabled: bool = True
    path: str = ".shipcheck/history.db"


@dataclass
class VulnReportingConfig:
    """Vulnerability reporting check configuration.

    Reserved for future fields; the check reads from product.yaml today.
    """


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
    code_integrity: CodeIntegrityConfig = field(default_factory=CodeIntegrityConfig)
    license_audit: LicenseAuditConfig = field(default_factory=LicenseAuditConfig)
    yocto_cve: YoctoCVEConfig = field(default_factory=YoctoCVEConfig)
    history: HistoryConfig = field(default_factory=HistoryConfig)
    vuln_reporting: VulnReportingConfig = field(default_factory=VulnReportingConfig)
    report: ReportConfig = field(default_factory=ReportConfig)
    product_config_path: str = "product.yaml"

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

        # The retired `secure_boot:` and `image_signing:` keys are silently
        # ignored. Migration is documented in the CHANGELOG; users still
        # carrying these blocks are not crashed but their values do not flow
        # into `code_integrity:`.
        code_integrity_data = data.get("code_integrity", {})
        code_integrity = CodeIntegrityConfig(
            known_test_keys=code_integrity_data.get("known_test_keys", []),
            expect_fit=code_integrity_data.get("expect_fit", True),
            expect_verity=code_integrity_data.get("expect_verity", True),
            expect_ima=code_integrity_data.get("expect_ima", False),
        )

        license_audit_data = data.get("license_audit", {})
        license_audit = LicenseAuditConfig(
            allowlist=license_audit_data.get("allowlist", []),
            denylist=license_audit_data.get("denylist", []),
            expected_licenses=license_audit_data.get("expected_licenses", []),
        )

        yocto_cve_data = data.get("yocto_cve", {})
        yocto_cve = YoctoCVEConfig(
            treat_ignored_as_patched=yocto_cve_data.get("treat_ignored_as_patched", False),
            summary_path=yocto_cve_data.get("summary_path"),
        )

        history_data = data.get("history", {})
        history = HistoryConfig(
            enabled=history_data.get("enabled", True),
            path=history_data.get("path", ".shipcheck/history.db"),
        )

        # VulnReportingConfig has no fields yet; tolerate the section's absence
        # and any unknown keys without crashing.
        data.get("vuln_reporting", {})
        vuln_reporting = VulnReportingConfig()

        return cls(
            build_dir=build_dir,
            framework=data.get("framework", "CRA"),
            checks=data.get("checks"),
            sbom=sbom,
            cve=cve,
            code_integrity=code_integrity,
            license_audit=license_audit,
            yocto_cve=yocto_cve,
            history=history,
            vuln_reporting=vuln_reporting,
            report=report,
            product_config_path=data.get("product_config_path", "product.yaml"),
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

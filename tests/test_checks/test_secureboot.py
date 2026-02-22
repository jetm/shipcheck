"""Tests for SecureBootCheck - RED phase.

Tests cover signing class detection, test key detection,
misconfiguration detection, and scoring logic.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from pathlib import Path

from shipcheck.checks.secureboot import SecureBootCheck
from shipcheck.models import CheckStatus


@pytest.fixture
def check() -> SecureBootCheck:
    return SecureBootCheck()


# --- Helpers ---


def _write_conf(build_dir: Path, filename: str, content: str) -> Path:
    """Write a config file under build_dir/conf/."""
    conf_dir = build_dir / "conf"
    conf_dir.mkdir(parents=True, exist_ok=True)
    path = conf_dir / filename
    path.write_text(content)
    return path


def _create_efi_artifacts(build_dir: Path) -> None:
    """Create dummy .efi files in the deploy directory."""
    deploy = build_dir / "tmp" / "deploy" / "images" / "machine"
    deploy.mkdir(parents=True, exist_ok=True)
    (deploy / "bootx64.efi").write_bytes(b"\x00" * 16)
    (deploy / "grubx64.efi").write_bytes(b"\x00" * 16)


def _create_key_files(build_dir: Path, *names: str) -> list[Path]:
    """Create dummy key files and return their paths."""
    key_dir = build_dir / "keys"
    key_dir.mkdir(parents=True, exist_ok=True)
    paths = []
    for name in names:
        path = key_dir / name
        path.write_bytes(b"\x00" * 32)
        paths.append(path)
    return paths


# --- TestSigningClassDetection ---


class TestSigningClassDetection:
    """Detect signing classes from conf files."""

    def test_detects_uefi_sign_in_local_conf(self, tmp_path: Path, check: SecureBootCheck) -> None:
        _write_conf(tmp_path, "local.conf", 'IMAGE_CLASSES += "uefi-sign"\n')
        result = check.run(tmp_path, {})
        assert result.score >= 20

    def test_detects_sbsign_in_local_conf(self, tmp_path: Path, check: SecureBootCheck) -> None:
        _write_conf(tmp_path, "local.conf", 'IMAGE_CLASSES += "sbsign"\n')
        result = check.run(tmp_path, {})
        assert result.score >= 20

    def test_detects_image_uefi_sign(self, tmp_path: Path, check: SecureBootCheck) -> None:
        _write_conf(
            tmp_path,
            "local.conf",
            'IMAGE_CLASSES += "image-uefi-sign"\n',
        )
        result = check.run(tmp_path, {})
        assert result.score >= 20

    def test_detects_secureboot_class(self, tmp_path: Path, check: SecureBootCheck) -> None:
        _write_conf(
            tmp_path,
            "local.conf",
            'IMAGE_CLASSES += "secureboot"\n',
        )
        result = check.run(tmp_path, {})
        assert result.score >= 20

    def test_detects_in_auto_conf(self, tmp_path: Path, check: SecureBootCheck) -> None:
        _write_conf(tmp_path, "auto.conf", 'IMAGE_CLASSES += "uefi-sign"\n')
        result = check.run(tmp_path, {})
        assert result.score >= 20

    def test_detects_append_syntax(self, tmp_path: Path, check: SecureBootCheck) -> None:
        _write_conf(
            tmp_path,
            "local.conf",
            'IMAGE_CLASSES:append = " uefi-sign"\n',
        )
        result = check.run(tmp_path, {})
        assert result.score >= 20

    def test_detects_assign_syntax(self, tmp_path: Path, check: SecureBootCheck) -> None:
        _write_conf(
            tmp_path,
            "local.conf",
            'IMAGE_CLASSES = "uefi-sign other-class"\n',
        )
        result = check.run(tmp_path, {})
        assert result.score >= 20

    def test_no_signing_class_when_config_missing(
        self, tmp_path: Path, check: SecureBootCheck
    ) -> None:
        result = check.run(tmp_path, {})
        assert result.score < 20

    def test_no_signing_class_in_unrelated_config(
        self, tmp_path: Path, check: SecureBootCheck
    ) -> None:
        _write_conf(
            tmp_path,
            "local.conf",
            'MACHINE = "qemux86-64"\nDISTRO = "poky"\n',
        )
        result = check.run(tmp_path, {})
        assert result.score < 20

    def test_signing_class_among_multiple(self, tmp_path: Path, check: SecureBootCheck) -> None:
        _write_conf(
            tmp_path,
            "local.conf",
            'IMAGE_CLASSES += "some-class uefi-sign another"\n',
        )
        result = check.run(tmp_path, {})
        assert result.score >= 20

    def test_local_conf_without_auto_conf(self, tmp_path: Path, check: SecureBootCheck) -> None:
        _write_conf(tmp_path, "local.conf", 'IMAGE_CLASSES += "uefi-sign"\n')
        result = check.run(tmp_path, {})
        assert result.score >= 20

    def test_detects_from_either_conf_file(self, tmp_path: Path, check: SecureBootCheck) -> None:
        _write_conf(tmp_path, "local.conf", 'MACHINE = "qemux86-64"\n')
        _write_conf(tmp_path, "auto.conf", 'IMAGE_CLASSES += "sbsign"\n')
        result = check.run(tmp_path, {})
        assert result.score >= 20


# --- TestTestKeyDetection ---


class TestTestKeyDetection:
    """Flag keys with test/development in name."""

    def test_flags_key_with_test_in_name(self, tmp_path: Path, check: SecureBootCheck) -> None:
        keys = _create_key_files(tmp_path, "test-signing.key")
        _write_conf(
            tmp_path,
            "local.conf",
            (f'IMAGE_CLASSES += "uefi-sign"\nSECURE_BOOT_SIGNING_KEY = "{keys[0]}"\n'),
        )
        result = check.run(tmp_path, {})
        assert any(f.severity in ("high", "critical") for f in result.findings)

    def test_flags_key_with_development_in_name(
        self, tmp_path: Path, check: SecureBootCheck
    ) -> None:
        keys = _create_key_files(tmp_path, "development-db.key")
        _write_conf(
            tmp_path,
            "local.conf",
            (f'IMAGE_CLASSES += "uefi-sign"\nSECURE_BOOT_SIGNING_KEY = "{keys[0]}"\n'),
        )
        result = check.run(tmp_path, {})
        assert any(f.severity in ("high", "critical") for f in result.findings)

    def test_flags_key_with_test_in_path(self, tmp_path: Path, check: SecureBootCheck) -> None:
        test_dir = tmp_path / "test-keys"
        test_dir.mkdir(parents=True)
        key_path = test_dir / "signing.key"
        key_path.write_bytes(b"\x00" * 32)
        _write_conf(
            tmp_path,
            "local.conf",
            (f'IMAGE_CLASSES += "uefi-sign"\nSECURE_BOOT_SIGNING_KEY = "{key_path}"\n'),
        )
        result = check.run(tmp_path, {})
        assert any(f.severity in ("high", "critical") for f in result.findings)

    def test_allows_proper_key_names(self, tmp_path: Path, check: SecureBootCheck) -> None:
        keys = _create_key_files(tmp_path, "production-signing.key")
        _write_conf(
            tmp_path,
            "local.conf",
            (f'IMAGE_CLASSES += "uefi-sign"\nSECURE_BOOT_SIGNING_KEY = "{keys[0]}"\n'),
        )
        result = check.run(tmp_path, {})
        test_findings = [
            f
            for f in result.findings
            if "test" in f.message.lower() or "development" in f.message.lower()
        ]
        assert len(test_findings) == 0

    def test_no_test_key_earns_10_points(self, tmp_path: Path, check: SecureBootCheck) -> None:
        keys = _create_key_files(tmp_path, "production.key")
        _write_conf(
            tmp_path,
            "local.conf",
            (f'IMAGE_CLASSES += "uefi-sign"\nSECURE_BOOT_SIGNING_KEY = "{keys[0]}"\n'),
        )
        result = check.run(tmp_path, {})
        # signing(20) + keys(15) + no test keys(10) = 45+
        assert result.score >= 45

    def test_test_key_loses_10_points(self, tmp_path: Path, check: SecureBootCheck) -> None:
        keys = _create_key_files(tmp_path, "test-signing.key")
        _write_conf(
            tmp_path,
            "local.conf",
            (f'IMAGE_CLASSES += "uefi-sign"\nSECURE_BOOT_SIGNING_KEY = "{keys[0]}"\n'),
        )
        result = check.run(tmp_path, {})
        # signing(20) + keys(15) + test key(0) = at most 40
        assert result.score <= 40

    def test_custom_known_test_key_pattern(self, tmp_path: Path, check: SecureBootCheck) -> None:
        keys = _create_key_files(tmp_path, "staging-db.key")
        _write_conf(
            tmp_path,
            "local.conf",
            (f'IMAGE_CLASSES += "uefi-sign"\nSECURE_BOOT_SIGNING_KEY = "{keys[0]}"\n'),
        )
        result = check.run(tmp_path, {"known_test_keys": ["staging"]})
        assert any(f.severity in ("high", "critical") for f in result.findings)

    def test_flags_db_key_with_test_name(self, tmp_path: Path, check: SecureBootCheck) -> None:
        keys = _create_key_files(tmp_path, "production.key", "test-db.key")
        _write_conf(
            tmp_path,
            "local.conf",
            (
                'IMAGE_CLASSES += "uefi-sign"\n'
                f'SECURE_BOOT_SIGNING_KEY = "{keys[0]}"\n'
                f'SECURE_BOOT_DB_KEY = "{keys[1]}"\n'
            ),
        )
        result = check.run(tmp_path, {})
        assert any(f.severity in ("high", "critical") for f in result.findings)


# --- TestMisconfigurationDetection ---


class TestMisconfigurationDetection:
    """EFI artifacts without signing, signing without keys."""

    def test_efi_artifacts_without_signing_class(
        self, tmp_path: Path, check: SecureBootCheck
    ) -> None:
        _create_efi_artifacts(tmp_path)
        _write_conf(tmp_path, "local.conf", 'MACHINE = "qemux86-64"\n')
        result = check.run(tmp_path, {})
        assert any(f.severity in ("high", "medium") for f in result.findings)
        assert any(
            "efi" in f.message.lower() or "sign" in f.message.lower() for f in result.findings
        )

    def test_signing_class_without_key_files(self, tmp_path: Path, check: SecureBootCheck) -> None:
        _write_conf(
            tmp_path,
            "local.conf",
            ('IMAGE_CLASSES += "uefi-sign"\nSECURE_BOOT_SIGNING_KEY = "/nonexistent/key.pem"\n'),
        )
        result = check.run(tmp_path, {})
        assert any(
            "key" in f.message.lower() or "missing" in f.message.lower() for f in result.findings
        )

    def test_signing_class_no_key_variable(self, tmp_path: Path, check: SecureBootCheck) -> None:
        _write_conf(tmp_path, "local.conf", 'IMAGE_CLASSES += "uefi-sign"\n')
        result = check.run(tmp_path, {})
        # Can't earn keys configured (15) points
        assert result.score < 35

    def test_no_misconfiguration_earns_5_points(
        self, tmp_path: Path, check: SecureBootCheck
    ) -> None:
        keys = _create_key_files(tmp_path, "production.key")
        _write_conf(
            tmp_path,
            "local.conf",
            (f'IMAGE_CLASSES += "uefi-sign"\nSECURE_BOOT_SIGNING_KEY = "{keys[0]}"\n'),
        )
        result = check.run(tmp_path, {})
        assert result.score == 50

    def test_efi_without_signing_loses_points(self, tmp_path: Path, check: SecureBootCheck) -> None:
        _create_efi_artifacts(tmp_path)
        _write_conf(tmp_path, "local.conf", 'MACHINE = "qemux86-64"\n')
        result = check.run(tmp_path, {})
        assert result.score < 5

    def test_consistent_config_no_misconfig_finding(
        self, tmp_path: Path, check: SecureBootCheck
    ) -> None:
        keys = _create_key_files(tmp_path, "production.key")
        _create_efi_artifacts(tmp_path)
        _write_conf(
            tmp_path,
            "local.conf",
            (f'IMAGE_CLASSES += "uefi-sign"\nSECURE_BOOT_SIGNING_KEY = "{keys[0]}"\n'),
        )
        result = check.run(tmp_path, {})
        misconfig = [
            f
            for f in result.findings
            if "misconfigur" in f.message.lower() or "inconsisten" in f.message.lower()
        ]
        assert len(misconfig) == 0


# --- TestScoring ---


class TestScoring:
    """Full score, partial scores, zero score."""

    def test_full_score_50(self, tmp_path: Path, check: SecureBootCheck) -> None:
        keys = _create_key_files(tmp_path, "production.key")
        _write_conf(
            tmp_path,
            "local.conf",
            (f'IMAGE_CLASSES += "uefi-sign"\nSECURE_BOOT_SIGNING_KEY = "{keys[0]}"\n'),
        )
        result = check.run(tmp_path, {})
        assert result.score == 50
        assert result.max_score == 50

    def test_max_score_always_50(self, tmp_path: Path, check: SecureBootCheck) -> None:
        result = check.run(tmp_path, {})
        assert result.max_score == 50

    def test_zero_score_no_config(self, tmp_path: Path, check: SecureBootCheck) -> None:
        result = check.run(tmp_path, {})
        assert result.score == 0

    def test_signing_class_only_partial(self, tmp_path: Path, check: SecureBootCheck) -> None:
        _write_conf(tmp_path, "local.conf", 'IMAGE_CLASSES += "uefi-sign"\n')
        result = check.run(tmp_path, {})
        # 20 (signing class) + partial other points
        assert result.score >= 20
        assert result.score < 50

    def test_signing_with_test_key_40(self, tmp_path: Path, check: SecureBootCheck) -> None:
        keys = _create_key_files(tmp_path, "test-signing.key")
        _write_conf(
            tmp_path,
            "local.conf",
            (f'IMAGE_CLASSES += "uefi-sign"\nSECURE_BOOT_SIGNING_KEY = "{keys[0]}"\n'),
        )
        result = check.run(tmp_path, {})
        # 20 + 15 + 0(test key) + 5(no misconfig) = 40
        assert result.score == 40

    def test_status_pass_on_full_score(self, tmp_path: Path, check: SecureBootCheck) -> None:
        keys = _create_key_files(tmp_path, "production.key")
        _write_conf(
            tmp_path,
            "local.conf",
            (f'IMAGE_CLASSES += "uefi-sign"\nSECURE_BOOT_SIGNING_KEY = "{keys[0]}"\n'),
        )
        result = check.run(tmp_path, {})
        assert result.status == CheckStatus.PASS

    def test_status_not_pass_on_zero_score(self, tmp_path: Path, check: SecureBootCheck) -> None:
        result = check.run(tmp_path, {})
        assert result.status in (CheckStatus.FAIL, CheckStatus.WARN)

    def test_status_on_partial_score(self, tmp_path: Path, check: SecureBootCheck) -> None:
        _write_conf(tmp_path, "local.conf", 'IMAGE_CLASSES += "uefi-sign"\n')
        result = check.run(tmp_path, {})
        assert result.status in (CheckStatus.WARN, CheckStatus.FAIL)

    def test_check_id(self, check: SecureBootCheck) -> None:
        assert check.id == "secure-boot"

    def test_check_name(self, check: SecureBootCheck) -> None:
        assert check.name == "Secure Boot"


# --- TestEdgeCases ---


class TestEdgeCases:
    """Empty build dir, missing conf dir, unusual configs."""

    def test_empty_build_dir(self, tmp_path: Path, check: SecureBootCheck) -> None:
        result = check.run(tmp_path, {})
        assert result.check_id == "secure-boot"
        assert result.check_name == "Secure Boot"
        assert result.score == 0
        assert result.max_score == 50
        assert result.status in (
            CheckStatus.FAIL,
            CheckStatus.WARN,
        )

    def test_missing_conf_dir(self, tmp_path: Path, check: SecureBootCheck) -> None:
        (tmp_path / "tmp").mkdir()
        result = check.run(tmp_path, {})
        assert result.score == 0
        assert result.status in (
            CheckStatus.FAIL,
            CheckStatus.WARN,
        )

    def test_empty_conf_files(self, tmp_path: Path, check: SecureBootCheck) -> None:
        _write_conf(tmp_path, "local.conf", "")
        _write_conf(tmp_path, "auto.conf", "")
        result = check.run(tmp_path, {})
        # No signing class, no keys, but no misconfig -> <=5
        assert result.score <= 5

    def test_commented_signing_class(self, tmp_path: Path, check: SecureBootCheck) -> None:
        _write_conf(
            tmp_path,
            "local.conf",
            '# IMAGE_CLASSES += "uefi-sign"\n',
        )
        result = check.run(tmp_path, {})
        assert result.score < 20

    def test_result_has_summary(self, tmp_path: Path, check: SecureBootCheck) -> None:
        result = check.run(tmp_path, {})
        assert isinstance(result.summary, str)
        assert len(result.summary) > 0

    def test_result_findings_are_list(self, tmp_path: Path, check: SecureBootCheck) -> None:
        result = check.run(tmp_path, {})
        assert isinstance(result.findings, list)

    def test_key_path_with_spaces(self, tmp_path: Path, check: SecureBootCheck) -> None:
        key_dir = tmp_path / "my keys"
        key_dir.mkdir(parents=True)
        key_path = key_dir / "signing.key"
        key_path.write_bytes(b"\x00" * 32)
        _write_conf(
            tmp_path,
            "local.conf",
            (f'IMAGE_CLASSES += "uefi-sign"\nSECURE_BOOT_SIGNING_KEY = "{key_path}"\n'),
        )
        result = check.run(tmp_path, {})
        # Key at path with spaces should still be recognized
        assert result.score >= 20

    def test_binary_conf_file_handled(self, tmp_path: Path, check: SecureBootCheck) -> None:
        """Binary content in conf files should not crash."""
        conf_dir = tmp_path / "conf"
        conf_dir.mkdir(parents=True)
        (conf_dir / "local.conf").write_bytes(b"\x00\xff\xfe" * 100)
        result = check.run(tmp_path, {})
        assert result.score <= 5
        assert result.status in (
            CheckStatus.FAIL,
            CheckStatus.WARN,
        )


# --- TestCRAMapping ---


class TestCRAMappingOnCheckResult:
    """CheckResult.cra_mapping must contain both `I.P1.d` and `I.P1.f`.

    CRA mapping comes from spec `cra-requirement-mapping/spec.md` -> "Existing
    checks emit mappings": Secure Boot evidences Annex I Part I (d) protection
    from unauthorised access and (f) protection of integrity.
    """

    def test_cra_mapping_empty_build_dir(self, tmp_path: Path, check: SecureBootCheck) -> None:
        result = check.run(tmp_path, {})
        assert "I.P1.d" in result.cra_mapping
        assert "I.P1.f" in result.cra_mapping

    def test_cra_mapping_missing_conf_dir(self, tmp_path: Path, check: SecureBootCheck) -> None:
        (tmp_path / "tmp").mkdir()
        result = check.run(tmp_path, {})
        assert "I.P1.d" in result.cra_mapping
        assert "I.P1.f" in result.cra_mapping

    def test_cra_mapping_no_signing_class(self, tmp_path: Path, check: SecureBootCheck) -> None:
        _write_conf(tmp_path, "local.conf", 'MACHINE = "qemux86-64"\n')
        result = check.run(tmp_path, {})
        assert "I.P1.d" in result.cra_mapping
        assert "I.P1.f" in result.cra_mapping

    def test_cra_mapping_signing_without_keys(self, tmp_path: Path, check: SecureBootCheck) -> None:
        _write_conf(tmp_path, "local.conf", 'IMAGE_CLASSES += "uefi-sign"\n')
        result = check.run(tmp_path, {})
        assert "I.P1.d" in result.cra_mapping
        assert "I.P1.f" in result.cra_mapping

    def test_cra_mapping_test_key(self, tmp_path: Path, check: SecureBootCheck) -> None:
        keys = _create_key_files(tmp_path, "test-signing.key")
        _write_conf(
            tmp_path,
            "local.conf",
            (f'IMAGE_CLASSES += "uefi-sign"\nSECURE_BOOT_SIGNING_KEY = "{keys[0]}"\n'),
        )
        result = check.run(tmp_path, {})
        assert "I.P1.d" in result.cra_mapping
        assert "I.P1.f" in result.cra_mapping

    def test_cra_mapping_fully_configured(self, tmp_path: Path, check: SecureBootCheck) -> None:
        keys = _create_key_files(tmp_path, "production.key")
        _write_conf(
            tmp_path,
            "local.conf",
            (f'IMAGE_CLASSES += "uefi-sign"\nSECURE_BOOT_SIGNING_KEY = "{keys[0]}"\n'),
        )
        result = check.run(tmp_path, {})
        assert "I.P1.d" in result.cra_mapping
        assert "I.P1.f" in result.cra_mapping

    def test_cra_mapping_efi_without_signing(self, tmp_path: Path, check: SecureBootCheck) -> None:
        _create_efi_artifacts(tmp_path)
        _write_conf(tmp_path, "local.conf", 'MACHINE = "qemux86-64"\n')
        result = check.run(tmp_path, {})
        assert "I.P1.d" in result.cra_mapping
        assert "I.P1.f" in result.cra_mapping


class TestCRAMappingOnFindings:
    """Every Secure Boot finding must carry `cra_mapping` including at least one
    of `I.P1.d` or `I.P1.f`.
    """

    def _assert_mapping(self, findings: list) -> None:
        assert findings, "expected at least one finding"
        for finding in findings:
            assert finding.cra_mapping, f"Finding '{finding.message}' has empty cra_mapping"
            assert "I.P1.d" in finding.cra_mapping or "I.P1.f" in finding.cra_mapping, (
                f"Finding '{finding.message}' missing both I.P1.d and I.P1.f "
                f"(got {finding.cra_mapping!r})"
            )

    def test_cra_mapping_no_configs(self, tmp_path: Path, check: SecureBootCheck) -> None:
        result = check.run(tmp_path, {})
        self._assert_mapping(result.findings)

    def test_cra_mapping_no_configs_with_efi(self, tmp_path: Path, check: SecureBootCheck) -> None:
        _create_efi_artifacts(tmp_path)
        result = check.run(tmp_path, {})
        self._assert_mapping(result.findings)

    def test_cra_mapping_no_signing_class(self, tmp_path: Path, check: SecureBootCheck) -> None:
        _write_conf(tmp_path, "local.conf", 'MACHINE = "qemux86-64"\n')
        result = check.run(tmp_path, {})
        self._assert_mapping(result.findings)

    def test_cra_mapping_signing_without_keys(self, tmp_path: Path, check: SecureBootCheck) -> None:
        _write_conf(tmp_path, "local.conf", 'IMAGE_CLASSES += "uefi-sign"\n')
        result = check.run(tmp_path, {})
        self._assert_mapping(result.findings)

    def test_cra_mapping_missing_key_file(self, tmp_path: Path, check: SecureBootCheck) -> None:
        _write_conf(
            tmp_path,
            "local.conf",
            ('IMAGE_CLASSES += "uefi-sign"\nSECURE_BOOT_SIGNING_KEY = "/nonexistent/key.pem"\n'),
        )
        result = check.run(tmp_path, {})
        self._assert_mapping(result.findings)

    def test_cra_mapping_test_key(self, tmp_path: Path, check: SecureBootCheck) -> None:
        keys = _create_key_files(tmp_path, "test-signing.key")
        _write_conf(
            tmp_path,
            "local.conf",
            (f'IMAGE_CLASSES += "uefi-sign"\nSECURE_BOOT_SIGNING_KEY = "{keys[0]}"\n'),
        )
        result = check.run(tmp_path, {})
        self._assert_mapping(result.findings)

    def test_cra_mapping_efi_without_signing(self, tmp_path: Path, check: SecureBootCheck) -> None:
        _create_efi_artifacts(tmp_path)
        _write_conf(tmp_path, "local.conf", 'MACHINE = "qemux86-64"\n')
        result = check.run(tmp_path, {})
        self._assert_mapping(result.findings)

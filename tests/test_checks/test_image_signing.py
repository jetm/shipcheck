"""Tests for ImageSigningCheck - RED phase.

Tests cover FIT image detection, dm-verity detection, SKIP status,
scoring logic, and edge cases.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from pathlib import Path

from shipcheck.checks.image_signing import ImageSigningCheck
from shipcheck.models import CheckStatus


@pytest.fixture
def check() -> ImageSigningCheck:
    return ImageSigningCheck()


def _deploy_dir(tmp_path: Path, machine: str = "qemuarm64") -> Path:
    """Create and return the deploy/images/<machine> directory."""
    d = tmp_path / "tmp" / "deploy" / "images" / machine
    d.mkdir(parents=True)
    return d


def _write_conf(
    tmp_path: Path,
    content: str,
    filename: str = "local.conf",
) -> Path:
    """Write a bitbake config file under conf/."""
    conf_dir = tmp_path / "conf"
    conf_dir.mkdir(parents=True, exist_ok=True)
    conf_file = conf_dir / filename
    conf_file.write_text(content)
    return conf_file


# FIT image signature marker: FDT magic + "signature" node indicator.
FIT_SIGNATURE_MARKER = b"\xd0\x0d\xfe\xed" + b"\x00" * 32 + b"signature"
FIT_UNSIGNED_CONTENT = b"\xd0\x0d\xfe\xed" + b"\x00" * 64


class TestFITDetection:
    """Tests for FIT image signature detection."""

    def test_signed_itb_detected(self, check: ImageSigningCheck, tmp_path: Path):
        deploy = _deploy_dir(tmp_path)
        itb = deploy / "fitImage.itb"
        itb.write_bytes(FIT_SIGNATURE_MARKER)
        config = {"expect_fit": True, "expect_verity": False}
        result = check.run(tmp_path, config)
        assert result.score >= 25

    def test_signed_fit_extension_detected(self, check: ImageSigningCheck, tmp_path: Path):
        deploy = _deploy_dir(tmp_path)
        (deploy / "image.fit").write_bytes(FIT_SIGNATURE_MARKER)
        config = {"expect_fit": True, "expect_verity": False}
        result = check.run(tmp_path, config)
        assert result.score >= 25

    def test_unsigned_fit_scores_zero(self, check: ImageSigningCheck, tmp_path: Path):
        deploy = _deploy_dir(tmp_path)
        (deploy / "fitImage.itb").write_bytes(FIT_UNSIGNED_CONTENT)
        config = {"expect_fit": True, "expect_verity": False}
        result = check.run(tmp_path, config)
        assert result.score == 0

    def test_no_fit_files_scores_zero(self, check: ImageSigningCheck, tmp_path: Path):
        _deploy_dir(tmp_path)
        config = {"expect_fit": True, "expect_verity": False}
        result = check.run(tmp_path, config)
        assert result.score == 0

    def test_fit_config_in_local_conf(self, check: ImageSigningCheck, tmp_path: Path):
        _deploy_dir(tmp_path)
        _write_conf(
            tmp_path,
            'UBOOT_SIGN_ENABLE = "1"\nUBOOT_SIGN_KEYDIR = "/path/to/keys"',
        )
        config = {"expect_fit": True, "expect_verity": False}
        result = check.run(tmp_path, config)
        assert result.score >= 25

    def test_fit_config_in_auto_conf(self, check: ImageSigningCheck, tmp_path: Path):
        _deploy_dir(tmp_path)
        _write_conf(
            tmp_path,
            'UBOOT_SIGN_ENABLE = "1"',
            filename="auto.conf",
        )
        config = {"expect_fit": True, "expect_verity": False}
        result = check.run(tmp_path, config)
        assert result.score >= 25


class TestDmVerityDetection:
    """Tests for dm-verity configuration detection."""

    def test_verity_in_image_classes(self, check: ImageSigningCheck, tmp_path: Path):
        _deploy_dir(tmp_path)
        _write_conf(
            tmp_path,
            'IMAGE_CLASSES += "dm-verity-img"\nDM_VERITY_IMAGE = "core-image-minimal"',
        )
        config = {"expect_fit": False, "expect_verity": True}
        result = check.run(tmp_path, config)
        assert result.score >= 25

    def test_verity_image_type_variable(self, check: ImageSigningCheck, tmp_path: Path):
        _deploy_dir(tmp_path)
        _write_conf(
            tmp_path,
            'DM_VERITY_IMAGE_TYPE = "ext4"',
        )
        config = {"expect_fit": False, "expect_verity": True}
        result = check.run(tmp_path, config)
        assert result.score >= 25

    def test_verity_hash_files(self, check: ImageSigningCheck, tmp_path: Path):
        deploy = _deploy_dir(tmp_path)
        verity = deploy / "core-image-minimal.verity"
        verity.write_bytes(b"\x00" * 32)
        config = {"expect_fit": False, "expect_verity": True}
        result = check.run(tmp_path, config)
        assert result.score >= 25

    def test_hashtree_files(self, check: ImageSigningCheck, tmp_path: Path):
        deploy = _deploy_dir(tmp_path)
        ht = deploy / "core-image-minimal.hashtree"
        ht.write_bytes(b"\x00" * 32)
        config = {"expect_fit": False, "expect_verity": True}
        result = check.run(tmp_path, config)
        assert result.score >= 25

    def test_no_verity_config_or_files(self, check: ImageSigningCheck, tmp_path: Path):
        _deploy_dir(tmp_path)
        config = {"expect_fit": False, "expect_verity": True}
        result = check.run(tmp_path, config)
        assert result.score == 0

    def test_verity_in_auto_conf(self, check: ImageSigningCheck, tmp_path: Path):
        _deploy_dir(tmp_path)
        _write_conf(
            tmp_path,
            'DM_VERITY_IMAGE = "core-image-full"',
            filename="auto.conf",
        )
        config = {"expect_fit": False, "expect_verity": True}
        result = check.run(tmp_path, config)
        assert result.score >= 25


class TestSkipStatus:
    """Tests for SKIP when neither mechanism is expected."""

    def test_skip_when_both_expect_false(self, check: ImageSigningCheck, tmp_path: Path):
        _deploy_dir(tmp_path)
        config = {"expect_fit": False, "expect_verity": False}
        result = check.run(tmp_path, config)
        assert result.status == CheckStatus.SKIP
        assert result.score == 0
        assert result.max_score == 50

    def test_skip_summary(self, check: ImageSigningCheck, tmp_path: Path):
        _deploy_dir(tmp_path)
        config = {"expect_fit": False, "expect_verity": False}
        result = check.run(tmp_path, config)
        summary_lower = result.summary.lower()
        assert (
            "skip" in summary_lower
            or "not expected" in summary_lower
            or "not applicable" in summary_lower
        )

    def test_not_skip_when_fit_expected(self, check: ImageSigningCheck, tmp_path: Path):
        _deploy_dir(tmp_path)
        config = {"expect_fit": True, "expect_verity": False}
        result = check.run(tmp_path, config)
        assert result.status != CheckStatus.SKIP

    def test_not_skip_when_verity_expected(self, check: ImageSigningCheck, tmp_path: Path):
        _deploy_dir(tmp_path)
        config = {"expect_fit": False, "expect_verity": True}
        result = check.run(tmp_path, config)
        assert result.status != CheckStatus.SKIP


class TestScoring:
    """Tests for scoring across mechanism combinations."""

    def test_both_present_scores_50(self, check: ImageSigningCheck, tmp_path: Path):
        deploy = _deploy_dir(tmp_path)
        (deploy / "fitImage.itb").write_bytes(FIT_SIGNATURE_MARKER)
        _write_conf(
            tmp_path,
            'DM_VERITY_IMAGE = "core-image-minimal"',
        )
        config = {"expect_fit": True, "expect_verity": True}
        result = check.run(tmp_path, config)
        assert result.score == 50
        assert result.max_score == 50
        assert result.status == CheckStatus.PASS

    def test_only_fit_both_expected_scores_25(self, check: ImageSigningCheck, tmp_path: Path):
        deploy = _deploy_dir(tmp_path)
        (deploy / "fitImage.itb").write_bytes(FIT_SIGNATURE_MARKER)
        config = {"expect_fit": True, "expect_verity": True}
        result = check.run(tmp_path, config)
        assert result.score == 25

    def test_only_verity_both_expected_scores_25(self, check: ImageSigningCheck, tmp_path: Path):
        _deploy_dir(tmp_path)
        _write_conf(
            tmp_path,
            'DM_VERITY_IMAGE = "core-image-minimal"',
        )
        config = {"expect_fit": True, "expect_verity": True}
        result = check.run(tmp_path, config)
        assert result.score == 25

    def test_neither_scores_0(self, check: ImageSigningCheck, tmp_path: Path):
        _deploy_dir(tmp_path)
        config = {"expect_fit": True, "expect_verity": True}
        result = check.run(tmp_path, config)
        assert result.score == 0
        assert result.status in {
            CheckStatus.FAIL,
            CheckStatus.WARN,
        }

    def test_fit_only_verity_not_expected_scores_50(self, check: ImageSigningCheck, tmp_path: Path):
        deploy = _deploy_dir(tmp_path)
        (deploy / "fitImage.itb").write_bytes(FIT_SIGNATURE_MARKER)
        config = {"expect_fit": True, "expect_verity": False}
        result = check.run(tmp_path, config)
        assert result.score == 50
        assert result.status == CheckStatus.PASS

    def test_verity_only_fit_not_expected_scores_50(self, check: ImageSigningCheck, tmp_path: Path):
        _deploy_dir(tmp_path)
        _write_conf(
            tmp_path,
            'DM_VERITY_IMAGE = "core-image-minimal"',
        )
        config = {"expect_fit": False, "expect_verity": True}
        result = check.run(tmp_path, config)
        assert result.score == 50
        assert result.status == CheckStatus.PASS

    def test_fit_absent_only_fit_expected_scores_0(self, check: ImageSigningCheck, tmp_path: Path):
        _deploy_dir(tmp_path)
        config = {"expect_fit": True, "expect_verity": False}
        result = check.run(tmp_path, config)
        assert result.score == 0

    def test_verity_absent_only_verity_expected_scores_0(
        self, check: ImageSigningCheck, tmp_path: Path
    ):
        _deploy_dir(tmp_path)
        config = {"expect_fit": False, "expect_verity": True}
        result = check.run(tmp_path, config)
        assert result.score == 0


class TestCheckMetadata:
    """Tests for check ID, name, and max_score."""

    def test_check_id(self, check: ImageSigningCheck):
        assert check.id == "image-signing"

    def test_check_name(self, check: ImageSigningCheck):
        assert check.name == "Image Signing"

    def test_max_score_in_result(self, check: ImageSigningCheck, tmp_path: Path):
        _deploy_dir(tmp_path)
        config = {"expect_fit": True, "expect_verity": True}
        result = check.run(tmp_path, config)
        assert result.max_score == 50

    def test_result_ids(self, check: ImageSigningCheck, tmp_path: Path):
        _deploy_dir(tmp_path)
        config = {"expect_fit": True, "expect_verity": True}
        result = check.run(tmp_path, config)
        assert result.check_id == "image-signing"
        assert result.check_name == "Image Signing"


class TestEdgeCases:
    """Tests for edge cases."""

    def test_empty_build_dir(self, check: ImageSigningCheck, tmp_path: Path):
        config = {"expect_fit": True, "expect_verity": True}
        result = check.run(tmp_path, config)
        assert result.score == 0
        assert result.status in {
            CheckStatus.FAIL,
            CheckStatus.WARN,
        }

    def test_missing_deploy_dir(self, check: ImageSigningCheck, tmp_path: Path):
        (tmp_path / "conf").mkdir()
        config = {"expect_fit": True, "expect_verity": True}
        result = check.run(tmp_path, config)
        assert result.score == 0

    def test_empty_config_uses_defaults(self, check: ImageSigningCheck, tmp_path: Path):
        _deploy_dir(tmp_path)
        result = check.run(tmp_path, {})
        assert result.score == 0
        assert result.status != CheckStatus.SKIP

    def test_multiple_machine_dirs(self, check: ImageSigningCheck, tmp_path: Path):
        """Deploy dir may have multiple machine subdirs."""
        d1 = _deploy_dir(tmp_path, machine="qemuarm64")
        d2 = _deploy_dir(tmp_path, machine="raspberrypi4")
        (d1 / "fitImage.itb").write_bytes(FIT_SIGNATURE_MARKER)
        (d2 / "image.verity").write_bytes(b"\x00" * 32)
        config = {"expect_fit": True, "expect_verity": True}
        result = check.run(tmp_path, config)
        assert result.score == 50

    def test_nonexistent_build_dir(self, check: ImageSigningCheck, tmp_path: Path):
        nonexistent = tmp_path / "does_not_exist"
        config = {"expect_fit": True, "expect_verity": True}
        result = check.run(nonexistent, config)
        assert result.score == 0

    def test_findings_when_mechanisms_missing(self, check: ImageSigningCheck, tmp_path: Path):
        _deploy_dir(tmp_path)
        config = {"expect_fit": True, "expect_verity": True}
        result = check.run(tmp_path, config)
        assert len(result.findings) > 0

    def test_result_has_summary(self, check: ImageSigningCheck, tmp_path: Path):
        _deploy_dir(tmp_path)
        config = {"expect_fit": True, "expect_verity": True}
        result = check.run(tmp_path, config)
        assert isinstance(result.summary, str)
        assert len(result.summary) > 0

    def test_truncated_fit_file(self, check: ImageSigningCheck, tmp_path: Path):
        """FIT file shorter than 4 bytes is treated as unsigned."""
        deploy = _deploy_dir(tmp_path)
        (deploy / "tiny.itb").write_bytes(b"\xd0\x0d")
        config = {"expect_fit": True, "expect_verity": False}
        result = check.run(tmp_path, config)
        assert result.score == 0

    def test_non_fdt_magic_fit_file(self, check: ImageSigningCheck, tmp_path: Path):
        """FIT file with wrong magic is not counted as unsigned FDT."""
        deploy = _deploy_dir(tmp_path)
        (deploy / "garbage.itb").write_bytes(b"\x00\x01\x02\x03" + b"\x00" * 64)
        config = {"expect_fit": True, "expect_verity": False}
        result = check.run(tmp_path, config)
        assert result.score == 0
        assert not any("Unsigned FIT" in f.message for f in result.findings)

    def test_fit_config_ignores_comments(self, check: ImageSigningCheck, tmp_path: Path):
        """Commented-out UBOOT_SIGN_ENABLE lines are ignored."""
        _deploy_dir(tmp_path)
        _write_conf(tmp_path, '# UBOOT_SIGN_ENABLE = "1"')
        config = {"expect_fit": True, "expect_verity": False}
        result = check.run(tmp_path, config)
        assert result.score == 0

    def test_verity_config_ignores_comments(self, check: ImageSigningCheck, tmp_path: Path):
        """Commented-out DM_VERITY_IMAGE lines are ignored."""
        _deploy_dir(tmp_path)
        _write_conf(tmp_path, '# DM_VERITY_IMAGE = "core-image"')
        config = {"expect_fit": False, "expect_verity": True}
        result = check.run(tmp_path, config)
        assert result.score == 0


class TestCRAMapping:
    """Tests for CRA requirement mappings on image-signing findings and result."""

    def test_result_cra_mapping_contains_ip1f(self, check: ImageSigningCheck, tmp_path: Path):
        """CheckResult.cra_mapping must contain 'I.P1.f' (integrity)."""
        _deploy_dir(tmp_path)
        config = {"expect_fit": True, "expect_verity": True}
        result = check.run(tmp_path, config)
        assert "I.P1.f" in result.cra_mapping

    def test_result_cra_mapping_present_fit_only(self, check: ImageSigningCheck, tmp_path: Path):
        """CheckResult.cra_mapping must contain 'I.P1.f' when only FIT expected."""
        _deploy_dir(tmp_path)
        config = {"expect_fit": True, "expect_verity": False}
        result = check.run(tmp_path, config)
        assert "I.P1.f" in result.cra_mapping

    def test_result_cra_mapping_present_verity_only(self, check: ImageSigningCheck, tmp_path: Path):
        """CheckResult.cra_mapping must contain 'I.P1.f' when only verity expected."""
        _deploy_dir(tmp_path)
        config = {"expect_fit": False, "expect_verity": True}
        result = check.run(tmp_path, config)
        assert "I.P1.f" in result.cra_mapping

    def test_every_finding_cra_mapping_has_ip1f(self, check: ImageSigningCheck, tmp_path: Path):
        """Every image-signing finding must carry 'I.P1.f' in its cra_mapping."""
        _deploy_dir(tmp_path)
        config = {"expect_fit": True, "expect_verity": True}
        result = check.run(tmp_path, config)
        assert len(result.findings) > 0, "Expected findings when nothing is present"
        for finding in result.findings:
            assert "I.P1.f" in finding.cra_mapping, (
                f"Finding '{finding.message}' missing I.P1.f mapping"
            )

    def test_unsigned_fit_finding_cra_mapping_has_ip1f(
        self, check: ImageSigningCheck, tmp_path: Path
    ):
        """Unsigned FIT finding must carry 'I.P1.f'."""
        deploy = _deploy_dir(tmp_path)
        (deploy / "fitImage.itb").write_bytes(FIT_UNSIGNED_CONTENT)
        config = {"expect_fit": True, "expect_verity": False}
        result = check.run(tmp_path, config)
        unsigned_findings = [f for f in result.findings if "Unsigned FIT" in f.message]
        assert unsigned_findings, "Expected an Unsigned FIT finding"
        for finding in unsigned_findings:
            assert "I.P1.f" in finding.cra_mapping

    def test_missing_fit_finding_cra_mapping_has_ip1f(
        self, check: ImageSigningCheck, tmp_path: Path
    ):
        """Missing FIT finding must carry 'I.P1.f'."""
        _deploy_dir(tmp_path)
        config = {"expect_fit": True, "expect_verity": False}
        result = check.run(tmp_path, config)
        fit_findings = [f for f in result.findings if "FIT" in f.message]
        assert fit_findings, "Expected a FIT-related finding"
        for finding in fit_findings:
            assert "I.P1.f" in finding.cra_mapping

    def test_verity_finding_cra_mapping_has_ip1f_and_ip1k(
        self, check: ImageSigningCheck, tmp_path: Path
    ):
        """dm-verity-specific findings must include both 'I.P1.f' and 'I.P1.k'."""
        _deploy_dir(tmp_path)
        config = {"expect_fit": False, "expect_verity": True}
        result = check.run(tmp_path, config)
        verity_findings = [
            f
            for f in result.findings
            if "verity" in f.message.lower() or "dm-verity" in f.message.lower()
        ]
        assert verity_findings, "Expected a dm-verity-related finding"
        for finding in verity_findings:
            assert "I.P1.f" in finding.cra_mapping, (
                f"verity finding '{finding.message}' missing I.P1.f"
            )
            assert "I.P1.k" in finding.cra_mapping, (
                f"verity finding '{finding.message}' missing I.P1.k"
            )

    def test_non_verity_finding_cra_mapping_does_not_require_ip1k(
        self, check: ImageSigningCheck, tmp_path: Path
    ):
        """FIT-only findings need I.P1.f but not necessarily I.P1.k."""
        deploy = _deploy_dir(tmp_path)
        (deploy / "fitImage.itb").write_bytes(FIT_UNSIGNED_CONTENT)
        config = {"expect_fit": True, "expect_verity": False}
        result = check.run(tmp_path, config)
        fit_findings = [
            f
            for f in result.findings
            if "verity" not in f.message.lower() and "dm-verity" not in f.message.lower()
        ]
        assert fit_findings, "Expected at least one non-verity finding"
        for finding in fit_findings:
            assert "I.P1.f" in finding.cra_mapping

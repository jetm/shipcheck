"""End-to-end integration tests for the shipcheck CLI.

These tests create a mock Yocto build directory with real-ish SPDX and CVE
fixtures, invoke `shipcheck check` via CliRunner, and verify terminal output,
file report content, readiness score, and exit code.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import TYPE_CHECKING

from typer.testing import CliRunner

from shipcheck.cli import app

if TYPE_CHECKING:
    import pytest

runner = CliRunner()

FIXTURES_DIR = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _setup_build_dir(
    tmp_path: Path,
    *,
    sbom_fixture: str = "valid-spdx-2.3.json",
    cve_fixture: str = "sbom-cve-check-output.json",
    include_sbom: bool = True,
    include_cve: bool = True,
) -> Path:
    """Create a mock Yocto build directory from test fixtures.

    Copies SPDX fixture into tmp/deploy/spdx/ and CVE fixture into
    tmp/deploy/images/ to match the discovery paths the checks expect.
    """
    build_dir = tmp_path / "build"
    build_dir.mkdir()

    if include_sbom:
        spdx_dir = build_dir / "tmp" / "deploy" / "spdx"
        spdx_dir.mkdir(parents=True)
        shutil.copy(
            FIXTURES_DIR / "sbom" / sbom_fixture,
            spdx_dir / "image.spdx.json",
        )

    if include_cve:
        images_dir = build_dir / "tmp" / "deploy" / "images"
        images_dir.mkdir(parents=True)
        shutil.copy(
            FIXTURES_DIR / "cve" / cve_fixture,
            images_dir / "scan.sbom-cve-check.yocto.json",
        )

    return build_dir


def _invoke_check(
    build_dir: Path,
    *,
    fmt: str = "markdown",
    checks: str | None = None,
    fail_on: str | None = None,
):
    """Invoke `shipcheck check` and return the CliRunner result."""
    args = ["check", "--build-dir", str(build_dir), "--format", fmt]
    if checks:
        args.extend(["--checks", checks])
    if fail_on:
        args.extend(["--fail-on", fail_on])
    return runner.invoke(app, args)


def _read_json_report(tmp_path: Path) -> dict:
    """Read and parse the JSON report file."""
    return json.loads((tmp_path / "shipcheck-report.json").read_text())


# ---------------------------------------------------------------------------
# Basic CLI invocation
# ---------------------------------------------------------------------------


class TestCheckCommandBasic:
    """Verify that `shipcheck check` runs end-to-end."""

    def test_exits_zero_without_fail_on(self, tmp_path: Path):
        build_dir = _setup_build_dir(tmp_path)
        result = _invoke_check(build_dir)
        assert result.exit_code == 0, result.output

    def test_terminal_output_contains_sbom_check(self, tmp_path: Path):
        build_dir = _setup_build_dir(tmp_path)
        result = _invoke_check(build_dir)
        assert "SBOM" in result.output

    def test_terminal_output_contains_cve_check(self, tmp_path: Path):
        build_dir = _setup_build_dir(tmp_path)
        result = _invoke_check(build_dir)
        assert "CVE" in result.output

    def test_terminal_output_contains_readiness_score(
        self,
        tmp_path: Path,
    ):
        build_dir = _setup_build_dir(tmp_path)
        result = _invoke_check(build_dir)
        assert "Readiness score:" in result.output

    def test_terminal_output_contains_version_header(
        self,
        tmp_path: Path,
    ):
        build_dir = _setup_build_dir(tmp_path)
        result = _invoke_check(build_dir)
        assert "shipcheck v" in result.output
        assert "Compliance Auditor" in result.output


# ---------------------------------------------------------------------------
# Default markdown report file output
# ---------------------------------------------------------------------------


class TestMarkdownReportOutput:
    """Verify default markdown report file is written."""

    def test_markdown_report_created(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        build_dir = _setup_build_dir(tmp_path)
        monkeypatch.chdir(tmp_path)
        result = _invoke_check(build_dir)
        assert result.exit_code == 0, result.output
        report = tmp_path / "shipcheck-report.md"
        assert report.exists(), f"Expected {report} to exist"

    def test_markdown_report_contains_check_results(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        build_dir = _setup_build_dir(tmp_path)
        monkeypatch.chdir(tmp_path)
        _invoke_check(build_dir)
        content = (tmp_path / "shipcheck-report.md").read_text()
        assert "SBOM" in content
        assert "CVE" in content

    def test_markdown_report_contains_framework_metadata(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        build_dir = _setup_build_dir(tmp_path)
        monkeypatch.chdir(tmp_path)
        _invoke_check(build_dir)
        content = (tmp_path / "shipcheck-report.md").read_text()
        assert "2024/2847" in content
        assert "TR-03183-2" in content

    def test_terminal_mentions_report_path(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        build_dir = _setup_build_dir(tmp_path)
        monkeypatch.chdir(tmp_path)
        result = _invoke_check(build_dir)
        assert "shipcheck-report.md" in result.output


# ---------------------------------------------------------------------------
# JSON format report
# ---------------------------------------------------------------------------


class TestJsonReportOutput:
    """Verify JSON report format via --format json."""

    def test_json_report_created(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        build_dir = _setup_build_dir(tmp_path)
        monkeypatch.chdir(tmp_path)
        result = _invoke_check(build_dir, fmt="json")
        assert result.exit_code == 0, result.output
        assert (tmp_path / "shipcheck-report.json").exists()

    def test_json_report_is_valid_json(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        build_dir = _setup_build_dir(tmp_path)
        monkeypatch.chdir(tmp_path)
        _invoke_check(build_dir, fmt="json")
        data = _read_json_report(tmp_path)
        assert isinstance(data, dict)

    def test_json_report_has_required_metadata(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        build_dir = _setup_build_dir(tmp_path)
        monkeypatch.chdir(tmp_path)
        _invoke_check(build_dir, fmt="json")
        data = _read_json_report(tmp_path)
        assert data["framework_version"] == "2024/2847"
        assert "TR-03183-2" in data["bsi_tr_version"]
        assert "shipcheck_version" in data
        assert "build_dir" in data
        assert "timestamp" in data

    def test_json_report_has_readiness_score(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        build_dir = _setup_build_dir(tmp_path)
        monkeypatch.chdir(tmp_path)
        _invoke_check(build_dir, fmt="json")
        data = _read_json_report(tmp_path)
        assert "readiness_score" in data
        score = data["readiness_score"]
        assert "score" in score
        assert "max_score" in score
        assert score["max_score"] == 200

    def test_json_report_has_checks_array(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        build_dir = _setup_build_dir(tmp_path)
        monkeypatch.chdir(tmp_path)
        _invoke_check(build_dir, fmt="json")
        data = _read_json_report(tmp_path)
        assert isinstance(data["checks"], list)
        assert len(data["checks"]) == 4
        check_ids = {c["check_id"] for c in data["checks"]}
        assert "sbom-generation" in check_ids
        assert "cve-tracking" in check_ids
        assert "secure-boot" in check_ids
        assert "image-signing" in check_ids

    def test_terminal_output_still_produced_with_json(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        build_dir = _setup_build_dir(tmp_path)
        monkeypatch.chdir(tmp_path)
        result = _invoke_check(build_dir, fmt="json")
        assert "Readiness score:" in result.output


# ---------------------------------------------------------------------------
# HTML format report
# ---------------------------------------------------------------------------


class TestHtmlReportOutput:
    """Verify HTML report format via --format html."""

    def test_html_report_created(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        build_dir = _setup_build_dir(tmp_path)
        monkeypatch.chdir(tmp_path)
        result = _invoke_check(build_dir, fmt="html")
        assert result.exit_code == 0, result.output
        assert (tmp_path / "shipcheck-report.html").exists()

    def test_html_report_is_self_contained(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        build_dir = _setup_build_dir(tmp_path)
        monkeypatch.chdir(tmp_path)
        _invoke_check(build_dir, fmt="html")
        content = (tmp_path / "shipcheck-report.html").read_text()
        assert "<html" in content
        assert "<style" in content


# ---------------------------------------------------------------------------
# --fail-on exit code gating
# ---------------------------------------------------------------------------


class TestFailOnExitCode:
    """Verify --fail-on severity gating controls exit code."""

    def test_no_fail_on_exits_zero(self, tmp_path: Path):
        """Without --fail-on, exit 0 even when findings exist."""
        build_dir = _setup_build_dir(tmp_path)
        result = _invoke_check(build_dir)
        assert result.exit_code == 0

    def test_fail_on_critical_missing_spdx(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        """Missing SPDX directory -> critical finding -> exit 1."""
        build_dir = _setup_build_dir(tmp_path, include_sbom=False)
        monkeypatch.chdir(tmp_path)
        result = _invoke_check(build_dir, fail_on="critical")
        assert result.exit_code == 1

    def test_fail_on_critical_missing_cve(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        """Missing CVE output -> critical finding -> exit 1."""
        build_dir = _setup_build_dir(tmp_path, include_cve=False)
        monkeypatch.chdir(tmp_path)
        result = _invoke_check(build_dir, fail_on="critical")
        assert result.exit_code == 1

    def test_fail_on_low_missing_artifacts(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        """--fail-on low exits 1 when critical findings exist."""
        build_dir = _setup_build_dir(
            tmp_path,
            include_sbom=False,
            include_cve=False,
        )
        monkeypatch.chdir(tmp_path)
        result = _invoke_check(build_dir, fail_on="low")
        assert result.exit_code == 1

    def test_no_fail_on_exits_zero_with_failures(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        """Without --fail-on, exit 0 even with FAIL status checks."""
        build_dir = _setup_build_dir(
            tmp_path,
            include_sbom=False,
            include_cve=False,
        )
        monkeypatch.chdir(tmp_path)
        result = _invoke_check(build_dir)
        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# --checks filter
# ---------------------------------------------------------------------------


class TestChecksFilter:
    """Verify --checks flag filters which checks run."""

    def test_only_sbom_check_runs(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        build_dir = _setup_build_dir(tmp_path)
        monkeypatch.chdir(tmp_path)
        result = _invoke_check(build_dir, checks="sbom-generation")
        assert result.exit_code == 0, result.output
        assert "SBOM" in result.output

    def test_only_sbom_in_json_report(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        build_dir = _setup_build_dir(tmp_path)
        monkeypatch.chdir(tmp_path)
        _invoke_check(
            build_dir,
            checks="sbom-generation",
            fmt="json",
        )
        data = _read_json_report(tmp_path)
        assert len(data["checks"]) == 1
        assert data["checks"][0]["check_id"] == "sbom-generation"

    def test_only_cve_check_runs(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        build_dir = _setup_build_dir(tmp_path)
        monkeypatch.chdir(tmp_path)
        _invoke_check(
            build_dir,
            checks="cve-tracking",
            fmt="json",
        )
        data = _read_json_report(tmp_path)
        assert len(data["checks"]) == 1
        assert data["checks"][0]["check_id"] == "cve-tracking"

    def test_filtered_score_max_is_50(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        build_dir = _setup_build_dir(tmp_path)
        monkeypatch.chdir(tmp_path)
        _invoke_check(
            build_dir,
            checks="sbom-generation",
            fmt="json",
        )
        data = _read_json_report(tmp_path)
        assert data["readiness_score"]["max_score"] == 50


# ---------------------------------------------------------------------------
# Missing build artifacts
# ---------------------------------------------------------------------------


class TestMissingArtifacts:
    """Verify behavior when build artifacts are missing."""

    def test_missing_spdx_dir_produces_fail(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        build_dir = _setup_build_dir(tmp_path, include_sbom=False)
        monkeypatch.chdir(tmp_path)
        _invoke_check(build_dir, fmt="json")
        data = _read_json_report(tmp_path)
        sbom = next(c for c in data["checks"] if c["check_id"] == "sbom-generation")
        assert sbom["status"] == "fail"
        assert sbom["score"] == 0

    def test_missing_cve_output_produces_fail(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        build_dir = _setup_build_dir(tmp_path, include_cve=False)
        monkeypatch.chdir(tmp_path)
        _invoke_check(build_dir, fmt="json")
        data = _read_json_report(tmp_path)
        cve = next(c for c in data["checks"] if c["check_id"] == "cve-tracking")
        assert cve["status"] == "fail"
        assert cve["score"] == 0

    def test_missing_both_score_zero(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        build_dir = _setup_build_dir(
            tmp_path,
            include_sbom=False,
            include_cve=False,
        )
        monkeypatch.chdir(tmp_path)
        _invoke_check(build_dir, fmt="json")
        data = _read_json_report(tmp_path)
        assert data["readiness_score"]["score"] == 0

    def test_terminal_shows_fail(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        build_dir = _setup_build_dir(
            tmp_path,
            include_sbom=False,
            include_cve=False,
        )
        monkeypatch.chdir(tmp_path)
        result = _invoke_check(build_dir)
        assert "FAIL" in result.output

    def test_findings_have_remediation(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        build_dir = _setup_build_dir(
            tmp_path,
            include_sbom=False,
            include_cve=False,
        )
        monkeypatch.chdir(tmp_path)
        _invoke_check(build_dir, fmt="json")
        data = _read_json_report(tmp_path)
        for check_data in data["checks"]:
            for finding in check_data["findings"]:
                if finding["severity"] in ("critical", "high"):
                    assert finding.get("remediation") is not None


# ---------------------------------------------------------------------------
# Readiness score validation
# ---------------------------------------------------------------------------


class TestReadinessScore:
    """Verify readiness score reflects check results."""

    def test_max_score_is_200(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        build_dir = _setup_build_dir(tmp_path)
        monkeypatch.chdir(tmp_path)
        _invoke_check(build_dir, fmt="json")
        data = _read_json_report(tmp_path)
        assert data["readiness_score"]["max_score"] == 200

    def test_score_between_zero_and_max(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        build_dir = _setup_build_dir(tmp_path)
        monkeypatch.chdir(tmp_path)
        _invoke_check(build_dir, fmt="json")
        data = _read_json_report(tmp_path)
        score = data["readiness_score"]["score"]
        max_score = data["readiness_score"]["max_score"]
        assert 0 <= score <= max_score

    def test_score_in_terminal_output(self, tmp_path: Path):
        build_dir = _setup_build_dir(tmp_path)
        result = _invoke_check(build_dir)
        assert "/200" in result.output


# ---------------------------------------------------------------------------
# Nonexistent build directory
# ---------------------------------------------------------------------------


class TestInvalidBuildDir:
    """Verify error handling for nonexistent build directory."""

    def test_nonexistent_dir_reports_failures(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        """Nonexistent dir doesn't crash - checks find nothing."""
        monkeypatch.chdir(tmp_path)
        result = _invoke_check(tmp_path / "does-not-exist")
        assert result.exit_code == 0
        assert "FAIL" in result.output


# ---------------------------------------------------------------------------
# Report content integrity
# ---------------------------------------------------------------------------


class TestReportContentIntegrity:
    """Cross-format consistency: terminal and JSON report agree."""

    def test_json_and_terminal_show_same_checks(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        build_dir = _setup_build_dir(tmp_path)
        monkeypatch.chdir(tmp_path)
        result = _invoke_check(build_dir, fmt="json")
        data = _read_json_report(tmp_path)
        for check_data in data["checks"]:
            assert check_data["check_name"] in result.output

    def test_json_build_dir_matches_cli_arg(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        build_dir = _setup_build_dir(tmp_path)
        monkeypatch.chdir(tmp_path)
        _invoke_check(build_dir, fmt="json")
        data = _read_json_report(tmp_path)
        assert str(build_dir) in data["build_dir"]

    def test_json_timestamp_is_iso8601(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        from datetime import datetime

        build_dir = _setup_build_dir(tmp_path)
        monkeypatch.chdir(tmp_path)
        _invoke_check(build_dir, fmt="json")
        data = _read_json_report(tmp_path)
        datetime.fromisoformat(data["timestamp"])

    def test_json_checks_have_expected_fields(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        build_dir = _setup_build_dir(tmp_path)
        monkeypatch.chdir(tmp_path)
        _invoke_check(build_dir, fmt="json")
        data = _read_json_report(tmp_path)
        for check_data in data["checks"]:
            assert "check_id" in check_data
            assert "check_name" in check_data
            assert "status" in check_data
            assert "score" in check_data
            assert "max_score" in check_data
            assert "findings" in check_data
            assert "summary" in check_data


# ---------------------------------------------------------------------------
# Secure Boot check via CLI
# ---------------------------------------------------------------------------


def _add_secureboot_config(build_dir: Path) -> None:
    """Add Secure Boot configuration files to a mock build directory."""
    conf_dir = build_dir / "conf"
    conf_dir.mkdir(exist_ok=True)
    keys_dir = build_dir / "keys"
    keys_dir.mkdir(exist_ok=True)

    (keys_dir / "db.key").write_text("fake-key-data")
    (keys_dir / "db.crt").write_text("fake-cert-data")

    (conf_dir / "local.conf").write_text(
        'MACHINE = "genericx86-64"\n'
        'DISTRO = "poky"\n'
        'IMAGE_CLASSES += "uefi-sign"\n'
        'SECURE_BOOT_SIGNING_KEY = "${TOPDIR}/keys/db.key"\n'
        'SECURE_BOOT_SIGNING_CERT = "${TOPDIR}/keys/db.crt"\n'
    )


def _add_efi_artifacts(build_dir: Path) -> None:
    """Add EFI artifacts to the deploy directory."""
    efi_dir = build_dir / "tmp" / "deploy" / "images" / "genericx86-64"
    efi_dir.mkdir(parents=True, exist_ok=True)
    (efi_dir / "bootx64.efi").write_bytes(b"\x00" * 64)


def _add_verity_config(build_dir: Path) -> None:
    """Add dm-verity configuration to a mock build directory."""
    conf_dir = build_dir / "conf"
    conf_dir.mkdir(exist_ok=True)
    (conf_dir / "local.conf").write_text(
        'MACHINE = "qemuarm64"\n'
        'DISTRO = "poky"\n'
        'IMAGE_CLASSES += "dm-verity-img"\n'
        'DM_VERITY_IMAGE = "core-image-minimal"\n'
        'DM_VERITY_IMAGE_TYPE = "ext4"\n'
    )


def _add_signed_fit(build_dir: Path) -> None:
    """Add a signed FIT image stub to the deploy directory."""
    images_dir = build_dir / "tmp" / "deploy" / "images"
    images_dir.mkdir(parents=True, exist_ok=True)
    src = FIXTURES_DIR / "imagesigning" / "signed.itb"
    shutil.copy(src, images_dir / "fitImage.itb")


class TestSecureBootCheckViaCLI:
    """Verify Secure Boot check appears in CLI output and reports."""

    def test_terminal_output_contains_secure_boot(self, tmp_path: Path):
        build_dir = _setup_build_dir(tmp_path)
        result = _invoke_check(build_dir)
        assert "Secure Boot" in result.output

    def test_json_report_includes_secure_boot_check(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        build_dir = _setup_build_dir(tmp_path)
        monkeypatch.chdir(tmp_path)
        _invoke_check(build_dir, fmt="json")
        data = _read_json_report(tmp_path)
        check_ids = {c["check_id"] for c in data["checks"]}
        assert "secure-boot" in check_ids

    def test_secure_boot_with_signing_config_scores_points(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        build_dir = _setup_build_dir(tmp_path)
        _add_secureboot_config(build_dir)
        _add_efi_artifacts(build_dir)
        monkeypatch.chdir(tmp_path)
        _invoke_check(build_dir, fmt="json")
        data = _read_json_report(tmp_path)
        sb = next(c for c in data["checks"] if c["check_id"] == "secure-boot")
        assert sb["score"] > 0
        assert sb["max_score"] == 50

    def test_secure_boot_without_config_scores_zero(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        build_dir = _setup_build_dir(tmp_path)
        monkeypatch.chdir(tmp_path)
        _invoke_check(build_dir, fmt="json")
        data = _read_json_report(tmp_path)
        sb = next(c for c in data["checks"] if c["check_id"] == "secure-boot")
        assert sb["score"] == 0

    def test_filter_secure_boot_only(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        build_dir = _setup_build_dir(tmp_path)
        _add_secureboot_config(build_dir)
        monkeypatch.chdir(tmp_path)
        _invoke_check(build_dir, checks="secure-boot", fmt="json")
        data = _read_json_report(tmp_path)
        assert len(data["checks"]) == 1
        assert data["checks"][0]["check_id"] == "secure-boot"
        assert data["readiness_score"]["max_score"] == 50


# ---------------------------------------------------------------------------
# Image Signing check via CLI
# ---------------------------------------------------------------------------


class TestImageSigningCheckViaCLI:
    """Verify Image Signing check appears in CLI output and reports."""

    def test_terminal_output_contains_image_signing(self, tmp_path: Path):
        build_dir = _setup_build_dir(tmp_path)
        result = _invoke_check(build_dir)
        assert "Image Signing" in result.output

    def test_json_report_includes_image_signing_check(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        build_dir = _setup_build_dir(tmp_path)
        monkeypatch.chdir(tmp_path)
        _invoke_check(build_dir, fmt="json")
        data = _read_json_report(tmp_path)
        check_ids = {c["check_id"] for c in data["checks"]}
        assert "image-signing" in check_ids

    def test_image_signing_with_verity_config_scores_points(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        build_dir = _setup_build_dir(tmp_path)
        _add_verity_config(build_dir)
        monkeypatch.chdir(tmp_path)
        _invoke_check(build_dir, fmt="json")
        data = _read_json_report(tmp_path)
        isig = next(c for c in data["checks"] if c["check_id"] == "image-signing")
        assert isig["score"] > 0
        assert isig["max_score"] == 50

    def test_image_signing_with_signed_fit_scores_points(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        build_dir = _setup_build_dir(tmp_path)
        _add_signed_fit(build_dir)
        monkeypatch.chdir(tmp_path)
        _invoke_check(build_dir, fmt="json")
        data = _read_json_report(tmp_path)
        isig = next(c for c in data["checks"] if c["check_id"] == "image-signing")
        assert isig["score"] > 0

    def test_image_signing_without_artifacts_has_findings(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        build_dir = _setup_build_dir(tmp_path)
        monkeypatch.chdir(tmp_path)
        _invoke_check(build_dir, fmt="json")
        data = _read_json_report(tmp_path)
        isig = next(c for c in data["checks"] if c["check_id"] == "image-signing")
        assert len(isig["findings"]) > 0

    def test_filter_image_signing_only(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        build_dir = _setup_build_dir(tmp_path)
        monkeypatch.chdir(tmp_path)
        _invoke_check(build_dir, checks="image-signing", fmt="json")
        data = _read_json_report(tmp_path)
        assert len(data["checks"]) == 1
        assert data["checks"][0]["check_id"] == "image-signing"
        assert data["readiness_score"]["max_score"] == 50


# ---------------------------------------------------------------------------
# Score aggregation with all 4 checks
# ---------------------------------------------------------------------------


class TestScoreAggregationAllChecks:
    """Verify score aggregation across all 4 checks."""

    def test_all_checks_contribute_to_total_score(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        build_dir = _setup_build_dir(tmp_path)
        _add_secureboot_config(build_dir)
        _add_efi_artifacts(build_dir)
        _add_signed_fit(build_dir)
        _add_verity_config(build_dir)
        monkeypatch.chdir(tmp_path)
        _invoke_check(build_dir, fmt="json")
        data = _read_json_report(tmp_path)
        total = sum(c["score"] for c in data["checks"])
        assert data["readiness_score"]["score"] == total
        assert data["readiness_score"]["max_score"] == 200

    def test_max_score_scales_with_filtered_checks(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        """Filtering to 2 checks yields max_score=100."""
        build_dir = _setup_build_dir(tmp_path)
        monkeypatch.chdir(tmp_path)
        _invoke_check(
            build_dir,
            checks="sbom-generation,cve-tracking",
            fmt="json",
        )
        data = _read_json_report(tmp_path)
        assert data["readiness_score"]["max_score"] == 100

    def test_terminal_score_shows_out_of_200(self, tmp_path: Path):
        build_dir = _setup_build_dir(tmp_path)
        result = _invoke_check(build_dir)
        assert "/200" in result.output

    def test_markdown_report_includes_all_four_checks(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        build_dir = _setup_build_dir(tmp_path)
        monkeypatch.chdir(tmp_path)
        _invoke_check(build_dir, fmt="markdown")
        content = (tmp_path / "shipcheck-report.md").read_text()
        assert "SBOM" in content
        assert "CVE" in content
        assert "Secure Boot" in content
        assert "Image Signing" in content

    def test_html_report_includes_all_four_checks(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        build_dir = _setup_build_dir(tmp_path)
        monkeypatch.chdir(tmp_path)
        _invoke_check(build_dir, fmt="html")
        content = (tmp_path / "shipcheck-report.html").read_text()
        assert "Secure Boot" in content
        assert "Image Signing" in content

    def test_missing_all_artifacts_max_score_still_200(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        build_dir = _setup_build_dir(
            tmp_path, include_sbom=False, include_cve=False
        )
        monkeypatch.chdir(tmp_path)
        _invoke_check(build_dir, fmt="json")
        data = _read_json_report(tmp_path)
        assert data["readiness_score"]["max_score"] == 200
        assert data["readiness_score"]["score"] == 0

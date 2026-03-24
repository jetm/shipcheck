"""End-to-end integration tests for the shipcheck CLI.

These tests create a mock Yocto build directory with real-ish SPDX and CVE
fixtures, invoke `shipcheck check` via CliRunner, and verify terminal output,
file report content, readiness score, and exit code.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from typer.testing import CliRunner

from shipcheck.cli import app

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


def _read_json_report(result) -> dict:  # type: ignore[no-untyped-def]
    """Parse the JSON payload emitted to stdout by `shipcheck check --format json`.

    Since task 1.2 routed ``--format json`` (without ``--out``) to stdout,
    the JSON payload is no longer written to ``./shipcheck-report.json``;
    tests read ``result.stdout`` from the ``CliRunner`` result directly.
    """
    return json.loads(result.stdout)


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

    def test_json_report_emitted_to_stdout(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        """`--format json` (no `--out`) emits JSON on stdout, not to disk."""
        build_dir = _setup_build_dir(tmp_path)
        monkeypatch.chdir(tmp_path)
        result = _invoke_check(build_dir, fmt="json")
        assert result.exit_code == 0, result.output
        # Payload parseable as JSON.
        json.loads(result.stdout)
        # No file side-effect in cwd; the contract is stdout-only.
        assert not (tmp_path / "shipcheck-report.json").exists()

    def test_json_report_is_valid_json(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        build_dir = _setup_build_dir(tmp_path)
        monkeypatch.chdir(tmp_path)
        result = _invoke_check(build_dir, fmt="json")
        data = _read_json_report(result)
        assert isinstance(data, dict)

    def test_json_report_has_required_metadata(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        build_dir = _setup_build_dir(tmp_path)
        monkeypatch.chdir(tmp_path)
        result = _invoke_check(build_dir, fmt="json")
        data = _read_json_report(result)
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
        result = _invoke_check(build_dir, fmt="json")
        data = _read_json_report(result)
        assert "readiness_score" in data
        score = data["readiness_score"]
        assert "score" in score
        assert "max_score" in score
        assert score["max_score"] == 350

    def test_json_report_has_checks_array(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        build_dir = _setup_build_dir(tmp_path)
        monkeypatch.chdir(tmp_path)
        result = _invoke_check(build_dir, fmt="json")
        data = _read_json_report(result)
        assert isinstance(data["checks"], list)
        assert len(data["checks"]) == 7
        check_ids = {c["check_id"] for c in data["checks"]}
        assert "sbom-generation" in check_ids
        assert "cve-tracking" in check_ids
        assert "secure-boot" in check_ids
        assert "image-signing" in check_ids


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
        result = _invoke_check(
            build_dir,
            checks="sbom-generation",
            fmt="json",
        )
        data = _read_json_report(result)
        assert len(data["checks"]) == 1
        assert data["checks"][0]["check_id"] == "sbom-generation"

    def test_only_cve_check_runs(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        build_dir = _setup_build_dir(tmp_path)
        monkeypatch.chdir(tmp_path)
        result = _invoke_check(
            build_dir,
            checks="cve-tracking",
            fmt="json",
        )
        data = _read_json_report(result)
        assert len(data["checks"]) == 1
        assert data["checks"][0]["check_id"] == "cve-tracking"

    def test_filtered_score_max_is_50(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        build_dir = _setup_build_dir(tmp_path)
        monkeypatch.chdir(tmp_path)
        result = _invoke_check(
            build_dir,
            checks="sbom-generation",
            fmt="json",
        )
        data = _read_json_report(result)
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
        result = _invoke_check(build_dir, fmt="json")
        data = _read_json_report(result)
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
        result = _invoke_check(build_dir, fmt="json")
        data = _read_json_report(result)
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
        result = _invoke_check(build_dir, fmt="json")
        data = _read_json_report(result)
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
        result = _invoke_check(build_dir, fmt="json")
        data = _read_json_report(result)
        for check_data in data["checks"]:
            for finding in check_data["findings"]:
                if finding["severity"] in ("critical", "high"):
                    assert finding.get("remediation") is not None


# ---------------------------------------------------------------------------
# Readiness score validation
# ---------------------------------------------------------------------------


class TestReadinessScore:
    """Verify readiness score reflects check results."""

    def test_max_score_is_350(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        build_dir = _setup_build_dir(tmp_path)
        monkeypatch.chdir(tmp_path)
        result = _invoke_check(build_dir, fmt="json")
        data = _read_json_report(result)
        assert data["readiness_score"]["max_score"] == 350

    def test_score_between_zero_and_max(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        build_dir = _setup_build_dir(tmp_path)
        monkeypatch.chdir(tmp_path)
        result = _invoke_check(build_dir, fmt="json")
        data = _read_json_report(result)
        score = data["readiness_score"]["score"]
        max_score = data["readiness_score"]["max_score"]
        assert 0 <= score <= max_score

    def test_score_in_terminal_output(self, tmp_path: Path):
        build_dir = _setup_build_dir(tmp_path)
        result = _invoke_check(build_dir)
        assert "/350" in result.output


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
        data = _read_json_report(result)
        for check_data in data["checks"]:
            assert check_data["check_name"] in result.output

    def test_json_build_dir_matches_cli_arg(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        build_dir = _setup_build_dir(tmp_path)
        monkeypatch.chdir(tmp_path)
        result = _invoke_check(build_dir, fmt="json")
        data = _read_json_report(result)
        assert str(build_dir) in data["build_dir"]

    def test_json_timestamp_is_iso8601(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        from datetime import datetime

        build_dir = _setup_build_dir(tmp_path)
        monkeypatch.chdir(tmp_path)
        result = _invoke_check(build_dir, fmt="json")
        data = _read_json_report(result)
        datetime.fromisoformat(data["timestamp"])

    def test_json_checks_have_expected_fields(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        build_dir = _setup_build_dir(tmp_path)
        monkeypatch.chdir(tmp_path)
        result = _invoke_check(build_dir, fmt="json")
        data = _read_json_report(result)
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
        result = _invoke_check(build_dir, fmt="json")
        data = _read_json_report(result)
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
        result = _invoke_check(build_dir, fmt="json")
        data = _read_json_report(result)
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
        result = _invoke_check(build_dir, fmt="json")
        data = _read_json_report(result)
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
        result = _invoke_check(build_dir, checks="secure-boot", fmt="json")
        data = _read_json_report(result)
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
        result = _invoke_check(build_dir, fmt="json")
        data = _read_json_report(result)
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
        result = _invoke_check(build_dir, fmt="json")
        data = _read_json_report(result)
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
        result = _invoke_check(build_dir, fmt="json")
        data = _read_json_report(result)
        isig = next(c for c in data["checks"] if c["check_id"] == "image-signing")
        assert isig["score"] > 0

    def test_image_signing_without_artifacts_has_findings(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        build_dir = _setup_build_dir(tmp_path)
        monkeypatch.chdir(tmp_path)
        result = _invoke_check(build_dir, fmt="json")
        data = _read_json_report(result)
        isig = next(c for c in data["checks"] if c["check_id"] == "image-signing")
        assert len(isig["findings"]) > 0

    def test_filter_image_signing_only(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        build_dir = _setup_build_dir(tmp_path)
        monkeypatch.chdir(tmp_path)
        result = _invoke_check(build_dir, checks="image-signing", fmt="json")
        data = _read_json_report(result)
        assert len(data["checks"]) == 1
        assert data["checks"][0]["check_id"] == "image-signing"
        assert data["readiness_score"]["max_score"] == 50


# ---------------------------------------------------------------------------
# Score aggregation with all registered checks
# ---------------------------------------------------------------------------


class TestScoreAggregationAllChecks:
    """Verify score aggregation across all registered checks."""

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
        result = _invoke_check(build_dir, fmt="json")
        data = _read_json_report(result)
        total = sum(c["score"] for c in data["checks"])
        assert data["readiness_score"]["score"] == total
        assert data["readiness_score"]["max_score"] == 350

    def test_max_score_scales_with_filtered_checks(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        """Filtering to 2 checks yields max_score=100."""
        build_dir = _setup_build_dir(tmp_path)
        monkeypatch.chdir(tmp_path)
        result = _invoke_check(
            build_dir,
            checks="sbom-generation,cve-tracking",
            fmt="json",
        )
        data = _read_json_report(result)
        assert data["readiness_score"]["max_score"] == 100

    def test_terminal_score_shows_out_of_350(self, tmp_path: Path):
        build_dir = _setup_build_dir(tmp_path)
        result = _invoke_check(build_dir)
        assert "/350" in result.output

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

    def test_missing_all_artifacts_max_score_still_350(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        build_dir = _setup_build_dir(tmp_path, include_sbom=False, include_cve=False)
        monkeypatch.chdir(tmp_path)
        result = _invoke_check(build_dir, fmt="json")
        data = _read_json_report(result)
        assert data["readiness_score"]["max_score"] == 350
        assert data["readiness_score"]["score"] == 0


# ---------------------------------------------------------------------------
# Evidence dossier end-to-end (task 10.10)
# ---------------------------------------------------------------------------


def _setup_evidence_build_dir(tmp_path: Path) -> Path:
    """Create a mock Yocto build directory populated for the evidence dossier.

    Lays down:
      - tmp/deploy/licenses/core-image-test/license.manifest (from permissive fixture)
      - tmp/deploy/images/core-image-test/core-image-test-qemux86-64.spdx.json
        (from SPDX 2.3 fixture)
      - tmp/deploy/spdx/core-image-test.spdx.json (mirror of the SPDX doc so
        the SBOM discovery path matches)
      - tmp/log/cve/cve-summary.json (from Yocto scarthgap cve-summary fixture)
      - product.yaml (from the complete product fixture)
    """
    build_dir = tmp_path / "build"
    build_dir.mkdir()

    licenses_src = FIXTURES_DIR / "licenses" / "core-image-minimal" / "license.manifest"
    sbom_src = FIXTURES_DIR / "sbom" / "valid-spdx-2.3.json"
    cve_src = FIXTURES_DIR / "yocto_cve" / "cve-summary-scarthgap.json"
    product_src = FIXTURES_DIR / "product" / "complete.yaml"

    for src in (licenses_src, sbom_src, cve_src, product_src):
        if not src.exists():
            pytest.skip(f"required fixture missing: {src}")

    licenses_dir = build_dir / "tmp" / "deploy" / "licenses" / "core-image-test"
    licenses_dir.mkdir(parents=True)
    shutil.copy(licenses_src, licenses_dir / "license.manifest")

    images_dir = build_dir / "tmp" / "deploy" / "images" / "core-image-test"
    images_dir.mkdir(parents=True)
    shutil.copy(
        sbom_src,
        images_dir / "core-image-test-qemux86-64.spdx.json",
    )
    # Mirror into tmp/deploy/spdx/ so the existing SBOM check can discover it.
    spdx_dir = build_dir / "tmp" / "deploy" / "spdx"
    spdx_dir.mkdir(parents=True)
    shutil.copy(sbom_src, spdx_dir / "core-image-test.spdx.json")

    cve_dir = build_dir / "tmp" / "log" / "cve"
    cve_dir.mkdir(parents=True)
    shutil.copy(cve_src, cve_dir / "cve-summary.json")

    shutil.copy(product_src, build_dir / "product.yaml")

    return build_dir


def _write_evidence_shipcheck_config(build_dir: Path) -> Path:
    """Write a `.shipcheck.yaml` enabling history and pointing at product.yaml.

    Returns the path the config was written to (current working directory).
    """
    config_path = Path(".shipcheck.yaml")
    config_path.write_text(
        "history:\n"
        "  enabled: true\n"
        f"  path: {build_dir}/.shipcheck/history.db\n"
        f"product_config_path: {build_dir}/product.yaml\n"
    )
    return config_path


@pytest.mark.integration
class TestEvidenceDossierEndToEnd:
    """End-to-end dossier generation (RED until CLI wiring in 10.4-10.9 lands).

    These tests exercise `shipcheck check --format evidence --out <dir>/` against
    a fixture build dir containing every evidence input: license.manifest, SBOM,
    yocto cve-summary.json, and product.yaml. They verify the dossier directory
    is populated with every expected artifact, the scan row is persisted to the
    history store, the CRA mapping validator ran cleanly, and the command exits
    zero. Until tasks 10.4 (--out), 10.5 (dossier cmd), 10.6 (docs), 10.7 (doc
    declaration), 10.8 (history hook), and 10.9 (CRA mapping validation hook)
    land, the assertions fail at runtime rather than collection time.
    """

    def test_dossier_directory_is_populated(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        build_dir = _setup_evidence_build_dir(tmp_path)
        monkeypatch.chdir(tmp_path)
        _write_evidence_shipcheck_config(build_dir)
        dossier_dir = tmp_path / "dossier"

        result = runner.invoke(
            app,
            [
                "check",
                "--build-dir",
                str(build_dir),
                "--format",
                "evidence",
                "--out",
                str(dossier_dir),
            ],
        )

        assert result.exit_code == 0, f"shipcheck check exited non-zero:\n{result.output}"
        assert dossier_dir.is_dir(), f"expected dossier output dir at {dossier_dir}"
        # Core evidence artifacts: emitted whenever --format evidence --out is used.
        assert (dossier_dir / "evidence-report.md").exists()
        assert (dossier_dir / "scan.json").exists()
        assert (dossier_dir / "cve-report.md").exists()

    def test_dossier_contains_license_audit(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        build_dir = _setup_evidence_build_dir(tmp_path)
        monkeypatch.chdir(tmp_path)
        _write_evidence_shipcheck_config(build_dir)
        dossier_dir = tmp_path / "dossier"

        result = runner.invoke(
            app,
            [
                "check",
                "--build-dir",
                str(build_dir),
                "--format",
                "evidence",
                "--out",
                str(dossier_dir),
            ],
        )

        assert result.exit_code == 0, result.output
        # license-audit check enabled by default once registered → license-audit.md emitted.
        assert (dossier_dir / "license-audit.md").exists()

    def test_dossier_contains_product_paperwork(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        build_dir = _setup_evidence_build_dir(tmp_path)
        monkeypatch.chdir(tmp_path)
        _write_evidence_shipcheck_config(build_dir)
        dossier_dir = tmp_path / "dossier"

        result = runner.invoke(
            app,
            [
                "check",
                "--build-dir",
                str(build_dir),
                "--format",
                "evidence",
                "--out",
                str(dossier_dir),
                "--product-config",
                str(build_dir / "product.yaml"),
            ],
        )

        assert result.exit_code == 0, result.output
        # product.yaml present → Annex VII draft and DoC must be emitted.
        assert (dossier_dir / "technical-documentation.md").exists()
        assert (dossier_dir / "declaration-of-conformity.md").exists()

    def test_history_row_persisted(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        build_dir = _setup_evidence_build_dir(tmp_path)
        monkeypatch.chdir(tmp_path)
        _write_evidence_shipcheck_config(build_dir)
        dossier_dir = tmp_path / "dossier"

        result = runner.invoke(
            app,
            [
                "check",
                "--build-dir",
                str(build_dir),
                "--format",
                "evidence",
                "--out",
                str(dossier_dir),
            ],
        )

        assert result.exit_code == 0, result.output
        db_path = build_dir / ".shipcheck" / "history.db"
        assert db_path.exists(), f"expected history DB at {db_path}"

        import sqlite3

        with sqlite3.connect(db_path) as conn:
            # The schema names are defined by group 6; any table holding scan rows
            # must contain at least one row after a successful check run.
            tables = [
                row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
            ]
            assert tables, "history DB has no tables"
            scan_tables = [t for t in tables if "scan" in t.lower()]
            assert scan_tables, f"no scan table found in history DB: {tables}"
            rows_total = 0
            for table in scan_tables:
                rows_total += conn.execute(
                    f"SELECT COUNT(*) FROM {table}"  # noqa: S608 - table name from controlled schema
                ).fetchone()[0]
            assert rows_total >= 1, f"expected at least one scan row across {scan_tables}"

    def test_cra_mapping_validation_passed(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        """CRA mapping validation must run and not raise during the pipeline.

        Task 10.9 wires `validate_cra_mappings(report)` in before rendering; any
        invalid mapping would exit ERROR-status non-zero. A clean exit on the
        full-evidence fixture is the signal the validator ran and passed.
        """
        build_dir = _setup_evidence_build_dir(tmp_path)
        monkeypatch.chdir(tmp_path)
        _write_evidence_shipcheck_config(build_dir)
        dossier_dir = tmp_path / "dossier"

        result = runner.invoke(
            app,
            [
                "check",
                "--build-dir",
                str(build_dir),
                "--format",
                "evidence",
                "--out",
                str(dossier_dir),
            ],
        )

        assert result.exit_code == 0, result.output
        assert "invalid CRA mapping" not in result.output.lower()
        assert "unknown cra" not in result.output.lower()


# ---------------------------------------------------------------------------
# CVE reconciliation across cve-tracking and yocto-cve-check
# ---------------------------------------------------------------------------


def _setup_duplicate_cve_build_dir(tmp_path: Path) -> Path:
    """Build dir where both cve-tracking and yocto-cve-check flag the same CVE.

    Seeds:
      - ``tmp/deploy/images/scan.sbom-cve-check.yocto.json`` consumed by
        cve-tracking. Contains an Unpatched finding for
        ``CVE-2024-1234`` on ``openssl-3.0.12``.
      - ``tmp/log/cve/cve-summary.json`` consumed by yocto-cve-check. Also
        flags ``CVE-2024-1234`` as Unpatched on ``openssl-3.0.12``.
    The SBOM fixture is needed so the sbom-generation check doesn't abort
    the run, and has no bearing on reconciliation.
    """
    build_dir = tmp_path / "build"
    build_dir.mkdir()

    spdx_dir = build_dir / "tmp" / "deploy" / "spdx"
    spdx_dir.mkdir(parents=True)
    shutil.copy(
        FIXTURES_DIR / "sbom" / "valid-spdx-2.3.json",
        spdx_dir / "image.spdx.json",
    )

    # cve-tracking input: Yocto sbom-cve-check format (nested package[*].issue[*])
    cve_tracking_payload = {
        "version": 1,
        "package": [
            {
                "name": "openssl",
                "version": "3.0.12",
                "issue": [
                    {
                        "id": "CVE-2024-1234",
                        "status": "Unpatched",
                        "scorev3": "7.5",
                        "summary": "Buffer overflow in TLS handshake",
                    }
                ],
            }
        ],
    }
    images_dir = build_dir / "tmp" / "deploy" / "images"
    images_dir.mkdir(parents=True)
    (images_dir / "scan.sbom-cve-check.yocto.json").write_text(json.dumps(cve_tracking_payload))

    # yocto-cve-check input: scarthgap flat issues[*]
    yocto_cve_payload = {
        "version": "2",
        "issues": [
            {
                "id": "CVE-2024-1234",
                "package": "openssl",
                "version": "3.0.12",
                "status": "Unpatched",
                "severity": "HIGH",
                "scorev3": "7.5",
                "summary": "Buffer overflow in TLS handshake",
            }
        ],
    }
    cve_log_dir = build_dir / "tmp" / "log" / "cve"
    cve_log_dir.mkdir(parents=True)
    (cve_log_dir / "cve-summary.json").write_text(json.dumps(yocto_cve_payload))

    return build_dir


@pytest.mark.integration
class TestCVEReconciliationEndToEnd:
    """Duplicate CVE findings across cve-tracking and yocto-cve-check merge.

    Covers the yocto-cve-check spec requirement "Reconciliation with existing
    CVE check" end-to-end: a CVE + package + version flagged by BOTH scanners
    must appear exactly once in the JSON report with ``sources`` unioning the
    two check ids.
    """

    def test_duplicate_cve_merges_into_single_finding(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        build_dir = _setup_duplicate_cve_build_dir(tmp_path)
        monkeypatch.chdir(tmp_path)

        result = _invoke_check(build_dir, fmt="json")
        assert result.exit_code == 0, result.output

        data = _read_json_report(result)

        # Flatten every finding across every check and pick the ones for our
        # target CVE/package/version triple.
        target = []
        for check_data in data["checks"]:
            for finding in check_data["findings"]:
                details = finding.get("details") or {}
                cve = details.get("cve") or details.get("cve_id")
                if (
                    cve == "CVE-2024-1234"
                    and details.get("package") == "openssl"
                    and details.get("version") == "3.0.12"
                ):
                    target.append(finding)

        assert len(target) == 1, (
            "Expected exactly one reconciled finding for "
            f"CVE-2024-1234/openssl/3.0.12, got {len(target)}: {target}"
        )

        merged = target[0]
        sources = set(merged.get("sources") or [])
        assert "cve-tracking" in sources, f"merged finding is missing cve-tracking source: {merged}"
        assert "yocto-cve-check" in sources, (
            f"merged finding is missing yocto-cve-check source: {merged}"
        )


# ---------------------------------------------------------------------------
# Pilot-0001 CVE discovery divergence regression (task 2.6)
# ---------------------------------------------------------------------------


def _write_yocto_summary_only_tree(build_dir: Path) -> Path:
    """Stage a build tree where cve-summary.json is the ONLY CVE evidence.

    No ``tmp/deploy/images/*.sbom-cve-check.yocto.json`` and no legacy
    ``*.rootfs.json`` / ``cve_check_summary*.json`` files exist, so both
    checks must fall through to ``tmp/log/cve/cve-summary.json`` via the
    shared :mod:`shipcheck.checks._cve_discovery` helper.

    The payload uses the Scarthgap flat ``issues[]`` shape and carries
    multiple unpatched CVEs so this fixture is distinct from the single-CVE
    fixture staged by task 2.3 under
    ``tests/fixtures/cve/yocto_summary_only/``.
    """
    cve_log_dir = build_dir / "tmp" / "log" / "cve"
    cve_log_dir.mkdir(parents=True)
    payload = {
        "version": "2",
        "issues": [
            {
                "id": "CVE-2024-9001",
                "package": "openssl",
                "version": "3.2.1",
                "status": "Unpatched",
                "severity": "HIGH",
                "scorev3": "7.5",
                "summary": "Null-deref in TLS handshake parser",
            },
            {
                "id": "CVE-2024-9002",
                "package": "busybox",
                "version": "1.36.1",
                "status": "Unpatched",
                "severity": "MEDIUM",
                "scorev3": "5.3",
                "summary": "Integer overflow in tar extraction",
            },
            {
                "id": "CVE-2024-9003",
                "package": "glibc",
                "version": "2.39",
                "status": "Unpatched",
                "severity": "HIGH",
                "scorev3": "7.8",
                "summary": "Heap OOB read in getaddrinfo",
            },
        ],
    }
    (cve_log_dir / "cve-summary.json").write_text(json.dumps(payload))
    return cve_log_dir / "cve-summary.json"


@pytest.mark.integration
class TestPilot0001CveDivergencePrevention:
    """Regression guard for the pilot-0001 divergence.

    Before , cve-tracking and yocto-cve-check disagreed on whether a
    Scarthgap build with only ``tmp/log/cve/cve-summary.json`` had CVE
    evidence: cve-tracking reported "No CVE scan output found" (FAIL) while
    yocto-cve-check happily parsed the same file.  Running both checks
    through the shared registry against that same tree must now yield
    non-empty findings for BOTH checks and both summaries must reference
    ``cve-summary.json`` so operators see the same evidence filename cited
    twice.  If this test breaks, the two checks have drifted again.
    """

    def test_pilot0001_cve_divergence_prevention(self, tmp_path: Path):
        from shipcheck.checks.registry import get_default_registry

        build_dir = tmp_path / "build"
        build_dir.mkdir()
        _write_yocto_summary_only_tree(build_dir)

        registry = get_default_registry()
        results = registry.run_checks(
            build_dir=build_dir,
            config={},
            check_ids=["cve-tracking", "yocto-cve-check"],
        )

        by_id = {r.check_id: r for r in results}
        assert set(by_id) == {"cve-tracking", "yocto-cve-check"}, (
            f"expected both CVE checks to run, got: {sorted(by_id)}"
        )

        cve_tracking = by_id["cve-tracking"]
        yocto_cve = by_id["yocto-cve-check"]

        # Both checks must produce findings - the whole point of the pilot
        # regression is that cve-tracking used to return zero findings and
        # FAIL while yocto-cve-check found the same file and emitted
        # findings.
        assert cve_tracking.findings, (
            f"cve-tracking produced no findings against cve-summary.json: "
            f"status={cve_tracking.status}, summary={cve_tracking.summary!r}"
        )
        assert yocto_cve.findings, (
            f"yocto-cve-check produced no findings against cve-summary.json: "
            f"status={yocto_cve.status}, summary={yocto_cve.summary!r}"
        )

        # Both summaries must name the same evidence file so the report
        # never shows divergent conclusions about the same input.
        assert "cve-summary.json" in cve_tracking.summary, (
            f"cve-tracking summary does not reference cve-summary.json: {cve_tracking.summary!r}"
        )
        assert "cve-summary.json" in yocto_cve.summary, (
            f"yocto-cve-check summary does not reference cve-summary.json: {yocto_cve.summary!r}"
        )

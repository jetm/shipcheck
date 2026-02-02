"""Tests for the shipcheck CLI check command."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from pathlib import Path
from typer.testing import CliRunner

from shipcheck.cli import app

runner = CliRunner()


@pytest.fixture()
def build_dir_with_spdx(tmp_path: Path) -> Path:
    """Create a minimal build dir with a valid SPDX 2.3 file."""
    spdx_dir = tmp_path / "tmp" / "deploy" / "spdx"
    spdx_dir.mkdir(parents=True)
    spdx_doc = {
        "spdxVersion": "SPDX-2.3",
        "creationInfo": {
            "created": "2026-01-01T00:00:00Z",
            "creators": ["Tool: shipcheck-test"],
        },
        "packages": [
            {
                "name": "test-pkg",
                "versionInfo": "1.0",
                "supplier": "Organization: TestCorp",
                "licenseDeclared": "Apache-2.0",
                "checksums": [{"algorithm": "SHA256", "checksumValue": "abc123"}],
            }
        ],
        "relationships": [
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relatedSpdxElement": "SPDXRef-Package",
                "relationshipType": "DESCRIBES",
            }
        ],
    }
    (spdx_dir / "image.spdx.json").write_text(json.dumps(spdx_doc))
    return tmp_path


@pytest.fixture()
def build_dir_empty(tmp_path: Path) -> Path:
    """Create a build dir with no check outputs (SPDX dir missing, no CVE output)."""
    tmp_path.mkdir(exist_ok=True)
    return tmp_path


class TestCheckCommand:
    """Tests for `shipcheck check`."""

    def test_check_produces_terminal_output(self, build_dir_with_spdx: Path) -> None:
        result = runner.invoke(app, ["check", "--build-dir", str(build_dir_with_spdx)])
        assert result.exit_code == 0
        assert "Readiness score" in result.output

    def test_check_writes_markdown_by_default(
        self, build_dir_with_spdx: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["check", "--build-dir", str(build_dir_with_spdx)])
        assert result.exit_code == 0
        report_path = tmp_path / "shipcheck-report.md"
        assert report_path.exists(), f"Expected {report_path} to be written"

    def test_check_writes_json_report(
        self, build_dir_with_spdx: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(
            app, ["check", "--build-dir", str(build_dir_with_spdx), "--format", "json"]
        )
        assert result.exit_code == 0
        report_path = tmp_path / "shipcheck-report.json"
        assert report_path.exists()
        data = json.loads(report_path.read_text())
        assert "readiness_score" in data
        assert "score" in data["readiness_score"]

    def test_check_writes_html_report(
        self, build_dir_with_spdx: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(
            app, ["check", "--build-dir", str(build_dir_with_spdx), "--format", "html"]
        )
        assert result.exit_code == 0
        report_path = tmp_path / "shipcheck-report.html"
        assert report_path.exists()
        content = report_path.read_text()
        assert "<html" in content

    def test_check_terminal_output_always_produced_with_json_format(
        self, build_dir_with_spdx: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(
            app, ["check", "--build-dir", str(build_dir_with_spdx), "--format", "json"]
        )
        assert result.exit_code == 0
        assert "Readiness score" in result.output

    def test_check_filters_checks(self, build_dir_with_spdx: Path) -> None:
        result = runner.invoke(
            app, ["check", "--build-dir", str(build_dir_with_spdx), "--checks", "sbom-generation"]
        )
        assert result.exit_code == 0
        assert "SBOM" in result.output

    def test_check_loads_config_file(
        self, build_dir_with_spdx: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        config_file = tmp_path / ".shipcheck.yaml"
        config_file.write_text(f"build_dir: {build_dir_with_spdx}\nreport:\n  format: json\n")
        result = runner.invoke(app, ["check", "--build-dir", str(build_dir_with_spdx)])
        assert result.exit_code == 0

    def test_check_cli_overrides_config(
        self, build_dir_with_spdx: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        config_file = tmp_path / ".shipcheck.yaml"
        config_file.write_text(f"build_dir: {build_dir_with_spdx}\nreport:\n  format: json\n")
        result = runner.invoke(
            app, ["check", "--build-dir", str(build_dir_with_spdx), "--format", "html"]
        )
        assert result.exit_code == 0
        assert (tmp_path / "shipcheck-report.html").exists()


class TestFailOn:
    """Tests for --fail-on exit code gating."""

    def test_no_fail_on_exits_zero_with_findings(self, build_dir_empty: Path) -> None:
        result = runner.invoke(app, ["check", "--build-dir", str(build_dir_empty)])
        assert result.exit_code == 0

    def test_fail_on_critical_exits_one_when_critical_findings(self, build_dir_empty: Path) -> None:
        result = runner.invoke(
            app, ["check", "--build-dir", str(build_dir_empty), "--fail-on", "critical"]
        )
        assert result.exit_code == 1

    def test_fail_on_critical_exits_zero_when_no_critical(self, build_dir_with_spdx: Path) -> None:
        result = runner.invoke(
            app,
            [
                "check",
                "--build-dir",
                str(build_dir_with_spdx),
                "--checks",
                "sbom-generation",
                "--fail-on",
                "critical",
            ],
        )
        # With valid SPDX, SBOM check should not have critical findings
        assert result.exit_code == 0

    def test_fail_on_low_exits_one_when_any_finding(self, build_dir_empty: Path) -> None:
        result = runner.invoke(
            app, ["check", "--build-dir", str(build_dir_empty), "--fail-on", "low"]
        )
        assert result.exit_code == 1

    def test_fail_on_high_exits_one_when_critical_exists(self, build_dir_empty: Path) -> None:
        result = runner.invoke(
            app, ["check", "--build-dir", str(build_dir_empty), "--fail-on", "high"]
        )
        assert result.exit_code == 1


class TestCheckErrors:
    """Tests for error handling in check command."""

    def test_missing_build_dir_arg_without_config(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["check"])
        assert result.exit_code != 0

    def test_invalid_format(self, build_dir_empty: Path) -> None:
        result = runner.invoke(
            app, ["check", "--build-dir", str(build_dir_empty), "--format", "xml"]
        )
        assert result.exit_code != 0

    def test_unknown_check_id(self, build_dir_empty: Path) -> None:
        result = runner.invoke(
            app, ["check", "--build-dir", str(build_dir_empty), "--checks", "nonexistent"]
        )
        assert result.exit_code != 0


class TestInitCommand:
    """Tests for `shipcheck init`."""

    def test_init_creates_config_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["init"])
        assert result.exit_code == 0
        config_path = tmp_path / ".shipcheck.yaml"
        assert config_path.exists(), "Expected .shipcheck.yaml to be created"

    def test_init_scaffold_contains_all_config_sections(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        runner.invoke(app, ["init"])
        content = (tmp_path / ".shipcheck.yaml").read_text()
        assert "build_dir" in content
        assert "framework" in content
        assert "checks" in content
        assert "sbom" in content
        assert "cve" in content
        assert "report" in content

    def test_init_scaffold_is_commented(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        runner.invoke(app, ["init"])
        content = (tmp_path / ".shipcheck.yaml").read_text()
        comment_lines = [line for line in content.splitlines() if line.startswith("#")]
        assert len(comment_lines) >= 5, "Scaffold should contain explanatory comments"

    def test_init_refuses_overwrite(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        existing = tmp_path / ".shipcheck.yaml"
        existing.write_text("build_dir: ./build\n")
        original_content = existing.read_text()

        result = runner.invoke(app, ["init"])
        assert result.exit_code == 0
        assert "already exists" in result.output
        assert existing.read_text() == original_content, "File content should not be modified"

    def test_init_prints_success_message(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["init"])
        assert ".shipcheck.yaml" in result.output

    def test_init_scaffold_contains_sbom_fields(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        runner.invoke(app, ["init"])
        content = (tmp_path / ".shipcheck.yaml").read_text()
        assert "required_fields" in content
        assert "supplier" in content
        assert "checksum" in content

    def test_init_scaffold_contains_cve_fields(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        runner.invoke(app, ["init"])
        content = (tmp_path / ".shipcheck.yaml").read_text()
        assert "suppress" in content

    def test_init_scaffold_contains_report_fields(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        runner.invoke(app, ["init"])
        content = (tmp_path / ".shipcheck.yaml").read_text()
        assert "format" in content
        assert "output" in content
        assert "fail_on" in content

    def test_init_scaffold_contains_secure_boot_section(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        runner.invoke(app, ["init"])
        content = (tmp_path / ".shipcheck.yaml").read_text()
        assert "secure_boot" in content
        assert "known_test_keys" in content

    def test_init_scaffold_contains_image_signing_section(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        runner.invoke(app, ["init"])
        content = (tmp_path / ".shipcheck.yaml").read_text()
        assert "image_signing" in content
        assert "expect_fit" in content
        assert "expect_verity" in content

    def test_init_scaffold_checks_list_includes_new_check_ids(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        runner.invoke(app, ["init"])
        content = (tmp_path / ".shipcheck.yaml").read_text()
        assert "secure-boot" in content
        assert "image-signing" in content


class TestBuildCheckConfig:
    """Tests for `_build_check_config()` mapping new check IDs."""

    def test_build_check_config_includes_secure_boot(self) -> None:
        from shipcheck.cli import _build_check_config
        from shipcheck.config import ShipcheckConfig

        config = ShipcheckConfig()
        result = _build_check_config(config)
        assert "secure-boot" in result

    def test_build_check_config_includes_image_signing(self) -> None:
        from shipcheck.cli import _build_check_config
        from shipcheck.config import ShipcheckConfig

        config = ShipcheckConfig()
        result = _build_check_config(config)
        assert "image-signing" in result

    def test_build_check_config_preserves_existing_checks(self) -> None:
        from shipcheck.cli import _build_check_config
        from shipcheck.config import ShipcheckConfig

        config = ShipcheckConfig()
        result = _build_check_config(config)
        assert "sbom-generation" in result
        assert "cve-tracking" in result

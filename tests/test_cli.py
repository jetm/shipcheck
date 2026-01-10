"""Tests for the shipcheck CLI check command."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
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

    def test_check_writes_markdown_by_default(self, build_dir_with_spdx: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["check", "--build-dir", str(build_dir_with_spdx)])
        assert result.exit_code == 0
        report_path = tmp_path / "shipcheck-report.md"
        assert report_path.exists(), f"Expected {report_path} to be written"

    def test_check_writes_json_report(self, build_dir_with_spdx: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["check", "--build-dir", str(build_dir_with_spdx), "--format", "json"])
        assert result.exit_code == 0
        report_path = tmp_path / "shipcheck-report.json"
        assert report_path.exists()
        data = json.loads(report_path.read_text())
        assert "readiness_score" in data
        assert "score" in data["readiness_score"]

    def test_check_writes_html_report(self, build_dir_with_spdx: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["check", "--build-dir", str(build_dir_with_spdx), "--format", "html"])
        assert result.exit_code == 0
        report_path = tmp_path / "shipcheck-report.html"
        assert report_path.exists()
        content = report_path.read_text()
        assert "<html" in content

    def test_check_terminal_output_always_produced_with_json_format(self, build_dir_with_spdx: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["check", "--build-dir", str(build_dir_with_spdx), "--format", "json"])
        assert result.exit_code == 0
        assert "Readiness score" in result.output

    def test_check_filters_checks(self, build_dir_with_spdx: Path) -> None:
        result = runner.invoke(app, ["check", "--build-dir", str(build_dir_with_spdx), "--checks", "sbom-generation"])
        assert result.exit_code == 0
        assert "SBOM" in result.output

    def test_check_loads_config_file(self, build_dir_with_spdx: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        config_file = tmp_path / ".shipcheck.yaml"
        config_file.write_text(f"build_dir: {build_dir_with_spdx}\nreport:\n  format: json\n")
        result = runner.invoke(app, ["check", "--build-dir", str(build_dir_with_spdx)])
        assert result.exit_code == 0

    def test_check_cli_overrides_config(self, build_dir_with_spdx: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        config_file = tmp_path / ".shipcheck.yaml"
        config_file.write_text(f"build_dir: {build_dir_with_spdx}\nreport:\n  format: json\n")
        result = runner.invoke(app, ["check", "--build-dir", str(build_dir_with_spdx), "--format", "html"])
        assert result.exit_code == 0
        assert (tmp_path / "shipcheck-report.html").exists()


class TestFailOn:
    """Tests for --fail-on exit code gating."""

    def test_no_fail_on_exits_zero_with_findings(self, build_dir_empty: Path) -> None:
        result = runner.invoke(app, ["check", "--build-dir", str(build_dir_empty)])
        assert result.exit_code == 0

    def test_fail_on_critical_exits_one_when_critical_findings(self, build_dir_empty: Path) -> None:
        result = runner.invoke(app, ["check", "--build-dir", str(build_dir_empty), "--fail-on", "critical"])
        assert result.exit_code == 1

    def test_fail_on_critical_exits_zero_when_no_critical(self, build_dir_with_spdx: Path) -> None:
        result = runner.invoke(app, ["check", "--build-dir", str(build_dir_with_spdx), "--checks", "sbom-generation", "--fail-on", "critical"])
        # With valid SPDX, SBOM check should not have critical findings
        assert result.exit_code == 0

    def test_fail_on_low_exits_one_when_any_finding(self, build_dir_empty: Path) -> None:
        result = runner.invoke(app, ["check", "--build-dir", str(build_dir_empty), "--fail-on", "low"])
        assert result.exit_code == 1

    def test_fail_on_high_exits_one_when_critical_exists(self, build_dir_empty: Path) -> None:
        result = runner.invoke(app, ["check", "--build-dir", str(build_dir_empty), "--fail-on", "high"])
        assert result.exit_code == 1


class TestCheckErrors:
    """Tests for error handling in check command."""

    def test_missing_build_dir_arg_without_config(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["check"])
        assert result.exit_code != 0

    def test_invalid_format(self, build_dir_empty: Path) -> None:
        result = runner.invoke(app, ["check", "--build-dir", str(build_dir_empty), "--format", "xml"])
        assert result.exit_code != 0

    def test_unknown_check_id(self, build_dir_empty: Path) -> None:
        result = runner.invoke(app, ["check", "--build-dir", str(build_dir_empty), "--checks", "nonexistent"])
        assert result.exit_code != 0

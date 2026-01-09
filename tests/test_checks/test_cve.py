"""Tests for CVE scan output discovery logic."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

from shipcheck.checks.cve import CVECheck, _discover_cve_output
from shipcheck.models import CheckStatus


def _write_cve_json(path: Path, data: dict | None = None) -> Path:
    """Write a CVE JSON file at the given path."""
    if data is None:
        data = {"version": 1, "package": []}
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data))
    return path


# --- Discovery tests ---


class TestDiscoverCveOutput:
    """Tests for _discover_cve_output priority-based glob search."""

    def test_discovery_sbom_cve_check_format_first(self, tmp_path: Path) -> None:
        """sbom-cve-check format is preferred when multiple formats exist."""
        images_dir = tmp_path / "tmp" / "deploy" / "images"
        _write_cve_json(images_dir / "core-image.sbom-cve-check.yocto.json")
        _write_cve_json(images_dir / "core-image.rootfs.json")
        _write_cve_json(images_dir / "qemux86-64" / "cve_check_summary.json")

        result = _discover_cve_output(tmp_path)
        assert result is not None
        assert result.name == "core-image.sbom-cve-check.yocto.json"

    def test_discovery_vex_bbclass_second(self, tmp_path: Path) -> None:
        """vex.bbclass format is used when sbom-cve-check is absent."""
        images_dir = tmp_path / "tmp" / "deploy" / "images"
        _write_cve_json(images_dir / "core-image.rootfs.json")
        _write_cve_json(images_dir / "qemux86-64" / "cve_check_summary.json")

        result = _discover_cve_output(tmp_path)
        assert result is not None
        assert result.name == "core-image.rootfs.json"

    def test_discovery_legacy_cve_check_third(self, tmp_path: Path) -> None:
        """Legacy cve-check summary is used as last resort."""
        images_dir = tmp_path / "tmp" / "deploy" / "images"
        sub = images_dir / "qemux86-64"
        _write_cve_json(sub / "cve_check_summary.json")

        result = _discover_cve_output(tmp_path)
        assert result is not None
        assert result.name == "cve_check_summary.json"

    def test_discovery_legacy_glob_star(self, tmp_path: Path) -> None:
        """Legacy pattern matches cve_check_summary with suffix (e.g. date)."""
        images_dir = tmp_path / "tmp" / "deploy" / "images"
        sub = images_dir / "qemux86-64"
        _write_cve_json(sub / "cve_check_summary_20260401.json")

        result = _discover_cve_output(tmp_path)
        assert result is not None
        assert "cve_check_summary" in result.name

    def test_discovery_returns_none_when_empty(self, tmp_path: Path) -> None:
        """Returns None when no CVE output files exist."""
        images_dir = tmp_path / "tmp" / "deploy" / "images"
        images_dir.mkdir(parents=True)

        result = _discover_cve_output(tmp_path)
        assert result is None

    def test_discovery_returns_none_when_no_images_dir(self, tmp_path: Path) -> None:
        """Returns None when images directory does not exist."""
        result = _discover_cve_output(tmp_path)
        assert result is None

    def test_discovery_first_match_within_pattern(self, tmp_path: Path) -> None:
        """When multiple files match the same pattern, returns the first (sorted)."""
        images_dir = tmp_path / "tmp" / "deploy" / "images"
        _write_cve_json(images_dir / "alpha.sbom-cve-check.yocto.json")
        _write_cve_json(images_dir / "beta.sbom-cve-check.yocto.json")

        result = _discover_cve_output(tmp_path)
        assert result is not None
        assert result.name == "alpha.sbom-cve-check.yocto.json"


class TestCVECheckDiscovery:
    """Integration tests for CVECheck.run discovery behavior."""

    def test_discovery_no_output_returns_fail(self, tmp_path: Path) -> None:
        """Check returns FAIL with score 0 when no CVE output found."""
        check = CVECheck()
        result = check.run(tmp_path, {})

        assert result.status == CheckStatus.FAIL
        assert result.score == 0
        assert len(result.findings) >= 1
        finding = result.findings[0]
        assert finding.severity == "critical"
        assert "inherit cve-check" in finding.remediation

    def test_discovery_finds_sbom_cve_check(self, tmp_path: Path) -> None:
        """Check successfully discovers and parses sbom-cve-check output."""
        images_dir = tmp_path / "tmp" / "deploy" / "images"
        _write_cve_json(
            images_dir / "image.sbom-cve-check.yocto.json",
            {"version": 1, "package": [{"name": "pkg", "version": "1.0", "issue": []}]},
        )

        check = CVECheck()
        result = check.run(tmp_path, {})

        assert result.status == CheckStatus.PASS
        assert result.score == 50

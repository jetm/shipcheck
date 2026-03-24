"""Unit tests for :mod:`shipcheck.checks._cve_discovery`.

Covers the four discovery scenarios from spec ``cve-check``:

- "sbom-cve-check output found" -> priority-1 glob match.
- "Legacy cve-check output found" -> priority-2 and priority-3 glob fallbacks.
- "cve-check.bbclass aggregate summary found" -> priority-4 fallback when no
  output exists under ``tmp/deploy/images/``.
- "No CVE scan output found" -> ``None`` when nothing matches at any tier.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from shipcheck.checks._cve_discovery import (
    CVE_DISCOVERY_PATTERNS,
    CVE_SUMMARY_RELPATH,
    IMAGES_SUBDIR,
    discover_cve_output,
)

if TYPE_CHECKING:
    from pathlib import Path


def _write_json(path: Path, data: dict | None = None) -> Path:
    """Create ``path`` (and parents) containing a minimal JSON document."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data if data is not None else {"version": 1}))
    return path


# --- CVE_DISCOVERY_PATTERNS shape -----------------------------------------


class TestCveDiscoveryPatterns:
    """The public priority-order constant must stay stable for callers."""

    def test_pattern_count(self) -> None:
        """Four tiers: three image globs plus the aggregate summary."""
        assert len(CVE_DISCOVERY_PATTERNS) == 4

    def test_pattern_priority_order(self) -> None:
        """Priority 1 = sbom-cve-check, then rootfs, then legacy, then summary."""
        expected = (
            f"{IMAGES_SUBDIR}/*.sbom-cve-check.yocto.json",
            f"{IMAGES_SUBDIR}/*.rootfs.json",
            f"{IMAGES_SUBDIR}/*/cve_check_summary*.json",
            CVE_SUMMARY_RELPATH,
        )
        assert expected == CVE_DISCOVERY_PATTERNS

    def test_aggregate_summary_relpath(self) -> None:
        """Tier 4 points at the cve-check.bbclass aggregate summary."""
        assert CVE_SUMMARY_RELPATH == "tmp/log/cve/cve-summary.json"


# --- Scenario: sbom-cve-check output found --------------------------------


class TestDiscoverSbomCveCheck:
    """Priority-1 glob: ``tmp/deploy/images/*.sbom-cve-check.yocto.json``."""

    def test_returns_sbom_cve_check_match(self, tmp_path: Path) -> None:
        """An sbom-cve-check file is returned when present."""
        images = tmp_path / IMAGES_SUBDIR
        target = _write_json(images / "core-image.sbom-cve-check.yocto.json")

        result = discover_cve_output(tmp_path)

        assert result == target

    def test_prefers_sbom_cve_check_over_all_lower_tiers(self, tmp_path: Path) -> None:
        """Priority-1 wins over rootfs, legacy, and aggregate summary."""
        images = tmp_path / IMAGES_SUBDIR
        sbom = _write_json(images / "core-image.sbom-cve-check.yocto.json")
        _write_json(images / "core-image.rootfs.json")
        _write_json(images / "qemux86-64" / "cve_check_summary.json")
        _write_json(tmp_path / CVE_SUMMARY_RELPATH)

        result = discover_cve_output(tmp_path)

        assert result == sbom

    def test_picks_first_sorted_when_multiple_sbom_files(self, tmp_path: Path) -> None:
        """Multiple matches within the same tier resolve by sorted order."""
        images = tmp_path / IMAGES_SUBDIR
        _write_json(images / "zzz-image.sbom-cve-check.yocto.json")
        _write_json(images / "aaa-image.sbom-cve-check.yocto.json")

        result = discover_cve_output(tmp_path)

        assert result is not None
        assert result.name == "aaa-image.sbom-cve-check.yocto.json"


# --- Scenario: Legacy cve-check output found ------------------------------


class TestDiscoverLegacyCveCheck:
    """Priority 2 and 3: ``*.rootfs.json`` and ``*/cve_check_summary*.json``."""

    def test_falls_back_to_rootfs_json(self, tmp_path: Path) -> None:
        """Rootfs JSON is used when sbom-cve-check is absent."""
        images = tmp_path / IMAGES_SUBDIR
        target = _write_json(images / "core-image.rootfs.json")
        _write_json(images / "qemux86-64" / "cve_check_summary.json")

        result = discover_cve_output(tmp_path)

        assert result == target

    def test_falls_back_to_legacy_summary(self, tmp_path: Path) -> None:
        """Legacy ``cve_check_summary.json`` is used when tiers 1-2 are absent."""
        images = tmp_path / IMAGES_SUBDIR
        target = _write_json(images / "qemux86-64" / "cve_check_summary.json")

        result = discover_cve_output(tmp_path)

        assert result == target

    def test_legacy_glob_matches_suffixed_summary(self, tmp_path: Path) -> None:
        """Priority-3 glob matches ``cve_check_summary_<suffix>.json`` too."""
        images = tmp_path / IMAGES_SUBDIR
        target = _write_json(images / "qemux86-64" / "cve_check_summary_20260401.json")

        result = discover_cve_output(tmp_path)

        assert result == target

    def test_prefers_legacy_over_aggregate_summary(self, tmp_path: Path) -> None:
        """Any ``tmp/deploy/images/`` match outranks the aggregate summary."""
        images = tmp_path / IMAGES_SUBDIR
        legacy = _write_json(images / "qemux86-64" / "cve_check_summary.json")
        _write_json(tmp_path / CVE_SUMMARY_RELPATH)

        result = discover_cve_output(tmp_path)

        assert result == legacy


# --- Scenario: cve-check.bbclass aggregate summary found ------------------


class TestDiscoverAggregateSummary:
    """Priority-4 fallback: ``tmp/log/cve/cve-summary.json``."""

    def test_returns_aggregate_summary_when_images_missing(self, tmp_path: Path) -> None:
        """No ``tmp/deploy/images/`` directory -> the aggregate summary wins."""
        target = _write_json(tmp_path / CVE_SUMMARY_RELPATH)

        result = discover_cve_output(tmp_path)

        assert result == target

    def test_returns_aggregate_summary_when_images_dir_empty(self, tmp_path: Path) -> None:
        """``tmp/deploy/images/`` exists but matches nothing -> tier 4 fires."""
        (tmp_path / IMAGES_SUBDIR).mkdir(parents=True)
        target = _write_json(tmp_path / CVE_SUMMARY_RELPATH)

        result = discover_cve_output(tmp_path)

        assert result == target

    def test_aggregate_summary_path_matches_constant(self, tmp_path: Path) -> None:
        """The returned path is rooted at ``CVE_SUMMARY_RELPATH``."""
        _write_json(tmp_path / CVE_SUMMARY_RELPATH)

        result = discover_cve_output(tmp_path)

        assert result is not None
        assert result == tmp_path / CVE_SUMMARY_RELPATH


# --- Scenario: No CVE scan output found -----------------------------------


class TestDiscoverNoOutput:
    """``None`` when no evidence exists at any tier."""

    def test_returns_none_for_empty_build_dir(self, tmp_path: Path) -> None:
        """Completely empty build directory -> ``None``."""
        assert discover_cve_output(tmp_path) is None

    def test_returns_none_when_images_dir_empty_and_no_summary(self, tmp_path: Path) -> None:
        """``tmp/deploy/images/`` exists but is empty and no aggregate summary."""
        (tmp_path / IMAGES_SUBDIR).mkdir(parents=True)

        assert discover_cve_output(tmp_path) is None

    def test_returns_none_when_summary_is_directory(self, tmp_path: Path) -> None:
        """The aggregate-summary tier requires a *file*, not a directory."""
        (tmp_path / CVE_SUMMARY_RELPATH).mkdir(parents=True)

        assert discover_cve_output(tmp_path) is None

    def test_returns_none_when_only_unrelated_files_present(self, tmp_path: Path) -> None:
        """Files under ``tmp/deploy/images/`` that match no pattern are ignored."""
        images = tmp_path / IMAGES_SUBDIR
        _write_json(images / "unrelated.json")
        _write_json(images / "some-image.manifest")

        assert discover_cve_output(tmp_path) is None

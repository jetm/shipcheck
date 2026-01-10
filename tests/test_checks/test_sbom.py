"""Tests for SBOM file discovery logic."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from pathlib import Path

from shipcheck.checks.sbom import (
    SBOMCheck,
    _detect_format,
    _discover_spdx_files,
    _has_describes,
    _load_spdx_docs,
    _package_count,
    _select_document,
    _validate_spdx2_metadata,
    _validate_spdx2_packages,
)
from shipcheck.models import CheckStatus


def _make_compliant_package(name: str = "pkg1") -> dict:
    """Build a fully compliant SPDX 2.3 package entry."""
    return {
        "SPDXID": f"SPDXRef-Package-{name}",
        "name": name,
        "versionInfo": "1.0.0",
        "supplier": f"Organization: {name}-org (contact@example.com)",
        "licenseDeclared": "MIT",
        "checksums": [
            {"algorithm": "SHA256", "checksumValue": "abc123" * 10},
        ],
    }


def _make_spdx_doc(
    *,
    packages: list[dict] | None = None,
    has_describes: bool = False,
    spdx_version: str = "SPDX-2.3",
) -> dict:
    """Build a minimal SPDX 2.3 JSON document for testing."""
    if packages is None:
        packages = [_make_compliant_package("pkg1")]

    relationships = []
    if has_describes:
        relationships.append(
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": "SPDXRef-Package-pkg1",
            }
        )

    return {
        "spdxVersion": spdx_version,
        "SPDXID": "SPDXRef-DOCUMENT",
        "creationInfo": {
            "created": "2026-01-01T00:00:00Z",
            "creators": ["Tool: shipcheck-test"],
        },
        "packages": packages,
        "relationships": relationships,
    }


def _write_spdx(path: Path, doc: dict) -> Path:
    """Write an SPDX JSON document to a file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc))
    return path


@pytest.fixture
def sbom_check() -> SBOMCheck:
    return SBOMCheck()


# --- Unit tests for helper functions ---


class TestDiscoverSpdxFiles:
    """Unit tests for _discover_spdx_files."""

    def test_returns_empty_when_dir_missing(self, tmp_path: Path):
        assert _discover_spdx_files(tmp_path) == []

    def test_returns_empty_when_dir_empty(self, tmp_path: Path):
        (tmp_path / "tmp" / "deploy" / "spdx").mkdir(parents=True)
        assert _discover_spdx_files(tmp_path) == []

    def test_finds_spdx_json_files(self, tmp_path: Path):
        spdx_dir = tmp_path / "tmp" / "deploy" / "spdx"
        _write_spdx(spdx_dir / "image.spdx.json", _make_spdx_doc())
        result = _discover_spdx_files(tmp_path)
        assert len(result) == 1
        assert result[0].name == "image.spdx.json"

    def test_finds_nested_files(self, tmp_path: Path):
        spdx_dir = tmp_path / "tmp" / "deploy" / "spdx"
        _write_spdx(spdx_dir / "arm" / "core-image.spdx.json", _make_spdx_doc())
        _write_spdx(spdx_dir / "recipe.spdx.json", _make_spdx_doc())
        result = _discover_spdx_files(tmp_path)
        assert len(result) == 2

    def test_ignores_non_spdx_json(self, tmp_path: Path):
        spdx_dir = tmp_path / "tmp" / "deploy" / "spdx"
        spdx_dir.mkdir(parents=True)
        (spdx_dir / "readme.txt").write_text("not spdx")
        (spdx_dir / "data.json").write_text("{}")
        _write_spdx(spdx_dir / "image.spdx.json", _make_spdx_doc())
        result = _discover_spdx_files(tmp_path)
        assert len(result) == 1


class TestLoadSpdxDocs:
    """Unit tests for _load_spdx_docs."""

    def test_loads_valid_json(self, tmp_path: Path):
        path = tmp_path / "valid.spdx.json"
        doc = _make_spdx_doc()
        path.write_text(json.dumps(doc))
        result = _load_spdx_docs([path])
        assert len(result) == 1
        assert result[0][1]["spdxVersion"] == "SPDX-2.3"

    def test_skips_invalid_json(self, tmp_path: Path):
        bad = tmp_path / "bad.spdx.json"
        bad.write_text("{broken json")
        good = tmp_path / "good.spdx.json"
        good.write_text(json.dumps(_make_spdx_doc()))
        result = _load_spdx_docs([bad, good])
        assert len(result) == 1

    def test_skips_non_dict_json(self, tmp_path: Path):
        path = tmp_path / "array.spdx.json"
        path.write_text("[1, 2, 3]")
        result = _load_spdx_docs([path])
        assert len(result) == 0


class TestHasDescribes:
    """Unit tests for _has_describes."""

    def test_true_when_describes_present(self):
        doc = _make_spdx_doc(has_describes=True)
        assert _has_describes(doc) is True

    def test_false_when_no_describes(self):
        doc = _make_spdx_doc(has_describes=False)
        assert _has_describes(doc) is False

    def test_false_when_no_relationships_key(self):
        assert _has_describes({}) is False

    def test_false_for_other_relationship_types(self):
        doc = {
            "relationships": [
                {
                    "spdxElementId": "SPDXRef-DOCUMENT",
                    "relationshipType": "CONTAINS",
                    "relatedSpdxElement": "SPDXRef-Package-pkg1",
                }
            ]
        }
        assert _has_describes(doc) is False


class TestPackageCount:
    """Unit tests for _package_count."""

    def test_counts_packages(self):
        doc = _make_spdx_doc(packages=[{"name": f"pkg{i}"} for i in range(5)])
        assert _package_count(doc) == 5

    def test_zero_when_no_packages_key(self):
        assert _package_count({}) == 0

    def test_zero_when_packages_not_list(self):
        assert _package_count({"packages": "invalid"}) == 0


class TestSelectDocument:
    """Unit tests for _select_document."""

    def test_returns_none_for_empty_list(self):
        assert _select_document([]) is None

    def test_returns_single_doc(self, tmp_path: Path):
        doc = _make_spdx_doc()
        path = tmp_path / "only.spdx.json"
        result = _select_document([(path, doc)])
        assert result is not None
        assert result[0] == path

    def test_prefers_describes_over_larger(self, tmp_path: Path):
        large = _make_spdx_doc(
            packages=[{"name": f"pkg{i}"} for i in range(10)],
            has_describes=False,
        )
        small_image = _make_spdx_doc(
            packages=[{"name": "img1"}, {"name": "img2"}],
            has_describes=True,
        )
        large_path = tmp_path / "large.spdx.json"
        image_path = tmp_path / "image.spdx.json"
        result = _select_document([(large_path, large), (image_path, small_image)])
        assert result is not None
        assert result[0] == image_path

    def test_falls_back_to_most_packages(self, tmp_path: Path):
        small = _make_spdx_doc(packages=[{"name": "s1"}], has_describes=False)
        large = _make_spdx_doc(
            packages=[{"name": f"l{i}"} for i in range(5)],
            has_describes=False,
        )
        small_path = tmp_path / "small.spdx.json"
        large_path = tmp_path / "large.spdx.json"
        result = _select_document([(small_path, small), (large_path, large)])
        assert result is not None
        assert result[0] == large_path

    def test_largest_image_doc_when_multiple_describes(self, tmp_path: Path):
        img1 = _make_spdx_doc(packages=[{"name": "a"}], has_describes=True)
        img2 = _make_spdx_doc(
            packages=[{"name": "b1"}, {"name": "b2"}, {"name": "b3"}],
            has_describes=True,
        )
        p1 = tmp_path / "img1.spdx.json"
        p2 = tmp_path / "img2.spdx.json"
        result = _select_document([(p1, img1), (p2, img2)])
        assert result is not None
        assert result[0] == p2


# --- Integration tests for SBOMCheck.run discovery behavior ---


class TestDiscoveryMissingDirectory:
    """SPDX directory does not exist -> FAIL with critical finding."""

    def test_returns_fail(self, tmp_path: Path, sbom_check: SBOMCheck):
        result = sbom_check.run(tmp_path, {})
        assert result.status == CheckStatus.FAIL

    def test_has_critical_finding(self, tmp_path: Path, sbom_check: SBOMCheck):
        result = sbom_check.run(tmp_path, {})
        assert len(result.findings) == 1
        assert result.findings[0].severity == "critical"

    def test_has_remediation_mentioning_spdx(self, tmp_path: Path, sbom_check: SBOMCheck):
        result = sbom_check.run(tmp_path, {})
        assert result.findings[0].remediation is not None
        assert "create-spdx" in result.findings[0].remediation

    def test_score_is_zero(self, tmp_path: Path, sbom_check: SBOMCheck):
        result = sbom_check.run(tmp_path, {})
        assert result.score == 0


class TestDiscoveryEmptyDirectory:
    """SPDX directory exists but contains no .spdx.json files -> FAIL."""

    def test_returns_fail(self, tmp_path: Path, sbom_check: SBOMCheck):
        (tmp_path / "tmp" / "deploy" / "spdx").mkdir(parents=True)
        result = sbom_check.run(tmp_path, {})
        assert result.status == CheckStatus.FAIL

    def test_has_critical_finding(self, tmp_path: Path, sbom_check: SBOMCheck):
        (tmp_path / "tmp" / "deploy" / "spdx").mkdir(parents=True)
        result = sbom_check.run(tmp_path, {})
        assert len(result.findings) == 1
        assert result.findings[0].severity == "critical"

    def test_score_is_zero(self, tmp_path: Path, sbom_check: SBOMCheck):
        (tmp_path / "tmp" / "deploy" / "spdx").mkdir(parents=True)
        result = sbom_check.run(tmp_path, {})
        assert result.score == 0


class TestDiscoveryImageLevelSelection:
    """When multiple SPDX files exist, select the one with DESCRIBES relationship."""

    def test_summary_reflects_image_doc_packages(self, tmp_path: Path, sbom_check: SBOMCheck):
        spdx_dir = tmp_path / "tmp" / "deploy" / "spdx"
        _write_spdx(spdx_dir / "recipe.spdx.json", _make_spdx_doc(has_describes=False))
        _write_spdx(
            spdx_dir / "image.spdx.json",
            _make_spdx_doc(
                packages=[{"name": f"pkg{i}"} for i in range(3)],
                has_describes=True,
            ),
        )
        result = sbom_check.run(tmp_path, {})
        assert "3 packages" in result.summary

    def test_image_doc_preferred_over_larger_recipe(self, tmp_path: Path, sbom_check: SBOMCheck):
        spdx_dir = tmp_path / "tmp" / "deploy" / "spdx"
        _write_spdx(
            spdx_dir / "recipe-big.spdx.json",
            _make_spdx_doc(
                packages=[{"name": f"r{i}"} for i in range(10)],
                has_describes=False,
            ),
        )
        _write_spdx(
            spdx_dir / "image-small.spdx.json",
            _make_spdx_doc(
                packages=[{"name": "img1"}, {"name": "img2"}],
                has_describes=True,
            ),
        )
        result = sbom_check.run(tmp_path, {})
        assert "2 packages" in result.summary
        assert "image-small.spdx.json" in result.summary


class TestDiscoveryFallbackMostPackages:
    """When no doc has DESCRIBES, fall back to the one with most packages."""

    def test_summary_reflects_largest_doc(self, tmp_path: Path, sbom_check: SBOMCheck):
        spdx_dir = tmp_path / "tmp" / "deploy" / "spdx"
        _write_spdx(
            spdx_dir / "small.spdx.json",
            _make_spdx_doc(packages=[{"name": "s1"}], has_describes=False),
        )
        _write_spdx(
            spdx_dir / "large.spdx.json",
            _make_spdx_doc(
                packages=[{"name": f"l{i}"} for i in range(5)],
                has_describes=False,
            ),
        )
        result = sbom_check.run(tmp_path, {})
        assert "5 packages" in result.summary
        assert "large.spdx.json" in result.summary


class TestDiscoverySingleFile:
    """Single SPDX file is used directly without failure."""

    def test_single_file_passes_discovery(self, tmp_path: Path, sbom_check: SBOMCheck):
        spdx_dir = tmp_path / "tmp" / "deploy" / "spdx"
        _write_spdx(spdx_dir / "image.spdx.json", _make_spdx_doc(has_describes=True))
        result = sbom_check.run(tmp_path, {})
        assert result.status == CheckStatus.PASS
        assert result.score > 0
        assert "image.spdx.json" in result.summary


class TestDiscoveryNestedFiles:
    """Files in subdirectories of spdx/ are found via ** glob."""

    def test_finds_files_in_subdirectories(self, tmp_path: Path, sbom_check: SBOMCheck):
        spdx_dir = tmp_path / "tmp" / "deploy" / "spdx"
        _write_spdx(spdx_dir / "arm" / "image.spdx.json", _make_spdx_doc(has_describes=True))
        result = sbom_check.run(tmp_path, {})
        assert result.status == CheckStatus.PASS
        assert result.score > 0


class TestDiscoveryInvalidJson:
    """Files that are not valid JSON are skipped gracefully."""

    def test_invalid_json_skipped_valid_used(self, tmp_path: Path, sbom_check: SBOMCheck):
        spdx_dir = tmp_path / "tmp" / "deploy" / "spdx"
        spdx_dir.mkdir(parents=True)
        (spdx_dir / "broken.spdx.json").write_text("{invalid json")
        _write_spdx(spdx_dir / "valid.spdx.json", _make_spdx_doc(has_describes=True))
        result = sbom_check.run(tmp_path, {})
        assert result.status == CheckStatus.PASS
        assert "valid.spdx.json" in result.summary

    def test_all_invalid_json_returns_fail(self, tmp_path: Path, sbom_check: SBOMCheck):
        spdx_dir = tmp_path / "tmp" / "deploy" / "spdx"
        spdx_dir.mkdir(parents=True)
        (spdx_dir / "broken.spdx.json").write_text("{invalid json")
        result = sbom_check.run(tmp_path, {})
        assert result.status == CheckStatus.FAIL
        assert result.findings[0].severity == "critical"


# --- Unit tests for format detection ---


class TestDetectFormat:
    """Unit tests for _detect_format."""

    def test_spdx_2x_detected_by_spdx_version(self):
        doc = {"spdxVersion": "SPDX-2.3"}
        assert _detect_format(doc) == "spdx-2"

    def test_spdx_2x_detects_any_2x_variant(self):
        doc = {"spdxVersion": "SPDX-2.2"}
        assert _detect_format(doc) == "spdx-2"

    def test_spdx_3_detected_by_context(self):
        doc = {"@context": "https://spdx.org/rdf/3.0.0/terms"}
        assert _detect_format(doc) == "spdx-3"

    def test_spdx_3_context_substring_match(self):
        doc = {"@context": "https://spdx.org/rdf/3.0.1/terms"}
        assert _detect_format(doc) == "spdx-3"

    def test_cyclonedx_detected_by_bom_format(self):
        doc = {"bomFormat": "CycloneDX"}
        assert _detect_format(doc) == "cyclonedx"

    def test_unrecognized_format(self):
        doc = {"some": "random", "json": "doc"}
        assert _detect_format(doc) is None

    def test_spdx_2_takes_priority_over_context(self):
        doc = {"spdxVersion": "SPDX-2.3", "@context": "https://spdx.org/rdf/3.0.0/terms"}
        assert _detect_format(doc) == "spdx-2"

    def test_spdx_version_must_start_with_spdx_2(self):
        doc = {"spdxVersion": "SPDX-3.0"}
        assert _detect_format(doc) != "spdx-2"


# --- Integration tests for format detection in SBOMCheck.run ---


def _make_spdx3_doc() -> dict:
    """Build a minimal SPDX 3.0 JSON-LD document."""
    return {
        "@context": "https://spdx.org/rdf/3.0.0/terms",
        "@graph": [
            {
                "type": "SpdxDocument",
                "name": "test-image",
                "creationInfo": {"specVersion": "3.0.0"},
            }
        ],
    }


def _make_cyclonedx_doc() -> dict:
    """Build a minimal CycloneDX 1.5 document."""
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [{"type": "library", "name": "test-pkg", "version": "1.0"}],
    }


class TestFormatDetectionSpdx2:
    """SPDX 2.x document triggers full validation path (task 2.4 adds validation)."""

    def test_spdx_2_format_detected(self, tmp_path: Path, sbom_check: SBOMCheck):
        spdx_dir = tmp_path / "tmp" / "deploy" / "spdx"
        _write_spdx(spdx_dir / "image.spdx.json", _make_spdx_doc(has_describes=True))
        result = sbom_check.run(tmp_path, {})
        assert "SPDX 2" in result.summary

    def test_spdx_2_status_not_fail_for_valid_doc(self, tmp_path: Path, sbom_check: SBOMCheck):
        spdx_dir = tmp_path / "tmp" / "deploy" / "spdx"
        _write_spdx(spdx_dir / "image.spdx.json", _make_spdx_doc(has_describes=True))
        result = sbom_check.run(tmp_path, {})
        assert result.status != CheckStatus.FAIL


class TestFormatDetectionSpdx3:
    """SPDX 3.0 document gets detection-only: PASS with note, score 10."""

    def test_spdx_3_passes_with_note(self, tmp_path: Path, sbom_check: SBOMCheck):
        spdx_dir = tmp_path / "tmp" / "deploy" / "spdx"
        _write_spdx(spdx_dir / "image.spdx.json", _make_spdx3_doc())
        result = sbom_check.run(tmp_path, {})
        assert result.status == CheckStatus.PASS
        assert "not fully validated" in result.summary

    def test_spdx_3_scores_10(self, tmp_path: Path, sbom_check: SBOMCheck):
        spdx_dir = tmp_path / "tmp" / "deploy" / "spdx"
        _write_spdx(spdx_dir / "image.spdx.json", _make_spdx3_doc())
        result = sbom_check.run(tmp_path, {})
        assert result.score == 10

    def test_spdx_3_no_findings(self, tmp_path: Path, sbom_check: SBOMCheck):
        spdx_dir = tmp_path / "tmp" / "deploy" / "spdx"
        _write_spdx(spdx_dir / "image.spdx.json", _make_spdx3_doc())
        result = sbom_check.run(tmp_path, {})
        assert result.findings == []


class TestFormatDetectionCycloneDX:
    """CycloneDX document gets detection-only: PASS with note, score 10."""

    def test_cyclonedx_passes_with_note(self, tmp_path: Path, sbom_check: SBOMCheck):
        spdx_dir = tmp_path / "tmp" / "deploy" / "spdx"
        _write_spdx(spdx_dir / "image.spdx.json", _make_cyclonedx_doc())
        result = sbom_check.run(tmp_path, {})
        assert result.status == CheckStatus.PASS
        assert "not fully validated" in result.summary

    def test_cyclonedx_scores_10(self, tmp_path: Path, sbom_check: SBOMCheck):
        spdx_dir = tmp_path / "tmp" / "deploy" / "spdx"
        _write_spdx(spdx_dir / "image.spdx.json", _make_cyclonedx_doc())
        result = sbom_check.run(tmp_path, {})
        assert result.score == 10

    def test_cyclonedx_no_findings(self, tmp_path: Path, sbom_check: SBOMCheck):
        spdx_dir = tmp_path / "tmp" / "deploy" / "spdx"
        _write_spdx(spdx_dir / "image.spdx.json", _make_cyclonedx_doc())
        result = sbom_check.run(tmp_path, {})
        assert result.findings == []


class TestFormatDetectionUnrecognized:
    """Unrecognized format produces a high-severity finding."""

    def test_unrecognized_format_returns_fail(self, tmp_path: Path, sbom_check: SBOMCheck):
        spdx_dir = tmp_path / "tmp" / "deploy" / "spdx"
        _write_spdx(spdx_dir / "image.spdx.json", {"some": "unknown", "format": "data"})
        result = sbom_check.run(tmp_path, {})
        assert result.status == CheckStatus.FAIL

    def test_unrecognized_format_has_high_finding(self, tmp_path: Path, sbom_check: SBOMCheck):
        spdx_dir = tmp_path / "tmp" / "deploy" / "spdx"
        _write_spdx(spdx_dir / "image.spdx.json", {"some": "unknown", "format": "data"})
        result = sbom_check.run(tmp_path, {})
        assert len(result.findings) == 1
        assert result.findings[0].severity == "high"

    def test_unrecognized_format_score(self, tmp_path: Path, sbom_check: SBOMCheck):
        spdx_dir = tmp_path / "tmp" / "deploy" / "spdx"
        _write_spdx(spdx_dir / "image.spdx.json", {"some": "unknown", "format": "data"})
        result = sbom_check.run(tmp_path, {})
        assert result.score == 0


class TestFormatDetectionWithFixtures:
    """Test format detection using the real fixture files."""

    @pytest.fixture
    def fixtures_dir(self) -> Path:
        from pathlib import Path

        return Path(__file__).parent.parent / "fixtures" / "sbom"

    def test_spdx_23_fixture(self, tmp_path: Path, sbom_check: SBOMCheck, fixtures_dir: Path):
        import shutil

        spdx_dir = tmp_path / "tmp" / "deploy" / "spdx"
        spdx_dir.mkdir(parents=True)
        shutil.copy(fixtures_dir / "valid-spdx-2.3.json", spdx_dir / "image.spdx.json")
        result = sbom_check.run(tmp_path, {})
        assert "SPDX 2" in result.summary
        assert result.status != CheckStatus.FAIL or any(
            f.severity in ("critical", "high") for f in result.findings
        )

    def test_spdx_30_fixture(self, tmp_path: Path, sbom_check: SBOMCheck, fixtures_dir: Path):
        import shutil

        spdx_dir = tmp_path / "tmp" / "deploy" / "spdx"
        spdx_dir.mkdir(parents=True)
        shutil.copy(fixtures_dir / "valid-spdx-3.0.json", spdx_dir / "image.spdx.json")
        result = sbom_check.run(tmp_path, {})
        assert result.score == 10
        assert "not fully validated" in result.summary

    def test_cyclonedx_fixture(self, tmp_path: Path, sbom_check: SBOMCheck, fixtures_dir: Path):
        import shutil

        spdx_dir = tmp_path / "tmp" / "deploy" / "spdx"
        spdx_dir.mkdir(parents=True)
        shutil.copy(fixtures_dir / "valid-cyclonedx-1.5.json", spdx_dir / "image.spdx.json")
        result = sbom_check.run(tmp_path, {})
        assert result.score == 10
        assert "not fully validated" in result.summary


# --- Unit tests for SPDX 2.3 field validation ---


class TestValidateSpdx2Metadata:
    """Unit tests for _validate_spdx2_metadata."""

    def test_valid_metadata_no_findings(self):
        doc = _make_spdx_doc(has_describes=True)
        findings = _validate_spdx2_metadata(doc)
        assert findings == []

    def test_missing_creation_info(self):
        doc = _make_spdx_doc(has_describes=True)
        del doc["creationInfo"]
        findings = _validate_spdx2_metadata(doc)
        assert len(findings) == 1
        assert findings[0].severity == "medium"
        assert "creationInfo" in findings[0].message

    def test_missing_created_timestamp(self):
        doc = _make_spdx_doc(has_describes=True)
        del doc["creationInfo"]["created"]
        findings = _validate_spdx2_metadata(doc)
        assert len(findings) == 1
        assert findings[0].severity == "medium"
        msg = findings[0].message.lower()
        assert "timestamp" in msg or "created" in msg

    def test_missing_creators(self):
        doc = _make_spdx_doc(has_describes=True)
        del doc["creationInfo"]["creators"]
        findings = _validate_spdx2_metadata(doc)
        assert len(findings) == 1
        assert findings[0].severity == "medium"

    def test_empty_creators(self):
        doc = _make_spdx_doc(has_describes=True)
        doc["creationInfo"]["creators"] = []
        findings = _validate_spdx2_metadata(doc)
        assert len(findings) == 1
        assert findings[0].severity == "medium"

    def test_missing_packages(self):
        doc = _make_spdx_doc(has_describes=True)
        doc["packages"] = []
        findings = _validate_spdx2_metadata(doc)
        assert any("packages" in f.message.lower() for f in findings)
        pkg_finding = [f for f in findings if "packages" in f.message.lower()][0]
        assert pkg_finding.severity == "medium"

    def test_no_describes_relationship(self):
        doc = _make_spdx_doc(has_describes=False)
        findings = _validate_spdx2_metadata(doc)
        assert any("DESCRIBES" in f.message for f in findings)
        describes_finding = [f for f in findings if "DESCRIBES" in f.message][0]
        assert describes_finding.severity == "medium"

    def test_multiple_metadata_issues(self):
        doc = _make_spdx_doc(has_describes=False)
        del doc["creationInfo"]
        doc["packages"] = []
        findings = _validate_spdx2_metadata(doc)
        assert len(findings) == 3


class TestValidateSpdx2Packages:
    """Unit tests for _validate_spdx2_packages."""

    def test_compliant_package_no_findings(self):
        packages = [_make_compliant_package("busybox")]
        findings, compliant_count = _validate_spdx2_packages(packages)
        assert findings == []
        assert compliant_count == 1

    def test_missing_name(self):
        pkg = _make_compliant_package()
        del pkg["name"]
        findings, compliant_count = _validate_spdx2_packages([pkg])
        assert len(findings) == 1
        assert findings[0].severity == "low"
        assert compliant_count == 0

    def test_missing_version_info(self):
        pkg = _make_compliant_package()
        del pkg["versionInfo"]
        findings, compliant_count = _validate_spdx2_packages([pkg])
        assert len(findings) == 1
        assert findings[0].severity == "low"
        assert compliant_count == 0

    def test_noassertion_supplier(self):
        pkg = _make_compliant_package()
        pkg["supplier"] = "NOASSERTION"
        findings, compliant_count = _validate_spdx2_packages([pkg])
        assert len(findings) == 1
        assert findings[0].severity == "low"
        assert "supplier" in findings[0].message.lower()
        assert compliant_count == 0

    def test_missing_supplier(self):
        pkg = _make_compliant_package()
        del pkg["supplier"]
        findings, compliant_count = _validate_spdx2_packages([pkg])
        assert len(findings) == 1
        assert findings[0].severity == "low"
        assert compliant_count == 0

    def test_noassertion_license_declared(self):
        pkg = _make_compliant_package()
        pkg["licenseDeclared"] = "NOASSERTION"
        findings, compliant_count = _validate_spdx2_packages([pkg])
        assert len(findings) == 1
        assert findings[0].severity == "low"
        assert "license" in findings[0].message.lower()
        assert compliant_count == 0

    def test_missing_license_declared(self):
        pkg = _make_compliant_package()
        del pkg["licenseDeclared"]
        findings, compliant_count = _validate_spdx2_packages([pkg])
        assert len(findings) == 1
        assert compliant_count == 0

    def test_empty_checksums(self):
        pkg = _make_compliant_package()
        pkg["checksums"] = []
        findings, compliant_count = _validate_spdx2_packages([pkg])
        assert len(findings) == 1
        assert findings[0].severity == "low"
        assert "checksum" in findings[0].message.lower()
        assert compliant_count == 0

    def test_missing_checksums(self):
        pkg = _make_compliant_package()
        del pkg["checksums"]
        findings, compliant_count = _validate_spdx2_packages([pkg])
        assert len(findings) == 1
        assert compliant_count == 0

    def test_multiple_issues_per_package(self):
        pkg = _make_compliant_package()
        pkg["supplier"] = "NOASSERTION"
        pkg["licenseDeclared"] = "NOASSERTION"
        pkg["checksums"] = []
        findings, compliant_count = _validate_spdx2_packages([pkg])
        assert len(findings) == 3
        assert compliant_count == 0

    def test_mixed_packages(self):
        good = _make_compliant_package("good")
        bad = _make_compliant_package("bad")
        bad["supplier"] = "NOASSERTION"
        findings, compliant_count = _validate_spdx2_packages([good, bad])
        assert len(findings) == 1
        assert compliant_count == 1

    def test_finding_includes_package_name(self):
        pkg = _make_compliant_package("busybox")
        pkg["supplier"] = "NOASSERTION"
        findings, _ = _validate_spdx2_packages([pkg])
        assert "busybox" in findings[0].message

    def test_multiple_packages_all_compliant(self):
        pkgs = [_make_compliant_package(f"pkg{i}") for i in range(5)]
        findings, compliant_count = _validate_spdx2_packages(pkgs)
        assert findings == []
        assert compliant_count == 5


# --- Integration tests for SPDX 2.3 validation in SBOMCheck.run ---


class TestValidationFullyCompliantDoc:
    """Fully compliant SPDX 2.3 document produces PASS with score 50."""

    def test_status_is_pass(self, tmp_path: Path, sbom_check: SBOMCheck):
        spdx_dir = tmp_path / "tmp" / "deploy" / "spdx"
        doc = _make_spdx_doc(
            packages=[_make_compliant_package(f"pkg{i}") for i in range(3)],
            has_describes=True,
        )
        _write_spdx(spdx_dir / "image.spdx.json", doc)
        result = sbom_check.run(tmp_path, {})
        assert result.status == CheckStatus.PASS

    def test_no_findings(self, tmp_path: Path, sbom_check: SBOMCheck):
        spdx_dir = tmp_path / "tmp" / "deploy" / "spdx"
        doc = _make_spdx_doc(
            packages=[_make_compliant_package(f"pkg{i}") for i in range(3)],
            has_describes=True,
        )
        _write_spdx(spdx_dir / "image.spdx.json", doc)
        result = sbom_check.run(tmp_path, {})
        assert result.findings == []


class TestValidationMissingMetadata:
    """Missing creationInfo produces medium finding."""

    def test_missing_creation_info_warns(self, tmp_path: Path, sbom_check: SBOMCheck):
        spdx_dir = tmp_path / "tmp" / "deploy" / "spdx"
        doc = _make_spdx_doc(has_describes=True)
        del doc["creationInfo"]
        _write_spdx(spdx_dir / "image.spdx.json", doc)
        result = sbom_check.run(tmp_path, {})
        assert result.status == CheckStatus.WARN
        assert any(f.severity == "medium" for f in result.findings)

    def test_missing_creators_warns(self, tmp_path: Path, sbom_check: SBOMCheck):
        spdx_dir = tmp_path / "tmp" / "deploy" / "spdx"
        doc = _make_spdx_doc(has_describes=True)
        doc["creationInfo"]["creators"] = []
        _write_spdx(spdx_dir / "image.spdx.json", doc)
        result = sbom_check.run(tmp_path, {})
        assert result.status == CheckStatus.WARN


class TestValidationMissingDescribes:
    """Missing DESCRIBES relationship produces medium finding."""

    def test_no_describes_warns(self, tmp_path: Path, sbom_check: SBOMCheck):
        spdx_dir = tmp_path / "tmp" / "deploy" / "spdx"
        doc = _make_spdx_doc(has_describes=False)
        _write_spdx(spdx_dir / "image.spdx.json", doc)
        result = sbom_check.run(tmp_path, {})
        assert result.status == CheckStatus.WARN
        assert any("DESCRIBES" in f.message for f in result.findings)


class TestValidationPackageIssues:
    """Per-package field issues produce low-severity findings."""

    def test_noassertion_supplier_low_finding(self, tmp_path: Path, sbom_check: SBOMCheck):
        spdx_dir = tmp_path / "tmp" / "deploy" / "spdx"
        pkg = _make_compliant_package("busybox")
        pkg["supplier"] = "NOASSERTION"
        doc = _make_spdx_doc(packages=[pkg], has_describes=True)
        _write_spdx(spdx_dir / "image.spdx.json", doc)
        result = sbom_check.run(tmp_path, {})
        assert result.status == CheckStatus.WARN
        assert any(f.severity == "low" for f in result.findings)

    def test_empty_checksums_low_finding(self, tmp_path: Path, sbom_check: SBOMCheck):
        spdx_dir = tmp_path / "tmp" / "deploy" / "spdx"
        pkg = _make_compliant_package("busybox")
        pkg["checksums"] = []
        doc = _make_spdx_doc(packages=[pkg], has_describes=True)
        _write_spdx(spdx_dir / "image.spdx.json", doc)
        result = sbom_check.run(tmp_path, {})
        assert any(f.severity == "low" for f in result.findings)

    def test_noassertion_license_low_finding(self, tmp_path: Path, sbom_check: SBOMCheck):
        spdx_dir = tmp_path / "tmp" / "deploy" / "spdx"
        pkg = _make_compliant_package("openssl")
        pkg["licenseDeclared"] = "NOASSERTION"
        doc = _make_spdx_doc(packages=[pkg], has_describes=True)
        _write_spdx(spdx_dir / "image.spdx.json", doc)
        result = sbom_check.run(tmp_path, {})
        assert any(f.severity == "low" for f in result.findings)


class TestValidationWithFixtures:
    """Integration tests using real fixture files."""

    @pytest.fixture
    def fixtures_dir(self) -> Path:
        from pathlib import Path

        return Path(__file__).parent.parent / "fixtures" / "sbom"

    def test_valid_spdx_23_passes(self, tmp_path: Path, sbom_check: SBOMCheck, fixtures_dir: Path):
        import shutil

        spdx_dir = tmp_path / "tmp" / "deploy" / "spdx"
        spdx_dir.mkdir(parents=True)
        shutil.copy(fixtures_dir / "valid-spdx-2.3.json", spdx_dir / "image.spdx.json")
        result = sbom_check.run(tmp_path, {})
        assert result.status == CheckStatus.PASS
        assert result.findings == []

    def test_missing_supplier_fixture_warns(
        self, tmp_path: Path, sbom_check: SBOMCheck, fixtures_dir: Path
    ):
        import shutil

        spdx_dir = tmp_path / "tmp" / "deploy" / "spdx"
        spdx_dir.mkdir(parents=True)
        shutil.copy(fixtures_dir / "missing-supplier.json", spdx_dir / "image.spdx.json")
        result = sbom_check.run(tmp_path, {})
        assert result.status == CheckStatus.WARN
        assert any(f.severity == "low" and "supplier" in f.message.lower() for f in result.findings)

    def test_missing_checksum_fixture_warns(
        self, tmp_path: Path, sbom_check: SBOMCheck, fixtures_dir: Path
    ):
        import shutil

        spdx_dir = tmp_path / "tmp" / "deploy" / "spdx"
        spdx_dir.mkdir(parents=True)
        shutil.copy(fixtures_dir / "missing-checksum.json", spdx_dir / "image.spdx.json")
        result = sbom_check.run(tmp_path, {})
        assert result.status == CheckStatus.WARN
        assert any(
            f.severity == "low" and "checksum" in f.message.lower() for f in result.findings
        )

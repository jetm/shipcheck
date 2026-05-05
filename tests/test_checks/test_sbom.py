"""Tests for SBOM file discovery logic."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from shipcheck.checks.sbom import (
    SPDX3_FIELD_ALIASES,
    SBOMCheck,
    _detect_format,
    _discover_spdx_files,
    _has_describes,
    _load_spdx_docs,
    _package_count,
    _select_best_document,
    _select_document,
    _select_spdx3_document,
    _validate_spdx2_metadata,
    _validate_spdx2_packages,
    _validate_spdx3_metadata,
    _validate_spdx3_packages,
    _validate_spdx3_root_element,
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

    def test_detect_format_v3_by_creation_info_spec_version(self):
        doc = {
            "@graph": [
                {"type": "CreationInfo", "specVersion": "3.0.0"},
            ],
        }
        assert _detect_format(doc) == "spdx-3"

    def test_detect_format_v3_via_at_type_key(self):
        doc = {
            "@graph": [
                {"@type": "CreationInfo", "specVersion": "3.0.1"},
            ],
        }
        assert _detect_format(doc) == "spdx-3"

    def test_detect_format_v3_via_namespaced_creation_info_type(self):
        doc = {
            "@graph": [
                {"type": "core_CreationInfo", "specVersion": "3.0.0"},
            ],
        }
        assert _detect_format(doc) == "spdx-3"

    def test_detect_format_v3_unknown_minor_still_detects(self):
        doc = {
            "@graph": [
                {"type": "CreationInfo", "specVersion": "3.1.0"},
            ],
        }
        assert _detect_format(doc) == "spdx-3"

    def test_cyclonedx_detected_by_bom_format(self):
        doc = {"bomFormat": "CycloneDX"}
        assert _detect_format(doc) == "cyclonedx"

    def test_unrecognized_format(self):
        doc = {"some": "random", "json": "doc"}
        assert _detect_format(doc) is None

    def test_spdx_2_takes_priority_over_graph(self):
        doc = {
            "spdxVersion": "SPDX-2.3",
            "@graph": [{"type": "CreationInfo", "specVersion": "3.0.0"}],
        }
        assert _detect_format(doc) == "spdx-2"

    def test_spdx_version_must_start_with_spdx_2(self):
        doc = {"spdxVersion": "SPDX-3.0"}
        assert _detect_format(doc) != "spdx-2"

    def test_detect_format_v3_not_detected_when_graph_missing(self):
        doc = {"@context": "https://spdx.org/rdf/3.0.0/terms"}
        assert _detect_format(doc) is None

    def test_detect_format_v3_not_detected_when_graph_empty(self):
        doc = {"@graph": []}
        assert _detect_format(doc) is None

    def test_detect_format_v3_not_detected_without_creation_info_element(self):
        doc = {
            "@graph": [
                {"type": "software_Package", "name": "busybox"},
            ],
        }
        assert _detect_format(doc) is None

    def test_detect_format_v3_not_detected_when_spec_version_missing(self):
        doc = {
            "@graph": [
                {"type": "CreationInfo"},
            ],
        }
        assert _detect_format(doc) is None

    def test_detect_format_v3_not_detected_when_spec_version_is_2x(self):
        doc = {
            "@graph": [
                {"type": "CreationInfo", "specVersion": "2.3"},
            ],
        }
        assert _detect_format(doc) is None

    def test_detect_format_v3_spdx_2x_doc_not_detected_as_3(self):
        doc = {"spdxVersion": "SPDX-2.3", "packages": [{"name": "x"}]}
        assert _detect_format(doc) != "spdx-3"


# --- Integration tests for format detection in SBOMCheck.run ---


def _make_spdx3_doc() -> dict:
    """Build a minimal valid SPDX 3.0 JSON-LD document.

    Carries a top-level `CreationInfo` Element with `specVersion="3.0.0"`
    plus a `Sbom` Element whose `rootElement` resolves by `spdxId` to the
    embedded `software_Package`. After task 4.1 lands, this document is
    structurally complete enough to score full metadata + rootElement
    points (10 + 5 + 5 = 20), with the per-Package portion still pending
    task 5.1.
    """
    return {
        "@context": "https://spdx.org/rdf/3.0.0/terms",
        "@graph": [
            {
                "type": "CreationInfo",
                "specVersion": "3.0.0",
                "created": "2026-01-01T00:00:00Z",
                "createdBy": ["urn:spdx:agent-test"],
            },
            {
                "type": "Sbom",
                "spdxId": "urn:spdx:sbom-test",
                "rootElement": ["urn:spdx:package-test"],
            },
            {
                "type": "software_Package",
                "spdxId": "urn:spdx:package-test",
                "name": "test-image",
            },
        ],
    }


def _make_cyclonedx_doc() -> dict:
    """Build a minimal CycloneDX 1.5 document."""
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [{"type": "library", "name": "test-pkg", "version": "1.0"}],
    }


class TestSpdx3FieldAliases:
    """Module-level SPDX3_FIELD_ALIASES constant must match the spec."""

    def test_field_aliases_keys_are_canonical(self):
        assert set(SPDX3_FIELD_ALIASES.keys()) == {
            "name",
            "version",
            "supplier",
            "license",
            "checksums",
        }

    def test_name_alias_tuple(self):
        assert SPDX3_FIELD_ALIASES["name"] == ("name",)

    def test_version_alias_priority(self):
        assert SPDX3_FIELD_ALIASES["version"] == (
            "software_packageVersion",
            "versionInfo",
            "packageVersion",
        )

    def test_supplier_alias_priority(self):
        assert SPDX3_FIELD_ALIASES["supplier"] == ("suppliedBy", "supplier")

    def test_license_alias_priority(self):
        assert SPDX3_FIELD_ALIASES["license"] == (
            "software_declaredLicense",
            "licenseDeclared",
        )

    def test_checksums_alias_priority(self):
        assert SPDX3_FIELD_ALIASES["checksums"] == ("verifiedUsing", "checksums")


class TestDetectFormatV3WithGenerator:
    """`_detect_format` against the synthetic Yocto-shaped fixture."""

    def test_detect_format_v3_yocto_shaped_fixture(self):
        from tests.fixtures.spdx3.generator import build_yocto_shaped_spdx3

        doc = build_yocto_shaped_spdx3()
        assert _detect_format(doc) == "spdx-3"


class TestSelectBestDocumentV3:
    """`_select_best_document` routes SPDX 3.0 docs through the v3 selector."""

    @staticmethod
    def _make_spdx3_with_archive_root(image_name: str = "rootfs-a") -> dict:
        """Build a tiny SPDX 3.0 doc whose Sbom rootElement resolves to an archive Package."""
        pkg_id = f"urn:spdx:package-{image_name}"
        return {
            "@graph": [
                {"type": "CreationInfo", "specVersion": "3.0.0"},
                {
                    "type": "Sbom",
                    "spdxId": f"urn:spdx:sbom-{image_name}",
                    "rootElement": [pkg_id],
                },
                {
                    "type": "software_Package",
                    "spdxId": pkg_id,
                    "name": image_name,
                    "software_primaryPurpose": "archive",
                },
            ],
        }

    @staticmethod
    def _make_spdx3_with_install_root(name: str = "non-rootfs") -> dict:
        """Build a SPDX 3.0 doc whose Sbom rootElement is an install Package (not an archive)."""
        pkg_id = f"urn:spdx:package-{name}"
        return {
            "@graph": [
                {"type": "CreationInfo", "specVersion": "3.0.0"},
                {
                    "type": "Sbom",
                    "spdxId": f"urn:spdx:sbom-{name}",
                    "rootElement": [pkg_id],
                },
                {
                    "type": "software_Package",
                    "spdxId": pkg_id,
                    "name": name,
                    "software_primaryPurpose": "install",
                },
                {
                    "type": "software_Package",
                    "spdxId": "urn:spdx:package-extra",
                    "name": "extra",
                    "software_primaryPurpose": "install",
                },
            ],
        }

    def test_select_best_document_v3_returns_none_when_no_docs(self):
        assert _select_best_document([]) is None

    def test_select_best_document_v3_routes_single_spdx3_doc(self, tmp_path: Path):
        doc = self._make_spdx3_with_archive_root("img")
        path = tmp_path / "img.spdx.json"
        result = _select_best_document([(path, doc)])
        assert result is not None
        assert result == (path, doc)

    def test_select_best_document_v3_archive_primary_purpose_wins_tiebreak(self, tmp_path: Path):
        archive_doc = self._make_spdx3_with_archive_root("rootfs-a")
        install_doc = self._make_spdx3_with_install_root("not-an-image")
        archive_path = tmp_path / "archive.spdx.json"
        install_path = tmp_path / "install.spdx.json"

        result = _select_best_document([(install_path, install_doc), (archive_path, archive_doc)])
        assert result is not None
        assert result[0] == archive_path

    def test_select_best_document_v3_falls_back_to_package_count_when_no_archive(
        self, tmp_path: Path
    ):
        small = self._make_spdx3_with_install_root("small")
        # Strip the extra package so `small` has 1 software_Package.
        small["@graph"] = [element for element in small["@graph"] if element.get("name") != "extra"]
        large = self._make_spdx3_with_install_root("large")  # has 2 software_Packages
        small_path = tmp_path / "small.spdx.json"
        large_path = tmp_path / "large.spdx.json"

        result = _select_spdx3_document([(small_path, small), (large_path, large)])
        assert result is not None
        assert result[0] == large_path

    def test_select_best_document_v3_routes_spdx2_docs_through_legacy_selector(
        self, tmp_path: Path
    ):
        spdx2_doc = _make_spdx_doc(has_describes=True)
        path = tmp_path / "spdx2.spdx.json"
        result = _select_best_document([(path, spdx2_doc)])
        assert result is not None
        assert result == (path, spdx2_doc)

    def test_select_best_document_v3_prefers_spdx3_when_both_formats_present(self, tmp_path: Path):
        spdx2_doc = _make_spdx_doc(has_describes=True)
        spdx3_doc = self._make_spdx3_with_archive_root("img")
        spdx2_path = tmp_path / "spdx2.spdx.json"
        spdx3_path = tmp_path / "spdx3.spdx.json"
        result = _select_best_document([(spdx2_path, spdx2_doc), (spdx3_path, spdx3_doc)])
        assert result is not None
        assert result[0] == spdx3_path

    def test_select_best_document_v3_unresolved_root_element_falls_to_package_count(
        self, tmp_path: Path
    ):
        # Sbom points at a spdxId that does not exist; should not be picked as image.
        broken = {
            "@graph": [
                {"type": "CreationInfo", "specVersion": "3.0.0"},
                {
                    "type": "Sbom",
                    "spdxId": "urn:spdx:sbom-broken",
                    "rootElement": ["urn:spdx:does-not-exist"],
                },
                {
                    "type": "software_Package",
                    "spdxId": "urn:spdx:package-x",
                    "name": "x",
                    "software_primaryPurpose": "install",
                },
            ],
        }
        archive_doc = self._make_spdx3_with_archive_root("real")
        broken_path = tmp_path / "broken.spdx.json"
        archive_path = tmp_path / "archive.spdx.json"
        result = _select_best_document([(broken_path, broken), (archive_path, archive_doc)])
        assert result is not None
        assert result[0] == archive_path

    def test_select_best_document_v3_namespaced_sbom_type_recognized(self, tmp_path: Path):
        doc = {
            "@graph": [
                {"type": "CreationInfo", "specVersion": "3.0.1"},
                {
                    "type": "software_Sbom",
                    "spdxId": "urn:spdx:sbom-namespaced",
                    "rootElement": ["urn:spdx:package-namespaced"],
                },
                {
                    "type": "software_Package",
                    "spdxId": "urn:spdx:package-namespaced",
                    "name": "namespaced",
                    "software_primaryPurpose": "archive",
                },
            ],
        }
        other = self._make_spdx3_with_install_root("other")
        path_ns = tmp_path / "namespaced.spdx.json"
        path_other = tmp_path / "other.spdx.json"
        result = _select_best_document([(path_other, other), (path_ns, doc)])
        assert result is not None
        assert result[0] == path_ns


class TestDetectFormatV3WithFixtureGenerator:
    """Round-trip via the synthetic Yocto-shaped fixture from task 1.2."""

    def test_select_best_document_v3_with_generator_fixture(self, tmp_path: Path):
        from tests.fixtures.spdx3.generator import build_yocto_shaped_spdx3

        doc = build_yocto_shaped_spdx3()
        path = tmp_path / "yocto.spdx.json"
        result = _select_best_document([(path, doc)])
        assert result is not None
        assert result[0] == path


class TestValidateSpdx3Metadata:
    """`_validate_spdx3_metadata` enforces CreationInfo `created` + `createdBy`.

    Required-field set is sourced from `audits/0003-spdx3-mapping/mapping.md`
    (group 2 of the v2.1.0 -> 3.0 mapping).
    """

    def test_validate_spdx3_metadata_both_fields_present_awards_5_points(self):
        doc = {
            "@graph": [
                {
                    "type": "CreationInfo",
                    "specVersion": "3.0.1",
                    "created": "2026-04-30T12:00:00Z",
                    "createdBy": [
                        "urn:spdx:agent-shipcheck",
                        "urn:spdx:tool-bitbake",
                    ],
                },
            ],
        }
        delta, findings = _validate_spdx3_metadata(doc)
        assert delta == 5
        assert findings == []

    def test_validate_spdx3_metadata_namespaced_type_recognized(self):
        # Use the namespaced `core_CreationInfo` form. Should also award 5.
        doc = {
            "@graph": [
                {
                    "type": "core_CreationInfo",
                    "specVersion": "3.0.1",
                    "created": "2026-04-30T12:00:00Z",
                    "createdBy": ["urn:spdx:agent-x"],
                },
            ],
        }
        delta, findings = _validate_spdx3_metadata(doc)
        assert delta == 5
        assert findings == []

    def test_validate_spdx3_metadata_missing_created_produces_medium_finding(self):
        doc = {
            "@graph": [
                {
                    "type": "CreationInfo",
                    "specVersion": "3.0.1",
                    "createdBy": ["urn:spdx:agent-shipcheck"],
                },
            ],
        }
        delta, findings = _validate_spdx3_metadata(doc)
        assert delta == 0
        assert len(findings) == 1
        assert findings[0].severity == "medium"
        assert "created" in findings[0].message
        assert "I.P2.1" in findings[0].cra_mapping
        assert "VII.2" in findings[0].cra_mapping
        # Validator MUST cite the audit mapping doc per design.md D4.
        assert "audits/0003-spdx3-mapping/mapping.md" in findings[0].message

    def test_validate_spdx3_metadata_empty_created_by_produces_medium_finding(self):
        doc = {
            "@graph": [
                {
                    "type": "CreationInfo",
                    "specVersion": "3.0.1",
                    "created": "2026-04-30T12:00:00Z",
                    "createdBy": [],
                },
            ],
        }
        delta, findings = _validate_spdx3_metadata(doc)
        assert delta == 0
        assert len(findings) == 1
        assert findings[0].severity == "medium"
        assert "createdBy" in findings[0].message
        assert "I.P2.1" in findings[0].cra_mapping
        assert "VII.2" in findings[0].cra_mapping

    def test_validate_spdx3_metadata_no_creation_info_produces_medium_finding(self):
        # Edge case: empty graph means no CreationInfo Element at all.
        doc = {"@graph": []}
        delta, findings = _validate_spdx3_metadata(doc)
        assert delta == 0
        assert len(findings) == 1
        assert findings[0].severity == "medium"
        assert "CreationInfo" in findings[0].message


class TestValidateSpdx3SbomRootElement:
    """`_validate_spdx3_root_element` enforces a resolvable Sbom.rootElement.

    Required field is sourced from `audits/0003-spdx3-mapping/mapping.md`
    (group 2 of the v2.1.0 -> 3.0 mapping, DESCRIBES row).
    """

    def test_validate_sbom_rootelement_resolves_cleanly_awards_5_points(self):
        doc = {
            "@graph": [
                {"type": "CreationInfo", "specVersion": "3.0.1"},
                {
                    "type": "Sbom",
                    "spdxId": "urn:spdx:sbom-image",
                    "rootElement": ["urn:spdx:package-rootfs"],
                },
                {
                    "type": "software_Package",
                    "spdxId": "urn:spdx:package-rootfs",
                    "name": "rootfs",
                },
            ],
        }
        delta, findings = _validate_spdx3_root_element(doc)
        assert delta == 5
        assert findings == []

    def test_validate_sbom_rootelement_namespaced_software_sbom_recognized(self):
        # Use the namespaced `software_Sbom` form to confirm both type aliases work.
        doc = {
            "@graph": [
                {"type": "core_CreationInfo", "specVersion": "3.0.1"},
                {
                    "type": "software_Sbom",
                    "spdxId": "urn:spdx:sbom-namespaced",
                    "rootElement": ["urn:spdx:package-namespaced"],
                },
                {
                    "type": "software_Package",
                    "spdxId": "urn:spdx:package-namespaced",
                    "name": "namespaced",
                },
            ],
        }
        delta, findings = _validate_spdx3_root_element(doc)
        assert delta == 5
        assert findings == []

    def test_validate_sbom_rootelement_no_sbom_produces_high_finding(self):
        # Document has Packages and a CreationInfo but no Sbom Element.
        doc = {
            "@graph": [
                {"type": "CreationInfo", "specVersion": "3.0.1"},
                {
                    "type": "software_Package",
                    "spdxId": "urn:spdx:package-x",
                    "name": "x",
                },
            ],
        }
        delta, findings = _validate_spdx3_root_element(doc)
        assert delta == 0
        assert len(findings) == 1
        assert findings[0].severity == "high"
        assert "no Sbom" in findings[0].message
        assert "I.P2.1" in findings[0].cra_mapping
        assert "VII.2" in findings[0].cra_mapping
        # Validator MUST cite the audit mapping doc.
        assert "audits/0003-spdx3-mapping/mapping.md" in findings[0].message

    def test_validate_sbom_rootelement_empty_list_produces_high_finding(self):
        doc = {
            "@graph": [
                {"type": "CreationInfo", "specVersion": "3.0.1"},
                {
                    "type": "Sbom",
                    "spdxId": "urn:spdx:sbom-empty",
                    "rootElement": [],
                },
            ],
        }
        delta, findings = _validate_spdx3_root_element(doc)
        assert delta == 0
        assert len(findings) == 1
        assert findings[0].severity == "high"
        assert "rootElement" in findings[0].message

    def test_validate_sbom_rootelement_unresolved_spdxid_produces_high_finding(self):
        doc = {
            "@graph": [
                {"type": "CreationInfo", "specVersion": "3.0.1"},
                {
                    "type": "Sbom",
                    "spdxId": "urn:spdx:sbom-broken",
                    "rootElement": ["urn:spdx:does-not-exist"],
                },
                {
                    "type": "software_Package",
                    "spdxId": "urn:spdx:package-other",
                    "name": "other",
                },
            ],
        }
        delta, findings = _validate_spdx3_root_element(doc)
        assert delta == 0
        assert len(findings) == 1
        assert findings[0].severity == "high"
        assert "resolve" in findings[0].message.lower()


def _make_compliant_spdx3_package(
    name: str = "pkg1",
    *,
    version_alias: str = "software_packageVersion",
) -> dict:
    """Build a fully compliant SPDX 3.0 software_Package Element.

    All five required logical fields (name, version, supplier, license,
    checksums) carry non-empty values via canonical-name aliases.
    """
    pkg = {
        "type": "software_Package",
        "spdxId": f"urn:spdx:package-{name}",
        "name": name,
        "suppliedBy": "urn:spdx:agent-vendor",
        "software_declaredLicense": "MIT",
        "verifiedUsing": [
            {"algorithm": "sha256", "hashValue": "abc123" * 10},
        ],
    }
    pkg[version_alias] = "1.2.3"
    return pkg


def _make_spdx3_doc_with_packages(packages: list[dict]) -> dict:
    """Build a structurally valid SPDX 3.0 doc with the given Packages.

    The first Package is referenced by the Sbom's rootElement so the
    metadata + rootElement validators score 5 + 5.
    """
    root_id = packages[0]["spdxId"] if packages else "urn:spdx:package-missing"
    return {
        "@context": "https://spdx.org/rdf/3.0.0/terms",
        "@graph": [
            {
                "type": "CreationInfo",
                "specVersion": "3.0.0",
                "created": "2026-01-01T00:00:00Z",
                "createdBy": ["urn:spdx:agent-test"],
            },
            {
                "type": "Sbom",
                "spdxId": "urn:spdx:sbom-test",
                "rootElement": [root_id],
            },
            *packages,
        ],
    }


class TestValidateSpdx3Packages:
    """`_validate_spdx3_packages` enforces the five BSI-required logical fields.

    Required-field set is sourced from `audits/0003-spdx3-mapping/mapping.md`
    (group 2 of the v2.1.0 -> 3.0 mapping).
    """

    def test_validate_spdx3_packages_all_fields_satisfied_via_canonical_names(self):
        doc = _make_spdx3_doc_with_packages([_make_compliant_spdx3_package("pkg1")])
        delta, findings = _validate_spdx3_packages(doc)
        assert delta == 30
        assert findings == []

    def test_validate_spdx3_packages_version_via_versioninfo_alias(self):
        pkg = _make_compliant_spdx3_package("pkg1", version_alias="versionInfo")
        doc = _make_spdx3_doc_with_packages([pkg])
        delta, findings = _validate_spdx3_packages(doc)
        assert delta == 30
        assert findings == []

    def test_validate_spdx3_packages_missing_version_produces_finding(self):
        pkg = _make_compliant_spdx3_package("pkg1")
        # Strip every version alias.
        for alias in SPDX3_FIELD_ALIASES["version"]:
            pkg.pop(alias, None)
        doc = _make_spdx3_doc_with_packages([pkg])
        delta, findings = _validate_spdx3_packages(doc)
        assert delta == 0
        assert len(findings) == 1
        assert findings[0].severity == "medium"
        assert "version" in findings[0].message
        assert "pkg1" in findings[0].message

    def test_validate_spdx3_packages_supplier_noassertion_missing(self):
        pkg = _make_compliant_spdx3_package("pkg1")
        pkg["suppliedBy"] = "NOASSERTION"
        doc = _make_spdx3_doc_with_packages([pkg])
        delta, findings = _validate_spdx3_packages(doc)
        assert delta == 0
        assert len(findings) == 1
        assert findings[0].severity == "medium"
        assert "supplier" in findings[0].message

    def test_validate_spdx3_packages_canonical_alias_outranks_legacy(self):
        pkg = _make_compliant_spdx3_package("pkg1")
        # Canonical alias has the real value; legacy alias is empty.
        pkg["software_packageVersion"] = "9.9.9"
        pkg["versionInfo"] = ""
        doc = _make_spdx3_doc_with_packages([pkg])
        delta, findings = _validate_spdx3_packages(doc)
        # First-match-wins: canonical alias resolves to the real value;
        # the empty legacy alias is never consulted.
        assert delta == 30
        assert findings == []

    def test_validate_spdx3_packages_security_vulnerability_ignored(self):
        pkg = _make_compliant_spdx3_package("pkg1")
        doc = _make_spdx3_doc_with_packages([pkg])
        doc["@graph"].append(
            {
                "type": "security_Vulnerability",
                "spdxId": "urn:spdx:vuln-1",
                "name": "CVE-2026-1234",
            }
        )
        delta, findings = _validate_spdx3_packages(doc)
        # 1 of 1 surviving Package compliant; security_ Element ignored.
        assert delta == 30
        assert findings == []

    def test_validate_spdx3_packages_security_vex_relationship_ignored(self):
        pkg = _make_compliant_spdx3_package("pkg1")
        doc = _make_spdx3_doc_with_packages([pkg])
        doc["@graph"].append(
            {
                "type": "security_VexNotAffectedVulnAssessmentRelationship",
                "spdxId": "urn:spdx:vex-1",
            }
        )
        delta, findings = _validate_spdx3_packages(doc)
        assert delta == 30
        assert findings == []

    def test_validate_spdx3_packages_no_packages_returns_zero(self):
        doc = {"@graph": [{"type": "CreationInfo", "specVersion": "3.0.0"}]}
        delta, findings = _validate_spdx3_packages(doc)
        assert delta == 0
        assert len(findings) == 1
        assert findings[0].severity == "medium"
        assert "no software_Package" in findings[0].message


class TestSecuritySkip:
    """The graph walker skips every Element whose type starts with `security_`."""

    def test_security_skip_cvss_relationship_excluded(self):
        pkg = _make_compliant_spdx3_package("pkg1")
        doc = _make_spdx3_doc_with_packages([pkg])
        doc["@graph"].append(
            {
                "type": "security_CvssV3VulnAssessmentRelationship",
                "spdxId": "urn:spdx:cvss-1",
            }
        )
        delta, findings = _validate_spdx3_packages(doc)
        # The CVSS Element is skipped entirely; the lone real Package is
        # the full denominator.
        assert delta == 30
        assert findings == []

    def test_security_skip_only_graph_yields_no_packages(self):
        doc = {
            "@graph": [
                {"type": "CreationInfo", "specVersion": "3.0.0"},
                {
                    "type": "security_Vulnerability",
                    "spdxId": "urn:spdx:vuln-1",
                },
                {
                    "type": "security_VexNotAffectedVulnAssessmentRelationship",
                    "spdxId": "urn:spdx:vex-1",
                },
            ],
        }
        delta, findings = _validate_spdx3_packages(doc)
        assert delta == 0
        assert len(findings) == 1
        assert findings[0].severity == "medium"
        assert "no software_Package" in findings[0].message


class TestSbomCheckV3EndToEnd:
    """`SBOMCheck.run` end-to-end scoring on full / partially-compliant docs."""

    def test_sbom_check_v3_fully_valid_10_packages_scores_50(
        self, tmp_path: Path, sbom_check: SBOMCheck
    ):
        packages = [_make_compliant_spdx3_package(f"pkg{i}") for i in range(10)]
        doc = _make_spdx3_doc_with_packages(packages)
        spdx_dir = tmp_path / "tmp" / "deploy" / "spdx"
        _write_spdx(spdx_dir / "image.spdx.json", doc)
        result = sbom_check.run(tmp_path, {})
        assert result.score == 50
        assert result.max_score == 50
        assert result.status == CheckStatus.PASS
        assert "SPDX 3.0 fully validated" in result.summary

    def test_sbom_check_v3_5_of_10_compliant_scores_35(self, tmp_path: Path, sbom_check: SBOMCheck):
        packages: list[dict] = []
        # 5 fully compliant.
        for i in range(5):
            packages.append(_make_compliant_spdx3_package(f"good{i}"))
        # 5 each missing exactly one different field.
        missing_fields = ("name", "version", "supplier", "license", "checksums")
        for i, logical_field in enumerate(missing_fields):
            pkg = _make_compliant_spdx3_package(f"bad{i}")
            for alias in SPDX3_FIELD_ALIASES[logical_field]:
                pkg.pop(alias, None)
            packages.append(pkg)
        doc = _make_spdx3_doc_with_packages(packages)
        spdx_dir = tmp_path / "tmp" / "deploy" / "spdx"
        _write_spdx(spdx_dir / "image.spdx.json", doc)
        result = sbom_check.run(tmp_path, {})
        # 10 (format) + 5 (metadata) + 5 (rootElement) + round(30 * 5/10) = 35
        assert result.score == 35
        assert result.max_score == 50


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
    """SPDX 3.0 document scores 20 (10 format + 5 metadata + 5 rootElement).

    The minimal `_make_spdx3_doc()` carries a single Package with only `name`
    populated, so per-Package validation produces 4 medium findings (missing
    version, supplier, license, checksums) and contributes 0 of 30 points.
    """

    def test_spdx_3_passes_with_note(self, tmp_path: Path, sbom_check: SBOMCheck):
        spdx_dir = tmp_path / "tmp" / "deploy" / "spdx"
        _write_spdx(spdx_dir / "image.spdx.json", _make_spdx3_doc())
        result = sbom_check.run(tmp_path, {})
        assert result.status == CheckStatus.WARN
        assert "SPDX 3.0 fully validated" in result.summary

    def test_spdx_3_scores_20(self, tmp_path: Path, sbom_check: SBOMCheck):
        spdx_dir = tmp_path / "tmp" / "deploy" / "spdx"
        _write_spdx(spdx_dir / "image.spdx.json", _make_spdx3_doc())
        result = sbom_check.run(tmp_path, {})
        assert result.score == 20

    def test_spdx_3_emits_per_package_findings(self, tmp_path: Path, sbom_check: SBOMCheck):
        spdx_dir = tmp_path / "tmp" / "deploy" / "spdx"
        _write_spdx(spdx_dir / "image.spdx.json", _make_spdx3_doc())
        result = sbom_check.run(tmp_path, {})
        # The minimal package has only `name`; expect one medium finding per
        # missing logical field (version, supplier, license, checksums).
        assert all(f.severity == "medium" for f in result.findings)
        missing_fields = {
            field
            for field in ("version", "supplier", "license", "checksums")
            if any(field in f.message for f in result.findings)
        }
        assert missing_fields == {"version", "supplier", "license", "checksums"}
        # Placeholder finding must no longer be emitted.
        assert not any("task 5.1" in f.message for f in result.findings)


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
        # The fixture uses SpdxDocument (not Sbom), so rootElement validation
        # contributes 0 of 5 points. Its two software_Package Elements lack the
        # five required fields, so per-Package validation contributes 0 of 30.
        # Total: 10 (format) + 5 (metadata) + 0 (rootElement) + 0 (per-Package).
        assert result.score == 15
        assert "SPDX 3.0 fully validated" in result.summary

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
        assert any(f.severity == "low" and "checksum" in f.message.lower() for f in result.findings)


# --- Scoring tests (task 2.5) ---


class TestScoringFullyCompliant:
    """Fully compliant SPDX 2.3 doc scores 50/50."""

    def test_scoring_perfect_score(self, tmp_path: Path, sbom_check: SBOMCheck):
        spdx_dir = tmp_path / "tmp" / "deploy" / "spdx"
        doc = _make_spdx_doc(
            packages=[_make_compliant_package(f"pkg{i}") for i in range(5)],
            has_describes=True,
        )
        _write_spdx(spdx_dir / "image.spdx.json", doc)
        result = sbom_check.run(tmp_path, {})
        assert result.score == 50
        assert result.max_score == 50

    def test_scoring_single_package_perfect(self, tmp_path: Path, sbom_check: SBOMCheck):
        spdx_dir = tmp_path / "tmp" / "deploy" / "spdx"
        doc = _make_spdx_doc(
            packages=[_make_compliant_package("only")],
            has_describes=True,
        )
        _write_spdx(spdx_dir / "image.spdx.json", doc)
        result = sbom_check.run(tmp_path, {})
        assert result.score == 50


class TestScoringPartialPackageCoverage:
    """Per-package coverage: 30 * (compliant / total), rounded."""

    def test_scoring_30_of_42_packages_compliant(self, tmp_path: Path, sbom_check: SBOMCheck):
        """Spec scenario: 30 of 42 packages have all required fields -> round(30*30/42) = 21."""
        spdx_dir = tmp_path / "tmp" / "deploy" / "spdx"
        compliant = [_make_compliant_package(f"good{i}") for i in range(30)]
        non_compliant = []
        for i in range(12):
            pkg = _make_compliant_package(f"bad{i}")
            pkg["supplier"] = "NOASSERTION"
            non_compliant.append(pkg)
        doc = _make_spdx_doc(
            packages=compliant + non_compliant,
            has_describes=True,
        )
        _write_spdx(spdx_dir / "image.spdx.json", doc)
        result = sbom_check.run(tmp_path, {})
        # 10 (format) + 5 (metadata) + 5 (DESCRIBES) + round(30*30/42) = 10+5+5+21 = 41
        assert result.score == 41

    def test_scoring_half_packages_compliant(self, tmp_path: Path, sbom_check: SBOMCheck):
        spdx_dir = tmp_path / "tmp" / "deploy" / "spdx"
        compliant = [_make_compliant_package(f"good{i}") for i in range(5)]
        non_compliant = []
        for i in range(5):
            pkg = _make_compliant_package(f"bad{i}")
            pkg["checksums"] = []
            non_compliant.append(pkg)
        doc = _make_spdx_doc(
            packages=compliant + non_compliant,
            has_describes=True,
        )
        _write_spdx(spdx_dir / "image.spdx.json", doc)
        result = sbom_check.run(tmp_path, {})
        # 10 + 5 + 5 + round(30*5/10) = 10+5+5+15 = 35
        assert result.score == 35

    def test_scoring_no_packages_compliant(self, tmp_path: Path, sbom_check: SBOMCheck):
        spdx_dir = tmp_path / "tmp" / "deploy" / "spdx"
        non_compliant = []
        for i in range(3):
            pkg = _make_compliant_package(f"bad{i}")
            pkg["supplier"] = "NOASSERTION"
            non_compliant.append(pkg)
        doc = _make_spdx_doc(
            packages=non_compliant,
            has_describes=True,
        )
        _write_spdx(spdx_dir / "image.spdx.json", doc)
        result = sbom_check.run(tmp_path, {})
        # 10 + 5 + 5 + round(30*0/3) = 20
        assert result.score == 20


class TestScoringMetadataDeduction:
    """Missing metadata costs 5 points."""

    def test_scoring_missing_creation_info(self, tmp_path: Path, sbom_check: SBOMCheck):
        spdx_dir = tmp_path / "tmp" / "deploy" / "spdx"
        doc = _make_spdx_doc(
            packages=[_make_compliant_package("pkg1")],
            has_describes=True,
        )
        del doc["creationInfo"]
        _write_spdx(spdx_dir / "image.spdx.json", doc)
        result = sbom_check.run(tmp_path, {})
        # 10 (format) + 0 (metadata missing) + 5 (DESCRIBES) + 30 (1/1 compliant) = 45
        assert result.score == 45

    def test_scoring_empty_creators(self, tmp_path: Path, sbom_check: SBOMCheck):
        spdx_dir = tmp_path / "tmp" / "deploy" / "spdx"
        doc = _make_spdx_doc(
            packages=[_make_compliant_package("pkg1")],
            has_describes=True,
        )
        doc["creationInfo"]["creators"] = []
        _write_spdx(spdx_dir / "image.spdx.json", doc)
        result = sbom_check.run(tmp_path, {})
        assert result.score == 45


class TestScoringDescribesDeduction:
    """Missing DESCRIBES costs 5 points."""

    def test_scoring_no_describes(self, tmp_path: Path, sbom_check: SBOMCheck):
        spdx_dir = tmp_path / "tmp" / "deploy" / "spdx"
        doc = _make_spdx_doc(
            packages=[_make_compliant_package("pkg1")],
            has_describes=False,
        )
        _write_spdx(spdx_dir / "image.spdx.json", doc)
        result = sbom_check.run(tmp_path, {})
        # 10 + 5 + 0 + 30 = 45
        assert result.score == 45


class TestScoringCombinedDeductions:
    """Multiple deductions stack."""

    def test_scoring_missing_metadata_and_describes(self, tmp_path: Path, sbom_check: SBOMCheck):
        spdx_dir = tmp_path / "tmp" / "deploy" / "spdx"
        doc = _make_spdx_doc(
            packages=[_make_compliant_package("pkg1")],
            has_describes=False,
        )
        del doc["creationInfo"]
        _write_spdx(spdx_dir / "image.spdx.json", doc)
        result = sbom_check.run(tmp_path, {})
        # 10 + 0 + 0 + 30 = 40
        assert result.score == 40

    def test_scoring_all_deductions(self, tmp_path: Path, sbom_check: SBOMCheck):
        """Missing metadata, no DESCRIBES, all packages non-compliant."""
        spdx_dir = tmp_path / "tmp" / "deploy" / "spdx"
        non_compliant = []
        for i in range(4):
            pkg = _make_compliant_package(f"bad{i}")
            pkg["supplier"] = "NOASSERTION"
            non_compliant.append(pkg)
        doc = _make_spdx_doc(
            packages=non_compliant,
            has_describes=False,
        )
        del doc["creationInfo"]
        _write_spdx(spdx_dir / "image.spdx.json", doc)
        result = sbom_check.run(tmp_path, {})
        # 10 + 0 + 0 + 0 = 10
        assert result.score == 10


class TestScoringDetectionOnly:
    """Detection-only formats (CycloneDX) cap at 10 points.

    SPDX 3.0 is fully validated after task 5.1: a structurally minimal
    document (one Package missing four of five required fields) scores
    20 (10 format + 5 metadata + 5 rootElement + 0 per-Package).
    """

    def test_scoring_spdx_3_partial_validation_scores_20(
        self, tmp_path: Path, sbom_check: SBOMCheck
    ):
        spdx_dir = tmp_path / "tmp" / "deploy" / "spdx"
        _write_spdx(spdx_dir / "image.spdx.json", _make_spdx3_doc())
        result = sbom_check.run(tmp_path, {})
        assert result.score == 20
        assert result.max_score == 50

    def test_scoring_cyclonedx_capped_at_10(self, tmp_path: Path, sbom_check: SBOMCheck):
        spdx_dir = tmp_path / "tmp" / "deploy" / "spdx"
        _write_spdx(spdx_dir / "image.spdx.json", _make_cyclonedx_doc())
        result = sbom_check.run(tmp_path, {})
        assert result.score == 10
        assert result.max_score == 50


class TestScoringEdgeCases:
    """Edge cases for score computation."""

    def test_scoring_unrecognized_format_scores_zero(self, tmp_path: Path, sbom_check: SBOMCheck):
        spdx_dir = tmp_path / "tmp" / "deploy" / "spdx"
        _write_spdx(spdx_dir / "image.spdx.json", {"unknown": "format"})
        result = sbom_check.run(tmp_path, {})
        assert result.score == 0

    def test_scoring_missing_spdx_dir_scores_zero(self, tmp_path: Path, sbom_check: SBOMCheck):
        result = sbom_check.run(tmp_path, {})
        assert result.score == 0

    def test_scoring_empty_spdx_dir_scores_zero(self, tmp_path: Path, sbom_check: SBOMCheck):
        (tmp_path / "tmp" / "deploy" / "spdx").mkdir(parents=True)
        result = sbom_check.run(tmp_path, {})
        assert result.score == 0

    def test_scoring_max_score_always_50(self, tmp_path: Path, sbom_check: SBOMCheck):
        spdx_dir = tmp_path / "tmp" / "deploy" / "spdx"
        doc = _make_spdx_doc(
            packages=[_make_compliant_package("pkg1")],
            has_describes=True,
        )
        _write_spdx(spdx_dir / "image.spdx.json", doc)
        result = sbom_check.run(tmp_path, {})
        assert result.max_score == 50


class TestCraMappingOnFindings:
    """Every Finding returned by SBOMCheck.run() carries `I.P2.1` in `cra_mapping`.

    CRA mapping comes from spec `cra-requirement-mapping/spec.md` → "Existing checks emit
    mappings": SBOM findings evidence Annex I Part II §1 (`I.P2.1` - SBOM provision).
    """

    def test_cra_mapping_missing_spdx_dir(self, tmp_path: Path, sbom_check: SBOMCheck):
        result = sbom_check.run(tmp_path, {})
        assert result.findings
        for finding in result.findings:
            assert "I.P2.1" in finding.cra_mapping

    def test_cra_mapping_empty_spdx_dir(self, tmp_path: Path, sbom_check: SBOMCheck):
        (tmp_path / "tmp" / "deploy" / "spdx").mkdir(parents=True)
        result = sbom_check.run(tmp_path, {})
        assert result.findings
        for finding in result.findings:
            assert "I.P2.1" in finding.cra_mapping

    def test_cra_mapping_all_invalid_json(self, tmp_path: Path, sbom_check: SBOMCheck):
        spdx_dir = tmp_path / "tmp" / "deploy" / "spdx"
        spdx_dir.mkdir(parents=True)
        (spdx_dir / "broken.spdx.json").write_text("{not valid json")
        result = sbom_check.run(tmp_path, {})
        assert result.findings
        for finding in result.findings:
            assert "I.P2.1" in finding.cra_mapping

    def test_cra_mapping_unrecognized_format(self, tmp_path: Path, sbom_check: SBOMCheck):
        spdx_dir = tmp_path / "tmp" / "deploy" / "spdx"
        _write_spdx(spdx_dir / "image.spdx.json", {"unknown": "format"})
        result = sbom_check.run(tmp_path, {})
        assert result.findings
        for finding in result.findings:
            assert "I.P2.1" in finding.cra_mapping

    def test_cra_mapping_missing_metadata_findings(self, tmp_path: Path, sbom_check: SBOMCheck):
        spdx_dir = tmp_path / "tmp" / "deploy" / "spdx"
        doc = _make_spdx_doc(has_describes=True)
        del doc["creationInfo"]
        _write_spdx(spdx_dir / "image.spdx.json", doc)
        result = sbom_check.run(tmp_path, {})
        assert result.findings
        for finding in result.findings:
            assert "I.P2.1" in finding.cra_mapping

    def test_cra_mapping_per_package_findings(self, tmp_path: Path, sbom_check: SBOMCheck):
        spdx_dir = tmp_path / "tmp" / "deploy" / "spdx"
        bad_pkg = _make_compliant_package("bad")
        bad_pkg["supplier"] = "NOASSERTION"
        bad_pkg["licenseDeclared"] = "NOASSERTION"
        doc = _make_spdx_doc(packages=[bad_pkg], has_describes=True)
        _write_spdx(spdx_dir / "image.spdx.json", doc)
        result = sbom_check.run(tmp_path, {})
        assert result.findings
        for finding in result.findings:
            assert "I.P2.1" in finding.cra_mapping


class TestCraMappingOnCheckResult:
    """CheckResult.cra_mapping contains `I.P2.1` for every SBOMCheck.run() path."""

    def test_cra_mapping_check_result_missing_spdx_dir(self, tmp_path: Path, sbom_check: SBOMCheck):
        result = sbom_check.run(tmp_path, {})
        assert "I.P2.1" in result.cra_mapping

    def test_cra_mapping_check_result_empty_spdx_dir(self, tmp_path: Path, sbom_check: SBOMCheck):
        (tmp_path / "tmp" / "deploy" / "spdx").mkdir(parents=True)
        result = sbom_check.run(tmp_path, {})
        assert "I.P2.1" in result.cra_mapping

    def test_cra_mapping_check_result_unrecognized_format(
        self, tmp_path: Path, sbom_check: SBOMCheck
    ):
        spdx_dir = tmp_path / "tmp" / "deploy" / "spdx"
        _write_spdx(spdx_dir / "image.spdx.json", {"unknown": "format"})
        result = sbom_check.run(tmp_path, {})
        assert "I.P2.1" in result.cra_mapping

    def test_cra_mapping_check_result_spdx3_detection_only(
        self, tmp_path: Path, sbom_check: SBOMCheck
    ):
        spdx_dir = tmp_path / "tmp" / "deploy" / "spdx"
        _write_spdx(spdx_dir / "image.spdx.json", _make_spdx3_doc())
        result = sbom_check.run(tmp_path, {})
        assert "I.P2.1" in result.cra_mapping

    def test_cra_mapping_check_result_cyclonedx_detection_only(
        self, tmp_path: Path, sbom_check: SBOMCheck
    ):
        spdx_dir = tmp_path / "tmp" / "deploy" / "spdx"
        _write_spdx(spdx_dir / "image.spdx.json", _make_cyclonedx_doc())
        result = sbom_check.run(tmp_path, {})
        assert "I.P2.1" in result.cra_mapping

    def test_cra_mapping_check_result_fully_compliant_spdx2(
        self, tmp_path: Path, sbom_check: SBOMCheck
    ):
        spdx_dir = tmp_path / "tmp" / "deploy" / "spdx"
        doc = _make_spdx_doc(
            packages=[_make_compliant_package("pkg1")],
            has_describes=True,
        )
        _write_spdx(spdx_dir / "image.spdx.json", doc)
        result = sbom_check.run(tmp_path, {})
        assert "I.P2.1" in result.cra_mapping


class TestCraMappingFormatValidation:
    """Findings about SBOM format validation additionally cite Annex VII §2.

    The catalog stores only top-level Annex VII IDs (`VII.2`), not sub-items like
    `VII.2.b`, so mappings use `VII.2`. Format-validation findings are those about
    the SPDX/CycloneDX format itself and the field-level compliance required by
    BSI TR-03183-2 (document metadata and per-package fields).
    """

    def test_cra_mapping_unrecognized_format_cites_vii_2(
        self, tmp_path: Path, sbom_check: SBOMCheck
    ):
        spdx_dir = tmp_path / "tmp" / "deploy" / "spdx"
        _write_spdx(spdx_dir / "image.spdx.json", {"unknown": "format"})
        result = sbom_check.run(tmp_path, {})
        format_findings = [f for f in result.findings if "format" in f.message.lower()]
        assert format_findings, "expected at least one finding about SBOM format"
        for finding in format_findings:
            assert "VII.2" in finding.cra_mapping

    def test_cra_mapping_metadata_field_findings_cite_vii_2(
        self, tmp_path: Path, sbom_check: SBOMCheck
    ):
        """Missing creationInfo fields are SPDX format-validation issues."""
        spdx_dir = tmp_path / "tmp" / "deploy" / "spdx"
        doc = _make_spdx_doc(has_describes=True)
        del doc["creationInfo"]
        _write_spdx(spdx_dir / "image.spdx.json", doc)
        result = sbom_check.run(tmp_path, {})
        assert result.findings
        for finding in result.findings:
            assert "VII.2" in finding.cra_mapping

    def test_cra_mapping_per_package_field_findings_cite_vii_2(
        self, tmp_path: Path, sbom_check: SBOMCheck
    ):
        """Missing per-package BSI-required fields are format-validation issues."""
        spdx_dir = tmp_path / "tmp" / "deploy" / "spdx"
        bad_pkg = _make_compliant_package("bad")
        bad_pkg["supplier"] = "NOASSERTION"
        doc = _make_spdx_doc(packages=[bad_pkg], has_describes=True)
        _write_spdx(spdx_dir / "image.spdx.json", doc)
        result = sbom_check.run(tmp_path, {})
        assert result.findings
        for finding in result.findings:
            assert "VII.2" in finding.cra_mapping


# --- Integration tests against the real pilot 0006 image-level slice ---


_REAL_SPDX3_FIXTURE = (
    Path(__file__).resolve().parent.parent
    / "fixtures"
    / "pilot_real"
    / "spdx3"
    / "tmp"
    / "deploy"
    / "images"
    / "qemux86-64"
    / "core-image-minimal-qemux86-64.rootfs.spdx.json"
)


@pytest.fixture
def real_spdx3_doc() -> dict:
    """Load the committed pilot 0006 image-level SPDX 3.0 slice as a dict."""
    return json.loads(_REAL_SPDX3_FIXTURE.read_text())


class TestSpdx3RealFixture:
    """Integration tests that load the real pilot 0006 SPDX 3.0 slice.

    Task 9.1 ground-truth reconciliation: assert the validator scores a
    real-shape Yocto image-level rootfs SPDX 3.0 document correctly. The
    fixture is a transitive-closure slice produced by
    ``scripts/extract_pilot_fixture_spdx3.py`` from the pilot 0006 build;
    see ``tests/fixtures/pilot_real/spdx3/PROVENANCE.md`` for the full
    provenance and the slicing parameters.

    Real Yocto image-level ``software_Package`` Elements carry name,
    primaryPurpose, and (for runtime install packages) version, but do
    NOT carry ``supplier``, ``software_declaredLicense``, or per-package
    ``verifiedUsing``. License is expressed via separate Relationship /
    hasConcludedLicense Elements pointing to simplelicensing_*
    Elements. That divergence from BSI v2.1.0's field-on-Package
    expectation is a data-model difference, not a validator bug; the
    expected end-to-end score is documented as a partial 20/50.
    """

    def test_spdx3_real_fixture_loads(self, real_spdx3_doc: dict):
        """Sanity: the committed slice is valid JSON with @graph + CreationInfo."""
        assert "@graph" in real_spdx3_doc
        graph = real_spdx3_doc["@graph"]
        assert isinstance(graph, list)
        assert len(graph) >= 1
        creation_infos = [
            el for el in graph if isinstance(el, dict) and el.get("type") == "CreationInfo"
        ]
        assert creation_infos, "fixture must contain at least one CreationInfo"
        spec_versions = [ci.get("specVersion") for ci in creation_infos if ci.get("specVersion")]
        assert spec_versions, "fixture must contain at least one specVersion"
        assert any(sv.startswith("3.0") for sv in spec_versions)

    def test_spdx3_real_fixture_detection(self, real_spdx3_doc: dict):
        """``_detect_format`` must classify the real fixture as ``spdx-3``."""
        assert _detect_format(real_spdx3_doc) == "spdx-3"

    def test_spdx3_real_fixture_validates_metadata(self, real_spdx3_doc: dict):
        """Metadata validator awards 5 points: real CreationInfo has both fields."""
        score, findings = _validate_spdx3_metadata(real_spdx3_doc)
        assert score == 5
        assert findings == []

    def test_spdx3_real_fixture_validates_root_element(self, real_spdx3_doc: dict):
        """rootElement validator awards 5 points: Sbom resolves to software_Package."""
        score, findings = _validate_spdx3_root_element(real_spdx3_doc)
        assert score == 5
        assert findings == []

    def test_spdx3_real_fixture_validates_packages(self, real_spdx3_doc: dict):
        """Per-Package validator returns score 0 plus medium findings.

        Yocto image-level packages do not carry supplier / license /
        per-package checksums, so every package emits the same triple of
        ``missing or invalid {supplier,license,checksums}`` findings. The
        archive package additionally lacks version. None are fully
        compliant under the BSI v2.1.0 mapping, so score is 0/30.
        """
        score, findings = _validate_spdx3_packages(real_spdx3_doc)
        assert score == 0
        assert findings, "real packages should produce missing-field findings"
        for finding in findings:
            assert finding.severity == "medium"
            assert "I.P2.1" in finding.cra_mapping
            assert "VII.2" in finding.cra_mapping
        # Every finding cites a missing logical field.
        missing_fields = {
            field
            for finding in findings
            for field in ("supplier", "license", "checksums", "version", "name")
            if f"missing or invalid {field}" in finding.message
        }
        assert "supplier" in missing_fields
        assert "license" in missing_fields

    def test_spdx3_real_fixture_end_to_end(
        self, tmp_path: Path, sbom_check: SBOMCheck, real_spdx3_doc: dict
    ):
        """End-to-end: SBOMCheck.run scores the real fixture as 20/50.

        Score breakdown:
          - 10 format detection (spdx-3)
          - 5 metadata (CreationInfo has created + createdBy)
          - 5 rootElement (Sbom rootElement resolves to software_Package)
          - 0 per-Package (no Package carries supplier/license/checksums)
        """
        spdx_dir = tmp_path / "tmp" / "deploy" / "spdx"
        _write_spdx(spdx_dir / "image.spdx.json", real_spdx3_doc)
        result = sbom_check.run(tmp_path, {})
        assert result.max_score == 50
        assert result.score == 20
        assert result.status == CheckStatus.WARN
        assert "SPDX 3.0" in result.summary
        # Findings are real-Yocto missing-field signals, not detection failures.
        for finding in result.findings:
            assert finding.severity in ("medium", "high", "low")

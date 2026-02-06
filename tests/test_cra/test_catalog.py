"""Tests for the CRA requirement catalog loader.

Per design Decision 3, the catalog is a static YAML file loaded once at startup
and exposed as an immutable mapping. The catalog is pinned to the OJ L
publication of Regulation (EU) 2024/2847 (20 November 2024); the
``source_version`` constant must change deliberately on refresh (see design
risks - "CRA catalog drift").
"""

from __future__ import annotations

import dataclasses

import pytest

from shipcheck.cra.loader import CraCatalog, CraRequirement, is_valid_id, load_catalog

PINNED_SOURCE_VERSION = "OJ L, 20.11.2024"

EXPECTED_ANNEX_COUNTS = {
    ("I", "1"): 13,  # Annex I Part I items (a)-(m)
    ("I", "2"): 8,  # Annex I Part II items (1)-(8)
    ("II", ""): 9,  # Annex II items (1)-(9)
    ("VII", ""): 8,  # Annex VII items (1)-(8)
}

EXPECTED_TOTAL = sum(EXPECTED_ANNEX_COUNTS.values())  # 38


class TestLoadCatalog:
    """Tests for load_catalog()."""

    def test_returns_cra_catalog_dataclass(self):
        catalog = load_catalog()

        assert isinstance(catalog, CraCatalog)
        assert dataclasses.is_dataclass(catalog)

    def test_source_version_matches_pinned_constant(self):
        catalog = load_catalog()

        assert catalog.source_version == PINNED_SOURCE_VERSION

    def test_contains_38_entries_total(self):
        catalog = load_catalog()

        assert len(catalog.requirements) == EXPECTED_TOTAL

    def test_entries_distributed_across_expected_annexes(self):
        catalog = load_catalog()

        counts: dict[tuple[str, str], int] = {}
        for req in catalog.requirements.values():
            key = (req.annex, req.part)
            counts[key] = counts.get(key, 0) + 1

        assert counts == EXPECTED_ANNEX_COUNTS

    def test_requirement_has_expected_fields(self):
        catalog = load_catalog()

        sample = next(iter(catalog.requirements.values()))

        assert isinstance(sample, CraRequirement)
        assert dataclasses.is_dataclass(sample)
        assert sample.id
        assert sample.annex
        assert sample.title
        assert sample.text

    def test_requirements_keyed_by_id(self):
        catalog = load_catalog()

        for req_id, req in catalog.requirements.items():
            assert req_id == req.id


class TestCatalogImmutability:
    """Catalog and its entries must reject mutation (MappingProxyType / frozen)."""

    def test_catalog_is_frozen_dataclass(self):
        catalog = load_catalog()

        with pytest.raises(dataclasses.FrozenInstanceError):
            catalog.source_version = "mutated"  # type: ignore[misc]

    def test_requirement_is_frozen_dataclass(self):
        catalog = load_catalog()
        req = next(iter(catalog.requirements.values()))

        with pytest.raises(dataclasses.FrozenInstanceError):
            req.title = "mutated"  # type: ignore[misc]

    def test_requirements_mapping_rejects_item_assignment(self):
        catalog = load_catalog()

        # MappingProxyType raises TypeError on __setitem__.
        with pytest.raises(TypeError):
            catalog.requirements["BOGUS.X.1"] = next(iter(catalog.requirements.values()))  # type: ignore[index]

    def test_requirements_mapping_rejects_deletion(self):
        catalog = load_catalog()
        any_id = next(iter(catalog.requirements))

        with pytest.raises(TypeError):
            del catalog.requirements[any_id]  # type: ignore[misc]


class TestIsValidId:
    """Tests for the is_valid_id helper."""

    def test_known_id_is_valid(self):
        catalog = load_catalog()
        known = next(iter(catalog.requirements))

        assert is_valid_id(known) is True

    def test_unknown_id_is_invalid(self):
        assert is_valid_id("BOGUS.X.1") is False

    def test_empty_string_is_invalid(self):
        assert is_valid_id("") is False

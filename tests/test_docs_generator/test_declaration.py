"""Tests for the Declaration of Conformity generator.

Task 9.1 of devspec change ``shipcheck-v03-cra-evidence``. Asserts the
contract of
:func:`shipcheck.docs_generator.declaration.generate_declaration`:

* the full (Annex V) Declaration of Conformity renders eight top-level
  fields in the order prescribed by Annex V of Regulation (EU) 2024/2847:

    1. product identification
    2. manufacturer identification
    3. sole-responsibility statement
    4. object of declaration
    5. conformity statement
    6. harmonised standards
    7. notified body
    8. additional information

* the simplified (Annex VI) form contains the fixed Annex VI sentence
  ``"Hereby, [manufacturer] declares that the product with digital
  elements type [type] is in compliance with Regulation (EU) 2024/2847"``
  with ``[manufacturer]`` and ``[type]`` substituted from the product
  config,
* the §6 harmonised-standards field renders the verbatim placeholder
  ``[TO BE FILLED BY MANUFACTURER: list applicable harmonised
  standards]`` because Commission mandate M/596 is still in progress
  and no harmonised standards have been published yet,
* a ``product.yaml`` that omits ``manufacturer.address`` raises an
  error whose message names the missing field (covered by using the
  pre-existing ``tests/fixtures/product/missing_address.yaml`` fixture),
* the date of issue defaults to today in ISO 8601 format
  (``YYYY-MM-DD``).

The import target ``shipcheck.docs_generator.declaration`` is
deliberately absent until task 9.2 - the whole module fails with
``ImportError`` at collection time, which is the valid RED for TDD.
"""

from __future__ import annotations

import datetime as dt
import re
from pathlib import Path

import pytest

from shipcheck.docs_generator.declaration import generate_declaration
from shipcheck.product import ProductConfig, ProductConfigError, load_product_config

FIXTURE_COMPLETE = Path("tests/fixtures/product/complete.yaml")
FIXTURE_MISSING_ADDRESS = Path("tests/fixtures/product/missing_address.yaml")

# The eight Annex V section titles, in the order mandated by the
# regulation. The generator is free to render them as ``## 1. Product
# identification`` or ``## Product identification`` - the test asserts
# only on a case-insensitive substring match per section so the template
# author can pick heading style while keeping the ordering contract.
ANNEX_V_FIELDS: tuple[str, ...] = (
    "product identification",
    "manufacturer identification",
    "sole-responsibility statement",
    "object of declaration",
    "conformity statement",
    "harmonised standards",
    "notified body",
    "additional information",
)

ANNEX_VI_TEMPLATE = (
    "Hereby, [manufacturer] declares that the product with digital "
    "elements type [type] is in compliance with Regulation (EU) 2024/2847"
)

HARMONISED_PLACEHOLDER = "[TO BE FILLED BY MANUFACTURER: list applicable harmonised standards]"


@pytest.fixture
def product() -> ProductConfig:
    return load_product_config(FIXTURE_COMPLETE)


@pytest.fixture
def out_path(tmp_path: Path) -> Path:
    return tmp_path / "declaration-of-conformity.md"


class TestFullDeclarationHasEightAnnexVFieldsInOrder:
    def test_all_eight_fields_present(
        self,
        product: ProductConfig,
        out_path: Path,
    ) -> None:
        generate_declaration(product, out_path)
        text = out_path.read_text(encoding="utf-8").lower()

        for field in ANNEX_V_FIELDS:
            assert field in text, f"full Declaration of Conformity missing Annex V field '{field}'"

    def test_fields_appear_in_annex_v_order(
        self,
        product: ProductConfig,
        out_path: Path,
    ) -> None:
        generate_declaration(product, out_path)
        text = out_path.read_text(encoding="utf-8").lower()

        positions: list[int] = []
        for field in ANNEX_V_FIELDS:
            idx = text.find(field)
            assert idx != -1, f"Annex V field '{field}' not present at all"
            positions.append(idx)

        assert positions == sorted(positions), (
            "Annex V fields must appear in regulation order; got positions "
            f"{positions} for {ANNEX_V_FIELDS}"
        )

    def test_simplified_flag_false_by_default_emits_full_form(
        self,
        product: ProductConfig,
        out_path: Path,
    ) -> None:
        # Default ``simplified=False`` must produce the full Annex V
        # document, not the one-sentence Annex VI form. We detect this by
        # confirming the ``notified body`` heading (Annex V only) is
        # present when no flag is passed.
        generate_declaration(product, out_path)
        text = out_path.read_text(encoding="utf-8").lower()
        assert "notified body" in text, (
            "default generate_declaration() must emit the full Annex V form"
        )


class TestSimplifiedDeclarationAnnexVIFixedText:
    def test_contains_fixed_annex_vi_sentence_with_substitutions(
        self,
        product: ProductConfig,
        out_path: Path,
    ) -> None:
        generate_declaration(product, out_path, simplified=True)
        text = out_path.read_text(encoding="utf-8")

        expected = (
            f"Hereby, {product.manufacturer_name} declares that the product "
            f"with digital elements type {product.product_type} is in "
            "compliance with Regulation (EU) 2024/2847"
        )
        assert expected in text, (
            "simplified DoC must contain the Annex VI fixed sentence with "
            "[manufacturer] and [type] substituted from product config. "
            f"Looked for:\n  {expected!r}\nIn:\n  {text!r}"
        )

    def test_simplified_form_substitutes_manufacturer_and_type(
        self,
        product: ProductConfig,
        out_path: Path,
    ) -> None:
        generate_declaration(product, out_path, simplified=True)
        text = out_path.read_text(encoding="utf-8")

        assert product.manufacturer_name in text, (
            f"simplified DoC did not substitute [manufacturer] with {product.manufacturer_name!r}"
        )
        assert product.product_type in text, (
            f"simplified DoC did not substitute [type] with {product.product_type!r}"
        )

    def test_simplified_form_does_not_leave_literal_placeholders(
        self,
        product: ProductConfig,
        out_path: Path,
    ) -> None:
        generate_declaration(product, out_path, simplified=True)
        text = out_path.read_text(encoding="utf-8")

        # The literal placeholders from the Annex VI template must be
        # replaced; leaving them in means the substitution step was
        # skipped.
        assert "[manufacturer]" not in text, (
            "simplified DoC must substitute [manufacturer] placeholder"
        )
        assert "[type]" not in text, "simplified DoC must substitute [type] placeholder"


class TestHarmonisedStandardsPlaceholder:
    def test_section_six_renders_verbatim_placeholder(
        self,
        product: ProductConfig,
        out_path: Path,
    ) -> None:
        generate_declaration(product, out_path)
        text = out_path.read_text(encoding="utf-8")

        assert HARMONISED_PLACEHOLDER in text, (
            "§6 harmonised-standards field must render the verbatim "
            f"placeholder {HARMONISED_PLACEHOLDER!r} because mandate M/596 "
            "harmonised standards are not yet published. Got:\n"
            f"{text!r}"
        )

    def test_placeholder_appears_inside_harmonised_standards_section(
        self,
        product: ProductConfig,
        out_path: Path,
    ) -> None:
        generate_declaration(product, out_path)
        text = out_path.read_text(encoding="utf-8")

        lowered = text.lower()
        heading_idx = lowered.find("harmonised standards")
        next_idx = lowered.find("notified body", heading_idx)
        assert heading_idx != -1, "missing 'harmonised standards' section"
        assert next_idx != -1, "missing 'notified body' section"

        section = text[heading_idx:next_idx]
        assert HARMONISED_PLACEHOLDER in section, (
            "harmonised-standards placeholder must live inside §6, not be "
            "hoisted into a different section. Got §6 body:\n"
            f"{section!r}"
        )


class TestMissingManufacturerAddressRaises:
    def test_missing_address_fixture_rejects_with_named_field(
        self,
        out_path: Path,
    ) -> None:
        # The task allows two equally valid surfaces for this error: the
        # product loader (preferred, since ``load_product_config`` is
        # specified to raise ``ProductConfigError`` naming the missing
        # field) or the generator itself. Either way the failure must
        # cite ``manufacturer.address``.
        with pytest.raises((ProductConfigError, ValueError)) as excinfo:
            product = load_product_config(FIXTURE_MISSING_ADDRESS)
            generate_declaration(product, out_path)

        assert "manufacturer.address" in str(excinfo.value), (
            f"error must name the missing field 'manufacturer.address'; got: {excinfo.value!r}"
        )


class TestDateOfIssueDefaultsToTodayIsoFormat:
    def test_iso_date_present(
        self,
        product: ProductConfig,
        out_path: Path,
    ) -> None:
        generate_declaration(product, out_path)
        text = out_path.read_text(encoding="utf-8")

        today = dt.date.today().isoformat()
        assert today in text, (
            "date of issue must default to today in ISO 8601 format "
            f"(YYYY-MM-DD); expected {today!r} in output, got:\n{text!r}"
        )

    def test_iso_date_format_is_yyyy_mm_dd(
        self,
        product: ProductConfig,
        out_path: Path,
    ) -> None:
        generate_declaration(product, out_path)
        text = out_path.read_text(encoding="utf-8")

        # The literal ISO 8601 calendar date form is ``YYYY-MM-DD``; the
        # generator must not fall back to a locale format like
        # ``1 April 2026`` or ``04/01/2026``.
        matches = re.findall(r"\b\d{4}-\d{2}-\d{2}\b", text)
        assert matches, (
            f"output must contain at least one ISO 8601 (YYYY-MM-DD) date; got:\n{text!r}"
        )

        today = dt.date.today().isoformat()
        assert today in matches, (
            "date of issue must default to today in ISO 8601 format; "
            f"expected {today!r} among dates found: {matches!r}"
        )

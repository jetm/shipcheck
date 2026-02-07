"""Tests for product.yaml loading and validation."""

from __future__ import annotations

import dataclasses
from pathlib import Path

import pytest

from shipcheck.product import ProductConfig, ProductConfigError, load_product_config

FIXTURES = Path(__file__).parent / "fixtures" / "product"


class TestLoadProductConfig:
    """Tests for load_product_config."""

    def test_missing_file_raises_with_path_in_message(self, tmp_path: Path):
        missing = tmp_path / "does-not-exist" / "product.yaml"

        with pytest.raises(ProductConfigError) as excinfo:
            load_product_config(missing)

        assert str(missing) in str(excinfo.value)

    def test_missing_cvd_policy_url_raises_naming_field(self):
        path = FIXTURES / "missing_cvd.yaml"

        with pytest.raises(ProductConfigError) as excinfo:
            load_product_config(path)

        assert "cvd.policy_url" in str(excinfo.value)

    def test_missing_manufacturer_address_raises_naming_field(self):
        path = FIXTURES / "missing_address.yaml"

        with pytest.raises(ProductConfigError) as excinfo:
            load_product_config(path)

        assert "manufacturer.address" in str(excinfo.value)

    def test_complete_returns_typed_product_config(self):
        path = FIXTURES / "complete.yaml"

        config = load_product_config(path)

        assert isinstance(config, ProductConfig)
        assert dataclasses.is_dataclass(config)

        assert config.schema_version == 1

        assert config.product_name == "Acme Gateway GW-100"
        assert config.product_type == "Industrial IoT edge gateway"
        assert config.product_version == "2.4.1"

        assert config.manufacturer_name == "Acme Embedded Systems GmbH"
        assert config.manufacturer_address == "Karlstrasse 42, 80333 Munich, Germany"
        assert config.manufacturer_contact == "compliance@acme-embedded.example"

        assert config.support_period_end_date == "2031-12-31"

        assert config.cvd_policy_url == "https://acme-embedded.example/security/cvd-policy"
        assert config.cvd_contact == "security@acme-embedded.example"

        assert config.update_distribution_mechanism == (
            "Signed OTA updates over HTTPS via the Acme Update Service"
        )

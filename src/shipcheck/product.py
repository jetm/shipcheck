"""Product metadata loading and validation for shipcheck.

The CRA evidence layer requires a declarative description of the product being
audited: who makes it, how long it is supported, where to report
vulnerabilities, and how updates are distributed. This information is supplied
via a ``product.yaml`` file.

The loader flattens the nested YAML shape into a dataclass with underscored
field names, but error messages preserve the dotted-path form (e.g.
``manufacturer.address``) so users can locate the missing field in the source
file.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

SUPPORTED_SCHEMA_VERSIONS = frozenset({1})


class ProductConfigError(ValueError):
    """Raised when ``product.yaml`` is missing, malformed, or incomplete."""


@dataclass
class ProductConfig:
    """Declarative product metadata used to render CRA evidence artefacts."""

    product_name: str
    product_type: str
    product_version: str
    manufacturer_name: str
    manufacturer_address: str
    manufacturer_contact: str
    support_period_end_date: str
    cvd_policy_url: str
    cvd_contact: str
    update_distribution_mechanism: str | None = None
    schema_version: int = 1


# Mapping of dotted-path YAML keys to the dataclass field they populate. The
# order here is the order in which missing fields are reported, which is also
# the order a human reader would scan the YAML file top-to-bottom.
_REQUIRED_FIELDS: tuple[tuple[str, str], ...] = (
    ("product.name", "product_name"),
    ("product.type", "product_type"),
    ("product.version", "product_version"),
    ("manufacturer.name", "manufacturer_name"),
    ("manufacturer.address", "manufacturer_address"),
    ("manufacturer.contact", "manufacturer_contact"),
    ("support_period.end_date", "support_period_end_date"),
    ("cvd.policy_url", "cvd_policy_url"),
    ("cvd.contact", "cvd_contact"),
)

_OPTIONAL_FIELDS: tuple[tuple[str, str], ...] = (
    ("update_distribution.mechanism", "update_distribution_mechanism"),
)


def _lookup(data: dict[str, Any], dotted: str) -> Any:
    """Return the value at ``dotted`` inside ``data`` or ``None`` if absent."""
    node: Any = data
    for part in dotted.split("."):
        if not isinstance(node, dict):
            return None
        node = node.get(part)
        if node is None:
            return None
    return node


def load_product_config(path: str | Path) -> ProductConfig:
    """Load and validate a ``product.yaml`` file.

    Raises ``ProductConfigError`` if the file is missing, cannot be parsed, uses
    an unsupported ``schema_version``, or omits any required field. The error
    message always names the problem using the dotted-path form that appears in
    the YAML source.
    """
    resolved = Path(path)

    if not resolved.exists():
        raise ProductConfigError(f"product.yaml not found: {resolved}")

    try:
        with resolved.open() as fh:
            raw = yaml.safe_load(fh)
    except yaml.YAMLError as exc:
        raise ProductConfigError(f"invalid YAML in {resolved}: {exc}") from exc

    if raw is None:
        raise ProductConfigError(f"empty product config: {resolved}")
    if not isinstance(raw, dict):
        raise ProductConfigError(
            f"product config must be a mapping, got {type(raw).__name__}: {resolved}"
        )

    schema_version = raw.get("schema_version", 1)
    if not isinstance(schema_version, int) or schema_version not in SUPPORTED_SCHEMA_VERSIONS:
        raise ProductConfigError(
            f"unsupported schema_version: {schema_version!r} "
            f"(supported: {sorted(SUPPORTED_SCHEMA_VERSIONS)})"
        )

    values: dict[str, Any] = {"schema_version": schema_version}

    for dotted, field_name in _REQUIRED_FIELDS:
        value = _lookup(raw, dotted)
        if value is None or (isinstance(value, str) and not value.strip()):
            raise ProductConfigError(f"missing required field: {dotted}")
        values[field_name] = value

    for dotted, field_name in _OPTIONAL_FIELDS:
        value = _lookup(raw, dotted)
        if isinstance(value, str) and not value.strip():
            value = None
        values[field_name] = value

    return ProductConfig(**values)

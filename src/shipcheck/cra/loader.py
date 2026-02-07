"""Loader for the CRA (Cyber Resilience Act) requirement catalog.

The catalog is a verbatim transcription of the Annex I, Annex II, and
Annex VII requirements of Regulation (EU) 2024/2847, pinned to the OJ L
publication dated 20 November 2024. It is shipped as a static YAML file
alongside this module and loaded once at import time.

Per design Decision 3, the catalog is exposed as an immutable structure:
``CraCatalog`` and ``CraRequirement`` are frozen dataclasses, and
``requirements`` is wrapped in ``MappingProxyType`` so callers cannot
mutate the shared state.

The ``source_version`` field must match the pinned publication string
exactly; a refresh of the regulation is a deliberate, human-reviewed
change (see design risks - "CRA catalog drift").
"""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING

import yaml

if TYPE_CHECKING:
    from collections.abc import Mapping

PINNED_SOURCE_VERSION = "OJ L, 20.11.2024"

_CATALOG_PATH = Path(__file__).parent / "requirements.yaml"


class CraCatalogError(ValueError):
    """Raised when ``requirements.yaml`` is missing, malformed, or unpinned."""


@dataclass(frozen=True)
class CraRequirement:
    """A single CRA requirement transcribed from the regulation.

    Attributes:
        id: Stable identifier (e.g. ``I.P1.a``, ``II.3``, ``VII.7``).
        annex: Annex roman numeral without the word "Annex" (``I``, ``II``,
            ``VII``).
        part: Sub-part of Annex I as a string (``"1"`` or ``"2"``).
            Empty string for annexes without sub-parts (II, VII).
            Kept as a string to preserve the encoding used by the YAML
            source - never coerce to int.
        item: Item identifier within the annex/part (``"a"``..``"m"`` for
            Annex I Part I; ``"1"``..``"N"`` otherwise).
        title: Short human-readable label (editorial, not from the OJ text).
        text: Verbatim requirement text from the regulation.
    """

    id: str
    annex: str
    part: str
    item: str
    title: str
    text: str


@dataclass(frozen=True)
class CraCatalog:
    """Immutable CRA requirement catalog pinned to a regulation publication.

    Attributes:
        requirements: Read-only mapping from requirement id to
            :class:`CraRequirement`. Backed by ``MappingProxyType`` so
            assignment and deletion raise ``TypeError``.
        source_version: The OJ L publication string the catalog was
            transcribed from (e.g. ``"OJ L, 20.11.2024"``).
    """

    requirements: Mapping[str, CraRequirement] = field(
        default_factory=lambda: MappingProxyType({})
    )
    source_version: str = ""


def _build_catalog(raw: object) -> CraCatalog:
    """Construct a :class:`CraCatalog` from parsed YAML content.

    Validates the pinned ``source_version`` and the structural shape of the
    ``requirements`` list. All string fields are preserved verbatim -
    notably ``part`` stays as a string so Annex I sub-parts compare equal
    to ``"1"``/``"2"`` rather than ``1``/``2``.
    """
    if not isinstance(raw, dict):
        raise CraCatalogError(
            "requirements.yaml must contain a top-level mapping"
        )

    source_version = raw.get("source_version")
    if source_version != PINNED_SOURCE_VERSION:
        raise CraCatalogError(
            f"requirements.yaml source_version must be "
            f"{PINNED_SOURCE_VERSION!r}, got {source_version!r}"
        )

    entries = raw.get("requirements")
    if not isinstance(entries, list) or not entries:
        raise CraCatalogError(
            "requirements.yaml must define a non-empty 'requirements' list"
        )

    built: dict[str, CraRequirement] = {}
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise CraCatalogError(
                f"requirements[{index}] must be a mapping, got {type(entry).__name__}"
            )
        try:
            req = CraRequirement(
                id=str(entry["id"]),
                annex=str(entry["annex"]),
                part=str(entry["part"]) if entry["part"] is not None else "",
                item=str(entry["item"]),
                title=str(entry["title"]),
                text=str(entry["text"]),
            )
        except KeyError as exc:
            raise CraCatalogError(
                f"requirements[{index}] missing required field {exc.args[0]!r}"
            ) from exc

        if req.id in built:
            raise CraCatalogError(f"duplicate requirement id {req.id!r}")
        built[req.id] = req

    return CraCatalog(
        requirements=MappingProxyType(built),
        source_version=source_version,
    )


@lru_cache(maxsize=1)
def load_catalog() -> CraCatalog:
    """Load and return the CRA requirement catalog (cached singleton).

    Returns:
        An immutable :class:`CraCatalog` with all 38 requirements from
        Annex I (Parts I and II), Annex II, and Annex VII of Regulation
        (EU) 2024/2847.

    Raises:
        CraCatalogError: If ``requirements.yaml`` is missing, malformed,
            or its ``source_version`` does not match
            :data:`PINNED_SOURCE_VERSION`.
    """
    try:
        with _CATALOG_PATH.open("r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh)
    except FileNotFoundError as exc:
        raise CraCatalogError(
            f"CRA catalog file not found at {_CATALOG_PATH}"
        ) from exc
    except yaml.YAMLError as exc:
        raise CraCatalogError(
            f"failed to parse {_CATALOG_PATH}: {exc}"
        ) from exc

    return _build_catalog(raw)


def is_valid_id(id: str) -> bool:  # noqa: A002 - matches documented API
    """Return ``True`` if ``id`` is a known CRA requirement identifier.

    Uses the cached :func:`load_catalog` singleton, so repeated lookups
    are O(1) and do not re-read the YAML file.
    """
    if not id:
        return False
    return id in load_catalog().requirements

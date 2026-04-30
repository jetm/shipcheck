"""Synthetic SPDX 3.0 fixture generator scaffold.

Builds a Yocto-shaped SPDX 3.0 JSON-LD document for shipcheck's parser
tests. The shape is patterned after Bootlin's `Spdx3SbomBuilder` in
`sbom-cve-check` (see ``README.md`` for the upstream reference and pinned
commit). No Bootlin code is copied; this module is independent and
Apache-2.0.

The generator imports ``spdx_python_model.bindings.v3_0_1`` for its
canonical enum values (``RelationshipType``, ``LifecycleScopeType``,
``ExternalIdentifierType``, ``software_SoftwarePurpose``) so the emitted
strings match what the SPDX 3.0.1 spec defines and what Yocto's
``create-spdx-3.0.bbclass`` emits at runtime. Element dicts are
assembled by hand in the JSON-LD ``@graph`` shape produced by the
library's serializer (``type`` field, ``spdxId`` field, blank-node
references for inline ``CreationInfo``).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from spdx_python_model.bindings import v3_0_1 as spdx30

ROOTFS_BUILD_TYPE = "http://openembedded.org/bitbake/do_create_rootfs_spdx/rootfs"
RECIPE_BUILD_TYPE = "http://openembedded.org/bitbake/do_create_spdx/recipe"

_NS = "https://example.com/spdxdocs/shipcheck-fixture"
_SPEC_VERSION = "3.0.1"
_CONTEXT = "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"
_CREATION_INFO_REF = "_:CreationInfo0"


def _short(iri: str) -> str:
    """Return the JSON-LD short form for an SPDX 3.0 IRI value.

    The bindings expose enum-valued fields as full IRIs
    (``https://spdx.org/rdf/3.0.1/terms/.../<short>``) but the JSON-LD
    serializer emits the trailing token (``archive``, ``hasInput``,
    ``cpe23``, ``build``). Yocto's ``create-spdx-3.0.bbclass`` writes
    documents in the same short form, so the fixture mirrors it.
    """
    return iri.rsplit("/", 1)[-1]


def _spdxid(kind: str, name: str) -> str:
    return f"{_NS}/{kind}/{name}"


def _creation_info() -> dict[str, Any]:
    return {
        "type": "CreationInfo",
        "@id": _CREATION_INFO_REF,
        "specVersion": _SPEC_VERSION,
        "created": datetime(2026, 4, 30, 0, 0, 0, tzinfo=UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "createdBy": [_spdxid("agent", "shipcheck-fixture-tool")],
    }


def _agent() -> dict[str, Any]:
    return {
        "type": "SoftwareAgent",
        "spdxId": _spdxid("agent", "shipcheck-fixture-tool"),
        "creationInfo": _CREATION_INFO_REF,
        "name": "shipcheck-fixture-tool",
    }


def _sbom(image_spdx_id: str) -> dict[str, Any]:
    return {
        "type": "software_Sbom",
        "spdxId": _spdxid("sbom", "rootfs"),
        "creationInfo": _CREATION_INFO_REF,
        "name": "rootfs-sbom",
        "rootElement": [image_spdx_id],
    }


def _rootfs_package(image_name: str) -> dict[str, Any]:
    return {
        "type": "software_Package",
        "spdxId": _spdxid("package", image_name),
        "creationInfo": _CREATION_INFO_REF,
        "name": image_name,
        "software_primaryPurpose": _short(spdx30.software_SoftwarePurpose.archive),
    }


def _rootfs_build(image_name: str) -> dict[str, Any]:
    return {
        "type": "build_Build",
        "spdxId": _spdxid("build", "rootfs"),
        "creationInfo": _CREATION_INFO_REF,
        "name": f"{image_name}:do_create_rootfs_spdx:rootfs",
        "build_buildType": ROOTFS_BUILD_TYPE,
    }


def _recipe_build(recipe_name: str) -> dict[str, Any]:
    return {
        "type": "build_Build",
        "spdxId": _spdxid("build", f"recipe-{recipe_name}"),
        "creationInfo": _CREATION_INFO_REF,
        "name": f"{recipe_name}:do_create_spdx:recipe",
        "build_buildType": RECIPE_BUILD_TYPE,
    }


def _runtime_package(name: str, version: str, cpe: str, purl: str) -> dict[str, Any]:
    return {
        "type": "software_Package",
        "spdxId": _spdxid("package", name),
        "creationInfo": _CREATION_INFO_REF,
        "name": name,
        "software_packageVersion": version,
        "software_primaryPurpose": _short(spdx30.software_SoftwarePurpose.install),
        "externalIdentifier": [
            {
                "type": "ExternalIdentifier",
                "externalIdentifierType": _short(spdx30.ExternalIdentifierType.cpe23),
                "identifier": cpe,
            },
            {
                "type": "ExternalIdentifier",
                "externalIdentifierType": _short(spdx30.ExternalIdentifierType.packageUrl),
                "identifier": purl,
            },
        ],
    }


def _scoped_relationship(
    rel_id: str,
    from_id: str,
    to_ids: list[str],
    relationship_type: str,
) -> dict[str, Any]:
    return {
        "type": "LifecycleScopedRelationship",
        "spdxId": _spdxid("relationship", rel_id),
        "creationInfo": _CREATION_INFO_REF,
        "from": from_id,
        "to": to_ids,
        "relationshipType": relationship_type,
        "scope": _short(spdx30.LifecycleScopeType.build),
    }


def build_yocto_shaped_spdx3() -> dict[str, Any]:
    """Return a Yocto-shaped SPDX 3.0.1 JSON-LD document as a dict.

    The document carries a ``CreationInfo`` Element, a ``software_Sbom``
    collection with one ``rootElement``, a rootfs ``software_Package``
    archive, a ``do_create_rootfs_spdx/rootfs`` ``build_Build``, two
    ``do_create_spdx/recipe`` ``build_Build`` Elements, and two runtime
    ``software_Package`` Elements with CPE23 and PURL
    ``externalIdentifier`` entries. ``hasInput`` / ``hasOutput`` scoped
    relationships connect the builds to their package inputs and outputs.

    The function is deterministic: identical input produces identical
    output, including ``spdxId`` values.
    """
    image_name = "test-image"
    rootfs_pkg = _rootfs_package(image_name)
    rootfs_pkg_id = rootfs_pkg["spdxId"]

    rootfs_build = _rootfs_build(image_name)
    recipe_build_a = _recipe_build("busybox")
    recipe_build_b = _recipe_build("openssl")

    pkg_a = _runtime_package(
        name="busybox",
        version="1.36.1",
        cpe="cpe:2.3:a:busybox:busybox:1.36.1:*:*:*:*:*:*:*",
        purl="pkg:generic/busybox@1.36.1",
    )
    pkg_b = _runtime_package(
        name="openssl",
        version="3.2.1",
        cpe="cpe:2.3:a:openssl:openssl:3.2.1:*:*:*:*:*:*:*",
        purl="pkg:generic/openssl@3.2.1",
    )

    rels = [
        _scoped_relationship(
            rel_id="rootfs-output",
            from_id=rootfs_build["spdxId"],
            to_ids=[rootfs_pkg_id],
            relationship_type=_short(spdx30.RelationshipType.hasOutput),
        ),
        _scoped_relationship(
            rel_id="rootfs-input",
            from_id=rootfs_build["spdxId"],
            to_ids=[pkg_a["spdxId"], pkg_b["spdxId"]],
            relationship_type=_short(spdx30.RelationshipType.hasInput),
        ),
        _scoped_relationship(
            rel_id="recipe-busybox-output",
            from_id=recipe_build_a["spdxId"],
            to_ids=[pkg_a["spdxId"]],
            relationship_type=_short(spdx30.RelationshipType.hasOutput),
        ),
        _scoped_relationship(
            rel_id="recipe-openssl-output",
            from_id=recipe_build_b["spdxId"],
            to_ids=[pkg_b["spdxId"]],
            relationship_type=_short(spdx30.RelationshipType.hasOutput),
        ),
    ]

    graph: list[dict[str, Any]] = [
        _creation_info(),
        _agent(),
        _sbom(rootfs_pkg_id),
        rootfs_pkg,
        rootfs_build,
        recipe_build_a,
        recipe_build_b,
        pkg_a,
        pkg_b,
        *rels,
    ]

    return {
        "@context": _CONTEXT,
        "@graph": graph,
    }

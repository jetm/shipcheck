#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.13"
# dependencies = []
# ///
"""Slice an image-level SPDX 3.0 rootfs document down to a 500 KB fixture.

Yocto's ``create-spdx-3.0.bbclass`` emits a single image-level
``*.rootfs.spdx.json`` file that carries the ``software_Sbom`` Element
plus a transitive ``@graph`` of every recipe, package, file, build,
relationship, and security finding. For a real ``core-image-minimal``
build that file is ~13 MB - far over the 500 KB pilot fixture budget.

This slicer walks the @graph from the Sbom Element outward, keeping a
small, fully-self-consistent transitive subset that exercises shipcheck's
SPDX 3.0 validator (CreationInfo metadata, rootElement resolution,
per-Package field-alias parsing). The slim file lands at
``tests/fixtures/pilot_real/spdx3/.../<image>.rootfs.spdx.json`` so the
integration test can load real Yocto bytes, not synthetic ones.

Algorithm:

1. Parse @graph and locate the unique ``software_Sbom`` Element.
2. Seed the keep-set with the Sbom Element plus the ``CreationInfo`` it
   references via ``creationInfo``.
3. Resolve each ``rootElement`` spdxId to its target Element. The first
   target with ``software_primaryPurpose == "archive"`` is kept; the
   ``filesystemImage`` File targets are dropped from the rootElement
   list to keep the closure small.
4. Pick a small representative subset of ``software_Package`` Elements
   (default 5: a mix of source-purpose and install-purpose) so per-Package
   scoring exercises the validator without dragging in all 128 packages.
5. For every kept Element, follow IRI/blank-node spdxId references in
   any field value (string or list of strings) and pull the referenced
   Element into the keep-set, up to a bounded BFS depth (default 2).
6. Re-emit @graph in original order, restricted to the keep-set, with
   the Sbom's rootElement narrowed to just the entries that resolve into
   that set.
7. Verify the output is JSON-serialisable and under the budget; if over,
   drop one Package and retry.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import deque
from pathlib import Path

DEFAULT_BUDGET_BYTES = 500_000
DEFAULT_MAX_PACKAGES = 5
DEFAULT_MAX_DEPTH = 2
DEFAULT_INPUT = Path(
    "pilots/0006-poky-scarthgap-spdx3/build/tmp/deploy/images/qemux86-64/"
    "core-image-minimal-qemux86-64.rootfs.spdx.json"
)
DEFAULT_OUTPUT = Path(
    "tests/fixtures/pilot_real/spdx3/tmp/deploy/images/qemux86-64/"
    "core-image-minimal-qemux86-64.rootfs.spdx.json"
)

_SBOM_TYPE = "software_Sbom"
_PACKAGE_TYPE = "software_Package"
_CREATION_INFO_TYPE = "CreationInfo"
_ARCHIVE_PURPOSE = "archive"


def _die(msg: str) -> None:
    print(f"extract_pilot_fixture_spdx3: {msg}", file=sys.stderr)
    sys.exit(1)


def _element_type(element: dict) -> str:
    value = element.get("type") or element.get("@type") or ""
    return value if isinstance(value, str) else ""


def _index_by_id(graph: list[dict]) -> dict[str, dict]:
    """Index Elements by ``spdxId`` (Identified) and ``@id`` (BlankNode)."""
    index: dict[str, dict] = {}
    for element in graph:
        if not isinstance(element, dict):
            continue
        for key in ("spdxId", "@id"):
            value = element.get(key)
            if isinstance(value, str) and value:
                index[value] = element
    return index


def _string_refs_in(value: object) -> list[str]:
    """Return all string values reachable from ``value``.

    SPDX 3.0 cross-references are always JSON strings (IRIs or blank-node
    labels like ``_:CreationInfo67``). Walks scalars, lists, and dicts.
    """
    refs: list[str] = []
    if isinstance(value, str):
        if value:
            refs.append(value)
    elif isinstance(value, list):
        for item in value:
            refs.extend(_string_refs_in(item))
    elif isinstance(value, dict):
        for k, v in value.items():
            if k in ("type", "@type"):
                continue
            refs.extend(_string_refs_in(v))
    return refs


def _select_packages(graph: list[dict], cap: int) -> list[dict]:
    """Pick a small representative slice of software_Package Elements.

    Prefer install-purpose packages (they carry name + version), then
    fill from source-purpose. Returns at most ``cap`` packages.
    """
    install_pkgs: list[dict] = []
    archive_pkgs: list[dict] = []
    source_pkgs: list[dict] = []
    for element in graph:
        if not isinstance(element, dict):
            continue
        if _element_type(element) != _PACKAGE_TYPE:
            continue
        purpose = element.get("software_primaryPurpose")
        if purpose == "install":
            install_pkgs.append(element)
        elif purpose == _ARCHIVE_PURPOSE:
            archive_pkgs.append(element)
        else:
            source_pkgs.append(element)
    # Stable, deterministic order via spdxId so the slicer is reproducible.
    install_pkgs.sort(key=lambda e: e.get("spdxId", ""))
    source_pkgs.sort(key=lambda e: e.get("spdxId", ""))
    selected: list[dict] = list(archive_pkgs)
    selected.extend(install_pkgs)
    if len(selected) < cap:
        need = cap - len(selected)
        selected.extend(source_pkgs[:need])
    return selected[:cap]


def _slice(
    graph: list[dict],
    *,
    max_packages: int,
    max_depth: int,
) -> list[dict]:
    """Return a subset of @graph that preserves Sbom + rootElement chain.

    Walks outward from the Sbom Element keeping referenced Elements up to
    ``max_depth`` BFS hops. Adds at most ``max_packages`` software_Package
    Elements to bound output size.
    """
    by_id = _index_by_id(graph)

    sbom = next(
        (el for el in graph if isinstance(el, dict) and _element_type(el) == _SBOM_TYPE),
        None,
    )
    if sbom is None:
        _die("no software_Sbom Element found in input @graph")
    assert sbom is not None  # for type checker

    kept_ids: set[int] = {id(sbom)}

    # Seed: CreationInfo for the Sbom itself.
    sbom_ci_ref = sbom.get("creationInfo")
    if isinstance(sbom_ci_ref, str):
        ci = by_id.get(sbom_ci_ref)
        if ci is not None:
            kept_ids.add(id(ci))

    # Always keep at least one CreationInfo whose specVersion starts with "3.".
    # Prefer the one referenced by the Sbom; fall back to any specVersion-bearing
    # CreationInfo so the validator's _find_creation_info / _validate_spdx3_metadata
    # has data to assert.
    spec_ci = next(
        (
            el
            for el in graph
            if isinstance(el, dict)
            and _element_type(el) == _CREATION_INFO_TYPE
            and isinstance(el.get("specVersion"), str)
            and el["specVersion"].startswith("3.")
        ),
        None,
    )
    if spec_ci is not None:
        kept_ids.add(id(spec_ci))

    # Pick a representative archive root + small Package set.
    selected_pkgs = _select_packages(graph, max_packages)
    for pkg in selected_pkgs:
        kept_ids.add(id(pkg))

    # Find the archive-purpose root from rootElement (the image package).
    roots = sbom.get("rootElement", [])
    archive_root: dict | None = None
    if isinstance(roots, list):
        for ref in roots:
            if not isinstance(ref, str):
                continue
            target = by_id.get(ref)
            if target is None:
                continue
            if target.get("software_primaryPurpose") == _ARCHIVE_PURPOSE:
                archive_root = target
                kept_ids.add(id(target))
                break

    # BFS to pull in transitively-referenced Elements (CreationInfo,
    # licenseExpressions, hashes, etc.).
    queue: deque[tuple[dict, int]] = deque()
    seed_targets: list[dict] = list(selected_pkgs)
    if archive_root is not None and archive_root not in seed_targets:
        seed_targets.append(archive_root)
    if spec_ci is not None and spec_ci not in seed_targets:
        seed_targets.append(spec_ci)
    for el in seed_targets:
        queue.append((el, 0))

    while queue:
        element, depth = queue.popleft()
        if depth >= max_depth:
            continue
        for value in element.values():
            for ref in _string_refs_in(value):
                target = by_id.get(ref)
                if target is None:
                    continue
                if id(target) in kept_ids:
                    continue
                kept_ids.add(id(target))
                queue.append((target, depth + 1))

    # Re-emit in original graph order so the slice keeps Yocto's layout.
    return [el for el in graph if isinstance(el, dict) and id(el) in kept_ids]


def _narrow_root_element(sliced: list[dict], kept_ids: set[str]) -> None:
    """Drop rootElement entries whose target is not in the slice.

    The slice may keep only the archive root (image package); the
    filesystemImage File entries are typically dropped because the slicer
    selects packages, not files. Mutates the Sbom Element in place.
    """
    for element in sliced:
        if _element_type(element) != _SBOM_TYPE:
            continue
        roots = element.get("rootElement")
        if not isinstance(roots, list):
            continue
        narrowed = [r for r in roots if isinstance(r, str) and r in kept_ids]
        element["rootElement"] = narrowed
        return


def _serialise(doc: dict) -> bytes:
    return (json.dumps(doc, indent=2, sort_keys=False) + "\n").encode("utf-8")


def _slice_until_under_budget(
    doc: dict,
    *,
    budget: int,
    max_packages: int,
    max_depth: int,
) -> tuple[dict, int]:
    """Re-slice with progressively fewer packages until the output fits."""
    graph = doc["@graph"]
    pkg_count = max_packages
    while pkg_count >= 1:
        sliced_graph = _slice(graph, max_packages=pkg_count, max_depth=max_depth)
        kept_ids: set[str] = set()
        for element in sliced_graph:
            for key in ("spdxId", "@id"):
                value = element.get(key)
                if isinstance(value, str) and value:
                    kept_ids.add(value)
        _narrow_root_element(sliced_graph, kept_ids)
        out_doc = {"@context": doc.get("@context", []), "@graph": sliced_graph}
        size = len(_serialise(out_doc))
        if size <= budget:
            return out_doc, size
        pkg_count -= 1
    _die(f"cannot fit slice under {budget} bytes even with 1 package")
    raise RuntimeError("unreachable")  # for type checker


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--budget-bytes", type=int, default=DEFAULT_BUDGET_BYTES)
    parser.add_argument("--max-packages", type=int, default=DEFAULT_MAX_PACKAGES)
    parser.add_argument("--max-depth", type=int, default=DEFAULT_MAX_DEPTH)
    args = parser.parse_args()

    if not args.input.is_file():
        _die(f"--input {args.input} does not exist or is not a file")

    doc = json.loads(args.input.read_text())
    if not isinstance(doc, dict) or "@graph" not in doc:
        _die("input is not an SPDX 3.0 JSON-LD document with @graph")

    out_doc, size = _slice_until_under_budget(
        doc,
        budget=args.budget_bytes,
        max_packages=args.max_packages,
        max_depth=args.max_depth,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(_serialise(out_doc))

    pkg_count = sum(
        1 for el in out_doc["@graph"] if isinstance(el, dict) and _element_type(el) == _PACKAGE_TYPE
    )
    sbom_count = sum(
        1 for el in out_doc["@graph"] if isinstance(el, dict) and _element_type(el) == _SBOM_TYPE
    )
    print(
        f"wrote {args.output} ({size} bytes, "
        f"{len(out_doc['@graph'])} graph entries, "
        f"{sbom_count} Sbom, {pkg_count} Package)"
    )


if __name__ == "__main__":
    main()

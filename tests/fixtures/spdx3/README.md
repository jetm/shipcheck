# SPDX 3.0 Synthetic Fixtures

## Purpose

This directory provides a programmatic generator for Yocto-shaped
SPDX 3.0.1 JSON-LD documents used by the `sbom-generation` check tests.
The fixture mirrors the document shape that Yocto's
`create-spdx-3.0.bbclass` emits at runtime: a single `software_Sbom`
collection rooted at a rootfs `software_Package` archive, a
`do_create_rootfs_spdx/rootfs` `build_Build`, recipe-level
`do_create_spdx/recipe` `build_Build` elements, runtime `software_Package`
elements carrying CPE23 and PURL `externalIdentifier` entries, and
`hasInput`/`hasOutput` `LifecycleScopedRelationship` elements with
`scope = build`.

The generator produces in-memory `dict` objects (not JSON strings) so
tests can introspect the document directly. Identifiers are
deterministic; identical input produces identical output.

## Structural reference

The document shape is patterned after Bootlin's `Spdx3SbomBuilder` test
fixture in the `sbom-cve-check` project:

- Repository: <https://github.com/bootlin/sbom-cve-check>
- File: `tests/checker/sbom_spdx3.py` on the `main` branch
- Pinned upstream commit at authoring time:
  `30a5b3e94bbdd27557d3b8b7b1917b9980fc2564`

The shape itself (rootfs Build with `hasOutput` to a rootfs Package
archive, recipe Builds with `hasOutput` to runtime Packages, runtime
Packages carrying `externalIdentifier` entries) is dictated by Yocto's
emit pipeline and the SPDX 3.0 specification, not invented by Bootlin.

**No Bootlin code is copied.** This generator is an independent
re-implementation under the project's Apache-2.0 license. Bootlin's
fixture builder relies on an internal `ObjectSet` helper class that is
not part of `spdx-python-model`; this generator constructs the JSON-LD
`@graph` directly, sourcing canonical short-form values
(`archive`, `hasInput`, `cpe23`, `build`, etc.) from the
`spdx_python_model.bindings.v3_0_1` enums to match the bytes that
`create-spdx-3.0.bbclass` produces.

# Fixture provenance — SPDX 3.0 slice

This fixture is a minimized slice of the pilot 0006 Yocto build, committed
for regression tests so shipcheck's SPDX 3.0 validator exercises real
bitbake output paths in CI without running a full pilot.

## Source

- poky commit: `cb2dcb4963e5fbe449f1bcb019eae883ddecc8ec`
- poky branch: `scarthgap` (LTS)
- build target: `core-image-minimal`
- machine: `qemux86-64`
- distro: `poky`
- SPDX class: `create-spdx-3.0` (opt-in via `INHERIT:remove = "create-spdx"; INHERIT += "create-spdx-3.0"`)
- specVersion observed: `3.0.1`
- extraction date: `2026-04-30`

## Pilot reference

`pilots/0006-poky-scarthgap-spdx3/kas.yml` is the build configuration that
produced these files. See that pilot's `REPORT.md` for the full build-host
log and gating outcome.

## Fixture form decision

Image-level (Sbom-rooted) slice.

The full image-level rootfs SPDX 3.0 file
(`tmp/deploy/images/qemux86-64/core-image-minimal-qemux86-64.rootfs.spdx.json`)
weighs ~13 MB on this build with 18,204 `@graph` entries (1 `software_Sbom`,
278 `CreationInfo`, 128 `software_Package`, 12,264
`security_VexFixedVulnAssessmentRelationship`, etc.). Task 9.1
(ground-truth reconciliation) replaces the v0.0.5-era four recipe-level
documents with a transitive-closure slice of the image-level file so the
real fixture exercises the validator's `software_Sbom`-rooted path,
matching the runtime artifact shipcheck reads on a real build.

The slice is produced by `scripts/extract_pilot_fixture_spdx3.py` (a
sibling to the SPDX 2.x extractor). The slicer:

- locates the unique `software_Sbom` Element,
- keeps the CreationInfo it references,
- keeps an archive-purpose root from `rootElement` plus a small,
  representative subset of `software_Package` Elements (5 by default,
  drawn deterministically from install-purpose first, then source-purpose),
- BFS-follows IRI / blank-node spdxId references for 2 hops to pull in
  any transitively-referenced Element (CreationInfo, hashes, etc.),
- second pass keeps every `Relationship` Element where `from` is a
  kept Package's `spdxId` and `relationshipType` is in the
  field-bearing allowlist (`hasConcludedLicense`, `hasDeclaredLicense`,
  `hasSuppliedBy`, `hasOriginatedBy`) - mirroring
  `SPDX3_RELATIONSHIP_TYPE_FIELD_MAP` in
  `src/shipcheck/checks/sbom.py` - and pulls each Relationship's `to`
  target Element (e.g. `simplelicensing_LicenseExpression`,
  `Organization`) plus its `creationInfo` into the slice so the
  validator's `_resolve_spdx3_field_via_relationships` path runs
  end-to-end on real Yocto bytes,
- narrows the Sbom's `rootElement` list to entries that resolve into
  the slice.

## Out of scope (tracked separately)

Recipe-level Yocto SPDX 3.0 files use a `SpdxDocument` root rather than
`Sbom`. shipcheck's `_validate_spdx3_root_element` only validates Sbom
roots today. Whether to also validate recipe-level `SpdxDocument`-rooted
documents in v0.0.7+ is tracked under follow-up signal **SIG-013**, not
in the spdx-3-validation change.

## Files committed

- `tmp/deploy/images/qemux86-64/core-image-minimal-qemux86-64.rootfs.spdx.json`
  — ~14 KB, 24 `@graph` entries (1 `software_Sbom`, 5 `software_Package`,
  10 `CreationInfo`, 4 `Relationship` (all `hasConcludedLicense`), 2
  `simplelicensing_LicenseExpression`, 1 `Organization`, 1 `Tool`).

Total: ~18 KB (well under the 500 KB pilot fixture budget).

## Real-fixture scoring expectations

The integration test in `tests/test_checks/test_sbom.py` expects a
partial 20/50 score on this fixture: 10 (format) + 5 (metadata) + 5
(rootElement resolves) + 0 (per-Package). The slice retains four
`hasConcludedLicense` Relationship Elements (one per install Package),
so the validator's `_resolve_spdx3_field_via_relationships` path
resolves the `license` field for those packages on this real fixture
- but the per-Package score is still 0 because no Package clears all
five logical fields. Yocto Scarthgap's `create-spdx-3.0.bbclass` does
not emit `hasSuppliedBy` Relationships (so `supplier` is missing for
every Package) and emits `verifiedUsing` only on source-purpose
Packages, not the install-purpose Packages this slice keeps (so
`checksums` is missing). The archive-purpose Package
(`core-image-minimal`) additionally lacks `software_packageVersion`
and any Relationship-encoded license. None of the 5 Packages clear all
five logical fields, so the proportional score is 0/30.

That floor is a Yocto-encoding gap, not a validator bug; the synthetic
fixture exercises the fully-compliant 50/50 path. See
`audits/0003-spdx3-mapping/upstream-poky-spdx3.md` for the smallest
upstream patch that would lift this real-fixture score to 50/50.

## Regenerate

```bash
# Regenerate the underlying build (produces ~13 MB of SPDX 3.0 output)
kas-container build pilots/0006-poky-scarthgap-spdx3/kas.yml

# Re-slice the image-level rootfs SPDX 3.0 file under 500 KB
uv run scripts/extract_pilot_fixture_spdx3.py
```

The slicer is deterministic given the same input file (Package selection
sorts by `spdxId`), so re-running it on the same build produces a
byte-identical fixture.

Refresh when poky Scarthgap point-releases shift SPDX 3.0 output layouts
or when shipcheck's discovery logic changes. See `docs/pilot.md` for the
full regeneration workflow.

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
- narrows the Sbom's `rootElement` list to entries that resolve into
  the slice.

The synthetic fixture from task 1.2 (`tests/fixtures/spdx3/generator.py`)
remains the ground truth for the full Yocto-shaped JSON-LD with
relationships and externalIdentifier objects; the real fixture is the
ground truth for what the validator will actually score on a live build.

## Out of scope (tracked separately)

Recipe-level Yocto SPDX 3.0 files use a `SpdxDocument` root rather than
`Sbom`. shipcheck's `_validate_spdx3_root_element` only validates Sbom
roots today. Whether to also validate recipe-level `SpdxDocument`-rooted
documents in v0.0.7+ is tracked under follow-up signal **SIG-013**, not
in the spdx-3-validation change.

## Files committed

- `tmp/deploy/images/qemux86-64/core-image-minimal-qemux86-64.rootfs.spdx.json`
  — ~9 KB, 16 `@graph` entries (1 `software_Sbom`, 5 `software_Package`,
  8 `CreationInfo`, 1 `Organization`, 1 `Tool`).

Total: ~13 KB (well under the 500 KB pilot fixture budget).

## Real-fixture scoring expectations

The integration test in `tests/test_checks/test_sbom.py` expects a
partial 20/50 score on this fixture: 10 (format) + 5 (metadata) + 5
(rootElement resolves) + 0 (per-Package). Yocto's image-level
`software_Package` Elements do not carry `supplier`,
`software_declaredLicense`, or per-package `verifiedUsing`; license is
expressed via separate `Relationship`/`hasConcludedLicense` Elements
pointing to `simplelicensing_LicenseExpression` Elements elsewhere in
`@graph`. That is a data-model difference from BSI v2.1.0's
field-on-Package expectation, not a validator bug. The synthetic fixture
exercises the fully-compliant path.

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

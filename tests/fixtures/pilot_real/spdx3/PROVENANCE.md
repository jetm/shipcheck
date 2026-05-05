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

Recipe-level only.

The image-level rootfs SPDX 3.0 file
(`tmp/deploy/images/qemux86-64/core-image-minimal-qemux86-64.rootfs.spdx.json`)
weighs 13.4 MB on this build — far over the 500 KB pilot fixture budget. A
slim image-level subset would lose the very rootElement-resolves and
software_Sbom semantics it would be committed to test, so the pragmatic
choice is to ship four small recipe-level documents that exercise the
JSON-LD `@graph` walker, `CreationInfo.specVersion` lookup, and
field-alias resolution paths.

The synthetic fixture from task 1.2 (`tests/fixtures/spdx3/generator.py`)
covers the `Sbom` rootElement path that recipe-level documents do not
carry.

## Files committed

- `tmp/deploy/spdx/3.0.1/qemux86_64/recipes/recipe-base-files.spdx.json` — 25 KB
- `tmp/deploy/spdx/3.0.1/qemux86_64/recipes/recipe-init-ifupdown.spdx.json` — 13 KB
- `tmp/deploy/spdx/3.0.1/qemux86_64/recipes/recipe-shadow-securetty.spdx.json` — 6 KB
- `tmp/deploy/spdx/3.0.1/qemux86_64/recipes/recipe-sysvinit-inittab.spdx.json` — 8 KB

Total: ~67 KB (well under 500 KB).

## Divergence findings (for task 9.1 reconciliation)

These deltas were observed between the synthetic fixture shape and real
Yocto SPDX 3.0 output. Task 9.1 ("Ground-truth reconciliation") is the
owner — fixes belong in `src/shipcheck/checks/sbom.py`, not in the
fixtures.

### 1. Recipe-level documents use `SpdxDocument`, not `Sbom`

Each recipe-level file has exactly one element with `type: "SpdxDocument"`
at the top of `@graph`. There is no `Sbom` Element in recipe-level
documents — Yocto only emits `software_Sbom` Elements at the image-level
(`tmp/deploy/images/<machine>/<image>.rootfs.spdx.json`).

The current `_validate_spdx3_root_element` validator (added in task 4.1)
only looks for `Sbom` Elements. Real recipe-level Yocto SPDX 3.0 files
will fail that validator. Task 9.1 must decide whether to:

- accept `SpdxDocument` as an alternative root container,
- restrict rootElement validation to documents that carry an `Sbom`
  Element, treating `SpdxDocument`-only documents as recipe-level metadata
  that does not need the rootElement check, or
- some other reconciliation backed by the BSI v2.1.0 → SPDX 3.0 mapping
  in `audits/0003-spdx3-mapping/mapping.md`.

### 2. Image-level Sbom carries the namespaced type `software_Sbom`

The 13.4 MB image-level file contains exactly one Sbom-form element, and
its type is `software_Sbom` (not bare `Sbom`). The current validator
matches on `type == "Sbom"`, which will miss the real Yocto image-level
Sbom. Task 9.1 must update the validator to accept the namespaced form.

This finding is documented here even though no image-level file is
committed to the fixture, because task 9.1's diff is the right place to
land the parser fix and the synthetic generator from task 1.2 should be
reviewed to confirm it does or does not emit the namespaced form.

## Regenerate

This fixture was extracted by hand-copy. `scripts/extract_pilot_fixture.py`
targets SPDX 2.x layouts and is not yet wired for SPDX 3.0 trees; a future
change can add a `--spdx3` flag, but doing so is out of scope for the
spdx-3-validation change.

To regenerate by hand:

1. Run `kas-container build pilots/0006-poky-scarthgap-spdx3/kas.yml`
2. Copy the four files above from
   `pilots/0006-poky-scarthgap-spdx3/build/tmp/deploy/spdx/3.0.1/qemux86_64/recipes/`
   into this directory's `tmp/deploy/spdx/3.0.1/qemux86_64/recipes/`.
3. Verify total size stays under 500 KB.

Refresh when poky Scarthgap point-releases shift SPDX 3.0 output layouts
or when shipcheck's discovery logic changes. See `docs/pilot.md` for the
full regeneration workflow.

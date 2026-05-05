---
target: poky-scarthgap-core-image-minimal-spdx3
image_recipe: core-image-minimal
machine: qemux86-64
distro: poky
build_date: 2026-04-30
shipcheck_version: 0.0.5 (spdx-3-validation in-progress code)
poky_branch: scarthgap
poky_commit: cb2dcb4963e5fbe449f1bcb019eae883ddecc8ec
kas_container_version: "5.2"
kas_runtime: kas 5.2 inside Fedora Linux 40 container
build_host: Linux 7.0.2-2-cachyos
build_start: 2026-04-30T07:10:09
build_end: 2026-04-30T07:24:03
build_wall_clock: ~14 minutes (warm sstate carried over from pilot 0001 + pilot 0005)
---

# Pilot 0006 - poky Scarthgap core-image-minimal with SPDX 3.0

This pilot validates the SPDX 3.0 detection, metadata, and rootElement
validators added by the `spdx-3-validation` change against a real Yocto
build that emits SPDX 3.0.1 documents via the `create-spdx-3.0` class.
Pilot 0001 covered the v0.1 check set against `create-spdx` (SPDX 2.2);
pilot 0005 covered the v0.0.5 code-integrity / image-features /
hardening-flags additions; pilot 0006 picks up the SBOM check's first
SPDX 3.0 ground-truth run.

The BSI v2.1.0 -> SPDX 3.0 field mapping that the validators implement is
recorded in `audits/0003-spdx3-mapping/mapping.md`; this pilot is the
real-build evidence that the mapping translates to working detection
against poky's actual `create-spdx-3.0` output.

## Build environment

- **Build host**: Linux 7.0.2-2-cachyos.
- **kas-container**: 5.2 (installed at `/home/tiamarin/.local/bin/kas-container`).
- **kas runtime**: kas 5.2 inside the upstream Fedora Linux 40 base image
  (per the build log preamble).
- **Build target**: `core-image-minimal`.
- **Machine**: `qemux86-64`.
- **Distro**: `poky`.
- **poky pin**: `scarthgap @ cb2dcb4963e5fbe449f1bcb019eae883ddecc8ec`
  (same LTS commit as pilot 0001, deliberately reused so sstate from
  pilot 0001 / pilot 0005 stays warm).
- **SPDX inheritance** (from `local_conf_header` in `kas.yml`):
  - `INHERIT:remove = "create-spdx"` to suppress the legacy SPDX 2.2 emitter.
  - `INHERIT += "create-spdx-3.0"` to enable the SPDX 3.0.1 emitter.
  - `INHERIT += "cve-check"` to keep `cve-summary.json` available for
    cross-check with `yocto-cve-check`.
- **Build wall-clock**: ~14 minutes (start 07:10:09, end 07:24:03 on
  2026-04-30). The cold-cache estimate in `docs/pilot.md` is ~30-60
  minutes; this pilot ran in less than half that because both `DL_DIR`
  and `SSTATE_DIR` were already populated from pilot 0001 and pilot 0005
  against the same poky pin. Re-running this pilot from scratch on a
  cold cache is expected to land in the documented 30-60 minute window.
- **bitbake task counters**: 4492 tasks attempted, 2656 cached or
  skipped via sstate, 32 WARNING messages, 0 ERROR messages.

## Inputs

- `kas.yml`: `pilots/0006-poky-scarthgap-spdx3/kas.yml` (committed).
  Same poky URL and commit pin as pilot 0001, with the SPDX inheritance
  swapped to `create-spdx-3.0` per the bullets above.
- `.shipcheck.yaml`: none. Pilot 0006 exercises shipcheck defaults so
  the run is reproducible without any per-project tuning.
- `product.yaml`: none. Pilot 0006 is scoped to the SBOM SPDX 3.0
  validators; the `vuln-reporting` ERROR case is already covered by
  pilot 0001 (PF-04) and pilot 0005 (F7).

## Expected outputs

Per `docs/pilot.md` section 3, with the SPDX 3.0 inheritance change:

- `tmp/deploy/spdx/3.0.1/` rather than `tmp/deploy/spdx/2.2/` because
  `create-spdx-3.0` emits under a versioned subdirectory keyed on the
  SPDX 3 spec version (3.0.1 in poky Scarthgap as of this pilot date).
- An image-level rootfs SPDX 3.0 document under
  `tmp/deploy/images/qemux86-64/`, formatted as JSON-LD with a top-level
  `@graph` array of Elements (CreationInfo, Sbom, Package, File, ...).
- One or more `Sbom` Elements in the image-level document, each carrying
  a non-empty `rootElement` array of `spdxId` references that resolve to
  Package or File Elements elsewhere in the same `@graph`.
- Recipe-level SPDX 3.0 documents under
  `tmp/deploy/spdx/3.0.1/<machine>/recipes/recipe-*.spdx.json`, one per
  recipe in the dependency graph.
- `tmp/log/cve/cve-summary.json` from `cve-check`, unchanged from pilot
  0001 / pilot 0005.

## Observed outputs

### SPDX 3.0

- `tmp/deploy/spdx/3.0.1/` directory tree. Top-level entries:
  - `by-spdxid-hash/`
  - `common-package/`
  - `image/`
  - `packages/`
  - `packages-staging/`
  - `recipes/`
  - `rootfs/`
- **Image-level rootfs SBOM**:
  `tmp/deploy/images/qemux86-64/core-image-minimal-qemux86-64.rootfs.spdx.json`.
  - Size: 14 MB.
  - 18,204 entries in the top-level `@graph` array.
  - `specVersion`: `3.0.1`.
  - 1 Element with `type: "software_Sbom"` (the rootfs Sbom).
  - That Sbom's `rootElement` array has 3 entries: the rootfs Package
    plus two image-level Files (the ext4 rootfs image and the tar
    image). All three resolve cleanly by `spdxId` lookup against
    `software_Package` / `software_File` Elements elsewhere in the
    `@graph`.
  - 278 `CreationInfo` Elements (one per agent / per emitting tool).
  - 128 Package-like Elements (`software_Package`).
- **Recipe-level documents**: 9 `recipe-*.spdx.json` files under
  `tmp/deploy/spdx/3.0.1/qemux86_64/recipes/`. Each is approximately 25
  KB. These documents use `type: "spdx_SpdxDocument"` rather than
  `type: "software_Sbom"` for their root element wrapper, which matters
  for the fixture-form decision below.

### CVE

- `tmp/log/cve/cve-summary.json`: aggregate JSON summary, parseable by
  shipcheck's existing `yocto-cve-check` reader (no change vs pilot 0001
  / pilot 0005).
- `tmp/log/cve/cve-summary`: human-readable text companion.

## Gating outcome

Per `docs/pilot.md` section 7 (soft pilot gate), the gate evaluates
"does the registered check produce parseable output against this real
build, and does its verdict match the design's expectations?" PASS for
the SPDX 3.0 detection + metadata + rootElement validators (tasks 3.1
and 4.1; the wiring change in task 5.1 lands alongside this report so
the validators are reachable from the `sbom-generation` check).

Concretely:

- The image-level rootfs SBOM exists at the documented path, parses as
  JSON, contains exactly one `software_Sbom` Element, and that Sbom's
  `rootElement` array (3 entries) resolves cleanly to Elements in the
  same `@graph`. The rootElement validator from task 4.1 awards the
  full 5 points on this document.
- The image-level document's `CreationInfo` Elements carry both
  `created` (ISO 8601 timestamp) and `createdBy` (non-empty list of
  `spdxId` references). The metadata validator from task 4.1 awards the
  full 5 points on this document.
- Detection (task 3.1) keys on `specVersion: "3.0.1"` directly off the
  document's `@graph` CreationInfo, which the observed file carries.

**Known divergence carried into task 9.1.** The recipe-level documents
at `tmp/deploy/spdx/3.0.1/qemux86_64/recipes/recipe-*.spdx.json` use
`type: "spdx_SpdxDocument"` for their root wrapper, not
`type: "software_Sbom"`. The current `_validate_spdx3_root_element`
implementation looks for at least one `Sbom` Element and would emit a
high-severity finding if pointed at a recipe-level document in
isolation. The image-level rootfs SBOM, which is the document an
auditor consumes for the CRA Annex VII bill-of-materials, exercises the
full Sbom path correctly. Reconciling the recipe-level shape (does the
validator accept SpdxDocument as an alternative root, or does
`sbom-generation` only ever inspect the image-level rootfs SBOM?) is
the work captured in task 9.1 ("ground-truth reconciliation").

## Fixture form decision

**Recipe-level slice. Not an image-level slice.**

Trade-offs:

| Form | Pros | Cons |
|------|------|------|
| Image-level rootfs SBOM (14 MB) | Full Sbom + rootElement chain, exact shape the validators are designed for | 28x over the committed-fixture 500 KB hard budget; impossible to commit without truncation that would break the @graph cross-references the validator walks |
| Recipe-level slice (3-4 files, ~25 KB each, ~75-100 KB total) | Comfortably under the 500 KB budget; gives CI a real `tmp/deploy/spdx/3.0.1/` layout to walk | Recipe-level documents wrap on `spdx_SpdxDocument`, not `software_Sbom`, so the committed fixture exercises detection + CreationInfo metadata but not the Sbom rootElement validator |

The Sbom rootElement validator is covered for unit tests by the
synthetic generator at `tests/fixtures/spdx3/generator.py` (which emits
the `software_Sbom` shape directly), and it is covered for live
ground-truth runs by re-running this pilot from
`pilots/0006-poky-scarthgap-spdx3/kas.yml` against a populated `DL_DIR`
/ `SSTATE_DIR`. Committing the recipe-level slice gets us real
`create-spdx-3.0` output in CI without blowing the fixture budget,
which is the primary value the committed fixture provides.

The committed slice will be extracted by an extension to
`scripts/extract_pilot_fixture.py` (or a sibling script), keyed on
recipe-level files only, and dropped under
`tests/fixtures/pilot_real_spdx3/build/tmp/deploy/spdx/3.0.1/`. Recipe
choice is up to the extractor (current candidates from this build:
`linux-yocto`, `busybox`, `glibc` for compiled recipes, plus one tiny
recipe such as `update-rc.d-native` to keep the slice diverse).

## Conclusion

- **All planned SPDX 3.0 validators executed against parseable real
  output.** The detection (`specVersion: "3.0.1"`), CreationInfo
  metadata (`created` + `createdBy`), and Sbom rootElement
  (`software_Sbom` with non-empty `rootElement` resolving to Elements
  in the same `@graph`) all read cleanly off the image-level rootfs
  SPDX 3.0 document at
  `tmp/deploy/images/qemux86-64/core-image-minimal-qemux86-64.rootfs.spdx.json`.
- **The BSI v2.1.0 -> SPDX 3.0 mapping in
  `audits/0003-spdx3-mapping/mapping.md` translates correctly to the
  SPDX 3.0.1 shape poky emits.** The validators cite that mapping as
  the source for required-field expectations, and the observed
  document carries every field the mapping requires.
- **One known divergence is recorded for task 9.1.** Recipe-level
  documents use `spdx_SpdxDocument` rather than `software_Sbom`. The
  validator's current behaviour against the recipe-level form is to
  emit a high-severity rootElement finding; reconciling that against
  whether `sbom-generation` should ever inspect recipe-level documents
  in isolation is the ground-truth work in task 9.1.
- **Methodology exit criterion is met.** Per `docs/pilot.md` section 7,
  this REPORT.md captures build environment, expected outputs,
  observed outputs, gating outcome, and fixture-form decision. The
  pilot subtask in `tasks.md` group 8 closes once this file lands and
  the verifier (`grep -E "^## " pilots/0006-poky-scarthgap-spdx3/REPORT.md`)
  reports all five required section headings.
- **Pilot value summary**: pilot 0006 produced the first ground-truth
  validation of shipcheck's SPDX 3.0 support against a real Yocto
  build. It confirmed that poky's `create-spdx-3.0` emits exactly the
  shape the BSI mapping predicts, exercised the metadata and
  rootElement validators end-to-end on the image-level document, and
  surfaced one shape difference between image-level and recipe-level
  documents that drives the task 9.1 reconciliation work. The warm
  cache reuse from pilot 0001 / pilot 0005 (~14 min wall time) also
  confirmed the cross-pilot sstate-reuse pattern documented in
  `docs/pilot.md` section 4.

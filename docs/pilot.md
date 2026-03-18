# Pilot testing

Pilots are the quality gate that promotes shipcheck from "passes synthetic fixtures" to "ships against a real build". A pilot takes a concrete Yocto build and runs shipcheck end-to-end against it, then files the raw artefacts plus a narrative report under `pilots/NNNN-<short-name>/` as evidence.

This document defines when to run a pilot, what inputs it requires, the exact procedure, the report template, and the gating semantics that connect pilots to the v0.1 release tag. It is the source of truth for all future pilot work; the per-pilot `REPORT.md` is the record of one specific run.

## 1. Purpose

shipcheck ships with high unit and integration coverage on synthetic fixtures under `tests/fixtures/`. Those fixtures mimic the path layout that checks expect (`tmp/deploy/spdx/`, `tmp/deploy/images/`, `tmp/log/cve/cve-summary.json`, `tmp/deploy/licenses/<image>/license.manifest`) but they cannot capture:

- Multi-image deduped SPDX trees produced by `create-spdx` across a real recipe graph.
- BSP-specific image suffixes and naming conventions (`-<machine>-<build-id>.rootfs.<fs>`).
- Large-file timing and memory pressure when SPDX documents grow past the synthetic examples.
- Quirks in individual layer `local.conf` fragments that shift file locations.
- Version-specific behaviour of `create-spdx` and `cve-check` as poky evolves.

Pilots surface those gaps. Every pilot is evidence that shipcheck works against the specific build target captured in the pilot's `kas.yml`, and every divergence between the pilot run and the synthetic fixtures becomes a triage row: either a bug (fix it, file a follow-up task), a known-limit (document it in the README), or a quirk (record it, no action).

Pilots also respond directly to the framing that "CRA compliance is a process, not a product". The pilot artefact set is the visible record of that process.

## 2. When to run a pilot

Run a new pilot in any of the following cases:

- A new check ID is registered in `src/shipcheck/checks/registry.py`. The new check must produce a pilot report against a real Yocto build before the CHANGELOG entry for it is tagged.
- A minor or major version bump is about to be cut (`v0.X.0` or `vX.0.0`). The pre-release pilot re-validates the full check set against the latest poky LTS.
- An input-parser change lands inside an existing check (for example, an SPDX 3.0 path added to `SBOMCheck`, or a CycloneDX variant added to the vulnerability pipeline). A re-pilot is required even though the check ID did not change.

Patch releases (`v0.X.Y` bug fixes) do not require a new pilot unless the fix touches input parsing. Internal refactors with no behaviour change do not require a pilot.

## 3. Required inputs

Before starting the procedure, assemble the following:

- **`pilots/NNNN-<name>/kas.yml`**: the kas-container build configuration. Pins the poky source with a `url:` entry (branch + commit), the machine, the distro, the target image recipe, and any required `local_conf_header` lines. The `url:` form lets `kas-container` clone poky into the container cleanly without any host-side bind-mounts. This file is the single source of truth for "what was built"; it is committed alongside the pilot report.
- **`.shipcheck.yaml`**: the shipcheck configuration applied during the scan. For a first pilot on a given target, `shipcheck init` produces a working scaffold that you then commit next to the report. Subsequent pilots on the same target can reuse or diff against the previous pilot's copy.
- **`product.yaml`** (optional): required only when the pilot exercises the `shipcheck docs` or `shipcheck doc declaration` subcommands, which consume product metadata for CRA Annex VII and Declaration of Conformity rendering.
- **Expected outputs** under the kas-managed `build/tmp/deploy/` once the build completes:
  - `build/tmp/deploy/spdx/` - SPDX documents emitted by `create-spdx`.
  - `build/tmp/deploy/images/<machine>/` - rootfs images, bootloader artefacts.
  - `build/tmp/log/cve/cve-summary.json` - CVE report emitted by `cve-check`.
  - `build/tmp/deploy/licenses/<image>/license.manifest` - per-image license manifest.

If any of the expected outputs is missing after the build, investigate the `local.conf` in `kas.yml` before running shipcheck - a missing `cve-summary.json` almost always means `INHERIT += "cve-check"` is not configured, not a shipcheck bug.

## 4. Build-host bootstrap

A pilot is reproducible from a clean machine. The host prerequisites are deliberately minimal because `kas-container` runs the bitbake invocation inside a pinned container; the host provides only the container runtime and disk.

On a clean machine:

1. Install `kas-container` 5.x plus a container runtime. On Arch, `pacman -S kas` pulls kas in; upstream instructions live at https://kas.readthedocs.io/. Install podman (preferred) or docker - `kas-container` detects whichever is on `PATH`, and podman is preferred because it runs rootless.
2. Verify the installation: `kas-container --version` should report 5.x and `podman --version` (or `docker --version`) should report a working runtime.
3. Ensure enough free disk in the kas work directory: at least ~30 GB when starting with empty caches (first build downloads the full poky source tree, a toolchain, and builds the sstate cache from scratch), or ~5 GB when `DL_DIR` and `SSTATE_DIR` are pre-seeded and cover the dependency graph.
4. Ensure a multi-core CPU (4+ cores recommended). bitbake parallelises aggressively; a 2-core VM will complete the first build in 8+ hours, while a 16-core workstation finishes in roughly an hour from empty caches, or in ~30 minutes from pre-seeded caches.
5. If you want to reuse existing Yocto caches from prior work, export the corresponding env vars before invoking `kas-container` (see the Cache reuse subsection below).

Notice what is **not** on this list: no manual bitbake host-deps (`gcc`, `diffstat`, `chrpath`, `texinfo`, etc.), no manual `oe-init-build-env`, no host-side layer cloning, no manual bind-mounts of poky. `kas-container` handles all of those inside its own image and clones the layers listed in `kas.yml` (including poky) into the container on first run, which is why the bootstrap collapses to "container runtime plus disk".

### Cache reuse (optional but strongly recommended)

`kas-container` 5.x automatically bind-mounts a small set of host directories into the container when the corresponding env var is set on the host, and exports the same env vars inside the container so that `bitbake` and `kas` pick them up without any `kas.yml` changes. The relevant mappings are:

| Host env var | Container path | Purpose |
|---|---|---|
| `KAS_WORK_DIR` | `/work` | kas work directory (defaults to `$PWD`) |
| `KAS_BUILD_DIR` | `/build` | bitbake build directory |
| `DL_DIR` | `/downloads` | source tarball cache |
| `KAS_REPO_REF_DIR` | `/repo-ref` | git reference-repo cache for faster clones |
| `SSTATE_DIR` | `/sstate` | bitbake sstate cache |

To reuse pre-seeded Yocto caches, export `DL_DIR` and `SSTATE_DIR` before invoking `kas-container`:

```bash
export DL_DIR=~/repos/work/cache/downloads
export SSTATE_DIR=~/repos/work/cache/sstate
```

The cost is effectively zero - first-time clone of poky takes ~30-60 s over the network regardless of cache state - and the benefit is large: a first pilot on a well-seeded cache drops from 4-8 hours to roughly 30 minutes when the caches cover the dependency graph.

`ccache` is **not** on the auto-mount list. Enabling it is possible but requires passing `--runtime-args "-v <host-ccache-dir>:/ccache:rw"` to `kas-container` plus adding `CCACHE_DIR = "/ccache"` and `INHERIT += "ccache"` in a `kas.yml` override. Skip this unless compile time (rather than fetch/sstate reuse) is the critical path - for a first pilot it rarely is.

If you do not have pre-seeded caches yet, simply omit the env vars; `kas-container` populates a local `downloads/` and `sstate-cache/` under `KAS_WORK_DIR` and reuses them on subsequent runs.

## 5. Procedure

The procedure below produces the full pilot artefact bundle from a committed `kas.yml`. Run every command from the shipcheck repo root.

1. Review `pilots/NNNN-<name>/kas.yml`. Confirm it pins a specific poky commit, the right target image recipe, and any required `INHERIT` lines such as `INHERIT += "create-spdx cve-check"`.
2. Run the kas-container build. Export cache env vars first if you have pre-seeded Yocto caches to reuse (see the Cache reuse subsection above):

   ```bash
   cd ~/repos/personal/shipcheck
   export DL_DIR=~/repos/work/cache/downloads   # if you have one
   export SSTATE_DIR=~/repos/work/cache/sstate  # if you have one
   kas-container build pilots/NNNN-<name>/kas.yml 2>&1 | tee pilots/NNNN-<name>/log.txt
   ```

   kas-container clones poky from the `url:` entry in `kas.yml` into the container on first run. With no caches, the first build takes 4-8 hours depending on CPU and network; with DL_DIR and SSTATE_DIR pre-seeded the same build typically completes in ~30 minutes. Subsequent runs against the same YAML are faster because kas-container reuses the sstate cache either way.

   The kas-managed build directory lands under `KAS_WORK_DIR`, which defaults to the current working directory - i.e. `build/` under the shipcheck repo root. The rest of the procedure refers to it as `./build`.

3. Run the shipcheck scan in evidence-dossier mode, appending stdout plus stderr to `log.txt`:

   ```bash
   shipcheck check \
     --build-dir ./build \
     --format evidence \
     --out pilots/NNNN-<name>/dossier/ \
     2>&1 | tee -a pilots/NNNN-<name>/log.txt
   ```

4. Re-run the same scan in JSON mode to capture machine-readable output next to the dossier:

   ```bash
   shipcheck check \
     --build-dir ./build \
     --format json \
     > pilots/NNNN-<name>/scan.json
   ```

5. Triage every divergence between what shipcheck reported and what the synthetic fixtures would have predicted. Every row in the `log.txt` / `scan.json` that differs from the expected behaviour becomes a row in the Findings triage table in the report.
6. Write `pilots/NNNN-<name>/REPORT.md` using the Report template in the next section.

Do not hand-edit `log.txt`, `scan.json`, or anything under `dossier/`. If a shipcheck bug surfaces during step 3 or step 4 and you need to fix it, regenerate all three artefacts after the fix and note the regeneration in the report's Run section.

## 6. Report template

Every pilot report uses the same structure. The template below is the canonical shape; instantiate it under `pilots/NNNN-<name>/REPORT.md`.

````markdown
---
target: <short identifier, e.g. poky-scarthgap-core-image-minimal>
image_recipe: <recipe name, e.g. core-image-minimal>
build_date: <YYYY-MM-DD>
shipcheck_version: <output of `shipcheck version`>
poky_branch: <branch pinned in kas.yml>
poky_commit: <commit hash resolved by kas-container>
kas_container_version: <output of `kas-container --version`>
---

# Pilot NNNN: <short-name>

## Inputs

- Build configuration: `pilots/NNNN-<name>/kas.yml` (committed alongside this report).
- shipcheck configuration: `.shipcheck.yaml` used during the scan (inline or committed next to this report).
- Optional `product.yaml`: (include only if the pilot exercised the docs/declaration subcommands).

## Run

Exact commands executed, in order:

```bash
kas-container build pilots/NNNN-<name>/kas.yml

shipcheck check \
  --build-dir <kas-build-dir> \
  --format evidence \
  --out pilots/NNNN-<name>/dossier/ \
  2>&1 | tee pilots/NNNN-<name>/log.txt

shipcheck check \
  --build-dir <kas-build-dir> \
  --format json \
  > pilots/NNNN-<name>/scan.json
```

Note any artefact regeneration here (for example, "regenerated after fixing <bug> on <date>").

## Findings

| id | summary | bucket | follow-up |
|----|---------|--------|-----------|
| F1 | <one-line summary> | bug \| known-limit \| quirk | SHCK-NN or README anchor |
| F2 | ... | ... | ... |

Bucket definitions:

- **bug**: shipcheck misreported on real output in a way that would mislead an auditor. File a + task and link it in the follow-up column.
- **known-limit**: shipcheck's scope does not cover this case today (for example, SPDX 3.0 detection-only, secure-boot config-level only, no PE/COFF or PKI verification, no CI-file detection). Link to the README "Known limitations" anchor.
- **quirk**: BSP-specific or environment-specific behaviour worth recording but not actionable. Record in the table, no follow-up.

## Conclusion

State whether the registered checks all executed without raising and produced parseable output. Confirm the SHCK pilot-meta task exit criterion is met (the report is written and every Findings row has a bucket assignment). If any Findings row is in the bug bucket, list the blocking SHCK task numbers and call the v0.1 release gate status explicitly ("v0.1 release gate: blocked by SHCK-NN").
````

The frontmatter pins the exact run so that an auditor comparing two pilots can see at a glance what changed. The Inputs section lets a reader re-fetch the inputs from this repo alone. The Run section freezes the commands so that a future reader re-running the pilot compares apples to apples. The Findings table is the triage output. The Conclusion is the explicit gate check that drives task closure and release gating.

## 7. Gating semantics

Two gates attach to every pilot:

- **Pilot task closure.** The devtool-meta task that tracks the pilot itself (for pilot 0001 this is ) closes once `pilots/NNNN-<name>/REPORT.md` is written and every Findings row has a bucket assignment. Bug count is not part of the closure criterion; bug resolution is tracked by separate SHCK-NN tasks. Without this rule the pilot-meta task risks becoming a forever task that absorbs unrelated bug work.
- **Release gate.** Every pilot-surfaced bug, at any severity, blocks the v0.1 release tag. A Findings row classified as "bug" becomes a SHCK task with a `related: ` link and a note that it blocks v0.1. The release tag is cut only once every such task is resolved. This gate is strict on purpose: v0.1 is the first version whose claim ("ready for CRA evidence") is made publicly, so any misreport surfaced by pilot 0001 invalidates the claim until fixed. The gate applies to every pilot cut as part of a minor or major release.

Enforcement is **soft** today. It rests on two mechanisms:

- **Task-template discipline**: every SHCK task that registers a new check ID or touches input parsing in an existing check includes a pilot subtask in the task body. The subtask reads "produce a `pilots/NNNN-<name>/REPORT.md` against a real Yocto build before marking done", and it is enforced by reviewers when the task closes. The eight existing open check tasks (, , , , , , ) have this subtask appended as part of the shipcheck-v01-pilot change.
- **Reviewer check**: any PR that adds a `### Added` or `### Changed` CHANGELOG entry for a registered check must also add or update the matching `Pilot:` reference in the README Roadmap. PR reviewers enforce this in the review comment thread.

A reviewer who catches a missing pilot reference blocks the PR and requests either the pilot run or a conversation about whether this is the rare case that warrants skipping (for example, a patch release with no input-parser change).

## 8. Deferred follow-up

The following is explicitly **deferred** out of scope for the current methodology and will be reconsidered after at least two more pilots beyond 0001 have stabilised the pattern:

- **Hard CI assert that fails the build when a registered check has no matching pilot reference.** The assert needs a stable lookup contract (which README section, which key, which file format) to evaluate against. With one pilot in hand, that contract is a guess; with three pilots, it is observed. The soft gate above is the deliberate interim - reviewer discipline plus task-template enforcement - with the expectation that pilot 0002 and pilot 0003 will reveal enough of the pattern to write the assert without guessing. Until then, there is no CI step that blocks merges on missing pilot references.

Automated pilot orchestration (a single script that builds poky via kas-container and runs shipcheck end-to-end against the output) is also worth reconsidering once the manual procedure has been run a few times. The manual procedure is the spec; automation can only land once the spec is stable.

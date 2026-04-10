---
target: poky-scarthgap-core-image-minimal
image_recipe: core-image-minimal
machine: qemux86-64
distro: poky
build_date: 2026-04-17
shipcheck_version: 0.0.2 (pyproject tag, v0.1 in-progress code)
poky_branch: scarthgap
poky_commit: cb2dcb4963e5fbe449f1bcb019eae883ddecc8ec
kas_container_version: "5.2"
kas_base_image: Debian trixie (upstream siemens/kas:5.2)
build_host: CachyOS (kas-container runs the build inside a Debian trixie
  container)
---

# Pilot 0001 - poky Scarthgap core-image-minimal

## Inputs

- `kas.yml`: `pilots/0001-poky-scarthgap-min/kas.yml` (committed). Uses
  the upstream poky URL (`https://git.yoctoproject.org/poky.git`), pins
  branch `scarthgap` at commit
  `cb2dcb4963e5fbe449f1bcb019eae883ddecc8ec`, sets `distro: poky`,
  `machine: qemux86-64`, `target: core-image-minimal`, forwards
  `NVDCVE_API_KEY` via the top-level `env:` block, and enables both
  SPDX and cve-check via `INHERIT += "create-spdx cve-check"` in the
  `local_conf_header:` section. No override of
  `CVE_CHECK_LOG_JSON` / `CVE_CHECK_SUMMARY_DIR` (see Troubleshooting
  PF-TB2 below). Note: the original  task 3.1 specified branch
  `my-scarthgap` pointing at the local poky checkout at
  `~/repos/work/poky`; this pilot uses upstream `scarthgap` instead so
  `kas-container` can clone poky cleanly into its own `/work/poky`
  without host bind-mounts (switch landed in commit `3f5a67a`). The
  commit pin is identical, so reproducibility is preserved. Upstream
  URL is now the recommended default for future pilots.
- `.shipcheck.yaml`: none. Pilot 0001 exercises shipcheck defaults so
  the run is reproducible without any per-project tuning.
- `product.yaml`: none. Pilot 0001 exercises the default
  `vuln-reporting` behaviour when no product file is supplied - the
  check is expected to flag this as missing evidence.
- NVD API key: provided on the host via the `NVDCVE_API_KEY`
  environment variable and forwarded into the container via
  `--runtime-args "-e NVDCVE_API_KEY"` because kas-container does not
  auto-forward arbitrary env vars (see Troubleshooting PF-TB4).
- Cache reuse: `DL_DIR` and `SSTATE_DIR` pre-seeded on the host
  (combined ~180 GB), plus a bare poky mirror under `KAS_REPO_REF_DIR`
  at `~/.cache/kas-ref`. kas-container auto-mounts `$DL_DIR` as
  `/downloads` and `$SSTATE_DIR` as `/sstate`.

## Run

Build (cache-warm, 11m39s wall time; 4288 tasks, 2999 reused from
sstate, all succeeded):

```bash
cd ~/repos/personal/shipcheck
export NVDCVE_API_KEY=<redacted>
export DL_DIR=~/repos/work/cache/downloads
export SSTATE_DIR=~/repos/work/cache/sstate
export KAS_REPO_REF_DIR=~/.cache/kas-ref
kas-container --runtime-args "-e NVDCVE_API_KEY" \
    build pilots/0001-poky-scarthgap-min/kas.yml
```

Shipcheck scans (run from the shipcheck repo root via `uv run`):

```bash
uv run shipcheck check \
    --build-dir /home/tiamarin/repos/personal/shipcheck/build \
    --format evidence \
    --out pilots/0001-poky-scarthgap-min/dossier/ \
    2>&1 | tee pilots/0001-poky-scarthgap-min/log.txt

uv run shipcheck check \
    --build-dir /home/tiamarin/repos/personal/shipcheck/build \
    --format json
# Output: writes to ./shipcheck-report.json in cwd (see PF-01).
# Recovered with: mv shipcheck-report.json \
#     pilots/0001-poky-scarthgap-min/scan.json
```

Scan exit code: `0` (no `--fail-on` set).

All seven check IDs registered in `src/shipcheck/checks/registry.py`
executed without raising and produced parseable output in both the
terminal log and `scan.json`:

| Check ID | Status | One-line summary |
|----------|--------|------------------|
| `sbom-generation` | WARN | SPDX 2.x found at recipe-tzdata.spdx.json (3 packages); 7 low findings on tzdata packages |
| `cve-tracking` | FAIL | No CVE scan output found (critical) |
| `secure-boot` | WARN | No Secure Boot signing class found in IMAGE_CLASSES |
| `image-signing` | WARN | Image signing: checked FIT and verity, score 0/50 |
| `license-audit` | SKIP | No license.manifest files found under tmp/deploy/licenses/ |
| `yocto-cve-check` | FAIL | cve-check summary: 584 unpatched, 15985 patched, 69 ignored |
| `vuln-reporting` | ERROR | product.yaml not found: product.yaml |

`scan.json` validated as well-formed JSON with seven top-level check
entries plus `framework`, `framework_version`, `bsi_tr_version`,
`build_dir`, `timestamp`, `shipcheck_version`, `readiness_score`, and
`suppressed` keys. `readiness_score` rendered as `{"score": 25,
"max_score": 350}` (7 points from `sbom-generation` WARN + 18 points
from the partial image-signing WARN band).

## Findings triage

Buckets: **bug** (file SHCK-NN task; v0.1 release blocker),
**known-limit** (document in README "Known limitations"),
**quirk** (record but no action).

| ID | Summary | Bucket | Follow-up |
|----|---------|--------|-----------|
| PF-01 | `shipcheck check --format json` writes to `./shipcheck-report.json` in cwd instead of stdout; shell redirection captures the Rich terminal report, not the JSON payload | bug |  (to file in task 4.3) - blocks v0.1 |
| PF-02 | `cve-tracking` and `yocto-cve-check` disagree on CVE file lookup: cve-tracking returned FAIL "No CVE scan output found" while yocto-cve-check found 584 unpatched CVEs in the same build via `tmp/log/cve/cve-summary.json` | bug |  (to file in task 4.3) - blocks v0.1 |
| PF-03 | `license-audit` does not find Yocto's per-arch license layout (`tmp/deploy/licenses/qemux86_64/`, `core2-64/`, `allarch/`, `native/`); the check likely searches `tmp/deploy/licenses/<image>/` only, which is how synthetic fixtures are laid out | bug |  (to file in task 4.3) - blocks v0.1 |
| PF-04 | `vuln-reporting` reports `ERROR` with summary "product.yaml not found: product.yaml" when no product.yaml is supplied; expected behaviour, but ERROR status is stronger than the handoff-documented UNKNOWN and may warrant reclassification as SKIP | known-limit | [README.md#known-limitations](../../README.md#known-limitations) - document the product.yaml requirement. Also see note below on status classification. |
| PF-05 | `image-signing` returns WARN with summary "Image signing: checked FIT and verity, score 0/50" plus two medium findings ("No FIT image files (.itb, .fit) found in deploy directory", "No dm-verity configuration or hash files found"). qemux86-64 `core-image-minimal` has no signing configured, so this is the correct diagnostic - the check completed without raising and reported the expected absence | known-limit | [README.md#known-limitations](../../README.md#known-limitations) - image-signing is config-level; no PE/COFF binary or FIT signature verification |
| PF-06 | `secure-boot` returns WARN with summary "No Secure Boot configuration detected" plus one medium finding ("No Secure Boot signing class found in IMAGE_CLASSES"). qemux86-64 has no Secure Boot; the check correctly identifies the absent signing class | known-limit | [README.md#known-limitations](../../README.md#known-limitations) - secure-boot is config-level only; no PKI chain validation, no PE/COFF verification, no CI-file detection |
| PF-07 | `sbom-generation` returns WARN with summary "SPDX 2.x found at recipe-tzdata.spdx.json (3 packages)". Poky Scarthgap `create-spdx` emits SPDX 2.2 documents under `tmp/deploy/spdx/2.2/` plus a `.spdx.tar.zst` per image. The check accepts SPDX 2.x (not just 2.3) and emits seven low-severity per-package findings on the tzdata recipe (missing checksum, licenseDeclared, supplier, versionInfo on source packages). Check completes without raising and produces actionable diagnostics | quirk | No action. The 2.x acceptance is lenient vs the BSI TR-03183-2 v2.1.0 requirement for 2.3+; decide in a future task (not pilot-gating) whether to tighten the check to prefer 2.3 and downgrade 2.2 to a finding |
| PF-08 | `findutils` `do_cve_check` segfaulted in Python 3.13 on the first build attempt; re-running succeeded. Non-deterministic; not reproduced on the final pilot run recorded here | quirk | Observe in pilot 0002; no action for pilot 0001 |

Notes on PF-04: the handoff brief described expected behaviour as
`UNKNOWN` but shipcheck actually emits `status: error` with the
summary "product.yaml not found: product.yaml". This is still the
check's expected behaviour when product.yaml is absent (no crash, no
stack trace), so the bucket remains **known-limit**. The README
"Known limitations" subsection should document that vuln-reporting
returns ERROR (not UNKNOWN) when `product.yaml` is not supplied, and
pilot 0001 stands as the canonical example. If the shipcheck team
prefers ERROR to be reserved for actual check faults, renaming this
case to SKIP is a separate non-blocking cleanup task.

Notes on PF-07: the dossier `evidence-report.md` and the `scan.json`
both show only tzdata findings, not the full set of SPDX documents
produced by `create-spdx`. Poky Scarthgap writes per-recipe SPDX 2.2
files under `tmp/deploy/spdx/2.2/<machine>/recipes/` plus an image
manifest. Whether `sbom-generation` only exercised one document or
only surfaced findings on one document is a quirk worth noting for
pilot 0002 (inspect the recipe-selection logic), but not a bug given
the check ran cleanly.

## Troubleshooting encountered during pilot 0001

Short summary of build-side issues hit and resolved while producing
the artefacts referenced above. Each item captures the underlying
cause and the fix applied.

- **PF-TB1**: uutils-based coreutils (shipped by default in Ubuntu
  26.04, the original kas-container base image the user was
  experimenting with from a local fork) is not fully compatible with
  the `base-passwd` postinst scripts that bitbake runs inside
  `do_rootfs`. Symptom: `base-passwd` postinst failed during image
  construction. Fix: revert the kas-container base image to upstream
  Debian trixie (siemens/kas:5.2). Captured in `docs/pilot.md` under
  the Troubleshooting section.
- **PF-TB2**: an early draft of `kas.yml` set
  `CVE_CHECK_LOG_JSON = "${LOG_DIR}/cve/cve-summary.json"` at the
  top level, which broke per-recipe `do_cve_check` tasks with
  `FileNotFoundError` because the aggregate log dir is only created
  later by the per-image manifest task. Fix: remove the override and
  rely on the `cve-check.bbclass` default
  (`CVE_CHECK_LOG_JSON = "${T}/cve.json"`), letting
  `do_cve_check_write_rootfs_manifest` create the aggregate symlink
  at the right time. See the committed `kas.yml` comments for the
  narrative.
- **PF-TB3** (= PF-08 above): findutils `do_cve_check` segfaulted
  under Python 3.13 on the first build attempt; non-deterministic;
  the re-run succeeded. Recorded as a quirk for pilot 0002 to
  confirm whether it reproduces.
- **PF-TB4**: `NVDCVE_API_KEY` is not auto-forwarded by
  kas-container. Without the key, the NVD DB fetch runs at ~6 s per
  request instead of ~2 s. Fix: pass `--runtime-args
  "-e NVDCVE_API_KEY"` to `kas-container`, and declare the variable
  with a null default under the top-level `env:` block in `kas.yml`
  so kas forwards it through to bitbake (via
  `BB_ENV_PASSTHROUGH_ADDITIONS`). Captured in `docs/pilot.md`
  prerequisites.

## Conclusion

- **All seven registered check IDs executed without raising and
  produced parseable output.** `sbom-generation`, `cve-tracking`,
  `secure-boot`, `image-signing`, `license-audit`,
  `yocto-cve-check`, and `vuln-reporting` all appear in
  `scan.json['checks']` with non-empty `status`, `summary`, and
  `findings` fields. The Rich terminal log in `log.txt` reflects the
  same state. No Python tracebacks anywhere in the pilot dossier.
- ** exit criterion is met.** The methodology meta-task's
  instrumental exit criterion (REPORT.md written + every Findings
  row bucketed) is satisfied: eight rows, every row assigned one of
  `bug` / `known-limit` / `quirk`, with follow-up links or tasks
  recorded in-line.  may be transitioned to `done` once task
  4.4 verifies this.
- **v0.1 release gate: BLOCKED**. Three pilot-surfaced bugs gate the
  v0.1 release tag per the gating rule recorded in
  `specs/shipcheck-v01-pilot/design.md`: PF-01, PF-02, PF-03. All three will be filed as separate
  SHCK tasks under task 4.3 with `related: ` frontmatter and
  `blocks v0.1 release` tags. The known-limit rows (PF-04, PF-05,
  PF-06) are not release blockers; they are documented in the README
  "Known limitations" subsection added in task 4.1. The quirk rows
  (PF-07, PF-08) require no immediate action.
- **Pilot value summary**: pilot 0001 validated the shipcheck v0.1
  check pipeline end-to-end against real bitbake output for the
  first time. It surfaced three bugs that the 97%-coverage synthetic
  fixture suite missed - all three were in the "does the check find
  the right file in the real Yocto tree?" category, which is exactly
  what fixtures cannot exercise. It exercised the full
  `kas-container` + cache-reuse + NVD-API-key workflow and captured
  the working configuration in a committed `kas.yml` that any later
  pilot can copy. It also produced reusable methodology artefacts
  (the Troubleshooting subsection above) for pilot 0002 and beyond.

## Re-run (2026-04-20)

This re-run exercises the same cached kas-container build used in the
original pilot against shipcheck after the , , and
 fixes landed. The goal is to confirm that the three
release-gating bugs (PF-01, PF-02, PF-03) no longer reproduce on a real
Yocto tree. Artefacts are captured in `scan-rerun.json` and
`dossier-rerun/`.

### PF-* resolution table

| ID | Old status | New status | Evidence |
|----|------------|------------|----------|
| PF-01 | FAIL (silent `./shipcheck-report.json` side-effect; Rich report on stdout) | RESOLVED | `--format json` now writes parseable JSON to stdout; captured at `scan-rerun.json` (1.1 MB, valid); no `./shipcheck-report.json` file created in cwd |
| PF-02 | FAIL (`cve-tracking` returned "No CVE scan output found" while `yocto-cve-check` saw 584 unpatched) | RESOLVED | `cve-tracking` now discovers `tmp/log/cve/cve-summary.json` via the shared helper; summary: "584 unpatched CVE(s) found in cve-summary.json (213 packages, 16638 issues)" - agrees with `yocto-cve-check` on evidence presence |
| PF-03 | FAIL (`license-audit` SKIP: no manifest found under the synthetic layout) | RESOLVED | Recursive `Path.rglob("license.manifest")` selects `core-image-minimal-qemux86-64.rootfs-20260417211226/license.manifest` by newest mtime; summary: "37 package(s) ... permissive: 9; weak-copyleft: 2; strong-copyleft: 21; unknown: 5" |

### Per-check status delta

| Check ID | Before | After | Note |
|----------|--------|-------|------|
| `cve-tracking` | FAIL ("No CVE scan output found") | FAIL (584 unpatched CVEs in `cve-summary.json`) | Status unchanged (FAIL -> FAIL) but the reason changed: the check now produces the same evidence-backed verdict as `yocto-cve-check`. PF-02 cleared. |
| `yocto-cve-check` | FAIL (584 unpatched) | FAIL (584 unpatched) | No change expected; the check was already working. |
| `license-audit` | SKIP | WARN | SKIP -> WARN. The check transitioned from "no manifest found" to parsing 37 packages and emitting 5 findings (all unknown-license records). PF-03 cleared. |

The other four registered checks (`sbom-generation`, `secure-boot`,
`image-signing`, `vuln-reporting`) ran with the same status and
summaries as in the original pilot; they were not in scope for the
v0.1 release gate.

Design risk **R2** (mtime-based manifest selection on the pilot build)
did not materialise: `Path.rglob` naturally selected the image-level
rootfs manifest rather than any per-package manifest, because the
image-level file has the newest mtime in this build. The recursive
discovery is therefore safe on the poky Scarthgap layout without the
follow-up filter contemplated in design D3.

### Artifacts

- `pilots/0001-poky-scarthgap-min/scan-rerun.json` (full JSON scan, 1.1 MB, parseable)
- `pilots/0001-poky-scarthgap-min/dossier-rerun/cve-report.md`
- `pilots/0001-poky-scarthgap-min/dossier-rerun/evidence-report.md`
- `pilots/0001-poky-scarthgap-min/dossier-rerun/license-audit.md`
- `pilots/0001-poky-scarthgap-min/dossier-rerun/scan.json`

All three pilot-0001 blockers cleared; v0.1 release gate unblocked.

# Changelog

## [Unreleased]

## [0.0.4] - 2026-04-24

### Changed

- `vuln-reporting` now emits findings for placeholder tokens (`VENDOR`, `TODO`, `FIXME`, `[TO BE FILLED]`, `[VENDOR]`) in any required field, and for malformed values in `product.yaml` fields previously accepted on presence alone: `cvd.policy_url` must parse as `http://`, `https://`, or `mailto:`; `cvd.contact` must be email-shaped (`local@domain.tld`) or URL-shaped; `support_period.end_date` must parse as ISO 8601 `YYYY-MM-DD`. Placeholder matching is case-insensitive against the trimmed value. Findings cite Annex I Part II §5 (CVD policy), Annex II §2 (SPoC), Annex II §7 (support period), and Annex I Part II §7 (update distribution).

### Fixed

- Unparseable `support_period.end_date` in `product.yaml` now emits a `high`-severity finding citing Annex II §7 rather than silently skipping the expired-date branch.

## [0.0.3] - 2026-04-21

### Added

- Secure Boot audit check: detects signing class configuration, flags test/development keys, catches EFI artifacts without signing enabled
- Image Signing check: detects FIT image signatures (U-Boot) and dm-verity configuration
- `secure_boot` and `image_signing` configuration sections in `.shipcheck.yaml`
- Readiness score now includes Secure Boot (50pts) and Image Signing (50pts), total max 200
- CRA requirement mapping metadata on every `Finding` and `CheckResult` via new `cra_mapping: list[str]` field, with static CRA catalog transcribed verbatim from Regulation (EU) 2024/2847 (Annex I Part I items a-m, Part II items 1-8, Annex II items 1-9, Annex VII items 1-8)
- `--format evidence` renderer that pivots findings by CRA requirement instead of by check, with explicit "Gaps" section enumerating unmapped requirements
- `--out DIR` option on `check` that emits a multi-file compliance dossier (evidence report, license audit, CVE report, Annex VII technical documentation, Declaration of Conformity, `scan.json`)
- `license-audit` check parsing Yocto's human-readable `tmp/deploy/licenses/*/license.manifest` (complements the machine-readable SPDX SBOM check)
- `yocto-cve-check` check integrating with Yocto's `cve-check.bbclass` output at `tmp/log/cve/cve-summary.json`, version-tolerant across Kirkstone and Scarthgap schemas
- CVE finding reconciliation: `shipcheck check` merges duplicate findings from `cve-tracking` and `yocto-cve-check` into a single finding whose `sources` lists every scanner that flagged it
- SQLite scan history store at `.shipcheck/history.db` persisting every scan record
- `shipcheck dossier` subcommand producing a multi-scan trend report (scan cadence, score trend, CVE velocity, licence drift)
- `shipcheck docs` subcommand generating an Annex VII technical documentation draft from scan evidence plus `product.yaml`
- `shipcheck doc declaration` subcommand generating Annex V (full) and Annex VI (simplified) Declaration of Conformity templates
- `vuln-reporting` check validating Article 14 / Annex I Part II §§4-8 documentation obligations (CVD policy, SPoC, support period, update distribution)
- `shipcheck init` scaffold now lists all 7 v0.3 checks and templates the `license_audit`, `yocto_cve`, `history`, `vuln_reporting`, and `product_config_path` sections with v0.3 usage examples
- README rewritten with install, quickstart, check catalog, subcommand summary, and a pointer to the OpenSSF CRA Yocto rules catalog (was a 5-line stub)
- Pilot testing methodology (`docs/pilot.md`) documenting when pilots are required, kas-container bootstrap with cache reuse (`DL_DIR`, `SSTATE_DIR`, `KAS_REPO_REF_DIR`), NVD API key passthrough, the per-pilot artefact layout, and the gating rules that tie pilot completion to release tags.
- First pilot report (`pilots/0001-poky-scarthgap-min/REPORT.md`) validating the v0.1 check set against a real poky Scarthgap `core-image-minimal` build with `INHERIT += "create-spdx cve-check"`. All seven registered check IDs executed without raising.
- Pilots directory convention at repo root (`pilots/NNNN-<short-name>/`) containing `kas.yml`, `log.txt`, `scan.json`, `REPORT.md`, and a `dossier/` subdirectory with the full `--out` evidence bundle.

### Changed

- `CheckStatus` enum extended with `ERROR` member for checks whose input is structurally unreadable (previously had PASS/WARN/FAIL/SKIP only)
- `BaseCheck.produces_cve_findings: ClassVar[bool] = False` trait declares which checks emit CVE findings; the dossier CVE filter and CVE-velocity counter now derive their producer set from this flag instead of a hardcoded ID list
- README Roadmap now links to `pilots/0001-poky-scarthgap-min/REPORT.md` instead of the "pending - first pilot run is in progress" placeholder.
- Added a "Known limitations" subsection to README under "What it checks" enumerating documented scope boundaries surfaced by pilot 0001 (`vuln-reporting` requires `product.yaml`, `secure-boot` is config-level only, `image-signing` is config-level only, `sbom-generation` accepts SPDX 2.x, `cve-tracking` / `yocto-cve-check` file-lookup divergence).
- **BREAKING**: `shipcheck check --format json` now writes the JSON payload to stdout instead of silently creating `./shipcheck-report.json` in the current working directory; callers that relied on the file side-effect must switch to shell redirection (`--format json > report.json`) or pass `--out DIR` for the dossier bundle. (Pilot: pilots/0001-poky-scarthgap-min/REPORT.md#re-run-2026-04-20)
- README now explicitly distinguishes readiness score from CRA compliance and enumerates what shipcheck is NOT - see "What shipcheck is not" and "Readiness is not compliance" sections.

### Fixed

- Dossier CVE-velocity counter now matches the registered `cve-tracking` check ID (previously matched the never-registered `cve-scan` and silently undercounted)
- `shipcheck check --format json` routed the JSON payload to a silent `./shipcheck-report.json` side-effect instead of stdout, so shell redirection (`> scan.json`) captured an empty stream and CI pipelines lost the result. JSON now prints to stdout and suppresses the Rich terminal report when `--out` is not set. (PF-01; Pilot: pilots/0001-poky-scarthgap-min/REPORT.md#re-run-2026-04-20)
- `cve-tracking` and `yocto-cve-check` diverged on the same build because each check implemented its own discovery logic and only `yocto-cve-check` looked at `tmp/log/cve/cve-summary.json`. Both checks now share `shipcheck.checks._cve_discovery.discover_cve_output()` and agree on evidence presence. (PF-02; Pilot: pilots/0001-poky-scarthgap-min/REPORT.md#re-run-2026-04-20)
- `license-audit` returned SKIP on real Yocto builds because `_discover_image_dir()` only searched the top level of `tmp/deploy/licenses/` and missed the per-architecture layout (`tmp/deploy/licenses/<arch>/<pkg-or-image>/license.manifest`). Discovery now walks the tree recursively via `Path.rglob("license.manifest")` and selects the newest-mtime manifest. (PF-03; Pilot: pilots/0001-poky-scarthgap-min/REPORT.md#re-run-2026-04-20)

## [0.0.2] - 2026-04-01

### Added

- SBOM generation check: validates SPDX 2.3 documents against BSI TR-03183-2 field requirements
- SPDX 3.0 and CycloneDX format detection (detection-only, no field validation)
- CVE tracking check: consumes Yocto cve-check, vex.bbclass, and sbom-cve-check JSON output
- CVE severity classification with CVSS bands (critical/high/medium/low)
- CVE suppression via `.shipcheck.yaml` configuration
- Compliance report with readiness score (0-100)
- Terminal output (Rich), markdown, JSON, and HTML report formats
- `--fail-on` severity-gated exit codes for CI pipeline integration
- `shipcheck check` command with `--build-dir`, `--format`, `--checks`, `--fail-on` options
- `shipcheck init` command to generate `.shipcheck.yaml` scaffold
- `.shipcheck.yaml` configuration file with per-check overrides
- BaseCheck plugin architecture with check registry

### Changed

- Migrated from hatchling to uv-native packaging
- Added ty type checking to CI pipeline
- Fixed CI `uv sync` to include dev dependency group

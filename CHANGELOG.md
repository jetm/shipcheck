# Changelog

## [Unreleased]

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

### Changed

- `CheckStatus` enum extended with `ERROR` member for checks whose input is structurally unreadable (previously had PASS/WARN/FAIL/SKIP only)

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

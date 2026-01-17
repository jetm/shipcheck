# Changelog

## [Unreleased]

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

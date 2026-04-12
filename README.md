# shipcheck

Embedded Linux compliance auditor for the EU Cyber Resilience Act (CRA).
Reads what your Yocto build emits — SBOMs, CVE scan output, signing
artefacts, license manifests — and reports whether the image is ready
to ship.

Status: pre-release. The 0.1 line is the first publishable cut.

## Install

```bash
uv tool install shipcheck
# or
pipx install shipcheck
```

## Quickstart

shipcheck audits the **build directory**, not the layer sources. Point
it at the directory bitbake writes into (the one that contains
`tmp/deploy/`, `conf/local.conf`, etc.):

```bash
cd path/to/your/yocto/build
shipcheck init                          # writes .shipcheck.yaml
shipcheck check --build-dir .
```

A typical CI invocation:

```bash
shipcheck check \
  --build-dir "${BUILDDIR}" \
  --fail-on high \
  --format json > shipcheck-report.json
```

For the multi-file CRA dossier (evidence report, CVE report, license
audit, Annex VII technical doc, Declaration of Conformity, raw scan
JSON):

```bash
shipcheck check \
  --build-dir "${BUILDDIR}" \
  --format evidence \
  --out shipcheck-dossier/
```

## What it checks

| Check id | What it inspects |
| -------- | ---------------- |
| `sbom-generation` | SPDX 2.3 documents under `tmp/deploy/spdx/` against BSI TR-03183-2; detects SPDX 3.0 / CycloneDX |
| `cve-tracking` | `cve-check`, `vex.bbclass`, and `sbom-cve-check` JSON under `tmp/deploy/images/` |
| `secure-boot` | UEFI / sbsign signing class inheritance and signing-key references |
| `image-signing` | FIT (U-Boot) signatures and dm-verity images under `tmp/deploy/images/` |
| `license-audit` | `tmp/deploy/licenses/<image>/license.manifest` against allow/denylist |
| `yocto-cve-check` | Yocto's `tmp/log/cve/cve-summary.json` (Kirkstone and Scarthgap schemas) |
| `vuln-reporting` | Article 14 / Annex I Part II §§4-8 documentation obligations from `product.yaml` |

CVE findings from `cve-tracking` and `yocto-cve-check` are reconciled
into a single finding whose `sources` lists every scanner that flagged
it.

### Known limitations

Pilot 0001 (poky Scarthgap `core-image-minimal`) validated the v0.1 check set
end-to-end against real bitbake output. The following are documented
limitations, not defects:

- **`vuln-reporting` requires `product.yaml`** - without a `product.yaml`
  providing Article 14 / Annex I Part II §§4-8 data (CVD policy, SPoC,
  support period, update distribution), the check returns SKIP with
  "product_config_path not configured" when `product_config_path` is
  absent from `.shipcheck.yaml`, or ERROR with "product.yaml not found"
  when the path is set but the file does not exist. Supply a valid
  `product.yaml` via `product_config_path` in `.shipcheck.yaml` to
  exercise the check.
- **`secure-boot` is config-level only** - detects the signing-class
  inheritance and flags known test keys in `.shipcheck.yaml`, but does
  NOT perform PE/COFF binary signature verification, PKI chain validation
  (PK/KEK/DB enrollment), or CI-file signing-step detection. Those depths
  are tracked as roadmap follow-ups (, ).
- **`image-signing` is config-level only** - detects FIT image signatures
  and dm-verity configuration from the build tree layout, but does NOT
  verify the cryptographic integrity of the signed artefacts. Cryptographic
  verification is tracked as a roadmap follow-up.
- **`sbom-generation` accepts SPDX 2.x, not only 2.3** - poky Scarthgap's
  `create-spdx` class emits SPDX 2.2 documents; shipcheck accepts both 2.2
  and 2.3 against the BSI TR-03183-2 v2.1.0 field requirements. SPDX 3.0
  is detected but not field-validated.
- **`cve-tracking` looks for specific Yocto output locations** - pilot 0001
  surfaced that `cve-tracking` and `yocto-cve-check` use different lookup
  logic; the more reliable path is `yocto-cve-check`, which reads
  `tmp/log/cve/cve-summary.json`. The reconciliation between the two is
  tracked as .

## Subcommands

| Command | Purpose |
| ------- | ------- |
| `shipcheck check` | Run the registered checks against a build directory |
| `shipcheck dossier` | Render a multi-scan trend report from the local history store |
| `shipcheck docs` | Generate the Annex VII technical documentation draft from history + `product.yaml` |
| `shipcheck doc declaration` | Generate the EU Declaration of Conformity (Annex V full or Annex VI simplified) |
| `shipcheck init` | Write a `.shipcheck.yaml` scaffold |
| `shipcheck version` | Print the installed version |

## Roadmap

shipcheck ships in capability phases. Each phase bundles a set of checks
with the report and evidence plumbing they need.

### Shipped (v0.1)

- **Phase 1 — SBOM + CVE + Report.** `sbom-generation` and `cve-tracking`
  checks; terminal / markdown / JSON / HTML reports; readiness score and
  `--fail-on` CI gating; `.shipcheck.yaml` configuration.
- **Phase 2 — Secure Boot, Image Signing, and CRA evidence layer.**
  `secure-boot` (sbsign / image-uefi-sign class detection, test-key
  flagging) and `image-signing` (FIT signatures, dm-verity) checks.
  Static CRA requirement catalog with `cra_mapping` metadata on every
  finding, `--format evidence` renderer, `--out DIR` multi-file dossier,
  `license-audit` and `yocto-cve-check` checks, CVE finding reconciliation
  across scanners, SQLite scan history at `.shipcheck/history.db`, the
  `dossier`, `docs`, and `doc declaration` subcommands, and a
  `vuln-reporting` check covering Article 14 / Annex I Part II §§4-8
  documentation obligations.

Pilot: see [`pilots/0001-poky-scarthgap-min/REPORT.md`](pilots/0001-poky-scarthgap-min/REPORT.md).

### Planned

- **Phase 3 — Update mechanism + OP-TEE.** Detect capsule update /
  swupdate / RAUC and verify signed updates; OP-TEE integration,
  measured boot, TPM.
- **Phase 3.5 — OCI attestation + kernel hardening.** OCI container SBOM
  attestation via `image-oci`; kernel hardening configs (FORTIFY_SOURCE,
  STACKPROTECTOR, KASLR); `harvest.json` export.
- **Phase 4 — CI integration.** GitLab CI and GitHub Actions templates,
  SARIF output for the GitHub Security tab, shared history aggregation
  across runs.
- **Phase 5 — Web dashboard.** FastAPI backend on top of the history
  store and dossier output; audit-facing share view; self-hostable.

### Depth follow-ups

Open improvements to existing checks rather than new phases:

- SPDX 3.0 and CycloneDX full field validation
- Secure Boot PE/COFF binary signature verification
- Secure Boot PKI chain validation (PK / KEK / DB enrollment)
- CI pipeline signing-step detection in `.gitlab-ci.yml` / GitHub workflows

## Configuration

Per-check configuration lives in `.shipcheck.yaml`. See the scaffold
emitted by `shipcheck init` for the full surface; the most common
sections are `cve.suppress`, `license_audit.allowlist`/`denylist`,
`yocto_cve.summary_path`, and `history.enabled`.

A `product.yaml` (referenced by `product_config_path`) supplies the
manufacturer / support-period / CVD information consumed by
`vuln-reporting`, the Annex VII generator, and the Declaration of
Conformity generator.

## CRA rule catalog

The rules shipcheck implements are part of a broader catalog
maintained by the OpenSSF Global Cyber Policy WG:
[`cra-yocto-rules.md`](https://github.com/ossf/wg-globalcyberpolicy/blob/main/docs/CRA/cra-yocto-rules.md).
Each rule names the shipcheck check that implements it (or `roadmap`
for gaps).

## License

Apache-2.0. See [LICENSE](LICENSE).

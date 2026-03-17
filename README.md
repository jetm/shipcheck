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

## Subcommands

| Command | Purpose |
| ------- | ------- |
| `shipcheck check` | Run the registered checks against a build directory |
| `shipcheck dossier` | Render a multi-scan trend report from the local history store |
| `shipcheck docs` | Generate the Annex VII technical documentation draft from history + `product.yaml` |
| `shipcheck doc declaration` | Generate the EU Declaration of Conformity (Annex V full or Annex VI simplified) |
| `shipcheck init` | Write a `.shipcheck.yaml` scaffold |
| `shipcheck version` | Print the installed version |

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

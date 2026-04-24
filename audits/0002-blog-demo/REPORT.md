# Blog Demo — VENDOR-placeholder evidence report

**Document status**: Human sign-off for a generated dossier. Not an official compliance attestation.
**Date**: 2026-04-24
**Subject**: Strict validation for the vuln-reporting check
**Audited commits**:

- `29f29d7` — `checks/vuln-reporting: validate shape and reject placeholder tokens` (the behavioural rewrite this audit is validating)
- `5c28066` — `audits/0002-blog-demo: capture VENDOR-placeholder dossier` (the run that produced the files under `dossier/`)

**Reviewer**: John Doe

---

## 1. Purpose

This artifact is the worked example behind the vuln-reporting strict-validation work. The change tightened `src/shipcheck/checks/vuln_reporting.py` from presence-only validation to shape-plus-placeholder validation: a `product.yaml` whose vendor-committed fields carry placeholder tokens (`VENDOR`, `TODO`, `FIXME`, `[TO BE FILLED]`, `[VENDOR]`) or malformed values must now be enumerated as findings rather than silently accepted.

The audit demonstrates that shift end-to-end. It feeds shipcheck a `product.yaml` with every manufacturer-committed field set to the literal string `VENDOR`, runs an evidence-format scan against the committed pilot-0001 build slice, and confirms the evidence report calls out every unfilled paperwork field while still populating the build-derived sections from real bitbake output. The fixture includes a trimmed [`sbom-cve-check`](https://github.com/bootlin/sbom-cve-check) output under `tmp/deploy/images/`, so shipcheck's CVE reconciliation runs against the preferred CVE source rather than the legacy `cve-check.bbclass` summary alone.

## 2. Command invoked

```bash
uv run shipcheck check \
  --build-dir tests/fixtures/pilot_real/build \
  --product-config audits/0002-blog-demo/product-vendor.yaml \
  --format evidence \
  --out audits/0002-blog-demo/dossier
```

Note on `--build-dir`: this run targets `tests/fixtures/pilot_real/build`, the committed 500 KB slice of the pilot-0001 (poky Scarthgap `core-image-minimal`) build tree, not `poky/build` (a working-tree-only bitbake output that was not retained after pilot-0001 landed). The committed fixture reproduces the directory layout bitbake emits for SBOM, CVE, and license manifests, so the build-derived checks behave as they would against a live build.

## 3. Findings summary (vuln-reporting)

Four findings, one per vendor-committed field populated with `VENDOR`. Shipcheck derived every build-side check (SBOM, CVE reconciliation, license manifest, Secure Boot posture, image signing posture) from the fixture; it refused to fabricate the paperwork-side fields and emitted the findings below instead.

| Field                              | Placeholder | Severity | Annex   |
|------------------------------------|-------------|----------|---------|
| `cvd.policy_url`                   | VENDOR      | high     | I.P2.5  |
| `cvd.contact`                      | VENDOR      | high     | II.2    |
| `support_period.end_date`          | VENDOR      | high     | II.7    |
| `update_distribution.mechanism`    | VENDOR      | medium   | I.P2.7  |

Product identity fields (`product.name`, `manufacturer.name`, `manufacturer.address`, `manufacturer.contact`) also set to `VENDOR` are carried straight through to the Annex VII draft and the Declaration of Conformity draft, where they surface as visible placeholder strings in the generated documents under `dossier/technical-documentation.md` and `dossier/declaration-of-conformity.md`. Those are not vuln-reporting findings; they are Annex VII / DoC placeholders by design.

## 4. Sign-off

The dossier under `dossier/` demonstrates the build-derived vs. vendor-committed split that the blog thesis requires. Shipcheck populated the SBOM section, the CVE reconciliation table, the license manifest audit, the Secure Boot posture summary, and the image signing posture summary automatically from the pilot-0001 fixture — no manufacturer input needed.

It also refused to fill in product identity, the CVD policy URL, the CVD single point of contact, the support-period end date, and the update-distribution mechanism. Each of those vendor-committed fields became an enumerated finding at the severity its owning Annex requirement dictates, and the Annex VII / DoC drafts render the unfilled identity fields as visible `VENDOR` strings rather than silently passing through.

This is the visual argument for the blog post: "CRA compliance is paperwork, not scanning." Scanning is solved — SBOM, CVE, licensing, signing posture all land automatically. The paperwork remains the manufacturer's job, and shipcheck now makes the paperwork gap loud rather than silent.

## 5. Pointer to the dossier

The full run is captured under `audits/0002-blog-demo/dossier/`:

- `evidence-report.md` — findings pivoted by CRA requirement (the primary artifact the blog post will screenshot).
- `cve-report.md` — CVE reconciliation per the `cve-tracking` and `yocto-cve-check` checks, both running against the committed `sbom-cve-check.yocto.json` output in the fixture.
- `license-audit.md` — license manifest summary from the `license-audit` check.
- `technical-documentation.md` — Annex VII draft, with visible `VENDOR` placeholders in items 1 and 4.
- `declaration-of-conformity.md` — DoC draft (Annex V full), marked `DRAFT - FOR MANUFACTURER REVIEW`.
- `scan.json` — raw check output for the run.

## 6. Context

The blog post cites this audit as the worked example of the thesis "CRA compliance is paperwork, not scanning." The audit pre-dates the blog so the post can screenshot a stable, committed evidence report instead of an ad-hoc run. Any re-run of the command in §2 against the same commits should reproduce the same four findings and the same placeholder renderings in the Annex VII / DoC drafts.

## Sign-off

Reviewed-by: John Doe, 2026-04-24, commits `29f29d7` (behaviour) and `5c28066` (dossier).

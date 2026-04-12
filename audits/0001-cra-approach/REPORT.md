# CRA Compliance Approach — Re-examination

**Document status**: Draft for manufacturer review. Not an official compliance attestation.
**Audited commit**: TBD (fill at sign-off)
**Date**: 2026-04-21
**Reviewer**: TBD

---

## 1. What problem is shipcheck solving?

The EU Cyber Resilience Act (Regulation (EU) 2024/2847, published in OJ L on 20 November 2024) imposes cybersecurity obligations on manufacturers placing "products with digital elements" on the EU market. The regulation defines 38 testable obligations across four Annexes, plus Article 28 / Annex V-VI (the EU Declaration of Conformity):

- **Annex I Part I**, items (a)-(m): product cybersecurity properties — no known exploitable vulnerabilities, secure-by-default configuration, security updates, unauthorised-access protection, data integrity and confidentiality, data minimisation, availability of essential functions, attack-surface limitation, logging and monitoring, secure removal of data and settings.
- **Annex I Part II**, items 1-8: vulnerability handling — SBOM, timely remediation, regular tests, public disclosure of fixed vulnerabilities, coordinated vulnerability disclosure policy, single point of contact, secure update distribution, free and timely dissemination.
- **Annex II**, items 1-9: user-facing information and instructions — manufacturer identification, SPoC for vulnerability reporting, product identification, intended purpose, misuse risks, DoC address, support period, detailed secure-use instructions, SBOM availability.
- **Annex VII**, items 1-8: technical documentation retained by the manufacturer — product description, design/development/vulnerability-handling process, risk assessment, support-period rationale, harmonised standards, conformity test reports, copy of DoC, SBOM on request.

Embedded Linux vendors overwhelmingly build with Yocto. Yocto already emits most of the technical evidence a compliance audit cares about — SPDX SBOM documents, CVE scan output, license manifests, signing-class configuration — but it emits them **for the build, not for an auditor**. There is no Yocto convention for "give me the dossier I hand to a regulator", no mapping from bitbake output to Annex requirements, and nothing that turns "20 GB of `tmp/deploy/`" into a Declaration of Conformity draft.

shipcheck fills exactly that gap: **it takes the evidence bitbake already produces, organises it by CRA requirement, and emits a dossier a human can sign**.

What it explicitly does *not* do is claim compliance. See §6 (Readiness vs compliance) and §7 (What shipcheck is not) for the boundaries.

## 2. How is it solving it?

Six moving parts:

### 2.1 Pinned, immutable CRA catalog

`src/shipcheck/cra/requirements.yaml` contains all 38 requirements transcribed verbatim from Regulation (EU) 2024/2847. The catalog is version-pinned:

```yaml
source_version: "OJ L, 20.11.2024"
```

The loader (`src/shipcheck/cra/loader.py`) raises `CraCatalogError` if `source_version` does not match the pinned constant. The parsed catalog is exposed as a `MappingProxyType` wrapping frozen dataclasses, so callers cannot mutate shared state. The ID scheme (`I.P1.a..I.P1.m`, `I.P2.1..I.P2.8`, `II.1..II.9`, `VII.1..VII.8`) is stable and human-citeable.

**Drift is a deliberate, human-reviewed event, not a silent dependency update**. See §8 for the proposed integrity workflow.

### 2.2 Plugin check architecture

`BaseCheck` (in `models.py`) is the ABC every check extends. Seven checks are currently registered:

| Check ID | What it reads |
|----------|---------------|
| `sbom-generation` | SPDX 2.x documents under `tmp/deploy/spdx/`, validated against BSI TR-03183-2 v2.1.0 field requirements |
| `cve-tracking` | `tmp/deploy/images/*.sbom-cve-check.yocto.json`, `*.rootfs.json`, `*/cve_check_summary*.json` |
| `yocto-cve-check` | `tmp/log/cve/cve-summary.json`, version-tolerant across Kirkstone and Scarthgap schemas |
| `license-audit` | `tmp/deploy/licenses/**/license.manifest`, recursive across per-architecture subdirectories |
| `secure-boot` | `conf/local.conf` `INHERIT` lines, sbsign/image-uefi-sign class references, test-key detection |
| `image-signing` | FIT image signatures (U-Boot), dm-verity configuration, EFI artefact presence |
| `vuln-reporting` | `product.yaml` (manufacturer manifest): CVD policy, SPoC, support period, update distribution |

Each check returns a `CheckResult` with a `CheckStatus` (PASS / WARN / FAIL / ERROR / SKIP), a score, a list of `Finding`s, and a summary. Every `Finding` and `CheckResult` carries a `cra_mapping: list[str]` — one or more catalog IDs the evidence is directed at.

### 2.3 Evidence collection from build artefacts, not runtime probes

All checks read files bitbake already emits. There are no runtime probes, no remote calls, no shell-outs to external tools, no crafted heuristics. The interpretation is deterministic: given the same bitbake output, shipcheck produces the same report.

This is a deliberate design choice. It means:

- An auditor can read ~1500 lines of check code and confirm exactly what each check inspects.
- A build can be audited after the fact — no need for a live device.
- There is no attack surface for runtime-probe interference (no shell, no network, no privileged reads).

### 2.4 Mapping validation pipeline

Before any renderer touches the report, `cli.py:315` calls `validate_cra_mappings(report)`. It walks every `cra_mapping` entry on every check and finding; if any ID is not in the pinned catalog, the pipeline aborts with a distinct exit code (`_CRA_VALIDATION_EXIT_CODE`) so CI consumers can distinguish this from a `--fail-on` threshold miss.

**Phantom requirement IDs cannot propagate to output.** A check claiming evidence for a requirement that does not exist in the catalog crashes the run before the dossier is written.

### 2.5 Output shapes

| Format / command | Purpose |
|------------------|---------|
| Terminal (Rich) | Interactive run; default |
| `--format markdown \| json \| html` | CI-friendly single-stream output |
| `--format evidence` | Pivots findings by CRA requirement instead of by check; reviewer sees "who satisfies I.P1.d" |
| `--out DIR` | Multi-file dossier bundle: evidence report, license audit, CVE report, **Annex VII technical documentation draft**, **EU Declaration of Conformity (Annex V full + Annex VI simplified)**, raw `scan.json` |
| `--fail-on {critical\|high\|medium\|low}` | CI exit-code gating |
| `shipcheck dossier` | Multi-scan trend report from the SQLite history store |
| `shipcheck docs` | Re-emit the Annex VII draft independently of a full scan |
| `shipcheck doc declaration` | Re-emit the DoC independently |

The **Annex VII generator** (`docs_generator/annex_vii.py`) walks items 1-8 in order. For each, it either injects evidence from findings (§2 SBOM finding table, §3 walk through every Annex I Part I requirement) or emits `N/A - <reason>`. It refuses to render if any item is missing from the catalog (`RuntimeError`), so the document is either structurally complete or the run aborts.

The **DoC generator** (`docs_generator/declaration.py`) supports both Annex V full (eight mandatory fields) and Annex VI simplified forms. The §6 harmonised-standards field is a verbatim placeholder, `[TO BE FILLED BY MANUFACTURER: list applicable harmonised standards]`, because Commission mandate M/596 for CRA harmonised standards is still in progress — no harmonised standards have been published. shipcheck cannot silently claim conformance with a standard that does not yet exist.

### 2.6 Product config (`product.yaml`)

Manufacturer identification, support-period end date, CVD contact, update-distribution strategy. These cannot be derived from a build — they are manufacturer policy. The product config feeds `vuln-reporting` (for Annex II §§2 and 7 evidence), the Annex VII generator (items 1, 4, 7), and the DoC generator (all fields). Missing fields surface as `[TO BE FILLED BY MANUFACTURER: <field>]` placeholders in the rendered output.

### Aside: readiness score

A readiness score (0-200) is aggregated across check outcomes. It is marketing-forward (designed for a dashboard), not compliance-forward. See §6 for why the score is not a compliance metric.

## 3. Why is this a proper solution?

### 3.1 Evidence over assertion

shipcheck does not claim compliance. It claims to faithfully reproduce what the build emitted, organised by the Annex requirement each piece evidences. The DoC and Annex VII doc are explicitly marked `DRAFT - FOR MANUFACTURER REVIEW` and contain explicit placeholders where a human must fill fields. **The manufacturer's signature on the DoC is the compliance attestation, not shipcheck's output.**

### 3.2 Pinned, verbatim catalog

Regulation text is transcribed from a pinned OJ L publication. Drift against the regulation can only happen if a human changes both the `source_version` constant and the YAML. It cannot happen silently via a dependency update or a transcription edit alone. The integrity workflow proposed in §8 closes the remaining gap (typo-in-transcription) by comparing the transcription against a pinned Formex 4 XML fetched from EUR-Lex.

### 3.3 Validation pipeline catches phantom mappings

Syntactic validation of every `cra_mapping` ID before rendering. The dossier cannot cite a requirement that does not exist in the catalog. This catches the most obvious failure mode: a check claiming evidence of "Annex I Part I item n" when the regulation only goes to item (m).

### 3.4 Reads what the build already emits

No runtime probes, no shell-outs, no network. The interpretation is deterministic and reviewable. Any engineer can read the 7 check modules and confirm what each one actually looks at.

### 3.5 Yocto-native, zero marginal friction

Fits the workflow embedded Linux teams already use. No parallel build, no agent install, no third-party service. `uv tool install shipcheck` and point it at the build directory.

### 3.6 Auditable stack

Python + YAML + Jinja2. No LLM in the critical path. No proprietary heuristics. Open source, Apache-2.0. An auditor reviews code, templates, and the verbatim regulation YAML — not a black box.

### 3.7 Alternatives are worse

| Alternative | Problem |
|-------------|---------|
| Manual audit per release | Slow, inconsistent, expensive, scales O(releases) |
| Commercial compliance tool | Closed-source, requires agent install, opaque mappings, not Yocto-native |
| Not shipping | Not viable for CRA-regulated products |
| DIY scripts per project | Every team reinvents; nothing shared; no common vocabulary with auditors |

## 4. Coverage (7-check set vs 38 CRA requirements)

Cross-reference derived from the code. "Mapped" = at least one shipped finding cites the ID in its `cra_mapping`. "Documented via product.yaml" = the Annex VII or DoC generator fills the item from the product manifest but no check cites it directly.

### Annex I Part I — 4/13 items mapped (31%)

| ID | Item | Status |
|----|------|--------|
| I.P1.a | No known exploitable vulnerabilities | ❌ Not directly mapped (implicit via I.P2.2/3 through CVE checks) |
| I.P1.b | Secure by default configuration | ❌ Not mapped |
| I.P1.c | Security updates | ✅ `secure-boot` |
| I.P1.d | Unauthorised access protection | ✅ `secure-boot` |
| I.P1.e | Data confidentiality | ❌ Not mapped |
| I.P1.f | Data integrity | ✅ `secure-boot`, `image-signing` |
| I.P1.g | Data minimisation | ❌ Not mapped (design/UX question) |
| I.P1.h | Availability of essential functions | ❌ Not mapped |
| I.P1.i | Minimise impact on others | ❌ Not mapped |
| I.P1.j | Limit attack surfaces | ❌ Not mapped |
| I.P1.k | Reduce incident impact | ✅ `image-signing` (dm-verity) |
| I.P1.l | Security logging and monitoring | ❌ Not mapped |
| I.P1.m | Secure data/settings removal | ❌ Not mapped |

Tracked as . Each of the 9 unmapped items must resolve to one of: new check, partial mapping via existing check, or documented out of scope.

### Annex I Part II — 5/8 items mapped (63%)

| ID | Item | Status |
|----|------|--------|
| I.P2.1 | SBOM | ✅ `sbom-generation` |
| I.P2.2 | Address/remediate vulns without delay | ✅ `cve-tracking`, `yocto-cve-check` |
| I.P2.3 | Regular security tests | ✅ `cve-tracking`, `yocto-cve-check` |
| I.P2.4 | Public disclosure of fixed vulns | ❌ Process obligation |
| I.P2.5 | CVD policy | ✅ `vuln-reporting` |
| I.P2.6 | Facilitate vuln info sharing | 🟡 Indirect via II.2 SPoC |
| I.P2.7 | Secure update distribution | ✅ `vuln-reporting` |
| I.P2.8 | Timely, free update dissemination | ❌ Process obligation |

### Annex II — 2/9 mapped + 3 documented via product.yaml (55% total)

| ID | Item | Status |
|----|------|--------|
| II.1 | Manufacturer ID | 📝 product.yaml → DoC |
| II.2 | SPoC for vuln reporting | ✅ `vuln-reporting` |
| II.3 | Unique product ID | 📝 product.yaml → Annex VII |
| II.4 | Intended purpose + security properties | ❌ Not mapped |
| II.5 | Foreseeable misuse risks | ❌ Not mapped |
| II.6 | DoC address | 📝 product.yaml |
| II.7 | Support period end-date | ✅ `vuln-reporting` |
| II.8 | Detailed secure-use instructions | ❌ User-doc gap |
| II.9 | SBOM availability (optional) | ❌ Not mapped |

### Annex VII — 8/8 addressed by generator (heterogeneously)

| ID | Item | Addressed via |
|----|------|---------------|
| VII.1 | General product description | product.yaml |
| VII.2 | Design / development / vuln handling | SBOM finding table + walk |
| VII.3 | Cybersecurity risk assessment | Walks Annex I Part I findings |
| VII.4 | Support period determination | product.yaml |
| VII.5 | Harmonised standards | 🟡 Verbatim placeholder (mandate M/596 pending) |
| VII.6 | Conformity test reports | Per-check summary table |
| VII.7 | Copy of DoC | DoC generator output |
| VII.8 | SBOM on market surveillance request | SBOM file on disk |

### Coverage verdict

shipcheck covers the **machine-verifiable subset** of CRA obligations well: SBOM, CVE tracking, cryptographic signing, and the update-policy metadata a manufacturer must declare. It does not cover:

- **Soft-property obligations** (most of Annex I Part I unmapped items) — data minimisation, DoS resilience, architecture-level attack-surface limitation, logging policy, secure decommissioning. Some of these may become machine-verifiable ( investigates); others are design/UX questions that require human review regardless of tooling.
- **Process obligations** (I.P2.4 public disclosure, I.P2.8 timely free dissemination) — evidence lives in manufacturer policy documents and release-management practice, not in build artefacts.
- **User-facing documentation obligations** (II.4, II.5, II.8) — require prose content review, not pattern matching.

These gaps are not shipcheck's problem to solve, but the dossier must **say so loudly** so a reviewer is not misled into thinking "7 checks pass" equals "CRA-compliant".

## 5. Trust model

### The attestation chain

```text
┌─────────────────┐
│  bitbake build  │  Emits SPDX, CVE JSON, license manifests, signing
│  (Yocto)        │  config, FIT/dm-verity artefacts. Correctness of
└────────┬────────┘  the evidence is Yocto's responsibility.
         │
         ▼
┌─────────────────┐
│ shipcheck check │  7 checks read specific files, parse
│ modules         │  deterministically, emit Findings with cra_mapping
└────────┬────────┘  lists pointing at catalog IDs. No runtime probes,
         │           no network, no shell-outs.
         ▼
┌─────────────────┐
│ validate_cra_   │  Every cra_mapping ID checked against pinned
│ mappings()      │  catalog. Unknown ID → pipeline aborts. Phantom
└────────┬────────┘  requirement citations cannot reach output.
         │
         ▼
┌─────────────────┐
│ Renderers       │  Annex VII generator walks VII.1-8 in order; fills
│ (dossier, AVII, │  from findings + product.yaml; emits N/A with
│  DoC)           │  reason when no evidence. DoC marked DRAFT, with
└────────┬────────┘  explicit [TO BE FILLED BY MANUFACTURER] placeholders.
         │
         ▼
┌─────────────────┐
│ Human reviewer  │  Reads dossier, verifies claims against product
│ + manufacturer  │  knowledge, completes placeholders, signs the DoC.
│ signature       │  THIS is the compliance attestation.
└─────────────────┘
```

### Trust anchors (verifiable externally)

1. **CRA catalog is pinned to OJ L 20.11.2024**. The catalog loader refuses to initialise if `source_version` does not match the pinned constant.
2. **Mapping validation is unconditional**. `validate_cra_mappings` runs in the CLI pipeline (`cli.py:315`) with a distinct exit code. Skipping it requires a code change, reviewable in git history.
3. **Annex VII completeness is enforced**. The generator raises `RuntimeError` if any of items 1-8 is missing from the catalog. The document is either structurally complete or the run aborts.
4. **Harmonised-standards placeholder is verbatim**. The DoC §6 field is hard-coded to `[TO BE FILLED BY MANUFACTURER: list applicable harmonised standards]`. shipcheck cannot silently claim conformance with a harmonised standard that does not yet exist.
5. **All code is Apache-2.0 and reviewable**. 861 tests at 90% line coverage. No closed components, no LLM in the critical path.

### Known weaknesses

- **Semantic mapping validity is not verified**. `validate_cra_mappings` only checks that IDs exist, not that a finding actually evidences the requirement. If a check author mapped a finding to I.P1.d when the evidence only supports I.P1.f, nothing catches it. Human review of each check's mapping choices remains required. (Addressed by  Phase 1 and this document.)
- **The catalog is a manual transcription**. A typo would propagate silently. No automated line-by-line diff against EUR-Lex is currently in place. See §8 for the proposed closure.
- **Dossier quality degrades with empty reports**. An empty build emits a dossier full of "N/A - no evidence" sections. Technically honest; potentially misleading to a reviewer reading out of context.
- **Readiness score is not a compliance score**. See §6.
- **shipcheck never asserts compliance**. Feature, not bug — but must be loud in the README and the dossier. See §7.

## 6. Readiness vs compliance

shipcheck reports a **readiness score** (0-200). The score aggregates weighted check outcomes into a single number:

| Phase | Check | Points |
|-------|-------|--------|
| v0.1 | sbom-generation, cve-tracking, report | 100 |
| v0.3 | secure-boot | 50 |
| v0.3 | image-signing | 50 |

200/200 means: **every registered shipcheck check passed on this build**. It does **not** mean: the product is CRA-compliant.

The distinction matters because:

- shipcheck does not cover all CRA obligations (see §4). A product can score 200/200 while being non-compliant on Annex II user-documentation obligations, I.P2.4/8 process obligations, or the Annex I Part I soft-property requirements shipcheck does not verify.
- The score weights reflect shipcheck's current check coverage, not the regulation's relative importance of each obligation. A build with no SBOM loses 100 of 200 points; a build with perfect SBOM but no CVD policy is still penalised much less.
- Compliance is a legal judgement made by the manufacturer with reference to the regulation and — once mandate M/596 completes — harmonised standards. shipcheck provides evidence; it does not make the judgement.

Readiness **correlates with** compliance: a build that scores high has most of the machine-verifiable evidence in place. But correlation is not attestation. The manufacturer's signature on the DoC is the attestation.

**The dossier, README, and terminal output will explicitly state**: "Readiness is not compliance. shipcheck is not an official CRA compliance tool. The manufacturer is responsible for the compliance determination." (This is a v0.1.0 gate item.)

## 7. What shipcheck is not

shipcheck is **not**:

- **An official CRA compliance tool**. No such tool exists at the time of writing (2026-04-21). The category is not defined by the regulation or by any implementing act.
- **A Notified Body**. Conformity assessment involving a notified body (where required by Annex VIII for critical products) is a separate, legally defined process. shipcheck has no role in it.
- **A certification authority**. shipcheck does not issue certificates, seals, or attestations.
- **A replacement for legal review**. A compliance determination is a legal judgement based on the regulation, product context, and risk assessment. Lawyers and compliance officers make it; shipcheck provides inputs.
- **A replacement for harmonised-standards testing** (once M/596 publishes). When harmonised standards are published, conformity with them provides presumption of compliance under Article 27. shipcheck may integrate harmonised-standards checks once they exist, but does not today.
- **Complete coverage of CRA obligations**. See §4. Process obligations, user-documentation obligations, and soft-property obligations are partly or wholly out of scope.

### What would an official CRA compliance tool look like? (Speculative)

No such category is defined by the regulation, and no harmonised standards have been published under mandate M/596 to specify one. The following is speculative based on adjacent regulatory frameworks (RED 2014/53, MDR 2017/745, Machinery Directive 2006/42) and Regulation 2019/881 on cybersecurity certification:

- **Accreditation under a harmonised standard**. A testing tool would be accredited under a standard like ISO/IEC 17025 or a CRA-specific standard once published, by a national accreditation body.
- **Notified-Body affiliation or recognition**. For critical products requiring third-party conformity assessment (Annex VIII), the tool would be operated by or recognised by a Notified Body.
- **Certification scheme under Regulation 2019/881**. The Cybersecurity Act establishes cybersecurity certification schemes via ENISA. A CRA-specific scheme could define tool requirements.
- **Harmonised-standards conformance testing**. Once EN standards published under M/596 define testable requirements, a compliance tool would verify conformance with them. This is the closest analogue to what shipcheck does today — except shipcheck tests against the regulation text directly, because the harmonised standards are pending.
- **Independent verification of manufacturer claims**. Today shipcheck trusts `product.yaml` as manufacturer-declared truth. A certified tool would verify at least some of those claims (e.g. SPoC reachability, CVD policy existence as a public URL).
- **Formal test methodology with reproducibility requirements**. Test procedures documented to a standard, test equipment calibrated, output format standardised, results archived per a retention policy.
- **Legal attestation capability**. Output signed by an accredited assessor; signatures cryptographically verifiable; storage for the 10-year retention period set by Article 31.
- **Audit trail with evidence retention**. Cryptographically hashed and timestamped evidence chain from raw inputs to final verdict, retained for the legally required period.

shipcheck today is the **opposite end of the spectrum**: a lightweight, Yocto-native, open-source evidence-collection tool that serves manufacturers who want internal visibility and a starting-point dossier. It is not, and does not aim to be, a certified compliance tool.

This positioning is deliberate. Certified compliance tools (if and when they exist) will be expensive, accredited, and operated by specialists. Every manufacturer — including small teams building embedded Linux products — needs day-to-day visibility into whether their builds are heading in the right direction. shipcheck fills that need.

## 8. Catalog integrity (proposed)

The catalog is currently a manual transcription. A typo in `requirements.yaml` would propagate silently. The integrity workflow proposed here closes that gap.

### Inputs from EUR-Lex

Regulation 2024/2847 is published at CELEX `32024R2847`. Formats available:

| Format | Parsable? | Role |
|--------|-----------|------|
| **Formex 4 XML** | Yes | Authoritative structured format. Diffable. |
| PDF | Needs OCR | Human-citeable reference copy. |
| HTML / XHTML | Partially | Presentation-oriented. |
| ELI RDF/JSON-LD | Yes | Metadata only (title, date, identifiers), not full text. |

### Proposed workflow

1. Ship the reference PDF at `docs/references/cra-regulation-2024-2847.pdf` (already present) with its SHA-256 pinned as a constant in `cra/loader.py`:

   ```python
   CRA_REFERENCE_PDF_SHA256 = "..."  # pinned
   ```

2. Ship the Formex 4 XML alongside at `docs/references/cra-regulation-2024-2847.xml` with its own pinned SHA-256:

   ```python
   CRA_REFERENCE_XML_SHA256 = "..."  # pinned
   ```

3. The catalog loader (on import) verifies both files match their pinned hashes. Tampering with either file causes a `CraCatalogError` at first use.

4. Ship `scripts/verify_cra_catalog.py` as a developer tool that:
   - Recomputes SHA-256 of both reference files, compares to pinned constants.
   - Parses the Formex XML, extracts `<P>` elements for Annex I/II/VII items.
   - Performs structural diff against `requirements.yaml`: any Annex item whose text differs between the YAML transcription and the XML source is reported.
   - Exits non-zero on any drift. Runs as a pre-commit hook and in CI.

5. Refreshing the catalog becomes a deliberate, auditable 4-step change: update PDF, update XML, update both SHA-256 constants, update YAML to match. The script confirms consistency across all four. A stale XML with a fresh YAML fails the check.

This does not guarantee the original transcription was correct (the initial catalog was typed in; nothing diffed it against an XML source yet). The initial correctness check is the Phase 1 audit outcome. After that, the workflow prevents regression.

### Tracking

Catalog integrity is not on the v0.1.0 gate but should land shortly after, as a dedicated devspec change. Phase 1 of  performs a one-off manual diff of the current `requirements.yaml` against Formex XML; the automated workflow above prevents drift going forward.

## 9. Findings

<to be populated during sign-off; findings land in the single bundle devspec change per  guidance>

Anticipated findings:

- **F-001**: README lacks a "What shipcheck is not" section and does not distinguish readiness from compliance. (Addressed in this change via new README sections.)
- **F-002**: Annex I Part I has 9 unmapped items; decisions required per-item. (Tracked as .)
- **F-003**: Catalog integrity workflow not yet in place; manual transcription is unverified against an authoritative XML source. (Tracked for a post-v0.1.0 devspec change.)
- **F-004**: Readiness score weighting is not explained in the dossier or README; users may read 200/200 as compliance attestation. (Addressed in this change via new README sections.)

## Sign-off

Reviewed-by: TBD, 2026-04-21, commit <TBD>

# BSI TR-03183-2 v2.1.0 → SPDX 3.0 field mapping

**Document status**: draft pending Yocto-list / SPDX-list review.
**Date**: 2026-04-30
**Scope**: Translates the SPDX 2.x required-field set that shipcheck's
`sbom-generation` check enforces (per BSI TR-03183-2 v2.1.0) into the
equivalent SPDX 3.0.1 element / field references, so the SPDX 3.0
validator can read the same contract.
**Reviewer**: TBD (Yocto and SPDX mailing lists invited).

---

## 1. Purpose

shipcheck's `sbom-generation` check validates SPDX 2.x documents against
the field set named in BSI TR-03183-2 v2.1.0 (the German federal SBOM
profile that is the closest published, citeable specification of "minimum
SBOM content for a regulated product"). BSI v2.1.0 names SPDX 2.x fields
directly. There is no published BSI v3.0 profile.

This document derives a unilateral translation from the v2.1.0
SPDX-2.x-named field set to the SPDX 3.0.1 element / field model so the
shipcheck SPDX 3.0 validator can apply the same contract. The derivation
is **draft pending Yocto-list / SPDX-list review** - the email reply to
Olivier Benjamin (Bootlin, co-author of `sbom-cve-check`) on the shipcheck
announcement explicitly invites his and the lists' challenge of any row.

shipcheck's trust posture is "read what's there, do not infer." Fields
with no clean 3.0 analogue carry the literal marker
`OMIT - no clean 3.0 analogue` with an inline note. Omitted fields
produce no validation rule and no score deduction; they are documented
gaps, not silent skips.

## 2. Source enumeration

The mapping covers exactly the fields the existing SPDX 2.x validators
read. The two source functions in `src/shipcheck/checks/sbom.py` are:

- `_validate_spdx2_metadata` - document-level checks: `creationInfo.created`,
  `creationInfo.creators` (non-empty list), `packages` (non-empty list),
  and the presence of a `DESCRIBES` relationship.
- `_validate_spdx2_packages` - per-package checks: `name`, `versionInfo`,
  `supplier` (rejects empty and `NOASSERTION`), `licenseDeclared`
  (rejects empty and `NOASSERTION`), and `checksums` (non-empty list).

No other 2.x fields are read. Adding rules outside this set is out of
scope for this change.

## 3. Citation conventions

- BSI references cite chapter/section anchors in BSI TR-03183-2 v2.1.0.
  The v2.1.0 text groups required SBOM fields under the package-level
  data-fields section; the chapter numbers below match the published
  PDF table of contents. If a row's section reference does not match
  the reader's copy, the conservative read is "BSI TR-03183-2 v2.1.0
  (SPDX 2.x package fields)" - see Section 6.
- SPDX 3.0 references cite the v3.0.1 spec at
  `https://spdx.github.io/spdx-spec/v3.0.1/`. Class names use the
  serialized binding form documented by the SPDX 3 SHACL ontology
  (e.g. `software_Package`, `software_packageVersion`, bare
  `CreationInfo` for the serialized property name on the document
  envelope). The v3.0.1 binding namespaces in the reference Python
  bindings (`spdx-python-model==0.0.5`) match: `software_Package`,
  `software_Sbom`, `core_CreationInfo` (with bare `CreationInfo` in
  serialized JSON-LD form).

## 4. Mapping table

| BSI v2.1.0 / SPDX 2.x field | SPDX 3.0 element + field | BSI v2.1.0 ref | SPDX 3.0.1 ref | Notes |
| --- | --- | --- | --- | --- |
| `creationInfo.created` (document) | `CreationInfo.created` on the document-level `CreationInfo` Element | BSI TR-03183-2 v2.1.0 §5.2.1 (SBOM creation metadata, "Timestamp") | `https://spdx.github.io/spdx-spec/v3.0.1/model/Core/Classes/CreationInfo/` - field `created` (xsd:dateTimeStamp) | One-to-one. ISO 8601 timestamp on the `CreationInfo` Element referenced by every Element in the document. shipcheck's 3.0 metadata validator MUST read this off the resolved `CreationInfo` Element rather than a top-level `creationInfo` dict (the 3.0 model has no top-level `creationInfo` envelope). |
| `creationInfo.creators` (document, non-empty list) | `CreationInfo.createdBy` (non-empty list of `spdxId` references to `Agent` / `Organization` / `Tool` Elements) | BSI TR-03183-2 v2.1.0 §5.2.1 (SBOM creation metadata, "Author") | `https://spdx.github.io/spdx-spec/v3.0.1/model/Core/Classes/CreationInfo/` - field `createdBy` (list of `Agent` references); `https://spdx.github.io/spdx-spec/v3.0.1/model/Core/Classes/Agent/` | The 2.x string-encoded creator list (`"Tool: bitbake-1.0"`, `"Organization: Acme"`) becomes a list of `spdxId` references to typed `Agent` / `Organization` / `Tool` Elements in the `@graph`. shipcheck's 3.0 metadata validator MUST verify the list is non-empty and (best-effort) that each entry resolves to an Element in the same document. Tool attribution split (`createdUsing` for tools vs `createdBy` for agents) is captured by `createdUsing`; shipcheck treats `createdBy ∪ createdUsing` as the v2.x `creators` set. |
| `packages` non-empty (document) | `@graph` contains at least one Element of `type` (or `@type`) `software_Package` (with `security_*`-prefixed Elements skipped per design.md D5) | BSI TR-03183-2 v2.1.0 §5.3 (Component data fields, presence requirement) | `https://spdx.github.io/spdx-spec/v3.0.1/model/Software/Classes/Package/` | The 2.x flat `packages: []` array becomes typed Elements in `@graph`. The graph walker MUST count only `software_Package` Elements; Elements whose `type`/`@type` begins with `security_` are skipped (see design.md D5 - VEX/security validation lives in `cve-tracking`). |
| `DESCRIBES` relationship (document, points at the rootfs package) | `software_Sbom.rootElement` (non-empty list; at least one entry resolves by `spdxId` lookup to a `software_Package` Element in `@graph`) | BSI TR-03183-2 v2.1.0 §5.2.2 (SBOM scope / "Describes" relationship) | `https://spdx.github.io/spdx-spec/v3.0.1/model/Software/Classes/Sbom/` - field `rootElement`; `https://spdx.github.io/spdx-spec/v3.0.1/model/Core/Classes/SpdxDocument/` | A document carries one or more `software_Sbom` Elements; each Sbom names its scope via `rootElement`. shipcheck's 3.0 selector picks the Sbom whose root resolves to a `software_Package` with `software_primaryPurpose == "archive"` (the image-level rootfs analogue of the 2.x DESCRIBES target); see design.md D3 for the score-allocation rationale (5 points if the Sbom rootElement resolves cleanly). |
| Per-package `name` | `software_Package.name` (inherited from `core_Element.name`) | BSI TR-03183-2 v2.1.0 §5.3.1 (Component name) | `https://spdx.github.io/spdx-spec/v3.0.1/model/Core/Classes/Element/` - field `name`; resolved on `software_Package` | One-to-one. Same property name on both formats. shipcheck alias tuple: `("name",)`. |
| Per-package `versionInfo` | `software_Package.software_packageVersion` (canonical 3.0.1 form) | BSI TR-03183-2 v2.1.0 §5.3.2 (Component version) | `https://spdx.github.io/spdx-spec/v3.0.1/model/Software/Classes/Package/` - field `software_packageVersion` (xsd:string) | Renamed and namespaced. shipcheck alias tuple: `("software_packageVersion", "versionInfo", "packageVersion")`. The `versionInfo` and bare `packageVersion` aliases catch tools that emit the 2.x field name verbatim under a 3.0 wrapper. Priority order is sourced from Yocto's `meta/classes-recipe/create-spdx-3.0.bbclass` emit pattern, which writes the namespaced form. |
| Per-package `supplier` (rejecting empty and `NOASSERTION`) | `software_Package.suppliedBy` (an `spdxId` reference to an `Agent` / `Organization` Element; `NOASSERTION` and missing both treated as missing-supplier) | BSI TR-03183-2 v2.1.0 §5.3.3 (Component supplier) | `https://spdx.github.io/spdx-spec/v3.0.1/model/Software/Classes/Package/` - field `suppliedBy` (range: `Agent`); `https://spdx.github.io/spdx-spec/v3.0.1/model/Core/Classes/Agent/` | Renamed and re-typed: the 2.x string `"Organization: Acme"` becomes a reference to a typed `Agent` Element. shipcheck alias tuple: `("suppliedBy", "supplier")`. The literal string `"NOASSERTION"` continues to be treated as missing (mirrors 2.x `_validate_spdx2_packages`). |
| Per-package `licenseDeclared` (rejecting empty and `NOASSERTION`) | `software_Package.software_declaredLicense` (xsd:string SPDX license expression; `NOASSERTION` and missing both treated as missing-license) | BSI TR-03183-2 v2.1.0 §5.3.4 (Component declared license) | `https://spdx.github.io/spdx-spec/v3.0.1/model/Software/Classes/Package/` - field `software_declaredLicense`; `https://spdx.github.io/spdx-spec/v3.0.1/model/SimpleLicensing/` | Renamed and namespaced. shipcheck alias tuple: `("software_declaredLicense", "licenseDeclared")`. The literal string `"NOASSERTION"` is treated as missing. The corresponding `software_concludedLicense` field (3.0 analogue of 2.x `licenseConcluded`) is NOT validated by this check - only `licenseDeclared` is in BSI v2.1.0's required set. |
| Per-package `checksums` (non-empty list) | `software_Package.verifiedUsing` (non-empty list of `core_Hash` Elements; each `core_Hash` carries `algorithm` and `hashValue`) | BSI TR-03183-2 v2.1.0 §5.3.5 (Component cryptographic hash) | `https://spdx.github.io/spdx-spec/v3.0.1/model/Core/Classes/Package/` - field `verifiedUsing`; `https://spdx.github.io/spdx-spec/v3.0.1/model/Core/Classes/Hash/` (range, with `algorithm`, `hashValue`) | Renamed and re-typed: the 2.x `[{algorithm, checksumValue}]` list becomes a list of typed `core_Hash` Elements (or `spdxId` references to them). shipcheck alias tuple: `("verifiedUsing", "checksums")`. shipcheck only checks list non-emptiness for 3.0, mirroring the 2.x rule; it does not validate algorithm strength here (out of scope for BSI v2.1.0). |

## 4a. Resolution path: field vs Relationship

Real Yocto Scarthgap (poky pin
`cb2dcb4963e5fbe449f1bcb019eae883ddecc8ec`, see
`audits/0003-spdx3-mapping/upstream-poky-spdx3.md`) does NOT emit
supplier and license as fields on the `software_Package` Element.
Instead, those values land in separate Elements (an `Organization`
for supplier; a `simplelicensing_LicenseExpression` for license)
linked to the Package via `Relationship` Elements. The validator
implements a two-phase resolution per logical field; the table below
records which phase each BSI field uses on real Scarthgap output.

| Logical field | Phase 1: field-on-Package | Phase 2: Relationship traversal | Real Scarthgap path |
| --- | --- | --- | --- |
| `name` | `name` (always present on the Package Element) | not consulted | Phase 1 |
| `version` | aliases `("software_packageVersion", "versionInfo", "packageVersion")` (Yocto writes `software_packageVersion`) | not consulted | Phase 1 |
| `supplier` | aliases `("suppliedBy", "supplier")` | `from == Package.spdxId`, `relationshipType ∈ {hasSuppliedBy, hasOriginatedBy}`, `to[0]` resolves to an `Organization` / `Agent` Element | Phase 2 (Yocto writes a `Relationship` per package; `suppliedBy` may also appear on the Package field but the runtime fixture observed at the Scarthgap pin omits it) |
| `license` | aliases `("software_declaredLicense", "licenseDeclared")` | `from == Package.spdxId`, `relationshipType ∈ {hasConcludedLicense, hasDeclaredLicense}`, `to[0]` resolves to a `simplelicensing_LicenseExpression` Element (whose `simplelicensing_licenseExpression` field carries the SPDX expression string) | Phase 2 (Yocto writes the license as a separate Element and links it via `hasConcludedLicense`; commit `02c8355a81` on master changes the package-level relationship to `hasDeclaredLicense`) |
| `checksums` | aliases `("verifiedUsing", "checksums")` | not consulted in v0.0.6 (per-Package checksums on `software_File` Elements would require multi-hop traversal; tracked under signal SIG-013) | Phase 1 (no relationship fallback shipped) |

### Resolution rules

1. **Field-on-Package wins.** If Phase 1 resolves a non-empty value
   that is not the literal string `NOASSERTION`, that value is used;
   Phase 2 is never consulted for that field on that Package.
2. **One hop only.** Phase 2 follows `Package.spdxId -> Relationship.from`
   then `Relationship.to[0] -> Element.spdxId`. The validator does not
   chase further references on the resolved target.
3. **`relationshipType` priority.** When two known relationship types
   resolve the same logical field, the lower-priority value wins:
   `hasConcludedLicense (1) > hasDeclaredLicense (2)`,
   `hasSuppliedBy (1) > hasOriginatedBy (2)`. Unknown types are
   ignored.
4. **`security_` skip.** Relationship Elements whose type begins with
   `security_` (e.g. `security_VexNotAffectedVulnAssessmentRelationship`)
   are excluded from the resolver before any matching, mirroring the
   skip rule already applied to package walking (design.md D5).
5. **`NOASSERTION` is missing.** A relationship target whose `to[0]`
   is the literal string `NOASSERTION`, or whose resolved Element
   carries `NOASSERTION` as its identifying value, is treated as
   missing - identical to the existing 2.x `_validate_spdx2_packages`
   rule.

The relationship-traversal extension was added in shipcheck v0.0.6
after pilot 0006 surfaced the encoding divergence. The amendment
event recording the spec change is logged in
`devspec/spdx-3-validation` (event_type `amendment`, `spec_file`
`specs/spdx3-field-validation`).

## 5. Fields with no clean 3.0 analogue

The audit pass against `_validate_spdx2_metadata` and
`_validate_spdx2_packages` did not surface any field that lacks a clean
3.0 analogue: every 2.x field shipcheck reads has a documented
counterpart in the SPDX 3.0.1 model (with the rename / re-type captured
in the table above).

The `OMIT - no clean 3.0 analogue` marker is reserved for the row that
needs it. None of the rows in Section 4 carry that marker today. If
review surfaces a 2.x field that the SPDX 3.0.1 ontology cannot express
cleanly (or expresses only via a normative substitution shipcheck is not
willing to make), the row will be amended to:

- Replace the SPDX 3.0 element + field cell with the literal string
  `OMIT - no clean 3.0 analogue`.
- Append an inline note explaining the gap (why no 3.0 field carries
  the same semantics, and what the consequence is for the validator -
  no rule, no score deduction, documented gap).

This section is the explicit hook for that amendment so reviewers know
the policy without re-reading design.md.

## 6. Citation caveat

The BSI TR-03183-2 v2.1.0 chapter / section numbers in Section 4 are
cited from the published English-edition table of contents. If the
reader's copy of the regulation uses different numbering (translation
revision, edition drift), the conservative read of every BSI cell is
"BSI TR-03183-2 v2.1.0 (SPDX 2.x package fields)" - the same anchor
shipcheck's existing 2.x validator cites in source comments. The
mapping is invariant under that read; only the section anchors need
correction.

shipcheck does not, and shall not, fabricate section numbers. If the
reader believes a row's section anchor is wrong, please reply on the
Yocto or SPDX list with the correct anchor and the row will be
corrected before v0.0.6 ships.

## 7. Bootlin attribution

The synthetic SPDX 3.0 fixture document shape used by shipcheck's
test suite (`tests/fixtures/spdx3/generator.py`) is patterned after
Bootlin's `sbom-cve-check` test fixtures - specifically the
`Spdx3SbomBuilder` in `tests/checker/sbom_spdx3.py` on the `main`
branch of `https://github.com/bootlin/sbom-cve-check`, pinned to
upstream commit `30a5b3e94bbdd27557d3b8b7b1917b9980fc2564`.

shipcheck re-implements the fixture under Apache-2.0. **No code is
copied** from `sbom-cve-check`. The structural mimicry (rootfs Build →
`software_Package` Elements with CPE/PURL identifiers →
`RelationshipType.hasInput` / `hasOutput` edges) reflects the shape
that Yocto's emit pipeline and the SPDX 3.0 spec dictate, not an
invention of Bootlin's. Attribution is recorded here and in
`tests/fixtures/spdx3/README.md`.

If the Bootlin team disputes the structural-mimicry framing or the
attribution wording, please reply on the Yocto list and the audit
doc will be revised in a follow-up change.

## 8. Review status

- **draft pending Yocto-list / SPDX-list review** - this document is
  not authoritative until reviewed.
- The user-review gate before the v0.0.6 release tag (tasks.md group
  11.1) requires the project owner to read this document end-to-end.
- The email reply to Olivier Benjamin invites his and the lists'
  challenge of any row.
- Future BSI publication of a v3.0 profile supersedes this mapping;
  the supersession will be tracked as a separate change.

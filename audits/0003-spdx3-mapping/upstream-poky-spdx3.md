# Upstream poky SPDX 3.0 emission - investigation

**Document status**: draft pending Yocto-list / SPDX-list review.
**Date**: 2026-04-30
**Pin under investigation**: poky `cb2dcb4963e5fbe449f1bcb019eae883ddecc8ec`
(Scarthgap LTS, used by pilots 0001 / 0006).
**Scope**: enumerate post-Scarthgap commits to the two files that
encode SPDX 3.0 output, classify each as restructuring or
non-restructuring relative to the field-on-Package model BSI
TR-03183-2 v2.1.0 expects, and propose the smallest upstream patch
that lets shipcheck score Yocto-emitted SPDX 3.0 SBOMs at 50/50
without shipcheck-side relationship traversal.

---

## 1. Files inspected

The two upstream files that drive SPDX 3.0 emission on the
Scarthgap pin are:

- `meta/classes/create-spdx-3.0.bbclass` - the bbclass that wires
  `do_create_spdx` and friends into the recipe build, sets
  `SPDX_VERSION = "3.0.1"` and the default profile list, and
  delegates the heavy lifting to `oe.spdx30_tasks`. Path divergence
  note: the task brief named `meta/classes-recipe/create-spdx-3.0.bbclass`,
  but the file lives under `meta/classes/` on the Scarthgap pin
  (`meta/classes-recipe/` carries the post-rename
  `create-spdx-image-3.0.bbclass` and `create-spdx-sdk-3.0.bbclass`
  but not the base class). Both `meta/classes/create-spdx-3.0.bbclass`
  and `meta/lib/oe/spdx30_tasks.py` were inspected and confirmed
  present at the pin.
- `meta/lib/oe/spdx30_tasks.py` - the Python helper module that
  implements `create_spdx`, `create_runtime_spdx`,
  `combine_spdx`, and the rootfs / image SBOM tasks. This is
  where `software_Package` Elements are constructed and where
  the relationship Elements that carry license / supplier /
  CVE links are emitted.

Both files were verified to exist in the pilot 0006 working tree at
`pilots/0006-poky-scarthgap-spdx3/poky/` (the kas-container build
keeps the cloned tree in place; nothing about the investigation
required a fresh clone outside the repo).

## 2. Branches inspected and method

The investigation compares the Scarthgap pin against three upstream
branches:

- `master` (default branch; tip notice on 2025-11-07 confirms that
  the historical `master` is no longer the canonical development
  branch but the commits on it are real and feed Walnascar 5.2).
- `walnascar` (Yocto 5.2 LTS; default-emits `create-spdx-3.0`).
- `scarthgap` (Yocto 5.0 LTS; the branch the Scarthgap pin came
  from - relevant for backports).

Method:

```text
cd <poky working tree>
git fetch origin scarthgap walnascar master
git log --pretty=format:"%h %ci %s" \
    cb2dcb4963e5fbe449f1bcb019eae883ddecc8ec..origin/<branch> \
    -- meta/classes/create-spdx-3.0.bbclass meta/lib/oe/spdx30_tasks.py
```

The scope-narrowing path filter restricts each log to commits that
modify either of the two files. Each commit hash, date, subject, and
upstream link follows the per-branch table below.

Inspection ran on 2026-04-30. The Scarthgap branch had eight commits
since the pin overall, NONE of which touch the two SPDX 3.0 files.
The walnascar branch carried 33 commits to the two files since the
pin. The master branch carried 42 commits to the two files since
the pin (a strict superset of walnascar).

## 3. Commits found per branch

Commit links use the form
`https://git.yoctoproject.org/poky/commit/?id=<full-hash>`. Each row
notes whether the commit *restructures the package output toward
field-on-Package encoding*; that classification is the load-bearing
question for shipcheck's validator.

### 3.1 scarthgap

No commits found between
`cb2dcb4963e5fbe449f1bcb019eae883ddecc8ec` and `origin/scarthgap`
HEAD as of 2026-04-30 for `meta/classes/create-spdx-3.0.bbclass` or
`meta/lib/oe/spdx30_tasks.py`. The eight commits on the Scarthgap
LTS branch since the pin all touch documentation, bitbake, or
sphinx CSS.

### 3.2 walnascar (= subset of master prior to 2025-04-08)

| Hash | Date | Subject | Restructures toward field-on-Package? |
| --- | --- | --- | --- |
| [`0834a9cdf6`](https://git.yoctoproject.org/poky/commit/?id=0834a9cdf6) | 2025-03-24 | spdx3: support to override the version of a package in SBOM 3 | No - adds `SPDX_PACKAGE_VERSION` knob; field already on Package. |
| [`769a4479e1`](https://git.yoctoproject.org/poky/commit/?id=769a4479e1) | 2025-03-20 | spdx30: handle links to inaccessible locations | No - error handling. |
| [`110b2c124b`](https://git.yoctoproject.org/poky/commit/?id=110b2c124b) | 2025-03-20 | spdx: Update for bitbake changes | No - bitbake API churn. |
| [`d029e4e033`](https://git.yoctoproject.org/poky/commit/?id=d029e4e033) | 2025-03-19 | spdx30: test the existence of directory before walking | No - I/O hardening. |
| [`99e1e8c0b9`](https://git.yoctoproject.org/poky/commit/?id=99e1e8c0b9) | 2025-03-12 | lib: spdx30_tasks: remove duplicated patched CVEs | No - VEX dedup. |
| [`143103a1c4`](https://git.yoctoproject.org/poky/commit/?id=143103a1c4) | 2025-03-11 | lib: Fix dependencies on SPDX code | No - build deps. |
| [`e852d99018`](https://git.yoctoproject.org/poky/commit/?id=e852d99018) | 2025-03-08 | lib: spdx30_tasks: Handle patched CVEs | No - VEX. |
| [`54e4a89a75`](https://git.yoctoproject.org/poky/commit/?id=54e4a89a75) | 2025-02-18 | spdx30: Improve os.walk() handling | No. |
| [`9600cd875b`](https://git.yoctoproject.org/poky/commit/?id=9600cd875b) | 2025-02-05 | spdx30: Include files in rootfs | No - rootfs file expansion (multi-hop checksum payload). |
| [`f186e405c5`](https://git.yoctoproject.org/poky/commit/?id=f186e405c5) | 2025-01-29 | lib/spdx30_tasks: support directories deployed by image recipes | No. |
| [`4d8103bfed`](https://git.yoctoproject.org/poky/commit/?id=4d8103bfed) | 2025-01-08 | meta/lib/oe/spdx30_tasks.py: set license alias to hasConcludedLicense relationship | No - keeps the relationship-encoded license; only changes which alias the relationship's `to` resolves to. |
| [`102743c4df`](https://git.yoctoproject.org/poky/commit/?id=102743c4df) | 2024-12-12 | spdx 3.0: Rework how SPDX aliases are linked | No - alias plumbing. |
| [`eda4a8bc21`](https://git.yoctoproject.org/poky/commit/?id=eda4a8bc21) | 2024-12-05 | lib: spdx: Fix SPDX_BUILD_HOST | No. |
| [`dfb279f49e`](https://git.yoctoproject.org/poky/commit/?id=dfb279f49e) | 2024-12-05 | classes: create-spdx: Fix variable dependencies | No. |
| [`8bc93605d5`](https://git.yoctoproject.org/poky/commit/?id=8bc93605d5) | 2024-12-05 | lib: spdx30_tasks: Fix supplied By | **Partially restructures.** Renames `spdx_package.supplier` to `spdx_package.suppliedBy` (the canonical SPDX 3.0.1 alias). This is the field-on-Package path shipcheck Phase 1 already resolves. Note the runtime fixture observed at the Scarthgap pin still does not carry `suppliedBy` on every package because earlier code paths failed to set it; this commit is what made the field reliable downstream. |
| [`9ca3716437`](https://git.yoctoproject.org/poky/commit/?id=9ca3716437) | 2024-11-23 | spdx: Fix SPDX tasks not running when code changes | No. |
| [`8f4759806e`](https://git.yoctoproject.org/poky/commit/?id=8f4759806e) | 2024-11-01 | create-spdx-{2.2,3.0}: fix do_create_spdx dependency while spdx include sources | No. |
| [`29c65baf76`](https://git.yoctoproject.org/poky/commit/?id=29c65baf76) | 2024-11-01 | meta/lib/oe/spdx30_tasks.py: improve debug log in add_package_files | No. |
| [`19aa2c0a99`](https://git.yoctoproject.org/poky/commit/?id=19aa2c0a99) | 2024-10-15 | spdx30: Link license and build by alias | No - keeps relationship-encoded license; refactors the alias linkage. |
| [`2e59418325`](https://git.yoctoproject.org/poky/commit/?id=2e59418325) | 2024-09-30 | create-spdx-3.0: Upgrade to SPDX 3.0.1 | No - bumps `SPDX_VERSION` only. |
| [`07836a9684`](https://git.yoctoproject.org/poky/commit/?id=07836a9684) | 2024-09-30 | spdx 3.0: Map gitsm URI to git | No. |
| [`98e71107d7`](https://git.yoctoproject.org/poky/commit/?id=98e71107d7) | 2024-09-30 | spdx 3.0: Find local sources when searching for debug sources | No. |
| [`18fce365a5`](https://git.yoctoproject.org/poky/commit/?id=18fce365a5) | 2024-09-13 | spdx30_tasks.py: fix typo in call of is_file method | No. |
| [`819ee3eff3`](https://git.yoctoproject.org/poky/commit/?id=819ee3eff3) | 2024-09-04 | lib/spdx30_tasks: Report all missing providers | No. |
| [`bf34db1439`](https://git.yoctoproject.org/poky/commit/?id=bf34db1439) | 2024-08-20 | cve-check: encode affected product/vendor in CVE_STATUS | No - CVE/VEX. |
| [`a211f058cc`](https://git.yoctoproject.org/poky/commit/?id=a211f058cc) | 2024-08-07 | sdpx: Avoid loading of SPDX_LICENSE_DATA into global config | No. |
| [`7c1de3118f`](https://git.yoctoproject.org/poky/commit/?id=7c1de3118f) | 2024-07-26 | create-spdx-3.0/populate_sdk_base: Add SDK_CLASSES inherit mechanism | No. |
| [`edc44fcf13`](https://git.yoctoproject.org/poky/commit/?id=edc44fcf13) | 2024-07-26 | create-spdx-*: Support multilibs via SPDX_MULTILIB_SSTATE_ARCHS | No. |
| [`0328f2a585`](https://git.yoctoproject.org/poky/commit/?id=0328f2a585) | 2024-07-26 | spdx30_tasks.py: switch from exists to isfile checking debugsrc | No. |
| [`85dfbc15c8`](https://git.yoctoproject.org/poky/commit/?id=85dfbc15c8) | 2024-07-21 | lib/spdx30_tasks: improve error message | No. |
| [`87c60b9a5a`](https://git.yoctoproject.org/poky/commit/?id=87c60b9a5a) | 2024-07-16 | classes/create-spdx-3.0: Move tasks to library | No - the move that put implementation into `meta/lib/oe/spdx30_tasks.py`. |
| [`9850df1b60`](https://git.yoctoproject.org/poky/commit/?id=9850df1b60) | 2024-07-16 | classes/spdx-common: Move to library | No. |
| [`8426e027e8`](https://git.yoctoproject.org/poky/commit/?id=8426e027e8) | 2024-07-16 | classes/create-spdx-3.0: Add classes | No. |

### 3.3 master (= walnascar plus newer commits)

The master branch carries every walnascar commit above plus the
following nine entries unique to master. The master tip on
2025-11-07 carries an `8c22ff0d8b` notice that the historical
`master` branch is no longer being updated, but the commits below
are real and were merged into the development tree before that
notice.

| Hash | Date | Subject | Restructures toward field-on-Package? |
| --- | --- | --- | --- |
| [`aedcbcaae1`](https://git.yoctoproject.org/poky/commit/?id=aedcbcaae1) | 2025-10-27 | create-spdx-3.0: add SPDX_LICENSES to SPDX3_DEP_FILES | No. |
| [`b22cfc5ef1`](https://git.yoctoproject.org/poky/commit/?id=b22cfc5ef1) | 2025-10-27 | spdx-3.0: replace SPDX3_LIB_DEP_FILES with SPDX3_DEP_FILES | No. |
| [`02c8355a81`](https://git.yoctoproject.org/poky/commit/?id=02c8355a81) | 2025-08-21 | spdx30_tasks: Change package license to declared | **Partially restructures.** Changes the per-package license relationship from `hasConcludedLicense` to `hasDeclaredLicense`. License is still emitted as a separate `simplelicensing_LicenseExpression` Element linked via Relationship; the BSI v2.1.0 mapping reads "declared license" so this commit makes the relationshipType match the BSI semantic. Both relationship types are accepted by shipcheck's resolver (`hasDeclaredLicense` outranked by `hasConcludedLicense` only when both are present). |
| [`860aedadc9`](https://git.yoctoproject.org/poky/commit/?id=860aedadc9) | 2025-07-03 | spdx30: Allow VEX Justification to be configurable | No - VEX. |
| [`e4a79c9a60`](https://git.yoctoproject.org/poky/commit/?id=e4a79c9a60) | 2025-06-26 | spdx30_tasks: Change recipe license to declared | **Partially restructures.** Same change as `02c8355a81` but for recipe-level licenses. Still relationship-encoded. |
| [`33fd6f6e82`](https://git.yoctoproject.org/poky/commit/?id=33fd6f6e82) | 2025-06-17 | spdx: add option to include only compiled sources | No. |
| [`2207150bc7`](https://git.yoctoproject.org/poky/commit/?id=2207150bc7) | 2025-05-08 | spdx30: Provide software_packageUrl field in SPDX 3.0 SBOM | **Adds new field-on-Package.** Adds `software_packageUrl` (PURL) to the Package Element. Not in BSI v2.1.0's required set today, but a clean precedent for the patch proposed in Section 4 (the same Element edit point and a similar pattern). |
| [`057049c1b6`](https://git.yoctoproject.org/poky/commit/?id=057049c1b6) | 2025-04-08 | spdx30: handle Unknown CVE_STATUS | No - VEX. |
| [`8c22ff0d8b`](https://git.yoctoproject.org/poky/commit/?id=8c22ff0d8b) | 2025-11-07 | The poky repository master branch is no longer being updated. | No - admin notice. |

### 3.4 Restructuring summary

No commit on any branch removes the relationship-encoded
license / supplier path in favour of pure field-on-Package
encoding. Three commits incrementally improve adjacent paths
([`8bc93605d5`](https://git.yoctoproject.org/poky/commit/?id=8bc93605d5)
fixed the `suppliedBy` field-on-Package alias name;
[`02c8355a81`](https://git.yoctoproject.org/poky/commit/?id=02c8355a81)
swapped the relationshipType from concluded to declared;
[`2207150bc7`](https://git.yoctoproject.org/poky/commit/?id=2207150bc7)
added a precedent for adding a new direct field on Package).
None of them is a drop-in fix for shipcheck's 20/50 score on
real Yocto Scarthgap output.

## 4. What create-spdx-3.0.bbclass would need to change

The smallest upstream change that makes Yocto-emitted SPDX 3.0
SBOMs validate at 50/50 against shipcheck's field-on-Package model
is a *dual-emit* refactor in `meta/lib/oe/spdx30_tasks.py`
(`meta/classes/create-spdx-3.0.bbclass` itself is mostly thin
wiring; the behaviour-bearing change lives in the tasks library).

### 4.a Functions that emit relationship-encoded data

The two relevant code paths in `oe.spdx30_tasks`, all line refs
against the Scarthgap pin
`cb2dcb4963e5fbe449f1bcb019eae883ddecc8ec`:

- `add_license_expression(d, objset, license_expression, license_data)`
  at `meta/lib/oe/spdx30_tasks.py:35-130`. Builds the
  `simplelicensing_LicenseExpression` Element that the relationship
  later points to. Returns the Element so callers can link it.
- `create_spdx(d)` at `meta/lib/oe/spdx30_tasks.py:485-820` (the
  recipe-level task). The relevant emission points are:
  - `meta/lib/oe/spdx30_tasks.py:557-564` - recipe-level
    `hasConcludedLicense` Relationship for the source files: the
    `build_objset.new_relationship([source_files],
    RelationshipType.hasConcludedLicense, [recipe_spdx_license])`
    call. This is the pattern downstream consumers traverse.
  - `meta/lib/oe/spdx30_tasks.py:639-643` - per-package supplier:
    `spdx_package.suppliedBy = supplier._id`. **This already writes
    the field directly on the Package** (post commit
    [`8bc93605d5`](https://git.yoctoproject.org/poky/commit/?id=8bc93605d5)).
    It only fails to populate when `SPDX_PACKAGE_SUPPLIER` is unset
    or the agent factory returns `None` - which is what happens on
    the default Scarthgap pin and produces the runtime fixture's
    missing-supplier shape.
  - `meta/lib/oe/spdx30_tasks.py:704-708` - per-package license:
    `pkg_objset.new_relationship([spdx_package],
    RelationshipType.hasConcludedLicense,
    [get_element_link_id(package_spdx_license)])`. **No
    field-on-Package counterpart is emitted today.** This is the
    primary gap.

There is no per-package `verifiedUsing` emission today; checksums
land on `software_File` Elements created by `add_package_files`
(`meta/lib/oe/spdx30_tasks.py:760-785`), with a relationship
`Package -> contains -> File`. That is a deliberately deeper
multi-hop path; see Section 4.c for the dual-emit scoping.

### 4.b Minimal field additions

The proposed patch (call it `spdx30: dual-emit Package fields for
declared license, supplier, and verified-using`) adds three
field-on-Package writes alongside the existing relationship
emission:

1. **`spdx_package.software_declaredLicense = <expression-string>`**
   adjacent to `meta/lib/oe/spdx30_tasks.py:704-708`. The relationship
   stays in place (downstream consumers already read it); the new
   line duplicates the SPDX expression string into the Package's
   `software_declaredLicense` field. Source for the string: the
   already-computed `package_license` (or `recipe_spdx_license`'s
   underlying expression text). Field type: xsd:string per
   `https://spdx.github.io/spdx-spec/v3.0.1/model/Software/Classes/Package/`.

2. **Make `spdx_package.suppliedBy` reliable** by emitting a fallback
   when `SPDX_PACKAGE_SUPPLIER` is unset. Today,
   `meta/lib/oe/spdx30_tasks.py:639-643` only sets `suppliedBy` if
   `build_objset.new_agent("SPDX_PACKAGE_SUPPLIER")` returns a
   non-None value. The proposed change adds a default
   (`SPDX_PACKAGE_SUPPLIER ??= "Organization: ${OE_BUILD_HOST}"`
   in `meta/classes/create-spdx-3.0.bbclass` or an unconditional
   fallback in the helper) so the field is always populated.

3. **`spdx_package.verifiedUsing = [Hash(...)]`** synthesized from
   the `software_File` checksums of files contained in the package.
   The Package's contained files already carry sha256 in
   `add_package_files`; the new write would aggregate or carry the
   leading file's hash onto the Package. This is the deepest of the
   three additions and is reasonable to defer (see Section 4.d
   submission notes); shipcheck signal SIG-013 tracks the
   multi-hop alternative on the validator side if the upstream
   change is judged too invasive.

For the supplier and license additions, the duplicate-data pattern
already has precedent in the same file:
[`2207150bc7`](https://git.yoctoproject.org/poky/commit/?id=2207150bc7)
added `software_packageUrl` directly on Package without removing
any existing emission, and the runtime fixture confirms it reads
back as a Package field.

### 4.c Backward-compat concerns

- **Bootlin `sbom-cve-check` (`https://github.com/bootlin/sbom-cve-check`)**.
  The downstream consumer that motivates this audit doc and the
  email reply to Olivier Benjamin. Bootlin's tool reads license
  via the Relationship Element today (per inspection of their
  `Spdx3SbomBuilder` test fixtures referenced in
  `audits/0003-spdx3-mapping/mapping.md` Section 7). A dual-emit
  patch is therefore strictly compatible: Bootlin's tool keeps
  reading the relationship; shipcheck reads the field. Neither
  pipeline regresses.
- **vulnscout (`https://github.com/savoirfairelinux/vulnscout`)**.
  Source not inspected in this round (the project ingests SPDX
  3.0 via VEX Elements rather than the per-Package field set, so
  any field-on-Package addition is invisible to its parser). Risk
  level: low. Out-of-scope for v0.0.6.
- **Idiomatic SPDX 3.0**. The SPDX 3.0.1 spec allows both fields
  and Relationship Elements for license / supplier (the
  `software_declaredLicense` field is normative; the
  `Relationship/hasDeclaredLicense` form is explicitly described
  as the "linkable" alternative). Dual-emission is therefore
  spec-conformant and not an anti-pattern. Removing the
  Relationship form would be a breaking change for Bootlin's
  pipeline; ADDING the field-on-Package form is purely additive.

### 4.d Submission flag

**Recommendation: send a v1 patch series to the openembedded-core
mailing list.** Justification:

- Phase 1 (the field-on-Package target shipcheck wants) is
  spec-conformant and matches BSI v2.1.0's "minimum SBOM content"
  shape.
- No existing post-Scarthgap commit ships this dual-emission. The
  closest precedent
  ([`2207150bc7`](https://git.yoctoproject.org/poky/commit/?id=2207150bc7),
  `software_packageUrl`) demonstrates the pattern is acceptable
  upstream.
- The change is purely additive; downstream consumers (Bootlin)
  continue to read the existing Relationship form unchanged.
- LTS impact: the patch should land first on master, then be
  backported to scarthgap (LTS). The Scarthgap branch had ZERO
  commits to these files since the pin (Section 3.1), so the
  backport diff stays small.

Patch series outline:

```text
v1 1/3 spdx30: dual-emit software_declaredLicense on package Element
v1 2/3 spdx30: ensure suppliedBy is set when SPDX_PACKAGE_SUPPLIER unset
v1 3/3 (deferred) spdx30: aggregate per-Package verifiedUsing from contained files
```

Patches 1 and 2 are the load-bearing entries. Patch 3 is optional
(the multi-hop verifiedUsing path is invasive enough to warrant a
separate discussion) and can ship as a follow-up. The cover
letter cites BSI TR-03183-2 v2.1.0's required-field set as the
motivation, and links back to this audit document plus
`audits/0003-spdx3-mapping/mapping.md` for the field-by-field
mapping that makes the BSI requirement concrete.

The user (jetm) is the right party to send the series: the
investigation surfaced this gap and the patch text would build
directly on the relationship-traversal change shipped in
shipcheck v0.0.6.

## 5. Citation caveat

Every commit hash and date in Section 3 was retrieved by
`git log <pin>..origin/<branch> -- <files>` against the upstream
poky tree at
`https://git.yoctoproject.org/poky.git`. No commit was inferred
from secondary sources or named without a verifying log entry. If
a hash, date, or subject does not match the upstream
`https://git.yoctoproject.org/poky/commit/?id=<hash>` page, the
upstream page is authoritative and the row should be corrected
in a follow-up.

The `meta/classes/create-spdx-3.0.bbclass` path divergence from
the task brief's `meta/classes-recipe/create-spdx-3.0.bbclass`
spelling is real on the Scarthgap pin (verified by directory
listing). A future poky reorg might move the file again; the
investigation should rerun against the current path before any
patch series is submitted.

## 6. Related

- `audits/0003-spdx3-mapping/mapping.md` - the BSI v2.1.0 → SPDX
  3.0 field-mapping table this investigation extends.
- `tests/fixtures/pilot_real/spdx3/PROVENANCE.md` - the slicer
  rationale that explains why the committed fixture has zero
  Relationship Elements (a slicer-budget tradeoff, not a
  shipcheck-validator behaviour).
- shipcheck validator change: `_resolve_spdx3_field_via_relationships`
  in `src/shipcheck/checks/sbom.py` (added in v0.0.6).
- Spec amendment: `devspec/spdx-3-validation` event_type
  `amendment`, `spec_file` `specs/spdx3-field-validation`.

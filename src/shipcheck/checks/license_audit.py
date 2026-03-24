"""License audit check for Yocto `license.manifest` files.

Parses Yocto's text-based license metadata found anywhere under
`<build-dir>/tmp/deploy/licenses/` (legacy per-image layout
`<image>/license.manifest` and the real per-architecture layout
`<arch>/<image-or-pkg>/license.manifest`), classifies each declared SPDX ID
into a canonical category, and surfaces copyleft-boundary risks alongside
unknown licences. Drift detection against a previous scan is stubbed out
here; it is wired to `HistoryStore` in a later task.
"""

from __future__ import annotations

import logging
from functools import lru_cache
from pathlib import Path

import yaml

from shipcheck.models import BaseCheck, CheckResult, CheckStatus, Finding, determine_status

logger = logging.getLogger(__name__)

LICENSES_SUBDIR = "tmp/deploy/licenses"
CRA_MAPPING: list[str] = ["I.P2.1", "VII.2"]

_CATEGORIES_FILE = Path(__file__).parent / "license_categories.yaml"
_UNKNOWN_CATEGORY = "unknown"
_COPYLEFT_BOUNDARY_CATEGORIES = {"strong-copyleft", "network-copyleft"}
_PROPRIETARY_CATEGORY = "proprietary"

_REMEDIATION_UNKNOWN = (
    "Add the licence ID to `src/shipcheck/checks/license_categories.yaml` "
    "under the correct category, or correct the package's LICENSE field."
)
_REMEDIATION_BOUNDARY = (
    "Review distribution terms: bundling copyleft software with proprietary "
    "components requires explicit vendor/legal sign-off."
)


@lru_cache(maxsize=1)
def _load_categories() -> dict[str, str]:
    """Load the SPDX-ID -> category mapping from license_categories.yaml.

    Returns a flat dict keyed by licence ID (e.g. ``"GPL-2.0-only": "strong-copyleft"``).
    """
    raw = yaml.safe_load(_CATEGORIES_FILE.read_text()) or {}
    mapping: dict[str, str] = {}
    for category, ids in raw.items():
        if not isinstance(ids, list):
            continue
        for spdx_id in ids:
            if isinstance(spdx_id, str):
                mapping[spdx_id] = category
    return mapping


def _classify(license_field: str) -> str:
    """Classify a raw LICENSE field from a Yocto manifest.

    Yocto frequently expresses compound licences like ``GPL-2.0-only & MIT`` or
    ``(MIT | BSD-3-Clause)``. We split on the common operators and classify
    each token; the package's category is the most restrictive category
    present. Unknown tokens dominate everything else so the maintainer is
    forced to look at them.
    """
    mapping = _load_categories()
    tokens = _split_license_expression(license_field)
    if not tokens:
        return _UNKNOWN_CATEGORY

    categories = {mapping.get(tok, _UNKNOWN_CATEGORY) for tok in tokens}

    # Precedence: unknown > network-copyleft > strong-copyleft > proprietary >
    # weak-copyleft > permissive. Unknown ranks highest so an un-mapped token
    # in a compound expression is never silently swallowed by a known sibling.
    precedence = [
        _UNKNOWN_CATEGORY,
        "network-copyleft",
        "strong-copyleft",
        _PROPRIETARY_CATEGORY,
        "weak-copyleft",
        "permissive",
    ]
    for category in precedence:
        if category in categories:
            return category
    return _UNKNOWN_CATEGORY


def _split_license_expression(expr: str) -> list[str]:
    """Split a Yocto LICENSE expression into individual SPDX tokens."""
    cleaned = expr.replace("(", " ").replace(")", " ")
    for sep in ("&", "|", ","):
        cleaned = cleaned.replace(sep, " ")
    return [tok.strip() for tok in cleaned.split() if tok.strip()]


def _discover_image_dir(build_dir: Path) -> Path | None:
    """Locate the directory containing the newest `license.manifest` under the tree.

    Walks `tmp/deploy/licenses/` recursively so that both the legacy per-image
    layout (`tmp/deploy/licenses/<image>/license.manifest`) and the real Yocto
    per-architecture layout
    (`tmp/deploy/licenses/<arch>/<image-or-pkg>/license.manifest`) are found
    by the same discovery pass. Among all matches, the one with the newest
    mtime wins and its parent directory is returned.

    Returns None when the `tmp/deploy/licenses/` directory itself is missing.
    When the directory exists but contains no manifests at any depth, also
    returns None so the caller can treat it as a SKIP.
    """
    licenses_dir = build_dir / LICENSES_SUBDIR
    if not licenses_dir.is_dir():
        return None

    candidates: list[tuple[float, Path]] = []
    for manifest in licenses_dir.rglob("license.manifest"):
        if not manifest.is_file():
            continue
        try:
            mtime = manifest.stat().st_mtime
        except OSError:
            parent = manifest.parent
            try:
                mtime = parent.stat().st_mtime
            except OSError:
                continue
        candidates.append((mtime, manifest))

    if not candidates:
        return None
    candidates.sort(key=lambda item: item[0])
    return candidates[-1][1].parent


def _parse_manifest(manifest: Path) -> list[dict[str, str]]:
    """Parse a Yocto license.manifest into a list of package records.

    Each record is a dict with string keys/values drawn from the manifest's
    ``PACKAGE NAME`` / ``PACKAGE VERSION`` / ``RECIPE NAME`` / ``LICENSE``
    fields. Blocks are separated by blank lines; malformed blocks are
    skipped silently rather than aborting the check.
    """
    text = manifest.read_text()
    records: list[dict[str, str]] = []
    current: dict[str, str] = {}

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            if current:
                records.append(current)
                current = {}
            continue
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        current[key.strip()] = value.strip()

    if current:
        records.append(current)

    return records


def _boundary_packages(
    classified: list[tuple[dict[str, str], str]],
) -> tuple[list[str], list[str]]:
    """Return (copyleft_pkgs, proprietary_pkgs) for the boundary check."""
    copyleft: list[str] = []
    proprietary: list[str] = []
    for record, category in classified:
        name = record.get("PACKAGE NAME", "<unknown>")
        if category in _COPYLEFT_BOUNDARY_CATEGORIES:
            copyleft.append(name)
        elif category == _PROPRIETARY_CATEGORY:
            proprietary.append(name)
    return copyleft, proprietary


def _drift_findings(
    build_dir: Path,
    classified: list[tuple[dict[str, str], str]],
    config: dict,
) -> list[Finding]:
    """Drift detection stub.

    When a ``history_store`` is supplied in the config dict and exposes a
    ``previous_licenses(build_dir)`` method, diff its mapping against the
    current scan and emit one low-severity finding per changed package. In
    the absence of a history store, return an empty list so drift is simply
    skipped until task 10.* wires this up properly.
    """
    history_store = config.get("history_store")
    if history_store is None:
        return []

    try:
        previous = history_store.previous_licenses(build_dir)
    except Exception:  # noqa: BLE001 - history store is best-effort
        logger.exception("Failed to load previous licences from history store")
        return []

    if not previous:
        return []

    findings: list[Finding] = []
    current: dict[str, str] = {
        record.get("PACKAGE NAME", ""): record.get("LICENSE", "") for record, _ in classified
    }
    for pkg, new_license in current.items():
        old_license = previous.get(pkg)
        if old_license and old_license != new_license:
            findings.append(
                Finding(
                    message=(f"License drift for package '{pkg}': {old_license} -> {new_license}"),
                    severity="low",
                    details={
                        "package": pkg,
                        "previous_license": old_license,
                        "current_license": new_license,
                        "drift": True,
                    },
                    cra_mapping=list(CRA_MAPPING),
                )
            )
    return findings


def _category_summary(
    classified: list[tuple[dict[str, str], str]],
) -> dict[str, int]:
    """Count packages per category for the result summary."""
    counts: dict[str, int] = {}
    for _, category in classified:
        counts[category] = counts.get(category, 0) + 1
    return counts


class LicenseAuditCheck(BaseCheck):
    """Audit Yocto `license.manifest` entries for copyleft risk and unknown IDs."""

    id = "license-audit"
    name = "License Audit"
    framework = ["CRA"]
    severity = "info"

    def run(self, build_dir: Path, config: dict) -> CheckResult:
        licenses_dir = build_dir / LICENSES_SUBDIR
        if not licenses_dir.is_dir():
            return CheckResult(
                check_id=self.id,
                check_name=self.name,
                status=CheckStatus.SKIP,
                score=0,
                max_score=50,
                findings=[],
                summary=(
                    f"License manifest directory not found at "
                    f"{LICENSES_SUBDIR}/ — skipping license audit"
                ),
                cra_mapping=list(CRA_MAPPING),
            )

        image_dir = _discover_image_dir(build_dir)
        if image_dir is None:
            return CheckResult(
                check_id=self.id,
                check_name=self.name,
                status=CheckStatus.SKIP,
                score=0,
                max_score=50,
                findings=[],
                summary=(
                    f"No license.manifest files found under "
                    f"{LICENSES_SUBDIR}/ — skipping license audit"
                ),
                cra_mapping=list(CRA_MAPPING),
            )

        manifest = image_dir / "license.manifest"
        records = _parse_manifest(manifest)

        classified: list[tuple[dict[str, str], str]] = [
            (rec, _classify(rec.get("LICENSE", ""))) for rec in records
        ]

        findings: list[Finding] = []

        for record, category in classified:
            if category != _UNKNOWN_CATEGORY:
                continue
            pkg_name = record.get("PACKAGE NAME", "<unknown>")
            raw_license = record.get("LICENSE", "<missing>")
            findings.append(
                Finding(
                    message=(
                        f"Unknown licence for package '{pkg_name}': "
                        f"'{raw_license}' not in canonical category map"
                    ),
                    severity="medium",
                    remediation=_REMEDIATION_UNKNOWN,
                    details={
                        "package": pkg_name,
                        "license": raw_license,
                        "category": _UNKNOWN_CATEGORY,
                    },
                    cra_mapping=list(CRA_MAPPING),
                )
            )

        copyleft_pkgs, proprietary_pkgs = _boundary_packages(classified)
        if copyleft_pkgs and proprietary_pkgs:
            findings.append(
                Finding(
                    message=(
                        "Copyleft boundary detected: "
                        f"{len(copyleft_pkgs)} copyleft package(s) "
                        f"and {len(proprietary_pkgs)} proprietary package(s) "
                        "present in the same image require explicit review"
                    ),
                    severity="medium",
                    remediation=_REMEDIATION_BOUNDARY,
                    details={
                        "copyleft_packages": sorted(copyleft_pkgs),
                        "proprietary_packages": sorted(proprietary_pkgs),
                        "boundary": True,
                    },
                    cra_mapping=list(CRA_MAPPING),
                )
            )

        findings.extend(_drift_findings(build_dir, classified, config))

        status = determine_status(findings)
        counts = _category_summary(classified)
        total = sum(counts.values())

        # Score: start at max_score, subtract 5 per unknown, 10 per boundary,
        # 1 per drift. Floor at zero so the ship-readiness percentage stays
        # comparable with the other checks.
        score = 50
        for finding in findings:
            details = finding.details or {}
            if details.get("category") == _UNKNOWN_CATEGORY:
                score -= 5
            elif details.get("boundary"):
                score -= 10
            elif details.get("drift"):
                score -= 1
        score = max(score, 0)

        parts = [
            f"{total} package(s) in {image_dir.name}/license.manifest",
        ]
        for category in (
            "permissive",
            "weak-copyleft",
            "strong-copyleft",
            "network-copyleft",
            _PROPRIETARY_CATEGORY,
            _UNKNOWN_CATEGORY,
        ):
            count = counts.get(category, 0)
            if count:
                parts.append(f"{category}: {count}")
        summary = "; ".join(parts)

        return CheckResult(
            check_id=self.id,
            check_name=self.name,
            status=status,
            score=score,
            max_score=50,
            findings=findings,
            summary=summary,
            cra_mapping=list(CRA_MAPPING),
        )

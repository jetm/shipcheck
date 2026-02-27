"""Multi-scan compliance dossier generation.

Pivots a :class:`~shipcheck.history.store.HistoryStore` into a dossier
that proves *sustained* compliance activity over time, not a single
point-in-time scan. Proposal track D1 frames this as the direct answer
to Mikko's "CRA compliance is a process, not a product artifact"
critique: the dossier lets vendors demonstrate regular CVE scans,
patching cadence, and licence-drift tracking across releases.

The dossier carries four temporal sections:

* **Scan cadence** - one entry per scan with timestamp, build_dir,
  finding_count and total score. Surfaces gaps in regular testing as
  required by Annex I Part II §3.
* **Score trend** - pairs of ``(timestamp, score)`` for a minimal score
  line the renderer can sparkline.
* **CVE velocity** - introduced / resolved / open counts derived from
  the per-check JSON of consecutive scans, evidencing Annex I Part II
  §2 "address without delay".
* **Licence drift** - per-scan records of which scans included the
  ``license-audit`` check, as a hook for future detailed drift records.

An empty query (no scans match the filters) short-circuits to a
``DossierData`` with ``is_empty=True`` whose ``__str__`` surfaces the
explicit ``"no scans recorded"`` marker the ``dossier`` CLI renderer
relies on.

CLI wiring of ``shipcheck dossier`` lives in task group 10; this module
stays renderer-agnostic so the same data can be re-used by the web
dashboard story in  without duplicating aggregation logic.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from jinja2 import Environment, FileSystemLoader

if TYPE_CHECKING:
    from shipcheck.history.store import HistoryStore

_TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"
_CVE_CHECK_IDS = frozenset({"cve-scan", "yocto-cve-check"})
_LICENSE_CHECK_IDS = frozenset({"license-audit"})


@dataclass(frozen=True)
class DossierData:
    """Multi-scan compliance dossier.

    The four section fields are populated from :func:`build_dossier`;
    :attr:`is_empty` short-circuits the renderer to a "no scans
    recorded" note so downstream formatting never emits a blank dossier.
    """

    scan_cadence: list[dict[str, Any]] = field(default_factory=list)
    score_trend: list[tuple[str, int]] = field(default_factory=list)
    cve_velocity: dict[str, int] = field(
        default_factory=lambda: {
            "cves_introduced": 0,
            "cves_resolved": 0,
            "cves_open": 0,
        }
    )
    license_drift: list[dict[str, Any]] = field(default_factory=list)
    is_empty: bool = False
    since: str | None = None
    build_dir: str | None = None

    def __str__(self) -> str:
        """Render the dossier as a human-readable Markdown string."""
        env = Environment(
            loader=FileSystemLoader(str(_TEMPLATE_DIR)),
            keep_trailing_newline=True,
            trim_blocks=True,
            lstrip_blocks=True,
        )
        template = env.get_template("dossier.md.j2")
        return template.render(dossier=self)


def _row_build_dir(row: dict[str, Any]) -> str:
    """Return the best available human-readable build_dir for ``row``.

    The history store persists the SHA-256 hash of the absolute
    build_dir path for indexed lookups, but may also retain the original
    path for audit trail rendering. The dossier prefers the readable
    path when available and falls back to the hash so the output never
    silently drops the identifier.
    """
    value = row.get("build_dir")
    if value:
        return str(value)
    return str(row.get("build_dir_hash", ""))


def _row_checks(row: dict[str, Any]) -> list[dict[str, Any]]:
    """Return the per-check JSON payload for ``row`` as a list of dicts.

    The store persists per-check status/score as JSON (either a string
    or an already-decoded structure depending on the adapter). Returns
    an empty list when the column is missing so aggregation helpers
    degrade gracefully on malformed rows.
    """
    raw = row.get("checks")
    if raw is None:
        raw = row.get("per_check_json")
    if raw is None:
        return []
    if isinstance(raw, str):
        try:
            decoded = json.loads(raw)
        except json.JSONDecodeError:
            return []
    else:
        decoded = raw
    if isinstance(decoded, dict):
        return [{"check_id": cid, **entry} for cid, entry in decoded.items()]
    if isinstance(decoded, list):
        return [entry for entry in decoded if isinstance(entry, dict)]
    return []


def _row_finding_count(row: dict[str, Any]) -> int:
    value = row.get("finding_count")
    return int(value) if value is not None else 0


def _row_score(row: dict[str, Any]) -> int:
    value = row.get("total_score")
    if value is None:
        value = row.get("score", 0)
    return int(value) if value is not None else 0


def _cve_open_count(row: dict[str, Any]) -> int:
    """Count findings emitted by CVE-producing checks for ``row``.

    The store persists per-check finding counts inside the ``checks``
    JSON blob. We treat the sum of findings across both ``cve-scan``
    and ``yocto-cve-check`` as the "open CVE" population for that scan;
    reconciliation of duplicates happens at report assembly, not in
    history aggregation.
    """
    total = 0
    for entry in _row_checks(row):
        check_id = entry.get("check_id")
        if check_id in _CVE_CHECK_IDS:
            count = entry.get("finding_count")
            if count is None:
                count = entry.get("findings")
            if isinstance(count, list):
                count = len(count)
            if count is not None:
                total += int(count)
    return total


def _row_has_license_audit(row: dict[str, Any]) -> bool:
    return any(
        entry.get("check_id") in _LICENSE_CHECK_IDS for entry in _row_checks(row)
    )


def build_dossier(
    store: HistoryStore,
    since: str | None = None,
    build_dir: str | None = None,
) -> DossierData:
    """Assemble a :class:`DossierData` from ``store``'s scan history.

    Args:
        store: History store to query.
        since: Optional ISO-8601 lower bound. Scans with a strictly
            earlier timestamp are excluded.
        build_dir: Optional build-directory filter. When provided, only
            scans recorded against this build-dir path (matched by the
            store's own hash or path column, per task 6.1 contract) are
            included.

    Returns:
        A dossier. When no scans match the filters, ``is_empty`` is set
        so ``__str__`` emits the "no scans recorded" marker the CLI and
        downstream renderers use to flag absence of evidence.
    """
    rows = store.query(since=since, build_dir=build_dir)

    if not rows:
        return DossierData(
            is_empty=True,
            since=since,
            build_dir=build_dir,
        )

    ordered = sorted(rows, key=lambda r: r.get("timestamp", ""))

    scan_cadence: list[dict[str, Any]] = []
    score_trend: list[tuple[str, int]] = []
    license_drift: list[dict[str, Any]] = []
    open_cve_counts: list[int] = []

    for row in ordered:
        ts = str(row.get("timestamp", ""))
        bdir = _row_build_dir(row)
        finding_count = _row_finding_count(row)
        score = _row_score(row)

        scan_cadence.append(
            {
                "timestamp": ts,
                "build_dir": bdir,
                "finding_count": finding_count,
                "score": score,
            }
        )
        score_trend.append((ts, score))
        open_cve_counts.append(_cve_open_count(row))

        if _row_has_license_audit(row):
            license_drift.append(
                {
                    "timestamp": ts,
                    "build_dir": bdir,
                    "has_license_audit": True,
                }
            )

    introduced = 0
    resolved = 0
    for prev, curr in zip(open_cve_counts, open_cve_counts[1:], strict=False):
        delta = curr - prev
        if delta > 0:
            introduced += delta
        elif delta < 0:
            resolved += -delta

    cve_velocity = {
        "cves_introduced": introduced,
        "cves_resolved": resolved,
        "cves_open": open_cve_counts[-1] if open_cve_counts else 0,
    }

    return DossierData(
        scan_cadence=scan_cadence,
        score_trend=score_trend,
        cve_velocity=cve_velocity,
        license_drift=license_drift,
        is_empty=False,
        since=since,
        build_dir=build_dir,
    )

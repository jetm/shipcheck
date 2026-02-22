"""CVE finding reconciliation across scanner sources.

When multiple CVE scanners (e.g. the heuristic JSON-based ``cve`` check
and the Yocto ``cve-check`` integration) flag the same vulnerability on
the same package/version, the raw result set duplicates findings. This
module walks every finding across every :class:`CheckResult` and merges
the duplicates so downstream renderers see one authoritative finding
per ``(cve, package, version)`` triple.

Merge semantics:

* Findings are grouped by the ``(cve, package, version)`` triple stored
  in ``Finding.details``. The CVE key may be stored as either ``cve``
  (yocto_cve.py) or ``cve_id`` (cve.py); both are recognised.
* Within a group, ``sources`` are unioned (dedup, sorted), ``severity``
  is the maximum per the ordering
  ``critical > high > medium > low > info`` (case-insensitive input,
  original casing preserved on output), and ``cra_mapping`` is unioned
  (dedup, sorted).
* Other fields (``message``, ``details``, ``remediation``) are taken
  from the first finding in stable iteration order.
* Findings missing any of ``(cve, package, version)`` are preserved
  unchanged; they are not merge candidates.

Output ordering is deterministic: results are sorted by ``check_name``
and findings within each result are sorted by ``(cve, package)`` when
present, else by ``message``.
"""

from __future__ import annotations

from shipcheck.models import CheckResult, Finding

_SEVERITY_ORDER = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}


def _cve_id(finding: Finding) -> str | None:
    """Return the CVE identifier from either ``cve`` or ``cve_id`` keys."""
    details = finding.details or {}
    return details.get("cve") or details.get("cve_id")


def _triple(finding: Finding) -> tuple[str, str, str] | None:
    """Return the merge key ``(cve, package, version)`` if all present."""
    details = finding.details or {}
    cve = _cve_id(finding)
    package = details.get("package")
    version = details.get("version")
    if cve and package and version:
        return (cve, package, version)
    return None


def _max_severity(severities: list[str]) -> str:
    """Return the highest severity per the critical > ... > info ordering.

    Input strings are compared case-insensitively. Unknown severities
    rank below ``info``. The returned value is whichever input string
    had the highest rank, preserving its original casing.
    """
    best_rank = -1
    best: str = severities[0] if severities else "info"
    for sev in severities:
        rank = _SEVERITY_ORDER.get(sev.lower(), -1)
        if rank > best_rank:
            best_rank = rank
            best = sev
    return best


def _merge_group(group: list[Finding]) -> Finding:
    """Merge findings sharing the same ``(cve, package, version)``."""
    first = group[0]

    sources: set[str] = set()
    cra: set[str] = set()
    severities: list[str] = []
    for f in group:
        sources.update(f.sources)
        cra.update(f.cra_mapping)
        severities.append(f.severity)

    return Finding(
        message=first.message,
        severity=_max_severity(severities),
        remediation=first.remediation,
        details=dict(first.details) if first.details else None,
        cra_mapping=sorted(cra),
        sources=sorted(sources),
    )


def _finding_sort_key(finding: Finding) -> tuple[int, str, str]:
    """Sort key: (cve, package) when present, else (message, '')."""
    details = finding.details or {}
    cve = _cve_id(finding)
    package = details.get("package")
    if cve and package:
        return (0, cve, package)
    return (1, finding.message, "")


def reconcile_findings(results: list[CheckResult]) -> list[CheckResult]:
    """Merge duplicate CVE findings across ``results``.

    Walks every finding across every ``CheckResult``, groups findings
    that share ``(cve, package, version)`` in ``details``, and merges
    each group into a single finding. Findings missing any part of the
    triple pass through unchanged.

    The merged finding for a group is emitted in the first result (by
    stable iteration order) that contributed to the group; duplicates
    in later results are dropped. Results are then sorted by
    ``check_name`` and each result's findings are sorted by
    ``(cve, package)`` or ``message`` for deterministic output.

    Args:
        results: Per-check results to reconcile.

    Returns:
        A new list of ``CheckResult`` objects with merged findings. The
        input is not mutated.
    """
    groups: dict[tuple[str, str, str], list[Finding]] = {}
    group_first_result: dict[tuple[str, str, str], int] = {}
    for idx, result in enumerate(results):
        for finding in result.findings:
            key = _triple(finding)
            if key is None:
                continue
            groups.setdefault(key, []).append(finding)
            if key not in group_first_result:
                group_first_result[key] = idx

    merged_by_key: dict[tuple[str, str, str], Finding] = {
        key: _merge_group(group) if len(group) > 1 else group[0]
        for key, group in groups.items()
    }

    new_results: list[CheckResult] = []
    emitted: set[tuple[str, str, str]] = set()
    for idx, result in enumerate(results):
        new_findings: list[Finding] = []
        for finding in result.findings:
            key = _triple(finding)
            if key is None:
                new_findings.append(finding)
                continue
            if group_first_result[key] != idx:
                continue
            if key in emitted:
                continue
            emitted.add(key)
            new_findings.append(merged_by_key[key])

        new_findings.sort(key=_finding_sort_key)
        new_results.append(
            CheckResult(
                check_id=result.check_id,
                check_name=result.check_name,
                status=result.status,
                score=result.score,
                max_score=result.max_score,
                findings=new_findings,
                summary=result.summary,
                cra_mapping=list(result.cra_mapping),
            )
        )

    new_results.sort(key=lambda r: r.check_name)
    return new_results

"""Yocto cve-check.bbclass integration: parse cve-summary.json output.

Reads ``<build-dir>/tmp/log/cve/cve-summary.json`` (path overridable via
``yocto_cve.summary_path``) and emits findings for Unpatched and Unknown
CVE statuses.  Ignored entries surface as INFO findings by default; the
``treat_ignored_as_patched`` config flag suppresses them.  Patched entries
never emit findings.

Two schema variants are supported:

* **Kirkstone / Dunfell** - ``{"version": "1", "package": [{..., "issue": [...]}]}``.
* **Scarthgap** - ``{"version": "2", "issues": [...]}``.

The parser is version-tolerant: either schema shape is accepted regardless
of the ``version`` string to match what real builds emit in practice.

Each finding carries ``sources=["yocto-cve-check"]`` and
``cra_mapping=["I.P2.2", "I.P2.3"]`` so reconciliation (see report.reconcile)
    can merge matches with the existing ``cve-tracking`` check.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from shipcheck.checks._cve_discovery import discover_cve_output
from shipcheck.models import BaseCheck, CheckResult, CheckStatus, Finding

logger = logging.getLogger(__name__)

DEFAULT_SUMMARY_RELPATH = Path("tmp") / "log" / "cve" / "cve-summary.json"

_CRA_MAPPING = ["I.P2.2", "I.P2.3"]
_SOURCES = ["yocto-cve-check"]

_SCORE_FIELDS = ("scorev4", "scorev3", "scorev2")

_SEVERITY_DEDUCTIONS: dict[str, int] = {
    "critical": 15,
    "high": 10,
    "medium": 5,
    "low": 2,
}


def _extract_cvss_score(issue: dict) -> float | None:
    """Best available CVSS score from an issue; None if absent or zero."""
    for key in _SCORE_FIELDS:
        raw = issue.get(key)
        if raw is None or raw == "" or raw == "0.0":
            continue
        try:
            return float(raw)
        except (TypeError, ValueError):
            continue
    return None


def _classify_severity(issue: dict) -> str:
    """Map CVSS (preferred) or explicit ``severity`` string to our severity band.

    Falls back to ``high`` when neither is usable, matching cve.py behavior.
    """
    cvss = _extract_cvss_score(issue)
    if cvss is not None:
        if cvss >= 9.0:
            return "critical"
        if cvss >= 7.0:
            return "high"
        if cvss >= 4.0:
            return "medium"
        return "low"

    explicit = issue.get("severity")
    if isinstance(explicit, str):
        normalized = explicit.strip().lower()
        if normalized in {"critical", "high", "medium", "low"}:
            return normalized

    return "high"


def _normalize_issues(data: dict) -> list[dict]:
    """Flatten both schema variants into a single list of issue records.

    Each normalized issue has at minimum ``id``, ``package``, ``version``,
    ``status`` (when available) plus any original fields that aid scoring
    and remediation messages.  Missing fields become empty strings so the
    rest of the check can operate uniformly.
    """
    issues: list[dict] = []

    # Kirkstone / Dunfell: nested package[*].issue[*]
    if isinstance(data.get("package"), list):
        for pkg in data["package"]:
            if not isinstance(pkg, dict):
                continue
            pkg_name = pkg.get("name", "")
            pkg_version = pkg.get("version", "")
            for issue in pkg.get("issue", []) or []:
                if not isinstance(issue, dict):
                    continue
                merged = dict(issue)
                merged.setdefault("package", pkg_name)
                merged.setdefault("version", pkg_version)
                issues.append(merged)

    # Scarthgap: flat issues[*] with package/version inline
    if isinstance(data.get("issues"), list):
        for issue in data["issues"]:
            if not isinstance(issue, dict):
                continue
            issues.append(dict(issue))

    return issues


def _classify_status(raw_status: object) -> str:
    """Bucket the raw ``status`` field into unpatched/patched/ignored/unknown."""
    if isinstance(raw_status, str):
        if raw_status == "Patched":
            return "patched"
        if raw_status == "Unpatched":
            return "unpatched"
        if raw_status == "Ignored":
            return "ignored"
    return "unknown"


def _finding_for_unpatched(issue: dict) -> Finding:
    cve_id = issue.get("id", "<unknown>")
    pkg = issue.get("package", "<unknown>")
    version = issue.get("version", "")
    severity = _classify_severity(issue)
    summary = issue.get("summary") or cve_id
    message = f"{cve_id}: {summary}"
    remediation = (
        f"Patch or mitigate {cve_id} in package {pkg} {version}. "
        "Check upstream for fixes or apply a CVE patch."
    ).strip()
    details = {
        "cve": cve_id,
        "package": pkg,
        "version": version,
        "status": "unpatched",
        "cvss": _extract_cvss_score(issue),
    }
    link = issue.get("link")
    if link:
        details["link"] = link
    return Finding(
        message=message,
        severity=severity,
        remediation=remediation,
        details=details,
        cra_mapping=list(_CRA_MAPPING),
        sources=list(_SOURCES),
    )


def _finding_for_unknown(issue: dict) -> Finding:
    cve_id = issue.get("id", "<unknown>")
    pkg = issue.get("package", "<unknown>")
    version = issue.get("version", "")
    raw_status = issue.get("status")
    message = (
        f"{cve_id}: unrecognized status {raw_status!r} from cve-check output for package {pkg}"
    )
    remediation = (
        "Inspect the cve-check.bbclass output and confirm the entry's status. "
        "Shipcheck treats unknown statuses as warnings until the reviewer confirms."
    )
    details = {
        "cve": cve_id,
        "package": pkg,
        "version": version,
        "status": "unknown",
        "raw_status": raw_status,
    }
    return Finding(
        message=message,
        severity="medium",
        remediation=remediation,
        details=details,
        cra_mapping=list(_CRA_MAPPING),
        sources=list(_SOURCES),
    )


def _finding_for_ignored(issue: dict) -> Finding:
    cve_id = issue.get("id", "<unknown>")
    pkg = issue.get("package", "<unknown>")
    version = issue.get("version", "")
    reason = issue.get("detail") or issue.get("reason") or "no reason recorded"
    message = f"{cve_id}: Ignored in cve-check ({reason})"
    details = {
        "cve": cve_id,
        "package": pkg,
        "version": version,
        "status": "ignored",
        "reason": reason,
    }
    return Finding(
        message=message,
        severity="info",
        remediation=(
            "Review the ignore justification against CRA Annex I Part II §3; "
            "record it in the vulnerability handling process documentation."
        ),
        details=details,
        cra_mapping=list(_CRA_MAPPING),
        sources=list(_SOURCES),
    )


def _resolve_summary_path(build_dir: Path, config_path: str | None) -> Path:
    """Resolve the summary path honoring the ``summary_path`` override.

        Absolute paths are used verbatim; relative paths are resolved under
        ``build_dir``.  ``None`` delegates to
        :func:`shipcheck.checks._cve_discovery.discover_cve_output` so the CVE
    checks agree on evidence location (pilot-0001 fix); when the
        shared helper also finds nothing, the canonical Yocto default is
        returned so the SKIP message still names the expected path.
    """
    if config_path is None:
        discovered = discover_cve_output(build_dir)
        if discovered is not None:
            return discovered
        return build_dir / DEFAULT_SUMMARY_RELPATH
    candidate = Path(config_path)
    if candidate.is_absolute():
        return candidate
    return build_dir / candidate


def _compute_score(findings: list[Finding]) -> int:
    """Deduct per non-info finding; floor at 0."""
    score = 50
    for finding in findings:
        score -= _SEVERITY_DEDUCTIONS.get(finding.severity, 0)
    return max(score, 0)


def _determine_status(findings: list[Finding]) -> CheckStatus:
    """PASS when no findings or only info; FAIL on critical/high; WARN otherwise."""
    non_info = [f for f in findings if f.severity != "info"]
    if not non_info:
        return CheckStatus.PASS
    severities = {f.severity for f in non_info}
    if severities & {"critical", "high"}:
        return CheckStatus.FAIL
    return CheckStatus.WARN


class YoctoCVECheck(BaseCheck):
    """Parse Yocto ``cve-check.bbclass`` summary and emit CRA-mapped findings."""

    id = "yocto-cve-check"
    name = "Yocto CVE Check"
    framework = ["CRA"]
    severity = "high"
    produces_cve_findings = True

    def run(self, build_dir: Path, config: dict) -> CheckResult:
        summary_path = _resolve_summary_path(build_dir, config.get("summary_path"))

        if not summary_path.exists():
            message = (
                f"No cve-check summary at {summary_path}. "
                'Add `INHERIT += "cve-check"` to local.conf or configure '
                "`yocto_cve.summary_path` in .shipcheck.yaml."
            )
            return CheckResult(
                check_id=self.id,
                check_name=self.name,
                status=CheckStatus.SKIP,
                score=0,
                max_score=50,
                findings=[],
                summary=message,
                cra_mapping=list(_CRA_MAPPING),
            )

        try:
            raw = summary_path.read_text()
            data = json.loads(raw)
        except (OSError, json.JSONDecodeError) as exc:
            detail = f"Failed to parse cve-check summary {summary_path}: {exc}"
            logger.exception("yocto-cve-check parse error: %s", summary_path)
            return CheckResult(
                check_id=self.id,
                check_name=self.name,
                status=CheckStatus.ERROR,
                score=0,
                max_score=50,
                findings=[
                    Finding(
                        message=detail,
                        severity="high",
                        remediation=(
                            "Re-run the Yocto build to regenerate cve-summary.json "
                            "or inspect it for truncation."
                        ),
                        details={
                            "summary_path": str(summary_path),
                            "error": str(exc),
                        },
                        cra_mapping=list(_CRA_MAPPING),
                        sources=list(_SOURCES),
                    )
                ],
                summary=detail,
                cra_mapping=list(_CRA_MAPPING),
            )

        if not isinstance(data, dict):
            detail = (
                f"cve-check summary {summary_path} has unexpected top-level "
                f"type {type(data).__name__}; expected object"
            )
            return CheckResult(
                check_id=self.id,
                check_name=self.name,
                status=CheckStatus.ERROR,
                score=0,
                max_score=50,
                findings=[
                    Finding(
                        message=detail,
                        severity="high",
                        remediation="Regenerate the cve-check summary and retry.",
                        details={"summary_path": str(summary_path)},
                        cra_mapping=list(_CRA_MAPPING),
                        sources=list(_SOURCES),
                    )
                ],
                summary=detail,
                cra_mapping=list(_CRA_MAPPING),
            )

        issues = _normalize_issues(data)
        treat_ignored_as_patched = bool(config.get("treat_ignored_as_patched", False))

        findings: list[Finding] = []
        counts = {"unpatched": 0, "patched": 0, "ignored": 0, "unknown": 0}

        for issue in issues:
            status = _classify_status(issue.get("status"))
            counts[status] += 1

            if status == "unpatched":
                findings.append(_finding_for_unpatched(issue))
            elif status == "ignored":
                if not treat_ignored_as_patched:
                    findings.append(_finding_for_ignored(issue))
            elif status == "unknown":
                findings.append(_finding_for_unknown(issue))
            # patched: no finding

        score = _compute_score(findings)
        status = _determine_status(findings)

        summary_parts = [
            f"{counts['unpatched']} unpatched",
            f"{counts['patched']} patched",
            f"{counts['ignored']} ignored",
        ]
        if counts["unknown"]:
            summary_parts.append(f"{counts['unknown']} unknown")
        summary_text = f"cve-check summary {summary_path.name}: " + ", ".join(summary_parts)

        return CheckResult(
            check_id=self.id,
            check_name=self.name,
            status=status,
            score=score,
            max_score=50,
            findings=findings,
            summary=summary_text,
            cra_mapping=list(_CRA_MAPPING),
        )

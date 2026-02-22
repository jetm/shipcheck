"""CVE vulnerability check."""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING

from shipcheck.models import BaseCheck, CheckResult, CheckStatus, Finding

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger(__name__)

IMAGES_SUBDIR = "tmp/deploy/images"

_REMEDIATION_NO_OUTPUT = (
    "No CVE scan output found. Add `inherit cve-check` to your image recipe "
    "or run sbom-cve-check against your SPDX SBOM."
)

_CVE_GLOB_PATTERNS = (
    "*.sbom-cve-check.yocto.json",
    "*.rootfs.json",
    "*/cve_check_summary*.json",
)

_REQUIRED_ISSUE_FIELDS = ("id", "status")

_SCORE_FIELDS = ("scorev4", "scorev3", "scorev2")


def _extract_cvss_score(issue: dict) -> float | None:
    """Extract the best available CVSS score from an issue dict.

    Priority: scorev4 > scorev3 > scorev2.
    Values of "0.0", empty string, or absent are treated as missing.
    """
    for field in _SCORE_FIELDS:
        raw = issue.get(field)
        if raw is None or raw == "" or raw == "0.0":
            continue
        return float(raw)
    return None


def _classify_severity(cvss: float | None) -> str:
    """Map a CVSS score to a severity band. Missing score -> high."""
    if cvss is None:
        return "high"
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    return "low"


def _build_findings(
    packages: list[dict],
    suppress_ids: set[str] | None = None,
) -> tuple[list[Finding], list[dict]]:
    """Generate findings for unpatched CVEs, applying suppression.

    Returns:
        A tuple of (findings, suppressed) where suppressed is a list of
        dicts with cve_id, package, and cvss for each suppressed CVE.
    """
    if suppress_ids is None:
        suppress_ids = set()
    findings: list[Finding] = []
    suppressed: list[dict] = []
    for pkg in packages:
        pkg_name = pkg.get("name", "<unknown>")
        for issue in pkg.get("issue", []):
            if issue["status"] != "Unpatched":
                continue
            cvss = _extract_cvss_score(issue)
            cve_id = issue["id"]
            if cve_id in suppress_ids:
                suppressed.append(
                    {
                        "cve_id": cve_id,
                        "package": pkg_name,
                        "cvss": cvss,
                    }
                )
                continue
            severity = _classify_severity(cvss)
            summary = issue.get("summary", cve_id)
            findings.append(
                Finding(
                    message=f"{cve_id}: {summary}",
                    severity=severity,
                    remediation=(
                        f"Patch or mitigate {cve_id} in package {pkg_name}. "
                        f"Check upstream for fixes or apply a CVE patch."
                    ),
                    details={
                        "cve_id": cve_id,
                        "cvss": cvss,
                        "package": pkg_name,
                    },
                    cra_mapping=["I.P2.2", "I.P2.3"],
                )
            )
    return findings, suppressed


def _determine_status(findings: list[Finding]) -> CheckStatus:
    """Determine check status from findings."""
    if not findings:
        return CheckStatus.PASS
    severities = {f.severity for f in findings}
    if severities & {"critical", "high"}:
        return CheckStatus.FAIL
    return CheckStatus.WARN


_SEVERITY_DEDUCTIONS: dict[str, int] = {
    "critical": 15,
    "high": 10,
    "medium": 5,
    "low": 2,
}


def _compute_score(findings: list[Finding]) -> int:
    """Compute CVE readiness score: start at 50, deduct per finding severity, floor at 0."""
    score = 50
    for finding in findings:
        score -= _SEVERITY_DEDUCTIONS.get(finding.severity, 0)
    return max(score, 0)


def _discover_cve_output(build_dir: Path) -> Path | None:
    """Search for CVE scan output in priority order, return first match.

    Lookup order:
        1. tmp/deploy/images/*.sbom-cve-check.yocto.json
        2. tmp/deploy/images/*.rootfs.json
        3. tmp/deploy/images/*/cve_check_summary*.json
    """
    images_dir = build_dir / IMAGES_SUBDIR
    if not images_dir.is_dir():
        return None

    for pattern in _CVE_GLOB_PATTERNS:
        matches = sorted(images_dir.glob(pattern))
        if matches:
            return matches[0]

    return None


def _parse_cve_json(cve_file: Path) -> list[dict]:
    """Parse a CVE JSON file and return the package list.

    Handles all three Yocto CVE output format variants:
    - sbom-cve-check: integer version, cpes field present
    - vex.bbclass: integer version, no cpes field
    - legacy cve-check: string version, no cpes field

    All fields except id and status on issues are optional.

    Returns:
        List of package dicts, each with 'name', 'version', 'issue', and
        any other fields present in the source JSON.

    Raises:
        ValueError: If the file is not valid JSON or lacks required structure.
    """
    try:
        data = json.loads(cve_file.read_text())
    except (json.JSONDecodeError, OSError) as e:
        msg = f"Failed to parse CVE JSON: {cve_file}: {e}"
        raise ValueError(msg) from e

    if "package" not in data:
        msg = f"Missing 'package' key in CVE JSON: {cve_file}"
        raise ValueError(msg)

    packages = data["package"]

    for pkg in packages:
        pkg_name = pkg.get("name", "<unknown>")
        for issue in pkg.get("issue", []):
            for field in _REQUIRED_ISSUE_FIELDS:
                if field not in issue:
                    msg = (
                        f"Package '{pkg_name}' has an issue missing required field"
                        f" '{field}' in {cve_file}"
                    )
                    raise ValueError(msg)

    return packages


class CVECheck(BaseCheck):
    """Assess CVE tracking from Yocto cve-check/sbom-cve-check/vex.bbclass output."""

    id = "cve-tracking"
    name = "CVE Tracking"
    framework = ["CRA"]
    severity = "critical"

    def run(self, build_dir: Path, config: dict) -> CheckResult:
        cve_file = _discover_cve_output(build_dir)

        if cve_file is None:
            result = CheckResult(
                check_id=self.id,
                check_name=self.name,
                status=CheckStatus.FAIL,
                score=0,
                max_score=50,
                findings=[
                    Finding(
                        message="No CVE scan output found in build directory.",
                        severity="critical",
                        remediation=_REMEDIATION_NO_OUTPUT,
                        cra_mapping=["I.P2.2", "I.P2.3"],
                    )
                ],
                summary="No CVE scan output found",
                cra_mapping=["I.P2.2", "I.P2.3"],
            )
            result.suppressed = []  # type: ignore[attr-defined]
            return result

        try:
            packages = _parse_cve_json(cve_file)
        except ValueError:
            logger.exception("Failed to parse CVE output: %s", cve_file)
            result = CheckResult(
                check_id=self.id,
                check_name=self.name,
                status=CheckStatus.FAIL,
                score=0,
                max_score=50,
                findings=[
                    Finding(
                        message=f"Failed to parse CVE output: {cve_file.name}",
                        severity="critical",
                        remediation=(
                            "Verify the CVE JSON file is valid and matches the expected format."
                        ),
                        cra_mapping=["I.P2.2", "I.P2.3"],
                    )
                ],
                summary=f"Failed to parse CVE output: {cve_file.name}",
                cra_mapping=["I.P2.2", "I.P2.3"],
            )
            result.suppressed = []  # type: ignore[attr-defined]
            return result

        suppress_ids = set(config.get("suppress", []))
        findings, suppressed = _build_findings(packages, suppress_ids)
        status = _determine_status(findings)

        score = _compute_score(findings)
        total_unpatched = len(findings)
        total_issues = sum(len(pkg.get("issue", [])) for pkg in packages)

        parts: list[str] = []
        if total_unpatched > 0:
            parts.append(
                f"{total_unpatched} unpatched CVE(s) found in {cve_file.name}"
                f" ({len(packages)} packages, {total_issues} issues)"
            )
        else:
            parts.append(
                f"CVE scan output found: {cve_file.name}"
                f" ({len(packages)} packages, {total_issues} issues)"
            )
        if suppressed:
            parts.append(f"{len(suppressed)} suppressed by configuration")
        summary = "; ".join(parts)

        result = CheckResult(
            check_id=self.id,
            check_name=self.name,
            status=status,
            score=score,
            max_score=50,
            findings=findings,
            summary=summary,
            cra_mapping=["I.P2.2", "I.P2.3"],
        )
        result.suppressed = suppressed  # type: ignore[attr-defined]
        return result

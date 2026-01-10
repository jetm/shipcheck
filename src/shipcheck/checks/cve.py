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


def _build_findings(packages: list[dict]) -> list[Finding]:
    """Generate findings for unpatched CVEs only."""
    findings: list[Finding] = []
    for pkg in packages:
        pkg_name = pkg.get("name", "<unknown>")
        for issue in pkg.get("issue", []):
            if issue["status"] != "Unpatched":
                continue
            cvss = _extract_cvss_score(issue)
            severity = _classify_severity(cvss)
            summary = issue.get("summary", issue["id"])
            findings.append(
                Finding(
                    message=f"{issue['id']}: {summary}",
                    severity=severity,
                    remediation=(
                        f"Patch or mitigate {issue['id']} in package {pkg_name}. "
                        f"Check upstream for fixes or apply a CVE patch."
                    ),
                    details={
                        "cve_id": issue["id"],
                        "cvss": cvss,
                        "package": pkg_name,
                    },
                )
            )
    return findings


def _determine_status(findings: list[Finding]) -> CheckStatus:
    """Determine check status from findings."""
    if not findings:
        return CheckStatus.PASS
    severities = {f.severity for f in findings}
    if severities & {"critical", "high"}:
        return CheckStatus.FAIL
    return CheckStatus.WARN


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
            return CheckResult(
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
                    )
                ],
                summary="No CVE scan output found",
            )

        try:
            packages = _parse_cve_json(cve_file)
        except ValueError:
            logger.exception("Failed to parse CVE output: %s", cve_file)
            return CheckResult(
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
                            "Verify the CVE JSON file is valid and matches"
                            " the expected format."
                        ),
                    )
                ],
                summary=f"Failed to parse CVE output: {cve_file.name}",
            )

        findings = _build_findings(packages)
        status = _determine_status(findings)

        # Scoring is implemented in task 3.6.
        total_unpatched = len(findings)
        total_issues = sum(len(pkg.get("issue", [])) for pkg in packages)
        if total_unpatched > 0:
            summary = (
                f"{total_unpatched} unpatched CVE(s) found in {cve_file.name}"
                f" ({len(packages)} packages, {total_issues} issues)"
            )
        else:
            summary = (
                f"CVE scan output found: {cve_file.name}"
                f" ({len(packages)} packages, {total_issues} issues)"
            )

        return CheckResult(
            check_id=self.id,
            check_name=self.name,
            status=status,
            score=50,
            max_score=50,
            findings=findings,
            summary=summary,
        )

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

        # Severity classification, suppression, and scoring
        # are implemented in tasks 3.4-3.6.
        total_issues = sum(len(pkg.get("issue", [])) for pkg in packages)
        return CheckResult(
            check_id=self.id,
            check_name=self.name,
            status=CheckStatus.PASS,
            score=50,
            max_score=50,
            findings=[],
            summary=(
                f"CVE scan output found: {cve_file.name}"
                f" ({len(packages)} packages, {total_issues} issues)"
            ),
        )

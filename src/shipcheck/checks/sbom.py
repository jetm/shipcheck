"""SBOM (Software Bill of Materials) check."""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING

from shipcheck.models import BaseCheck, CheckResult, Finding, determine_status

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger(__name__)

SPDX_SUBDIR = "tmp/deploy/spdx"
_REMEDIATION_SPDX = (
    "Enable SPDX SBOM generation by adding `inherit create-spdx`"
    " to your image recipe or local.conf."
)


def _discover_spdx_files(build_dir: Path) -> list[Path]:
    """Scan build_dir/tmp/deploy/spdx/ for **/*.spdx.json files."""
    spdx_dir = build_dir / SPDX_SUBDIR
    if not spdx_dir.is_dir():
        return []
    return sorted(spdx_dir.glob("**/*.spdx.json"))


def _load_spdx_docs(paths: list[Path]) -> list[tuple[Path, dict]]:
    """Load and parse SPDX JSON files, skipping invalid JSON."""
    docs = []
    for path in paths:
        try:
            data = json.loads(path.read_text())
            if isinstance(data, dict):
                docs.append((path, data))
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Skipping %s: %s", path, exc)
    return docs


def _has_describes(doc: dict) -> bool:
    """Check if an SPDX document has a DESCRIBES relationship."""
    return any(rel.get("relationshipType") == "DESCRIBES" for rel in doc.get("relationships", []))


def _package_count(doc: dict) -> int:
    """Count packages in an SPDX document."""
    packages = doc.get("packages", [])
    return len(packages) if isinstance(packages, list) else 0


def _select_document(docs: list[tuple[Path, dict]]) -> tuple[Path, dict] | None:
    """Select the best SPDX document for validation.

    Priority:
    1. Image-level document (has DESCRIBES relationship)
    2. Document with the most packages (fallback)
    """
    if not docs:
        return None

    image_docs = [(p, d) for p, d in docs if _has_describes(d)]
    if image_docs:
        return max(image_docs, key=lambda x: _package_count(x[1]))

    return max(docs, key=lambda x: _package_count(x[1]))


def _detect_format(doc: dict) -> str | None:
    """Detect the SBOM document format.

    Returns:
        "spdx-2" for SPDX 2.x, "spdx-3" for SPDX 3.0,
        "cyclonedx" for CycloneDX, or None if unrecognized.
    """
    spdx_version = doc.get("spdxVersion", "")
    if isinstance(spdx_version, str) and spdx_version.startswith("SPDX-2"):
        return "spdx-2"

    context = doc.get("@context", "")
    if isinstance(context, str) and "spdx.org" in context:
        return "spdx-3"

    if "bomFormat" in doc:
        return "cyclonedx"

    return None


class SBOMCheck(BaseCheck):
    """Validate SPDX 2.3 SBOM documents against BSI TR-03183-2 field requirements."""

    id = "sbom-generation"
    name = "SBOM Generation"
    framework = ["CRA"]
    severity = "critical"

    def run(self, build_dir: Path, config: dict) -> CheckResult:
        findings: list[Finding] = []
        spdx_dir = build_dir / SPDX_SUBDIR

        if not spdx_dir.is_dir():
            findings.append(
                Finding(
                    message="SPDX directory not found at tmp/deploy/spdx/",
                    severity="critical",
                    remediation=_REMEDIATION_SPDX,
                )
            )
            return CheckResult(
                check_id=self.id,
                check_name=self.name,
                status=determine_status(findings),
                score=0,
                max_score=50,
                findings=findings,
                summary="No SPDX directory found",
            )

        spdx_files = _discover_spdx_files(build_dir)
        docs = _load_spdx_docs(spdx_files)

        if not spdx_files or not docs:
            if not spdx_files:
                msg = "No .spdx.json files found"
            else:
                msg = "No valid .spdx.json files found"
            findings.append(
                Finding(
                    message=f"{msg} in tmp/deploy/spdx/",
                    severity="critical",
                    remediation=_REMEDIATION_SPDX,
                )
            )
            return CheckResult(
                check_id=self.id,
                check_name=self.name,
                status=determine_status(findings),
                score=0,
                max_score=50,
                findings=findings,
                summary=msg,
            )

        selected = _select_document(docs)
        if selected is None:
            findings.append(
                Finding(
                    message="No suitable SPDX document found",
                    severity="critical",
                    remediation=_REMEDIATION_SPDX,
                )
            )
            return CheckResult(
                check_id=self.id,
                check_name=self.name,
                status=determine_status(findings),
                score=0,
                max_score=50,
                findings=findings,
                summary="No suitable SPDX document found",
            )

        path, doc = selected
        pkg_count = _package_count(doc)

        fmt = _detect_format(doc)

        if fmt is None:
            findings.append(
                Finding(
                    message=(
                        "SBOM format not recognized"
                        " (expected SPDX 2.x, SPDX 3.0, or CycloneDX)"
                    ),
                    severity="high",
                    remediation=_REMEDIATION_SPDX,
                )
            )
            return CheckResult(
                check_id=self.id,
                check_name=self.name,
                status=determine_status(findings),
                score=0,
                max_score=50,
                findings=findings,
                summary="Unrecognized SBOM format",
            )

        if fmt in ("spdx-3", "cyclonedx"):
            fmt_label = "SPDX 3.0" if fmt == "spdx-3" else "CycloneDX"
            summary = f"{fmt_label} detected — format detected but not fully validated in v0.1"
            return CheckResult(
                check_id=self.id,
                check_name=self.name,
                status=determine_status(findings),
                score=10,
                max_score=50,
                findings=findings,
                summary=summary,
            )

        # SPDX 2.x — field validation added by tasks 2.4-2.5
        summary = f"SPDX 2.x found at {path.name} ({pkg_count} packages)"
        return CheckResult(
            check_id=self.id,
            check_name=self.name,
            status=determine_status(findings),
            score=10,
            max_score=50,
            findings=findings,
            summary=summary,
        )

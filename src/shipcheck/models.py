"""Domain models shared across shipcheck."""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, ClassVar

if TYPE_CHECKING:
    from pathlib import Path


class CheckStatus(StrEnum):
    """Outcome of a single check."""

    PASS = "pass"
    FAIL = "fail"
    WARN = "warn"
    SKIP = "skip"
    ERROR = "error"


@dataclass
class Finding:
    """A single issue found during a check."""

    message: str
    severity: str  # "critical" | "high" | "medium" | "low"
    remediation: str | None = None
    details: dict | None = None
    cra_mapping: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)


def determine_status(findings: list[Finding]) -> CheckStatus:
    """Compute CheckStatus from a list of findings.

    Rules:
        - No findings -> PASS
        - Any critical or high finding -> FAIL
        - Only medium or low findings -> WARN
    """
    if not findings:
        return CheckStatus.PASS
    severities = {f.severity for f in findings}
    if severities & {"critical", "high"}:
        return CheckStatus.FAIL
    return CheckStatus.WARN


@dataclass
class CheckResult:
    """Result of running one check."""

    check_id: str
    check_name: str
    status: CheckStatus
    score: int
    max_score: int
    findings: list[Finding]
    summary: str
    cra_mapping: list[str] = field(default_factory=list)


@dataclass
class ReportData:
    """Aggregated report data for a compliance scan."""

    checks: list[CheckResult]
    total_score: int
    max_total_score: int
    framework: str
    framework_version: str
    bsi_tr_version: str
    build_dir: str
    timestamp: str
    shipcheck_version: str


class BaseCheck(abc.ABC):
    """Abstract base class for all shipcheck checks."""

    id: str
    name: str
    framework: list[str]
    severity: str

    # Set to True on subclasses whose findings represent CVEs. The dossier
    # CVE filter, the multi-file `cve-report.md` emit, and any future CVE
    # aggregator discover producers via this flag instead of a hard-coded
    # ID set, so adding a new CVE source is a one-line override on the
    # check class with no central registration step.
    produces_cve_findings: ClassVar[bool] = False

    @abc.abstractmethod
    def run(self, build_dir: Path, config: dict) -> CheckResult:
        """Run the check against a Yocto build directory.

        Args:
            build_dir: Path to the Yocto build directory.
            config: Per-check configuration from .shipcheck.yaml.

        Returns:
            CheckResult with status, score, findings, and summary.
        """
        ...

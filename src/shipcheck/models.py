"""Domain models shared across shipcheck."""

from __future__ import annotations

import abc
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path


class CheckStatus(StrEnum):
    """Outcome of a single check."""

    PASS = "pass"
    FAIL = "fail"
    WARN = "warn"
    SKIP = "skip"


@dataclass
class Finding:
    """A single issue found during a check."""

    message: str
    severity: str  # "critical" | "high" | "medium" | "low"
    remediation: str | None = None
    details: dict | None = None


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

"""Domain models shared across shipcheck."""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class CheckStatus(StrEnum):
    """Outcome of a single check."""

    PASS = "pass"
    WARN = "warn"
    FAIL = "fail"
    ERROR = "error"
    SKIP = "skip"


@dataclass
class Finding:
    """A single issue found during a check."""

    title: str
    description: str
    severity: str  # "critical" | "high" | "medium" | "low" | "info"
    reference: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class CheckResult:
    """Result of running one check."""

    check_name: str
    status: CheckStatus
    findings: list[Finding] = field(default_factory=list)
    message: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def passed(self) -> bool:
        return self.status == CheckStatus.PASS

    @property
    def failed(self) -> bool:
        return self.status == CheckStatus.FAIL


@dataclass
class ReportData:
    """Aggregated report data for a compliance scan."""

    build_dir: str
    results: list[CheckResult] = field(default_factory=list)
    score: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def overall_status(self) -> CheckStatus:
        statuses = {r.status for r in self.results}
        if CheckStatus.ERROR in statuses:
            return CheckStatus.ERROR
        if CheckStatus.FAIL in statuses:
            return CheckStatus.FAIL
        if CheckStatus.WARN in statuses:
            return CheckStatus.WARN
        return CheckStatus.PASS


class BaseCheck(abc.ABC):
    """Abstract base class for all shipcheck checks."""

    #: Human-readable name shown in reports.
    name: str = ""

    @abc.abstractmethod
    def run(self, build_dir: str, **kwargs: Any) -> CheckResult:
        """Execute the check and return a result."""
        ...

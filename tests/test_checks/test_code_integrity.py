"""Scaffold tests for the unified code-integrity check.

Task 1.2 (RED phase). These tests pin the public surface of the new
package: the ``CodeIntegrityCheck`` class identity and the
``MechanismResult`` dataclass shape. Detector and aggregator behavior is
exercised by later tasks (1.3 - 1.7) under separate test classes in this
same file.
"""

from __future__ import annotations

from dataclasses import fields

import pytest

from shipcheck.checks.code_integrity import CodeIntegrityCheck, MechanismResult
from shipcheck.models import BaseCheck, Finding


class TestScaffold:
    """Pin the package's public surface defined in task 1.2."""

    def test_check_is_basecheck_subclass(self) -> None:
        assert issubclass(CodeIntegrityCheck, BaseCheck)

    def test_check_id(self) -> None:
        assert CodeIntegrityCheck.id == "code-integrity"

    def test_check_name(self) -> None:
        assert CodeIntegrityCheck.name == "Code Integrity"

    def test_check_framework(self) -> None:
        assert CodeIntegrityCheck.framework == ["CRA"]

    def test_check_severity(self) -> None:
        assert CodeIntegrityCheck.severity == "critical"

    def test_check_instantiable(self) -> None:
        # BaseCheck is abc.ABC; the subclass must implement run() so that
        # instantiation succeeds.
        instance = CodeIntegrityCheck()
        assert isinstance(instance, BaseCheck)

    def test_check_run_is_callable(self) -> None:
        # Skeleton run() must exist and be callable; later tasks fill in
        # the aggregator logic.
        instance = CodeIntegrityCheck()
        assert callable(instance.run)

    def test_mechanism_result_field_names(self) -> None:
        names = {f.name for f in fields(MechanismResult)}
        assert names == {"present", "confidence", "evidence", "misconfigurations"}

    def test_mechanism_result_defaults(self) -> None:
        # All fields should be constructible without positional arguments
        # so detectors can build a "not present" result without ceremony.
        result = MechanismResult()
        assert result.present is False
        assert result.confidence == "low"
        assert result.evidence == []
        assert result.misconfigurations == []

    def test_mechanism_result_accepts_findings(self) -> None:
        finding = Finding(message="bad key", severity="high")
        result = MechanismResult(
            present=True,
            confidence="high",
            evidence=["conf/local.conf"],
            misconfigurations=[finding],
        )
        assert result.present is True
        assert result.confidence == "high"
        assert result.evidence == ["conf/local.conf"]
        assert result.misconfigurations == [finding]

    @pytest.mark.parametrize("confidence", ["high", "medium", "low"])
    def test_mechanism_result_confidence_levels(self, confidence: str) -> None:
        # The dataclass holds a string; the contract documented in the
        # spec is high/medium/low. Exercise each level so a future
        # tightening (e.g. enum) breaks loudly.
        result = MechanismResult(present=True, confidence=confidence)
        assert result.confidence == confidence

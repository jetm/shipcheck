"""Tests for the check registry."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from shipcheck.checks.registry import CheckRegistry
from shipcheck.models import BaseCheck, CheckResult, CheckStatus, Finding

if TYPE_CHECKING:
    from pathlib import Path


class StubCheck(BaseCheck):
    """Minimal check for testing the registry."""

    id = "stub-check"
    name = "Stub Check"
    framework = ["CRA"]
    severity = "low"

    def __init__(self, *, check_id: str = "stub-check", name: str = "Stub Check") -> None:
        self.id = check_id
        self.name = name

    def run(self, build_dir: Path, config: dict) -> CheckResult:
        return CheckResult(
            check_id=self.id,
            check_name=self.name,
            status=CheckStatus.PASS,
            score=50,
            max_score=50,
            findings=[],
            summary=f"{self.name} passed",
        )


class FailingCheck(BaseCheck):
    """Check that returns FAIL for testing."""

    id = "failing-check"
    name = "Failing Check"
    framework = ["CRA"]
    severity = "high"

    def run(self, build_dir: Path, config: dict) -> CheckResult:
        return CheckResult(
            check_id=self.id,
            check_name=self.name,
            status=CheckStatus.FAIL,
            score=0,
            max_score=50,
            findings=[
                Finding(
                    message="Something is wrong",
                    severity="high",
                    remediation="Fix it",
                ),
            ],
            summary="Failing check failed",
        )


class TestCheckRegistryRegistration:
    """Tests for check registration."""

    def test_register_single_check(self) -> None:
        registry = CheckRegistry()
        check = StubCheck()
        registry.register(check)

        assert len(registry.checks) == 1
        assert registry.checks[0] is check

    def test_register_multiple_checks_preserves_order(self) -> None:
        registry = CheckRegistry()
        first = StubCheck(check_id="first", name="First")
        second = StubCheck(check_id="second", name="Second")
        third = StubCheck(check_id="third", name="Third")

        registry.register(first)
        registry.register(second)
        registry.register(third)

        assert [c.id for c in registry.checks] == ["first", "second", "third"]

    def test_register_duplicate_id_raises(self) -> None:
        registry = CheckRegistry()
        registry.register(StubCheck(check_id="dupe", name="First"))

        with pytest.raises(ValueError, match="already registered"):
            registry.register(StubCheck(check_id="dupe", name="Second"))

    def test_checks_property_returns_copy(self) -> None:
        registry = CheckRegistry()
        registry.register(StubCheck())
        checks = registry.checks
        checks.clear()

        assert len(registry.checks) == 1


class TestCheckRegistryExecution:
    """Tests for check execution."""

    def test_run_all_checks(self, tmp_path: Path) -> None:
        registry = CheckRegistry()
        registry.register(StubCheck(check_id="check-a", name="Check A"))
        registry.register(StubCheck(check_id="check-b", name="Check B"))

        results = registry.run_checks(build_dir=tmp_path, config={})

        assert len(results) == 2
        assert results[0].check_id == "check-a"
        assert results[1].check_id == "check-b"

    def test_execution_order_matches_registration(self, tmp_path: Path) -> None:
        registry = CheckRegistry()
        registry.register(StubCheck(check_id="z-last", name="Z Last"))
        registry.register(StubCheck(check_id="a-first", name="A First"))

        results = registry.run_checks(build_dir=tmp_path, config={})

        assert [r.check_id for r in results] == ["z-last", "a-first"]

    def test_run_checks_passes_build_dir(self, tmp_path: Path) -> None:
        class DirCapture(BaseCheck):
            id = "dir-capture"
            name = "Dir Capture"
            framework = ["CRA"]
            severity = "low"
            captured_dir: Path | None = None

            def run(self, build_dir: Path, config: dict) -> CheckResult:
                self.captured_dir = build_dir
                return CheckResult(
                    check_id=self.id,
                    check_name=self.name,
                    status=CheckStatus.PASS,
                    score=50,
                    max_score=50,
                    findings=[],
                    summary="ok",
                )

        check = DirCapture()
        registry = CheckRegistry()
        registry.register(check)
        registry.run_checks(build_dir=tmp_path, config={})

        assert check.captured_dir == tmp_path

    def test_run_checks_passes_per_check_config(self, tmp_path: Path) -> None:
        class ConfigCapture(BaseCheck):
            id = "config-capture"
            name = "Config Capture"
            framework = ["CRA"]
            severity = "low"
            captured_config: dict | None = None

            def run(self, build_dir: Path, config: dict) -> CheckResult:
                self.captured_config = config
                return CheckResult(
                    check_id=self.id,
                    check_name=self.name,
                    status=CheckStatus.PASS,
                    score=50,
                    max_score=50,
                    findings=[],
                    summary="ok",
                )

        check = ConfigCapture()
        registry = CheckRegistry()
        registry.register(check)
        full_config = {"config-capture": {"key": "value"}, "other": {"x": 1}}
        registry.run_checks(build_dir=tmp_path, config=full_config)

        assert check.captured_config == {"key": "value"}

    def test_run_checks_passes_empty_dict_when_no_per_check_config(self, tmp_path: Path) -> None:
        class ConfigCapture(BaseCheck):
            id = "config-capture"
            name = "Config Capture"
            framework = ["CRA"]
            severity = "low"
            captured_config: dict | None = None

            def run(self, build_dir: Path, config: dict) -> CheckResult:
                self.captured_config = config
                return CheckResult(
                    check_id=self.id,
                    check_name=self.name,
                    status=CheckStatus.PASS,
                    score=50,
                    max_score=50,
                    findings=[],
                    summary="ok",
                )

        check = ConfigCapture()
        registry = CheckRegistry()
        registry.register(check)
        registry.run_checks(build_dir=tmp_path, config={})

        assert check.captured_config == {}


class TestCheckRegistryFiltering:
    """Tests for --checks flag filtering."""

    def test_filter_by_single_check_id(self, tmp_path: Path) -> None:
        registry = CheckRegistry()
        registry.register(StubCheck(check_id="sbom-generation", name="SBOM"))
        registry.register(StubCheck(check_id="cve-tracking", name="CVE"))

        results = registry.run_checks(build_dir=tmp_path, config={}, check_ids=["cve-tracking"])

        assert len(results) == 1
        assert results[0].check_id == "cve-tracking"

    def test_filter_by_multiple_check_ids(self, tmp_path: Path) -> None:
        registry = CheckRegistry()
        registry.register(StubCheck(check_id="check-a", name="A"))
        registry.register(StubCheck(check_id="check-b", name="B"))
        registry.register(StubCheck(check_id="check-c", name="C"))

        results = registry.run_checks(
            build_dir=tmp_path, config={}, check_ids=["check-a", "check-c"]
        )

        assert len(results) == 2
        assert [r.check_id for r in results] == ["check-a", "check-c"]

    def test_filter_preserves_registration_order(self, tmp_path: Path) -> None:
        registry = CheckRegistry()
        registry.register(StubCheck(check_id="first", name="First"))
        registry.register(StubCheck(check_id="second", name="Second"))
        registry.register(StubCheck(check_id="third", name="Third"))

        results = registry.run_checks(build_dir=tmp_path, config={}, check_ids=["third", "first"])

        assert [r.check_id for r in results] == ["first", "third"]

    def test_filter_with_none_runs_all(self, tmp_path: Path) -> None:
        registry = CheckRegistry()
        registry.register(StubCheck(check_id="a", name="A"))
        registry.register(StubCheck(check_id="b", name="B"))

        results = registry.run_checks(build_dir=tmp_path, config={}, check_ids=None)

        assert len(results) == 2

    def test_filter_with_unknown_id_raises(self, tmp_path: Path) -> None:
        registry = CheckRegistry()
        registry.register(StubCheck(check_id="known", name="Known"))

        with pytest.raises(ValueError, match="Unknown check.*nonexistent"):
            registry.run_checks(build_dir=tmp_path, config={}, check_ids=["nonexistent"])


class TestDefaultRegistry:
    """Tests for the default registry with built-in checks."""

    def test_default_registry_has_builtin_checks(self) -> None:
        from shipcheck.checks.registry import get_default_registry

        registry = get_default_registry()
        check_ids = [c.id for c in registry.checks]

        assert "sbom-generation" in check_ids
        assert "cve-tracking" in check_ids

    def test_default_registry_order_sbom_before_cve(self) -> None:
        from shipcheck.checks.registry import get_default_registry

        registry = get_default_registry()
        check_ids = [c.id for c in registry.checks]

        assert check_ids.index("sbom-generation") < check_ids.index("cve-tracking")

    def test_default_registry_returns_fresh_instance(self) -> None:
        from shipcheck.checks.registry import get_default_registry

        r1 = get_default_registry()
        r2 = get_default_registry()

        assert r1 is not r2

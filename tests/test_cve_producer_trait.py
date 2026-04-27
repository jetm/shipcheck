"""Tests for the ``BaseCheck.produces_cve_findings`` trait.

The trait replaces the previous hardcoded ``_CVE_CHECK_IDS = {"cve-tracking",
"yocto-cve-check"}`` set used by both the dossier CVE filter (cli.py) and the
multi-scan CVE-velocity counter (history/dossier.py). A new CVE-producing
check should be picked up by both paths simply by setting
``produces_cve_findings = True`` on the class - no central registration step
required.

These tests register a fake CVE check via a monkeypatched registry and assert
that:

* :func:`shipcheck.cli._cve_check_ids` includes the fake's id,
* :func:`shipcheck.cli._cve_scoped_report` keeps the fake check's results
  (i.e. ``cve-report.md`` would include those findings),
* the existing built-in checks behave identically (no regression).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from shipcheck import cli
from shipcheck.checks.registry import CheckRegistry, get_default_registry
from shipcheck.history import dossier as dossier_module
from shipcheck.models import BaseCheck, CheckResult, CheckStatus, Finding, ReportData

if TYPE_CHECKING:
    from pathlib import Path


class _FakeCVECheck(BaseCheck):
    id = "fake-cve-source"
    name = "Fake CVE Source"
    framework = ["CRA"]
    severity = "high"
    produces_cve_findings = True

    def run(self, build_dir: Path, config: dict) -> CheckResult:  # pragma: no cover
        return CheckResult(
            check_id=self.id,
            check_name=self.name,
            status=CheckStatus.PASS,
            score=50,
            max_score=50,
            findings=[],
            summary="",
        )


class _FakeNonCVECheck(BaseCheck):
    id = "fake-non-cve-source"
    name = "Fake Non-CVE Source"
    framework = ["CRA"]
    severity = "low"
    # produces_cve_findings inherits the default (False)

    def run(self, build_dir: Path, config: dict) -> CheckResult:  # pragma: no cover
        return CheckResult(
            check_id=self.id,
            check_name=self.name,
            status=CheckStatus.PASS,
            score=50,
            max_score=50,
            findings=[],
            summary="",
        )


def _registry_with(*checks: BaseCheck) -> CheckRegistry:
    registry = CheckRegistry()
    for check in checks:
        registry.register(check)
    return registry


def _make_report_with(*results: CheckResult) -> ReportData:
    total = sum(r.score for r in results)
    max_total = sum(r.max_score for r in results)
    return ReportData(
        checks=list(results),
        total_score=total,
        max_total_score=max_total,
        framework="CRA",
        framework_version="2024/2847",
        bsi_tr_version="TR-03183-2 v2.1.0",
        build_dir="/tmp/fake-build",
        timestamp="2026-04-16T00:00:00Z",
        shipcheck_version="0.0.0",
    )


class TestProducesCveFindingsTrait:
    """The trait flag is the single source of truth for CVE-producer membership."""

    def test_default_is_false_on_basecheck(self):
        assert BaseCheck.produces_cve_findings is False

    def test_built_in_cve_checks_set_the_flag(self):
        registry = get_default_registry()
        producers = {c.id for c in registry.checks if c.produces_cve_findings}
        assert producers == {"cve-tracking", "yocto-cve-check"}

    def test_non_cve_checks_inherit_default(self):
        registry = get_default_registry()
        non_producers = {c.id for c in registry.checks if not c.produces_cve_findings}
        assert {
            "sbom-generation",
            "code-integrity",
            "image-features",
            "hardening-flags",
            "license-audit",
        } <= non_producers


class TestCveCheckIdsHelper:
    """``cli._cve_check_ids`` is a thin wrapper over the registered trait."""

    def test_returns_built_in_producers_by_default(self):
        assert cli._cve_check_ids() == frozenset({"cve-tracking", "yocto-cve-check"})

    def test_picks_up_a_fake_cve_check_when_registered(self, monkeypatch):
        fake_registry = _registry_with(_FakeCVECheck(), _FakeNonCVECheck())
        monkeypatch.setattr(cli, "get_default_registry", lambda: fake_registry)

        assert cli._cve_check_ids() == frozenset({"fake-cve-source"})

    def test_excludes_checks_that_do_not_set_the_flag(self, monkeypatch):
        fake_registry = _registry_with(_FakeNonCVECheck())
        monkeypatch.setattr(cli, "get_default_registry", lambda: fake_registry)

        assert cli._cve_check_ids() == frozenset()


class TestCveScopedReport:
    """``cli._cve_scoped_report`` is the dossier's cve-report.md filter."""

    def test_includes_fake_cve_check_findings(self, monkeypatch):
        fake_registry = _registry_with(_FakeCVECheck(), _FakeNonCVECheck())
        monkeypatch.setattr(cli, "get_default_registry", lambda: fake_registry)

        cve_finding = Finding(
            message="CVE-2026-9999 affects libfake",
            severity="high",
            details={"cve": "CVE-2026-9999", "package": "libfake"},
        )
        cve_result = CheckResult(
            check_id="fake-cve-source",
            check_name="Fake CVE Source",
            status=CheckStatus.FAIL,
            score=0,
            max_score=50,
            findings=[cve_finding],
            summary="1 unresolved CVE",
        )
        non_cve_result = CheckResult(
            check_id="fake-non-cve-source",
            check_name="Fake Non-CVE Source",
            status=CheckStatus.PASS,
            score=50,
            max_score=50,
            findings=[],
            summary="",
        )

        report = _make_report_with(cve_result, non_cve_result)
        scoped = cli._cve_scoped_report(report)

        assert [c.check_id for c in scoped.checks] == ["fake-cve-source"]
        assert scoped.checks[0].findings == [cve_finding]

    def test_drops_non_cve_check_results(self, monkeypatch):
        fake_registry = _registry_with(_FakeCVECheck())
        monkeypatch.setattr(cli, "get_default_registry", lambda: fake_registry)

        sbom_result = CheckResult(
            check_id="sbom-generation",
            check_name="SBOM",
            status=CheckStatus.PASS,
            score=50,
            max_score=50,
            findings=[],
            summary="",
        )
        report = _make_report_with(sbom_result)

        scoped = cli._cve_scoped_report(report)

        assert scoped.checks == []


class TestDossierCveOpenCount:
    """``history.dossier._cve_open_count`` derives producers from the trait."""

    def test_counts_findings_from_fake_cve_check(self, monkeypatch):
        fake_registry = _registry_with(_FakeCVECheck())
        monkeypatch.setattr(
            "shipcheck.checks.registry.get_default_registry",
            lambda: fake_registry,
        )

        row = {
            "checks": [
                {"check_id": "fake-cve-source", "finding_count": 3},
                {"check_id": "sbom-generation", "finding_count": 99},
            ],
        }

        assert dossier_module._cve_open_count(row) == 3

    def test_excludes_non_cve_checks(self, monkeypatch):
        fake_registry = _registry_with(_FakeCVECheck())
        monkeypatch.setattr(
            "shipcheck.checks.registry.get_default_registry",
            lambda: fake_registry,
        )

        row = {
            "checks": [
                {"check_id": "license-audit", "finding_count": 7},
            ],
        }

        assert dossier_module._cve_open_count(row) == 0


@pytest.mark.parametrize(
    "consumer",
    [cli._cve_check_ids, dossier_module._cve_check_ids],
)
def test_helpers_share_the_same_trait_source(consumer, monkeypatch):
    """Both consumers must agree on the producer set so the dossier
    filter and the CVE-velocity counter never disagree on what counts."""
    fake_registry = _registry_with(_FakeCVECheck(), _FakeNonCVECheck())
    monkeypatch.setattr(cli, "get_default_registry", lambda: fake_registry)
    monkeypatch.setattr(
        "shipcheck.checks.registry.get_default_registry",
        lambda: fake_registry,
    )

    assert consumer() == frozenset({"fake-cve-source"})

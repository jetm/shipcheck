"""Tests for :mod:`shipcheck.history.dossier`.

Task 6.3 of devspec change ``shipcheck-v03-cra-evidence``. Pins the
contract of ``build_dossier(store, since=None, build_dir=None) ->
DossierData``:

* the returned dossier exposes the four temporal sections the spec
  names: **scan cadence**, **score trend**, **CVE introduction and
  resolution velocity**, and **licence drift timeline**,
* the ``since`` filter excludes scans whose timestamp is strictly
  earlier than the supplied ISO-8601 date,
* the ``build_dir`` filter restricts the dossier to scans recorded
  against a specific build directory (multi-product vendors),
* an empty store yields a dossier containing an explicit
  ``"no scans recorded"`` marker so the downstream renderer can surface
  the absence of evidence rather than a silent empty report.

The import targets ``shipcheck.history.dossier.build_dossier`` and
``shipcheck.history.dossier.DossierData`` are deliberately absent until
task 6.4 - this module is expected to fail at collection time with
``ImportError``, which is the valid RED signal for TDD. The helper
seeding logic exercises ``shipcheck.history.store.HistoryStore`` which
is specified by task 6.1 (persist/query contract: timestamp,
build_dir_hash, per-check status/score, finding counts).
"""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING

import pytest

from shipcheck.history.dossier import DossierData, build_dossier
from shipcheck.history.store import HistoryStore
from shipcheck.models import CheckResult, CheckStatus, Finding, ReportData

if TYPE_CHECKING:
    from pathlib import Path


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_report(
    *,
    timestamp: str,
    build_dir: str,
    cve_findings: int = 0,
    license_findings: int = 0,
    total_score: int = 100,
    max_total_score: int = 100,
) -> ReportData:
    """Build a minimal ``ReportData`` suitable for the history store.

    ``cve_findings`` and ``license_findings`` let the tests drive the
    velocity and drift sections with distinguishable numbers per scan
    without pulling in the real check fixtures.
    """

    cve_check = CheckResult(
        check_id="cve-tracking",
        check_name="CVE tracking",
        status=CheckStatus.WARN if cve_findings else CheckStatus.PASS,
        score=50 - cve_findings,
        max_score=50,
        findings=[
            Finding(
                message=f"CVE-2026-{1000 + i} affecting openssl",
                severity="medium",
                cra_mapping=["I.P2.2", "I.P2.3"],
            )
            for i in range(cve_findings)
        ],
        summary=f"{cve_findings} unresolved CVEs",
        cra_mapping=["I.P2.2", "I.P2.3"],
    )
    license_check = CheckResult(
        check_id="license-audit",
        check_name="License audit",
        status=CheckStatus.WARN if license_findings else CheckStatus.PASS,
        score=50 - license_findings,
        max_score=50,
        findings=[
            Finding(
                message=f"unknown-license-package-{i}",
                severity="low",
                cra_mapping=["I.P2.1", "VII.2.b"],
            )
            for i in range(license_findings)
        ],
        summary=f"{license_findings} unknown licences",
        cra_mapping=["I.P2.1", "VII.2.b"],
    )
    total = cve_check.score + license_check.score
    return ReportData(
        checks=[cve_check, license_check],
        total_score=total if total_score is None else total_score,
        max_total_score=max_total_score,
        framework="CRA",
        framework_version="2024/2847",
        bsi_tr_version="TR-03183-2 v2.1.0",
        build_dir=build_dir,
        timestamp=timestamp,
        shipcheck_version="0.3.0",
    )


def _seed_three_scans(store: HistoryStore, build_dir: str = "/srv/yocto/tmp") -> list[ReportData]:
    """Persist three synthetic scans on escalating dates.

    The scans are deliberately ordered so that tests can assert cadence
    and velocity: scan 1 has no findings, scan 2 introduces CVEs and
    licence drift, scan 3 resolves one CVE but retains drift.
    """

    scan_a = _make_report(
        timestamp="2026-01-15T10:00:00Z",
        build_dir=build_dir,
        cve_findings=0,
        license_findings=0,
        total_score=100,
    )
    scan_b = _make_report(
        timestamp="2026-02-15T10:00:00Z",
        build_dir=build_dir,
        cve_findings=3,
        license_findings=1,
        total_score=96,
    )
    scan_c = _make_report(
        timestamp="2026-03-15T10:00:00Z",
        build_dir=build_dir,
        cve_findings=2,
        license_findings=1,
        total_score=97,
    )
    for scan in (scan_a, scan_b, scan_c):
        store.persist(scan)
    return [scan_a, scan_b, scan_c]


@pytest.fixture
def store(tmp_path: Path) -> HistoryStore:
    """Return a fresh ``HistoryStore`` backed by a per-test SQLite file."""

    return HistoryStore(tmp_path / "history.db")


# ---------------------------------------------------------------------------
# (a) Four canonical sections
# ---------------------------------------------------------------------------


class TestDossierSections:
    """``build_dossier`` returns a structure with the four spec sections."""

    def test_returns_dossier_data_instance(self, store: HistoryStore):
        _seed_three_scans(store)
        dossier = build_dossier(store)

        assert isinstance(dossier, DossierData)

    def test_has_scan_cadence_section(self, store: HistoryStore):
        _seed_three_scans(store)
        dossier = build_dossier(store)

        assert hasattr(dossier, "scan_cadence"), (
            "DossierData must expose a scan_cadence section per spec"
        )
        assert dossier.scan_cadence is not None

    def test_has_score_trend_section(self, store: HistoryStore):
        _seed_three_scans(store)
        dossier = build_dossier(store)

        assert hasattr(dossier, "score_trend"), (
            "DossierData must expose a score_trend section per spec"
        )
        assert dossier.score_trend is not None

    def test_has_cve_velocity_section(self, store: HistoryStore):
        _seed_three_scans(store)
        dossier = build_dossier(store)

        assert hasattr(dossier, "cve_velocity"), (
            "DossierData must expose a cve_velocity section per spec (introduction and resolution)"
        )
        assert dossier.cve_velocity is not None

    def test_has_license_drift_timeline_section(self, store: HistoryStore):
        _seed_three_scans(store)
        dossier = build_dossier(store)

        assert hasattr(dossier, "license_drift"), (
            "DossierData must expose a license_drift timeline section per spec"
        )
        assert dossier.license_drift is not None


# ---------------------------------------------------------------------------
# (b) `since` filter honored
# ---------------------------------------------------------------------------


class TestSinceFilter:
    """The ``since`` argument restricts the dossier to recent scans."""

    def test_since_excludes_older_scans(self, store: HistoryStore):
        _seed_three_scans(store)

        dossier = build_dossier(store, since="2026-02-01")
        rendered = str(dossier)

        # Only the Feb and Mar scans should be visible.
        assert "2026-02-15" in rendered
        assert "2026-03-15" in rendered
        # The January scan must be excluded.
        assert "2026-01-15" not in rendered

    def test_since_with_no_matching_scans_returns_no_scans_marker(self, store: HistoryStore):
        _seed_three_scans(store)

        dossier = build_dossier(store, since="2027-01-01")
        rendered = str(dossier)

        assert "no scans recorded" in rendered.lower()

    def test_since_none_includes_all_scans(self, store: HistoryStore):
        _seed_three_scans(store)

        dossier = build_dossier(store, since=None)
        rendered = str(dossier)

        assert "2026-01-15" in rendered
        assert "2026-02-15" in rendered
        assert "2026-03-15" in rendered


# ---------------------------------------------------------------------------
# (c) `build_dir` filter honored
# ---------------------------------------------------------------------------


class TestBuildDirFilter:
    """``build_dir`` restricts the dossier to a specific product build."""

    def test_build_dir_excludes_other_products(self, store: HistoryStore):
        # Seed three scans under the default build dir...
        default_scans = _seed_three_scans(store, build_dir="/srv/yocto/product-a")
        # ...plus two scans under a different product.
        other_a = replace(
            default_scans[0],
            build_dir="/srv/yocto/product-b",
            timestamp="2026-01-20T10:00:00Z",
        )
        other_b = replace(
            default_scans[1],
            build_dir="/srv/yocto/product-b",
            timestamp="2026-02-20T10:00:00Z",
        )
        store.persist(other_a)
        store.persist(other_b)

        dossier = build_dossier(store, build_dir="/srv/yocto/product-a")
        rendered = str(dossier)

        assert "product-a" in rendered
        assert "product-b" not in rendered

    def test_build_dir_none_includes_all_products(self, store: HistoryStore):
        default_scans = _seed_three_scans(store, build_dir="/srv/yocto/product-a")
        other = replace(
            default_scans[0],
            build_dir="/srv/yocto/product-b",
            timestamp="2026-01-20T10:00:00Z",
        )
        store.persist(other)

        dossier = build_dossier(store, build_dir=None)
        rendered = str(dossier)

        assert "product-a" in rendered
        assert "product-b" in rendered

    def test_build_dir_with_no_matching_product_returns_no_scans_marker(self, store: HistoryStore):
        _seed_three_scans(store, build_dir="/srv/yocto/product-a")

        dossier = build_dossier(store, build_dir="/srv/yocto/does-not-exist")
        rendered = str(dossier)

        assert "no scans recorded" in rendered.lower()


# ---------------------------------------------------------------------------
# (d) Empty store marker
# ---------------------------------------------------------------------------


class TestEmptyStoreMarker:
    """An empty history store still yields a well-formed dossier."""

    def test_empty_store_returns_dossier_data(self, store: HistoryStore):
        dossier = build_dossier(store)

        assert isinstance(dossier, DossierData)

    def test_empty_store_renders_explicit_no_scans_marker(self, store: HistoryStore):
        dossier = build_dossier(store)
        rendered = str(dossier)

        assert "no scans recorded" in rendered.lower(), (
            "Empty dossier must surface an explicit 'no scans recorded' "
            "marker so renderers can flag absence of evidence rather than "
            "emit a blank section"
        )

    def test_empty_store_with_since_and_build_dir_still_marks_no_scans(self, store: HistoryStore):
        dossier = build_dossier(store, since="2026-01-01", build_dir="/srv/yocto/anything")
        rendered = str(dossier)

        assert "no scans recorded" in rendered.lower()

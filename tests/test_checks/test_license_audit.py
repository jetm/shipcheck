"""Tests for the Yocto license.manifest audit check.

These tests drive task 4.4 (`src/shipcheck/checks/license_audit.py`). They
import `LicenseAuditCheck` which does not yet exist, so collection will fail
with ImportError until task 4.4 lands - that ImportError is the expected RED
state produced by this file.

Fixtures at `tests/fixtures/licenses/<image>/license.manifest` are created by
task 4.1. Each test that needs a manifest copies the relevant fixture into
`tmp_path/tmp/deploy/licenses/<image>/license.manifest` so the check sees a
realistic Yocto build tree.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

from shipcheck.checks.license_audit import LicenseAuditCheck
from shipcheck.models import CheckStatus, Finding

FIXTURE_ROOT = Path(__file__).parent.parent / "fixtures" / "licenses"
LICENSE_SUBDIR = "tmp/deploy/licenses"


# --- helpers ---


def _copy_image(fixture_name: str, build_dir: Path, *, image_name: str | None = None) -> Path:
    """Copy a fixture image directory into build_dir/tmp/deploy/licenses/.

    Returns the destination image directory.
    """
    src = FIXTURE_ROOT / fixture_name / "license.manifest"
    assert src.is_file(), f"missing fixture {src}"
    dest_dir = build_dir / LICENSE_SUBDIR / (image_name or fixture_name)
    dest_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dest_dir / "license.manifest")
    return dest_dir


def _set_mtime(path: Path, epoch: float) -> None:
    """Pin the mtime of a path (and its contained manifest) for determinism."""
    manifest = path / "license.manifest"
    if manifest.is_file():
        os.utime(manifest, (epoch, epoch))
    os.utime(path, (epoch, epoch))


def _collect_text(result) -> str:
    """Flatten summary + finding messages + details into one lowercase blob."""
    parts: list[str] = [result.summary]
    for finding in result.findings:
        parts.append(finding.message)
        if finding.details is not None:
            parts.append(str(finding.details))
    return " ".join(parts)


@pytest.fixture
def check() -> LicenseAuditCheck:
    return LicenseAuditCheck()


# --- (b) SKIP when tmp/deploy/licenses/ is absent ---


class TestDiscoverySkipWhenMissing:
    def test_returns_skip_status(self, tmp_path: Path, check: LicenseAuditCheck):
        result = check.run(tmp_path, {})
        assert result.status == CheckStatus.SKIP

    def test_no_high_severity_findings(self, tmp_path: Path, check: LicenseAuditCheck):
        result = check.run(tmp_path, {})
        high_sev = [f for f in result.findings if f.severity in {"critical", "high", "medium"}]
        assert high_sev == []

    def test_summary_indicates_skip_reason(self, tmp_path: Path, check: LicenseAuditCheck):
        result = check.run(tmp_path, {})
        lowered = result.summary.lower()
        assert "licenses" in lowered or "skip" in lowered or "not found" in lowered


# --- (a) Discovery picks most-recent image dir when multiple exist ---


class TestDiscoveryPicksMostRecent:
    def test_selects_newer_image_when_two_exist(
        self, tmp_path: Path, check: LicenseAuditCheck
    ):
        older = _copy_image("core-image-minimal", tmp_path, image_name="core-image-minimal")
        newer = _copy_image("core-image-mixed", tmp_path, image_name="core-image-mixed")

        _set_mtime(older, 1_700_000_000.0)
        _set_mtime(newer, 1_800_000_000.0)

        result = check.run(tmp_path, {})

        # core-image-mixed contains GPL-2.0-only (strong-copyleft).
        # core-image-minimal is purely permissive. If discovery picked the
        # newer (mixed) directory, we expect GPL / strong-copyleft markers.
        blob = _collect_text(result)
        assert "GPL" in blob or "strong-copyleft" in blob or "strong_copyleft" in blob

    def test_prefers_newer_even_when_alphabetically_earlier(
        self, tmp_path: Path, check: LicenseAuditCheck
    ):
        # 'core-image-agpl' sorts alphabetically before 'core-image-minimal'.
        # Make the alphabetically-earlier one OLDER; discovery must still pick
        # the newer, alphabetically-later one.
        agpl = _copy_image("core-image-agpl", tmp_path, image_name="core-image-agpl")
        minimal = _copy_image(
            "core-image-minimal", tmp_path, image_name="core-image-minimal"
        )

        _set_mtime(agpl, 1_600_000_000.0)
        _set_mtime(minimal, 1_900_000_000.0)

        result = check.run(tmp_path, {})

        blob = _collect_text(result).lower()
        assert "agpl" not in blob
        assert "network-copyleft" not in blob and "network_copyleft" not in blob


# --- (c) Classification: SPDX IDs map to documented categories ---


class TestClassification:
    def test_mit_is_permissive(self, tmp_path: Path, check: LicenseAuditCheck):
        _copy_image("core-image-minimal", tmp_path)
        result = check.run(tmp_path, {})
        blob = _collect_text(result).lower()
        assert "strong-copyleft" not in blob and "strong_copyleft" not in blob
        assert "network-copyleft" not in blob and "network_copyleft" not in blob
        assert result.status != CheckStatus.FAIL

    def test_gpl_2_only_is_strong_copyleft(
        self, tmp_path: Path, check: LicenseAuditCheck
    ):
        _copy_image("core-image-mixed", tmp_path)
        result = check.run(tmp_path, {})
        blob = _collect_text(result)
        assert (
            "strong-copyleft" in blob
            or "strong_copyleft" in blob
            or "GPL-2.0-only" in blob
        )

    def test_agpl_3_only_is_network_copyleft(
        self, tmp_path: Path, check: LicenseAuditCheck
    ):
        _copy_image("core-image-agpl", tmp_path)
        result = check.run(tmp_path, {})
        blob = _collect_text(result)
        assert (
            "network-copyleft" in blob
            or "network_copyleft" in blob
            or "AGPL-3.0-only" in blob
        )

    def test_apache_2_is_permissive(self, tmp_path: Path, check: LicenseAuditCheck):
        # Apache-2.0 appears in core-image-minimal alongside MIT/BSD-3-Clause.
        # Nothing in that manifest should classify as copyleft.
        _copy_image("core-image-minimal", tmp_path)
        result = check.run(tmp_path, {})
        blob = _collect_text(result).lower()
        assert "copyleft" not in blob

    def test_lgpl_2_1_only_is_weak_copyleft(
        self, tmp_path: Path, check: LicenseAuditCheck
    ):
        # No fixture covers LGPL-2.1-only on its own, so synthesise one inline.
        image_dir = tmp_path / LICENSE_SUBDIR / "core-image-lgpl"
        image_dir.mkdir(parents=True)
        (image_dir / "license.manifest").write_text(
            "PACKAGE NAME: glib-2.0\n"
            "PACKAGE VERSION: 2.78.0\n"
            "RECIPE NAME: glib-2.0\n"
            "LICENSE: LGPL-2.1-only\n"
        )
        result = check.run(tmp_path, {})
        blob = _collect_text(result)
        assert (
            "weak-copyleft" in blob
            or "weak_copyleft" in blob
            or "LGPL-2.1-only" in blob
        )


# --- (d) Unknown licence produces a WARN-severity finding ---


def _unknown_findings(findings: list[Finding]) -> list[Finding]:
    return [
        f
        for f in findings
        if "unknown" in f.message.lower()
        or (f.details is not None and "unknown" in str(f.details).lower())
    ]


class TestUnknownLicenseWarns:
    def test_unknown_license_emits_finding(
        self, tmp_path: Path, check: LicenseAuditCheck
    ):
        _copy_image("core-image-unknown", tmp_path)
        result = check.run(tmp_path, {})
        assert _unknown_findings(result.findings), (
            "expected at least one 'unknown' finding for core-image-unknown fixture"
        )

    def test_unknown_license_severity_is_warn_level(
        self, tmp_path: Path, check: LicenseAuditCheck
    ):
        _copy_image("core-image-unknown", tmp_path)
        result = check.run(tmp_path, {})
        findings = _unknown_findings(result.findings)
        assert findings
        # WARN status requires severities below critical/high - use medium or low.
        assert all(f.severity in {"medium", "low"} for f in findings)

    def test_check_status_is_warn_on_unknown(
        self, tmp_path: Path, check: LicenseAuditCheck
    ):
        _copy_image("core-image-unknown", tmp_path)
        result = check.run(tmp_path, {})
        assert result.status == CheckStatus.WARN


# --- (e) Copyleft boundary WARN when strong-copyleft + proprietary coexist ---


def _boundary_findings(findings: list[Finding]) -> list[Finding]:
    return [
        f
        for f in findings
        if "boundary" in f.message.lower()
        or (f.details is not None and "boundary" in str(f.details).lower())
    ]


class TestCopyleftBoundary:
    def test_boundary_finding_when_gpl_and_proprietary(
        self, tmp_path: Path, check: LicenseAuditCheck
    ):
        _copy_image("core-image-gpl-proprietary", tmp_path)
        result = check.run(tmp_path, {})
        assert _boundary_findings(result.findings), (
            "expected a copyleft-boundary finding when strong-copyleft and "
            "proprietary coexist"
        )

    def test_boundary_finding_is_warn_severity(
        self, tmp_path: Path, check: LicenseAuditCheck
    ):
        _copy_image("core-image-gpl-proprietary", tmp_path)
        result = check.run(tmp_path, {})
        findings = _boundary_findings(result.findings)
        assert findings
        assert all(f.severity in {"medium", "low"} for f in findings)


# --- (f) No boundary finding when only permissive + strong-copyleft coexist ---


class TestNoBoundaryWithoutProprietary:
    def test_no_boundary_in_mixed_gpl_mit(
        self, tmp_path: Path, check: LicenseAuditCheck
    ):
        # core-image-mixed: GPL-2.0-only + MIT + Apache-2.0; no proprietary.
        _copy_image("core-image-mixed", tmp_path)
        result = check.run(tmp_path, {})
        assert _boundary_findings(result.findings) == [], (
            "did not expect a copyleft-boundary finding when only permissive "
            "and strong-copyleft coexist"
        )


# --- (g) cra_mapping contains at least one of {"I.P2.1", "VII.2"} ---


class TestCraMappingOnEveryFinding:
    EXPECTED = {"I.P2.1", "VII.2"}

    @pytest.mark.parametrize(
        "fixture_name",
        [
            "core-image-minimal",
            "core-image-mixed",
            "core-image-gpl-proprietary",
            "core-image-agpl",
            "core-image-unknown",
        ],
    )
    def test_every_finding_has_expected_mapping(
        self,
        tmp_path: Path,
        check: LicenseAuditCheck,
        fixture_name: str,
    ):
        _copy_image(fixture_name, tmp_path)
        result = check.run(tmp_path, {})
        for finding in result.findings:
            assert finding.cra_mapping, (
                f"finding {finding.message!r} has empty cra_mapping; "
                f"expected one of {sorted(self.EXPECTED)}"
            )
            assert set(finding.cra_mapping) & self.EXPECTED, (
                f"finding {finding.message!r} cra_mapping="
                f"{finding.cra_mapping!r} must include one of "
                f"{sorted(self.EXPECTED)}"
            )

    def test_check_result_level_mapping_present(
        self, tmp_path: Path, check: LicenseAuditCheck
    ):
        _copy_image("core-image-mixed", tmp_path)
        result = check.run(tmp_path, {})
        assert result.cra_mapping, "CheckResult.cra_mapping must be non-empty"
        assert set(result.cra_mapping) & self.EXPECTED, (
            f"CheckResult.cra_mapping={result.cra_mapping!r} must include "
            f"one of {sorted(self.EXPECTED)}"
        )

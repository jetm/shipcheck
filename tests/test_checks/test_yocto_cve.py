"""Tests for YoctoCVECheck: cve-check.bbclass summary parsing and reconciliation.

These tests are intentionally RED until tasks 5.3+ implement
``shipcheck.checks.yocto_cve.YoctoCVECheck``. Fixtures are produced by task 5.1.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from shipcheck.checks.yocto_cve import YoctoCVECheck
from shipcheck.models import CheckStatus

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "yocto_cve"

_DEFAULT_SUMMARY_RELPATH = Path("tmp") / "log" / "cve" / "cve-summary.json"


def _place_summary(build_dir: Path, fixture_name: str, relpath: Path = _DEFAULT_SUMMARY_RELPATH) -> Path:
    """Copy a fixture summary file into ``build_dir`` at ``relpath``."""
    src = FIXTURES_DIR / fixture_name
    dst = build_dir / relpath
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(src, dst)
    return dst


def _run(build_dir: Path, config: dict | None = None):
    """Run the check with a fresh instance and (optionally) per-check config."""
    check = YoctoCVECheck()
    return check.run(build_dir, config or {})


# --- (a) SKIP when summary file missing -------------------------------------


class TestSummaryMissing:
    """SKIP when the expected summary path does not exist."""

    def test_skip_when_default_path_missing(self, tmp_path: Path) -> None:
        """Empty build dir yields SKIP referencing the default path."""
        result = _run(tmp_path)

        assert result.status == CheckStatus.SKIP
        expected = str(_DEFAULT_SUMMARY_RELPATH)
        # The message must name the expected path (not just be vaguely "not found").
        assert expected in result.summary or any(
            expected in (f.message or "") for f in result.findings
        ), f"expected path {expected!r} not named in SKIP message"

    def test_skip_when_parent_dir_missing(self, tmp_path: Path) -> None:
        """SKIP is stable even when ``tmp/log/cve/`` directory doesn't exist."""
        result = _run(tmp_path)

        assert result.status == CheckStatus.SKIP


# --- (b) ERROR on malformed JSON --------------------------------------------


class TestMalformedSummary:
    """ERROR with parse detail when the summary file cannot be decoded."""

    def test_error_on_malformed_json(self, tmp_path: Path) -> None:
        _place_summary(tmp_path, "malformed.json")

        result = _run(tmp_path)

        assert result.status == CheckStatus.ERROR
        # At least one finding explains why the parse failed.
        assert result.findings, "ERROR status must include a parse-detail finding"
        detail_text = " ".join(
            [result.summary or ""] + [f.message or "" for f in result.findings]
        ).lower()
        assert any(
            token in detail_text for token in ("parse", "json", "decode", "malformed")
        ), f"finding does not describe a parse error: {detail_text!r}"


# --- (c)+(d) schema tolerance: Kirkstone nested and Scarthgap flat ----------


def _finding_cve_ids(result) -> set[str]:
    """Collect CVE identifiers referenced by findings (message or details)."""
    ids: set[str] = set()
    for f in result.findings:
        blob = f.message or ""
        if f.details:
            blob += " " + json.dumps(f.details)
        for token in blob.replace(",", " ").split():
            if token.startswith("CVE-"):
                ids.add(token.strip(":.,);"))
    return ids


class TestKirkstoneSchema:
    """Nested ``package[*].issue[*]`` layout (Kirkstone / Dunfell)."""

    def test_parses_unpatched_only(self, tmp_path: Path) -> None:
        """Exactly the 2 Unpatched entries in the fixture become findings.

        Fixture contains: CVE-2023-0286 Patched, CVE-2023-0464 Unpatched,
        CVE-2023-0465 Ignored, CVE-2022-48174 Unpatched, CVE-2023-42363 Patched.
        """
        _place_summary(tmp_path, "cve-summary-kirkstone.json")

        result = _run(tmp_path)

        assert result.status != CheckStatus.ERROR
        ids = _finding_cve_ids(result)
        assert "CVE-2023-0464" in ids
        assert "CVE-2022-48174" in ids
        # Patched entries must not appear as findings.
        assert "CVE-2023-0286" not in ids
        assert "CVE-2023-42363" not in ids


class TestScarthgapSchema:
    """Flat ``issues[*]`` layout (Scarthgap)."""

    def test_parses_unpatched_only(self, tmp_path: Path) -> None:
        """Exactly the 2 Unpatched entries in the fixture become findings."""
        _place_summary(tmp_path, "cve-summary-scarthgap.json")

        result = _run(tmp_path)

        assert result.status != CheckStatus.ERROR
        ids = _finding_cve_ids(result)
        assert "CVE-2024-0001" in ids
        assert "CVE-2024-0004" in ids
        # Patched entries must not appear as findings.
        assert "CVE-2024-0003" not in ids
        assert "CVE-2024-0005" not in ids


# --- (e) Ignored handling ---------------------------------------------------


class TestIgnoredHandling:
    """Ignored entries emit INFO finding by default, none when treated as patched."""

    def test_ignored_emits_info_by_default(self, tmp_path: Path) -> None:
        """With ``treat_ignored_as_patched`` false (default), Ignored -> INFO finding."""
        _place_summary(tmp_path, "cve-summary-kirkstone.json")

        result = _run(tmp_path, {"treat_ignored_as_patched": False})

        ids_by_severity: dict[str, set[str]] = {}
        for f in result.findings:
            blob = f.message or ""
            if f.details:
                blob += " " + json.dumps(f.details)
            for token in blob.replace(",", " ").split():
                if token.startswith("CVE-"):
                    ids_by_severity.setdefault(f.severity.lower(), set()).add(
                        token.strip(":.,);")
                    )

        info_ids = ids_by_severity.get("info", set())
        assert "CVE-2023-0465" in info_ids, (
            f"expected Ignored CVE-2023-0465 as INFO finding; got {ids_by_severity!r}"
        )

    def test_ignored_suppressed_when_treated_as_patched(self, tmp_path: Path) -> None:
        """With ``treat_ignored_as_patched=True`` Ignored entries emit no finding."""
        _place_summary(tmp_path, "cve-summary-kirkstone.json")

        result = _run(tmp_path, {"treat_ignored_as_patched": True})

        assert "CVE-2023-0465" not in _finding_cve_ids(result)

    def test_patched_entries_never_emit_findings(self, tmp_path: Path) -> None:
        """Patched entries must not appear as findings regardless of config."""
        _place_summary(tmp_path, "cve-summary-scarthgap.json")

        for flag in (False, True):
            result = _run(tmp_path, {"treat_ignored_as_patched": flag})
            ids = _finding_cve_ids(result)
            assert "CVE-2024-0003" not in ids
            assert "CVE-2024-0005" not in ids


# --- (f) CRA mapping on every finding ---------------------------------------


class TestCraMapping:
    """Each finding carries an Annex I Part II §2 / §3 reference."""

    @pytest.mark.parametrize("fixture", ["cve-summary-kirkstone.json", "cve-summary-scarthgap.json"])
    def test_every_finding_maps_to_annex_i_part_ii(self, tmp_path: Path, fixture: str) -> None:
        _place_summary(tmp_path, fixture)

        result = _run(tmp_path)

        assert result.findings, f"{fixture} should produce at least one finding"
        allowed = {"I.P2.2", "I.P2.3"}
        for finding in result.findings:
            mapping = set(finding.cra_mapping or [])
            assert mapping & allowed, (
                f"finding {finding.message!r} has cra_mapping={finding.cra_mapping!r}; "
                f"expected at least one of {sorted(allowed)}"
            )


# --- (g) summary_path config override ---------------------------------------


class TestSummaryPathOverride:
    """The ``yocto_cve.summary_path`` config key must be honored."""

    def test_custom_summary_path_is_used(self, tmp_path: Path) -> None:
        """A non-default path under build_dir resolves when set in config."""
        custom_rel = Path("custom") / "cve-out" / "summary.json"
        _place_summary(tmp_path, "cve-summary-scarthgap.json", relpath=custom_rel)

        # Default path is deliberately NOT populated; without the override
        # the check must SKIP. With the override it must parse the fixture.
        default_result = _run(tmp_path)
        assert default_result.status == CheckStatus.SKIP

        result = _run(tmp_path, {"summary_path": str(custom_rel)})

        assert result.status != CheckStatus.SKIP
        assert result.status != CheckStatus.ERROR
        ids = _finding_cve_ids(result)
        assert "CVE-2024-0001" in ids
        assert "CVE-2024-0004" in ids

    def test_absolute_summary_path_is_used(self, tmp_path: Path) -> None:
        """Absolute paths in ``summary_path`` are honored as-is."""
        out_dir = tmp_path / "external"
        out_dir.mkdir()
        abs_summary = out_dir / "summary.json"
        shutil.copyfile(FIXTURES_DIR / "cve-summary-scarthgap.json", abs_summary)

        result = _run(tmp_path, {"summary_path": str(abs_summary)})

        assert result.status != CheckStatus.SKIP
        assert result.status != CheckStatus.ERROR
        assert "CVE-2024-0001" in _finding_cve_ids(result)

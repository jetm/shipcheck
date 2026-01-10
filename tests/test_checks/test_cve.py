"""Tests for CVE check: discovery, parsing, and integration."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from shipcheck.checks.cve import (
    CVECheck,
    _classify_severity,
    _discover_cve_output,
    _extract_cvss_score,
    _parse_cve_json,
)
from shipcheck.models import CheckStatus


def _write_cve_json(path: Path, data: dict | None = None) -> Path:
    """Write a CVE JSON file at the given path."""
    if data is None:
        data = {"version": 1, "package": []}
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data))
    return path


FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "cve"


# --- Discovery tests ---


class TestDiscoverCveOutput:
    """Tests for _discover_cve_output priority-based glob search."""

    def test_discovery_sbom_cve_check_format_first(self, tmp_path: Path) -> None:
        """sbom-cve-check format is preferred when multiple formats exist."""
        images_dir = tmp_path / "tmp" / "deploy" / "images"
        _write_cve_json(images_dir / "core-image.sbom-cve-check.yocto.json")
        _write_cve_json(images_dir / "core-image.rootfs.json")
        _write_cve_json(images_dir / "qemux86-64" / "cve_check_summary.json")

        result = _discover_cve_output(tmp_path)
        assert result is not None
        assert result.name == "core-image.sbom-cve-check.yocto.json"

    def test_discovery_vex_bbclass_second(self, tmp_path: Path) -> None:
        """vex.bbclass format is used when sbom-cve-check is absent."""
        images_dir = tmp_path / "tmp" / "deploy" / "images"
        _write_cve_json(images_dir / "core-image.rootfs.json")
        _write_cve_json(images_dir / "qemux86-64" / "cve_check_summary.json")

        result = _discover_cve_output(tmp_path)
        assert result is not None
        assert result.name == "core-image.rootfs.json"

    def test_discovery_legacy_cve_check_third(self, tmp_path: Path) -> None:
        """Legacy cve-check summary is used as last resort."""
        images_dir = tmp_path / "tmp" / "deploy" / "images"
        sub = images_dir / "qemux86-64"
        _write_cve_json(sub / "cve_check_summary.json")

        result = _discover_cve_output(tmp_path)
        assert result is not None
        assert result.name == "cve_check_summary.json"

    def test_discovery_legacy_glob_star(self, tmp_path: Path) -> None:
        """Legacy pattern matches cve_check_summary with suffix (e.g. date)."""
        images_dir = tmp_path / "tmp" / "deploy" / "images"
        sub = images_dir / "qemux86-64"
        _write_cve_json(sub / "cve_check_summary_20260401.json")

        result = _discover_cve_output(tmp_path)
        assert result is not None
        assert "cve_check_summary" in result.name

    def test_discovery_returns_none_when_empty(self, tmp_path: Path) -> None:
        """Returns None when no CVE output files exist."""
        images_dir = tmp_path / "tmp" / "deploy" / "images"
        images_dir.mkdir(parents=True)

        result = _discover_cve_output(tmp_path)
        assert result is None

    def test_discovery_returns_none_when_no_images_dir(self, tmp_path: Path) -> None:
        """Returns None when images directory does not exist."""
        result = _discover_cve_output(tmp_path)
        assert result is None

    def test_discovery_first_match_within_pattern(self, tmp_path: Path) -> None:
        """When multiple files match the same pattern, returns the first (sorted)."""
        images_dir = tmp_path / "tmp" / "deploy" / "images"
        _write_cve_json(images_dir / "alpha.sbom-cve-check.yocto.json")
        _write_cve_json(images_dir / "beta.sbom-cve-check.yocto.json")

        result = _discover_cve_output(tmp_path)
        assert result is not None
        assert result.name == "alpha.sbom-cve-check.yocto.json"


class TestCVECheckDiscovery:
    """Integration tests for CVECheck.run discovery behavior."""

    def test_discovery_no_output_returns_fail(self, tmp_path: Path) -> None:
        """Check returns FAIL with score 0 when no CVE output found."""
        check = CVECheck()
        result = check.run(tmp_path, {})

        assert result.status == CheckStatus.FAIL
        assert result.score == 0
        assert len(result.findings) >= 1
        finding = result.findings[0]
        assert finding.severity == "critical"
        assert "inherit cve-check" in finding.remediation

    def test_discovery_finds_sbom_cve_check(self, tmp_path: Path) -> None:
        """Check successfully discovers and parses sbom-cve-check output."""
        images_dir = tmp_path / "tmp" / "deploy" / "images"
        _write_cve_json(
            images_dir / "image.sbom-cve-check.yocto.json",
            {"version": 1, "package": [{"name": "pkg", "version": "1.0", "issue": []}]},
        )

        check = CVECheck()
        result = check.run(tmp_path, {})

        assert result.status == CheckStatus.PASS
        assert result.score == 50


# --- Parsing tests ---


class TestParseCveJson:
    """Tests for _parse_cve_json handling format variants."""

    def test_parsing_sbom_cve_check_integer_version(self) -> None:
        """sbom-cve-check format with integer version field parses correctly."""
        packages = _parse_cve_json(FIXTURES_DIR / "sbom-cve-check-output.json")

        assert len(packages) == 3
        openssl = packages[0]
        assert openssl["name"] == "openssl"
        assert openssl["version"] == "3.1.4"
        assert "cpes" in openssl
        assert len(openssl["issue"]) == 3

    def test_parsing_legacy_string_version(self) -> None:
        """Legacy format with string version field parses correctly."""
        packages = _parse_cve_json(FIXTURES_DIR / "legacy-cve-check-summary.json")

        assert len(packages) == 3
        libpng = packages[0]
        assert libpng["name"] == "libpng"

    def test_parsing_vex_bbclass_no_cpes(self) -> None:
        """vex.bbclass format without cpes field parses correctly."""
        packages = _parse_cve_json(FIXTURES_DIR / "vex-bbclass-output.json")

        assert len(packages) == 2
        curl = packages[0]
        assert curl["name"] == "curl"
        assert "cpes" not in curl

    def test_parsing_required_id_and_status(self) -> None:
        """Each issue has required id and status fields."""
        packages = _parse_cve_json(FIXTURES_DIR / "sbom-cve-check-output.json")

        for pkg in packages:
            for issue in pkg["issue"]:
                assert "id" in issue, f"Missing 'id' in issue of package {pkg['name']}"
                assert "status" in issue, f"Missing 'status' in issue of package {pkg['name']}"
                assert issue["id"].startswith("CVE-")
                assert issue["status"] in ("Patched", "Unpatched", "Ignored")

    def test_parsing_optional_score_fields(self) -> None:
        """Score fields (scorev2, scorev3, scorev4) are optional and preserved when present."""
        packages = _parse_cve_json(FIXTURES_DIR / "sbom-cve-check-output.json")

        openssl_issues = packages[0]["issue"]
        first_issue = openssl_issues[0]
        assert first_issue["scorev3"] == "9.8"
        assert first_issue["scorev4"] == "9.5"

        third_issue = openssl_issues[2]
        assert third_issue["scorev3"] == "5.3"
        assert "scorev4" not in third_issue

    def test_parsing_missing_cvss_scores(self) -> None:
        """Issues with absent, '0.0', or empty string scores parse without error."""
        packages = _parse_cve_json(FIXTURES_DIR / "no-cvss-score.json")

        assert len(packages) == 2
        libxml2_issues = packages[0]["issue"]
        assert len(libxml2_issues) == 4

        absent_score = libxml2_issues[0]
        assert absent_score["id"] == "CVE-2024-0600"
        assert "scorev3" not in absent_score

        zero_score = libxml2_issues[1]
        assert zero_score["id"] == "CVE-2024-0601"
        assert zero_score["scorev3"] == "0.0"

        empty_score = packages[1]["issue"][0]
        assert empty_score["id"] == "CVE-2024-0700"
        assert empty_score["scorev3"] == ""

    def test_parsing_optional_issue_fields_preserved(self) -> None:
        """Optional fields like vector, link, summary, detail are preserved."""
        packages = _parse_cve_json(FIXTURES_DIR / "sbom-cve-check-output.json")

        issue = packages[0]["issue"][0]
        assert issue["vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        assert issue["link"] == "https://nvd.nist.gov/vuln/detail/CVE-2024-0001"
        assert issue["summary"] == "Remote code execution via buffer overflow"

    def test_parsing_empty_package_list(self, tmp_path: Path) -> None:
        """JSON with empty package list returns empty list."""
        f = _write_cve_json(tmp_path / "empty.json", {"version": 1, "package": []})
        packages = _parse_cve_json(f)
        assert packages == []

    def test_parsing_package_with_no_issues(self, tmp_path: Path) -> None:
        """Package with empty issue list is included in results."""
        data = {"version": 1, "package": [{"name": "pkg", "version": "1.0", "issue": []}]}
        f = _write_cve_json(tmp_path / "no-issues.json", data)
        packages = _parse_cve_json(f)
        assert len(packages) == 1
        assert packages[0]["issue"] == []

    def test_parsing_invalid_json_raises(self, tmp_path: Path) -> None:
        """Invalid JSON raises ValueError."""
        bad = tmp_path / "bad.json"
        bad.parent.mkdir(parents=True, exist_ok=True)
        bad.write_text("not json {{{")

        with pytest.raises(ValueError, match="Failed to parse CVE JSON"):
            _parse_cve_json(bad)

    def test_parsing_missing_package_key_raises(self, tmp_path: Path) -> None:
        """JSON without 'package' key raises ValueError."""
        f = _write_cve_json(tmp_path / "no-pkg.json", {"version": 1})

        with pytest.raises(ValueError, match="Missing 'package'"):
            _parse_cve_json(f)

    def test_parsing_issue_missing_id_raises(self, tmp_path: Path) -> None:
        """Issue without 'id' raises ValueError."""
        data = {
            "version": 1,
            "package": [{"name": "pkg", "version": "1.0", "issue": [{"status": "Unpatched"}]}],
        }
        f = _write_cve_json(tmp_path / "no-id.json", data)

        with pytest.raises(ValueError, match="missing required field 'id'"):
            _parse_cve_json(f)

    def test_parsing_issue_missing_status_raises(self, tmp_path: Path) -> None:
        """Issue without 'status' raises ValueError."""
        data = {
            "version": 1,
            "package": [{"name": "pkg", "version": "1.0", "issue": [{"id": "CVE-2024-9999"}]}],
        }
        f = _write_cve_json(tmp_path / "no-status.json", data)

        with pytest.raises(ValueError, match="missing required field 'status'"):
            _parse_cve_json(f)

# --- Severity classification tests ---


class TestExtractCvssScore:
    """Tests for _extract_cvss_score: v4 > v3 > v2 priority."""

    def test_prefers_scorev4_over_v3(self) -> None:
        issue = {"id": "CVE-2024-0001", "status": "Unpatched", "scorev4": "9.5", "scorev3": "9.8"}
        assert _extract_cvss_score(issue) == 9.5

    def test_falls_back_to_scorev3(self) -> None:
        issue = {"id": "CVE-2024-0001", "status": "Unpatched", "scorev3": "7.5"}
        assert _extract_cvss_score(issue) == 7.5

    def test_falls_back_to_scorev2(self) -> None:
        issue = {"id": "CVE-2024-0001", "status": "Unpatched", "scorev2": "6.0"}
        assert _extract_cvss_score(issue) == 6.0

    def test_returns_none_when_all_absent(self) -> None:
        issue = {"id": "CVE-2024-0001", "status": "Unpatched"}
        assert _extract_cvss_score(issue) is None

    def test_treats_zero_as_missing(self) -> None:
        issue = {"id": "CVE-2024-0001", "status": "Unpatched", "scorev3": "0.0"}
        assert _extract_cvss_score(issue) is None

    def test_treats_empty_string_as_missing(self) -> None:
        issue = {"id": "CVE-2024-0001", "status": "Unpatched", "scorev3": ""}
        assert _extract_cvss_score(issue) is None

    def test_skips_zero_v4_uses_v3(self) -> None:
        issue = {"id": "CVE-2024-0001", "status": "Unpatched", "scorev4": "0.0", "scorev3": "8.1"}
        assert _extract_cvss_score(issue) == 8.1

    def test_all_zero_returns_none(self) -> None:
        issue = {
            "id": "CVE-2024-0001",
            "status": "Unpatched",
            "scorev2": "0.0",
            "scorev3": "0.0",
            "scorev4": "0.0",
        }
        assert _extract_cvss_score(issue) is None


class TestClassifySeverity:
    """Tests for _classify_severity: CVSS band mapping."""

    def test_critical_band(self) -> None:
        assert _classify_severity(9.0) == "critical"
        assert _classify_severity(10.0) == "critical"
        assert _classify_severity(9.8) == "critical"

    def test_high_band(self) -> None:
        assert _classify_severity(7.0) == "high"
        assert _classify_severity(8.9) == "high"

    def test_medium_band(self) -> None:
        assert _classify_severity(4.0) == "medium"
        assert _classify_severity(6.9) == "medium"

    def test_low_band(self) -> None:
        assert _classify_severity(0.1) == "low"
        assert _classify_severity(3.9) == "low"

    def test_missing_score_is_high(self) -> None:
        assert _classify_severity(None) == "high"


class TestCVECheckSeverityClassification:
    """Integration tests for CVE severity classification in CVECheck.run."""

    def test_severity_unpatched_critical(self, tmp_path: Path) -> None:
        """Unpatched CVE with CVSS 9.8 produces a critical finding."""
        data = {
            "version": 1,
            "package": [
                {
                    "name": "openssl",
                    "version": "3.1.4",
                    "issue": [
                        {"id": "CVE-2024-0001", "status": "Unpatched", "scorev3": "9.8"},
                    ],
                }
            ],
        }
        images_dir = tmp_path / "tmp" / "deploy" / "images"
        _write_cve_json(images_dir / "test.sbom-cve-check.yocto.json", data)

        check = CVECheck()
        result = check.run(tmp_path, {})

        assert len(result.findings) == 1
        assert result.findings[0].severity == "critical"
        assert "CVE-2024-0001" in result.findings[0].message

    def test_severity_unpatched_no_score_is_high(self, tmp_path: Path) -> None:
        """Unpatched CVE with no CVSS score produces a high finding."""
        data = {
            "version": 1,
            "package": [
                {
                    "name": "libxml2",
                    "version": "2.12.3",
                    "issue": [
                        {"id": "CVE-2024-0600", "status": "Unpatched"},
                    ],
                }
            ],
        }
        images_dir = tmp_path / "tmp" / "deploy" / "images"
        _write_cve_json(images_dir / "test.sbom-cve-check.yocto.json", data)

        check = CVECheck()
        result = check.run(tmp_path, {})

        assert len(result.findings) == 1
        assert result.findings[0].severity == "high"

    def test_severity_patched_cve_no_finding(self, tmp_path: Path) -> None:
        """Patched CVEs produce no findings."""
        data = {
            "version": 1,
            "package": [
                {
                    "name": "openssl",
                    "version": "3.1.4",
                    "issue": [
                        {"id": "CVE-2024-0002", "status": "Patched", "scorev3": "7.5"},
                    ],
                }
            ],
        }
        images_dir = tmp_path / "tmp" / "deploy" / "images"
        _write_cve_json(images_dir / "test.sbom-cve-check.yocto.json", data)

        check = CVECheck()
        result = check.run(tmp_path, {})

        assert result.findings == []
        assert result.status == CheckStatus.PASS

    def test_severity_ignored_cve_no_finding(self, tmp_path: Path) -> None:
        """Ignored CVEs produce no findings."""
        data = {
            "version": 1,
            "package": [
                {
                    "name": "busybox",
                    "version": "1.36.1",
                    "issue": [
                        {"id": "CVE-2024-0010", "status": "Ignored", "scorev3": "3.3"},
                    ],
                }
            ],
        }
        images_dir = tmp_path / "tmp" / "deploy" / "images"
        _write_cve_json(images_dir / "test.sbom-cve-check.yocto.json", data)

        check = CVECheck()
        result = check.run(tmp_path, {})

        assert result.findings == []
        assert result.status == CheckStatus.PASS

    def test_severity_v4_preferred_over_v3(self, tmp_path: Path) -> None:
        """Score v4 is used when both v4 and v3 are present."""
        data = {
            "version": 1,
            "package": [
                {
                    "name": "openssl",
                    "version": "3.1.4",
                    "issue": [
                        {
                            "id": "CVE-2024-0001",
                            "status": "Unpatched",
                            "scorev3": "9.8",
                            "scorev4": "6.5",
                        },
                    ],
                }
            ],
        }
        images_dir = tmp_path / "tmp" / "deploy" / "images"
        _write_cve_json(images_dir / "test.sbom-cve-check.yocto.json", data)

        check = CVECheck()
        result = check.run(tmp_path, {})

        assert len(result.findings) == 1
        # v4=6.5 -> medium, not critical (v3=9.8 would be critical)
        assert result.findings[0].severity == "medium"

    def test_severity_finding_has_details(self, tmp_path: Path) -> None:
        """Finding includes structured details with cve_id, cvss, and package."""
        data = {
            "version": 1,
            "package": [
                {
                    "name": "openssl",
                    "version": "3.1.4",
                    "issue": [
                        {"id": "CVE-2024-0001", "status": "Unpatched", "scorev3": "9.8"},
                    ],
                }
            ],
        }
        images_dir = tmp_path / "tmp" / "deploy" / "images"
        _write_cve_json(images_dir / "test.sbom-cve-check.yocto.json", data)

        check = CVECheck()
        result = check.run(tmp_path, {})

        finding = result.findings[0]
        assert finding.details is not None
        assert finding.details["cve_id"] == "CVE-2024-0001"
        assert finding.details["cvss"] == 9.8
        assert finding.details["package"] == "openssl"

    def test_severity_finding_details_missing_score(self, tmp_path: Path) -> None:
        """Finding details has cvss=None when no score available."""
        data = {
            "version": 1,
            "package": [
                {
                    "name": "libxml2",
                    "version": "2.12.3",
                    "issue": [
                        {"id": "CVE-2024-0600", "status": "Unpatched"},
                    ],
                }
            ],
        }
        images_dir = tmp_path / "tmp" / "deploy" / "images"
        _write_cve_json(images_dir / "test.sbom-cve-check.yocto.json", data)

        check = CVECheck()
        result = check.run(tmp_path, {})

        finding = result.findings[0]
        assert finding.details["cvss"] is None

    def test_severity_mixed_statuses(self, tmp_path: Path) -> None:
        """Only unpatched CVEs produce findings; patched and ignored are skipped."""
        data = {
            "version": 1,
            "package": [
                {
                    "name": "openssl",
                    "version": "3.1.4",
                    "issue": [
                        {"id": "CVE-2024-0001", "status": "Unpatched", "scorev3": "9.8"},
                        {"id": "CVE-2024-0002", "status": "Patched", "scorev3": "7.5"},
                        {"id": "CVE-2024-0003", "status": "Unpatched", "scorev3": "5.3"},
                    ],
                },
                {
                    "name": "busybox",
                    "version": "1.36.1",
                    "issue": [
                        {"id": "CVE-2024-0010", "status": "Ignored", "scorev3": "3.3"},
                    ],
                },
            ],
        }
        images_dir = tmp_path / "tmp" / "deploy" / "images"
        _write_cve_json(images_dir / "test.sbom-cve-check.yocto.json", data)

        check = CVECheck()
        result = check.run(tmp_path, {})

        assert len(result.findings) == 2
        cve_ids = {f.details["cve_id"] for f in result.findings}
        assert cve_ids == {"CVE-2024-0001", "CVE-2024-0003"}
        severities = {f.severity for f in result.findings}
        assert "critical" in severities  # CVE-2024-0001 (9.8)
        assert "medium" in severities  # CVE-2024-0003 (5.3)

    def test_severity_check_status_fail_on_critical(self, tmp_path: Path) -> None:
        """Check status is FAIL when critical findings exist."""
        data = {
            "version": 1,
            "package": [
                {
                    "name": "openssl",
                    "version": "3.1.4",
                    "issue": [
                        {"id": "CVE-2024-0001", "status": "Unpatched", "scorev3": "9.8"},
                    ],
                }
            ],
        }
        images_dir = tmp_path / "tmp" / "deploy" / "images"
        _write_cve_json(images_dir / "test.sbom-cve-check.yocto.json", data)

        check = CVECheck()
        result = check.run(tmp_path, {})
        assert result.status == CheckStatus.FAIL

    def test_severity_check_status_warn_on_medium_only(self, tmp_path: Path) -> None:
        """Check status is WARN when only medium/low findings exist."""
        data = {
            "version": 1,
            "package": [
                {
                    "name": "pkg",
                    "version": "1.0",
                    "issue": [
                        {"id": "CVE-2024-0099", "status": "Unpatched", "scorev3": "5.3"},
                    ],
                }
            ],
        }
        images_dir = tmp_path / "tmp" / "deploy" / "images"
        _write_cve_json(images_dir / "test.sbom-cve-check.yocto.json", data)

        check = CVECheck()
        result = check.run(tmp_path, {})
        assert result.status == CheckStatus.WARN

    def test_severity_finding_has_remediation(self, tmp_path: Path) -> None:
        """Critical/high findings include non-null remediation."""
        data = {
            "version": 1,
            "package": [
                {
                    "name": "openssl",
                    "version": "3.1.4",
                    "issue": [
                        {"id": "CVE-2024-0001", "status": "Unpatched", "scorev3": "9.8"},
                    ],
                }
            ],
        }
        images_dir = tmp_path / "tmp" / "deploy" / "images"
        _write_cve_json(images_dir / "test.sbom-cve-check.yocto.json", data)

        check = CVECheck()
        result = check.run(tmp_path, {})

        finding = result.findings[0]
        assert finding.remediation is not None
        assert len(finding.remediation) > 0

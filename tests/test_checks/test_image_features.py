"""Tests for the ``image-features`` check.

Pins the public surface and behavior of ``ImageFeaturesCheck`` defined
in task 2.1 of the ``code-integrity-and-hardening`` change. Coverage
mirrors the scenarios named in
``specs/image-features/spec.md``:

- Three severity scenarios (high, medium, low)
- Multi-finding scenario (``debug-tweaks`` plus an explicit entry)
- PASS when ``IMAGE_FEATURES`` is unset
- PASS when ``IMAGE_FEATURES`` contains only safe entries
- ``cra_mapping`` per finding and per result
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from shipcheck.checks.image_features import ImageFeaturesCheck
from shipcheck.models import BaseCheck, CheckStatus

if TYPE_CHECKING:
    from pathlib import Path


def _write_conf(build_dir: Path, filename: str, content: str) -> Path:
    """Write a config file under build_dir/conf/."""
    conf_dir = build_dir / "conf"
    conf_dir.mkdir(parents=True, exist_ok=True)
    path = conf_dir / filename
    path.write_text(content)
    return path


class TestScaffold:
    """Pin the public surface of ``ImageFeaturesCheck``."""

    def test_check_is_basecheck_subclass(self) -> None:
        assert issubclass(ImageFeaturesCheck, BaseCheck)

    def test_check_id(self) -> None:
        assert ImageFeaturesCheck.id == "image-features"

    def test_check_name(self) -> None:
        assert ImageFeaturesCheck.name == "Image Features"

    def test_check_framework(self) -> None:
        assert ImageFeaturesCheck.framework == ["CRA"]

    def test_check_severity(self) -> None:
        assert ImageFeaturesCheck.severity == "critical"

    def test_check_instantiable(self) -> None:
        instance = ImageFeaturesCheck()
        assert isinstance(instance, BaseCheck)


class TestSeverityScenarios:
    """Exercise the three severity scenarios from the spec."""

    def _run(self, build_dir: Path) -> object:
        return ImageFeaturesCheck().run(build_dir, {})

    def test_debug_tweaks_produces_high_severity_finding(self, tmp_path: Path) -> None:
        _write_conf(tmp_path, "local.conf", 'IMAGE_FEATURES += "debug-tweaks"\n')
        result = self._run(tmp_path)
        matches = [f for f in result.findings if "debug-tweaks" in f.message]
        assert matches, "expected a finding for debug-tweaks"
        assert all(f.severity == "high" for f in matches)
        assert result.status == CheckStatus.FAIL

    def test_allow_empty_password_produces_high_severity_finding(self, tmp_path: Path) -> None:
        _write_conf(tmp_path, "local.conf", 'IMAGE_FEATURES += "allow-empty-password"\n')
        result = self._run(tmp_path)
        matches = [f for f in result.findings if "allow-empty-password" in f.message]
        assert matches
        assert all(f.severity == "high" for f in matches)

    def test_empty_root_password_produces_high_severity_finding(self, tmp_path: Path) -> None:
        _write_conf(tmp_path, "local.conf", 'IMAGE_FEATURES += "empty-root-password"\n')
        result = self._run(tmp_path)
        matches = [f for f in result.findings if "empty-root-password" in f.message]
        assert matches
        assert all(f.severity == "high" for f in matches)

    def test_allow_root_login_produces_high_severity_finding(self, tmp_path: Path) -> None:
        _write_conf(tmp_path, "local.conf", 'IMAGE_FEATURES += "allow-root-login"\n')
        result = self._run(tmp_path)
        matches = [f for f in result.findings if "allow-root-login" in f.message]
        assert matches
        assert all(f.severity == "high" for f in matches)

    def test_tools_debug_produces_medium_severity_finding(self, tmp_path: Path) -> None:
        _write_conf(tmp_path, "local.conf", 'IMAGE_FEATURES += "tools-debug"\n')
        result = self._run(tmp_path)
        matches = [f for f in result.findings if "tools-debug" in f.message]
        assert matches
        assert all(f.severity == "medium" for f in matches)
        # Only medium / low findings -> WARN
        assert result.status == CheckStatus.WARN

    def test_dbg_pkgs_produces_medium_severity_finding(self, tmp_path: Path) -> None:
        _write_conf(tmp_path, "local.conf", 'IMAGE_FEATURES += "dbg-pkgs"\n')
        result = self._run(tmp_path)
        matches = [f for f in result.findings if "dbg-pkgs" in f.message]
        assert matches
        assert all(f.severity == "medium" for f in matches)

    def test_eclipse_debug_produces_medium_severity_finding(self, tmp_path: Path) -> None:
        _write_conf(tmp_path, "local.conf", 'IMAGE_FEATURES += "eclipse-debug"\n')
        result = self._run(tmp_path)
        matches = [f for f in result.findings if "eclipse-debug" in f.message]
        assert matches
        assert all(f.severity == "medium" for f in matches)

    def test_dev_pkgs_produces_low_severity_finding(self, tmp_path: Path) -> None:
        _write_conf(tmp_path, "local.conf", 'IMAGE_FEATURES += "dev-pkgs"\n')
        result = self._run(tmp_path)
        matches = [f for f in result.findings if "dev-pkgs" in f.message]
        assert matches
        assert all(f.severity == "low" for f in matches)
        assert result.status == CheckStatus.WARN


class TestMultiFindingScenario:
    """Each matched literal entry is reported individually."""

    def test_debug_tweaks_plus_explicit_entry_produces_two_findings(self, tmp_path: Path) -> None:
        _write_conf(
            tmp_path,
            "local.conf",
            'IMAGE_FEATURES += "debug-tweaks allow-root-login"\n',
        )
        result = ImageFeaturesCheck().run(tmp_path, {})
        feature_messages = [f.message for f in result.findings]
        assert any("debug-tweaks" in m for m in feature_messages)
        assert any("allow-root-login" in m for m in feature_messages)
        # Two distinct findings, not a combined one.
        debug_count = sum(1 for f in result.findings if "debug-tweaks" in f.message)
        login_count = sum(1 for f in result.findings if "allow-root-login" in f.message)
        assert debug_count == 1
        assert login_count == 1
        assert len(result.findings) >= 2

    def test_multiple_entries_each_produce_a_finding(self, tmp_path: Path) -> None:
        _write_conf(
            tmp_path,
            "local.conf",
            'IMAGE_FEATURES += "debug-tweaks tools-debug dev-pkgs"\n',
        )
        result = ImageFeaturesCheck().run(tmp_path, {})
        # Each of the three entries appears in exactly one finding.
        for feature, sev in (
            ("debug-tweaks", "high"),
            ("tools-debug", "medium"),
            ("dev-pkgs", "low"),
        ):
            matches = [f for f in result.findings if feature in f.message]
            assert len(matches) == 1, f"expected one finding for {feature}"
            assert matches[0].severity == sev


class TestPassScenarios:
    """PASS when no insecure feature is matched."""

    def test_unset_image_features_yields_pass(self, tmp_path: Path) -> None:
        _write_conf(tmp_path, "local.conf", 'MACHINE = "qemux86-64"\n')
        result = ImageFeaturesCheck().run(tmp_path, {})
        assert result.status == CheckStatus.PASS
        assert result.findings == []

    def test_no_conf_files_yields_pass(self, tmp_path: Path) -> None:
        result = ImageFeaturesCheck().run(tmp_path, {})
        assert result.status == CheckStatus.PASS
        assert result.findings == []

    def test_only_safe_entries_yields_pass(self, tmp_path: Path) -> None:
        _write_conf(
            tmp_path,
            "local.conf",
            'IMAGE_FEATURES += "package-management splash"\n',
        )
        result = ImageFeaturesCheck().run(tmp_path, {})
        assert result.status == CheckStatus.PASS
        assert result.findings == []


class TestParsing:
    """The parser reuses the same patterns as other checks."""

    def test_detects_in_auto_conf(self, tmp_path: Path) -> None:
        _write_conf(tmp_path, "auto.conf", 'IMAGE_FEATURES += "debug-tweaks"\n')
        result = ImageFeaturesCheck().run(tmp_path, {})
        assert any("debug-tweaks" in f.message for f in result.findings)

    def test_detects_append_syntax(self, tmp_path: Path) -> None:
        _write_conf(tmp_path, "local.conf", 'IMAGE_FEATURES:append = " debug-tweaks"\n')
        result = ImageFeaturesCheck().run(tmp_path, {})
        assert any("debug-tweaks" in f.message for f in result.findings)

    def test_skips_commented_lines(self, tmp_path: Path) -> None:
        _write_conf(tmp_path, "local.conf", '# IMAGE_FEATURES += "debug-tweaks"\n')
        result = ImageFeaturesCheck().run(tmp_path, {})
        assert result.status == CheckStatus.PASS
        assert result.findings == []


class TestCraMapping:
    """``cra_mapping`` per finding and per result."""

    def test_check_result_cra_mapping_is_b_and_j(self, tmp_path: Path) -> None:
        _write_conf(tmp_path, "local.conf", 'IMAGE_FEATURES += "debug-tweaks"\n')
        result = ImageFeaturesCheck().run(tmp_path, {})
        assert result.cra_mapping == ["I.P1.b", "I.P1.j"]

    def test_high_finding_cites_b_and_j(self, tmp_path: Path) -> None:
        _write_conf(tmp_path, "local.conf", 'IMAGE_FEATURES += "debug-tweaks"\n')
        result = ImageFeaturesCheck().run(tmp_path, {})
        high = [f for f in result.findings if f.severity == "high"]
        assert high
        for finding in high:
            assert "I.P1.b" in finding.cra_mapping
            assert "I.P1.j" in finding.cra_mapping

    @pytest.mark.parametrize("feature", ["tools-debug", "dbg-pkgs", "eclipse-debug", "dev-pkgs"])
    def test_lower_severity_finding_cites_at_least_j(self, tmp_path: Path, feature: str) -> None:
        _write_conf(tmp_path, "local.conf", f'IMAGE_FEATURES += "{feature}"\n')
        result = ImageFeaturesCheck().run(tmp_path, {})
        matches = [f for f in result.findings if feature in f.message]
        assert matches
        for finding in matches:
            assert "I.P1.j" in finding.cra_mapping

    def test_check_result_cra_mapping_present_when_passing(self, tmp_path: Path) -> None:
        _write_conf(tmp_path, "local.conf", 'IMAGE_FEATURES += "package-management"\n')
        result = ImageFeaturesCheck().run(tmp_path, {})
        # CheckResult.cra_mapping should still be the canonical pair even
        # when the run returns PASS so consumers can render the mapping
        # uniformly.
        assert result.cra_mapping == ["I.P1.b", "I.P1.j"]

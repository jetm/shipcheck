"""Tests for the ``hardening-flags`` check.

Pins the public surface and detection behavior of
``HardeningFlagsCheck`` defined in task 3.1 of the
``code-integrity-and-hardening`` change. Coverage mirrors the seven
specific scenarios named in
``specs/hardening-flags/spec.md``:

- Signal A direct require in ``conf/local.conf``
- Signal A indirect via ``conf/distro/<distro>.conf``
- Signal A absent
- Signal B all four flag classes present
- Signal B subset (one class) present
- Signal B none present
- Per-recipe override (``TUNE_CCARGS:append:pn-foo``) ignored

Status semantics tests live in task 3.2's ``TestStatus``; the focus
here is detection only.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from shipcheck.checks.hardening_flags import (
    HardeningFlagsCheck,
    detect_signal_a,
    detect_signal_b,
)
from shipcheck.models import BaseCheck

if TYPE_CHECKING:
    from pathlib import Path


def _write_conf(build_dir: Path, relpath: str, content: str) -> Path:
    """Write a config file under ``build_dir/conf/`` (or any sub-path).

    ``relpath`` is interpreted relative to ``build_dir/conf``. The
    parent directories are created as needed.
    """
    path = build_dir / "conf" / relpath
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    return path


class TestScaffold:
    """Pin the public surface of ``HardeningFlagsCheck``."""

    def test_check_is_basecheck_subclass(self) -> None:
        assert issubclass(HardeningFlagsCheck, BaseCheck)

    def test_check_id(self) -> None:
        assert HardeningFlagsCheck.id == "hardening-flags"

    def test_check_name(self) -> None:
        assert HardeningFlagsCheck.name == "Hardening Flags"

    def test_check_framework(self) -> None:
        assert HardeningFlagsCheck.framework == ["CRA"]

    def test_check_severity(self) -> None:
        assert HardeningFlagsCheck.severity == "critical"

    def test_check_cra_mapping(self) -> None:
        assert HardeningFlagsCheck.cra_mapping == ["I.P2.c", "I.P2.j"]

    def test_check_instantiable(self) -> None:
        instance = HardeningFlagsCheck()
        assert isinstance(instance, BaseCheck)


class TestSignalA:
    """Detect ``security_flags.inc`` inclusion via ``require``/``include``."""

    def test_signal_a_direct_require_in_local_conf(self, tmp_path: Path) -> None:
        _write_conf(
            tmp_path,
            "local.conf",
            'require conf/distro/include/security_flags.inc\nMACHINE = "qemux86-64"\n',
        )
        result = detect_signal_a(tmp_path)
        assert result.present is True
        # The including file is surfaced for the finding message.
        assert any(p.name == "local.conf" for p in result.including_files), (
            f"expected local.conf in including_files, got {result.including_files}"
        )

    def test_signal_a_direct_include_directive_in_local_conf(self, tmp_path: Path) -> None:
        # ``include`` is the conditional cousin of ``require``; the spec
        # says either directive triggers detection.
        _write_conf(
            tmp_path,
            "local.conf",
            "include conf/distro/include/security_flags.inc\n",
        )
        result = detect_signal_a(tmp_path)
        assert result.present is True

    def test_signal_a_indirect_via_distro_conf(self, tmp_path: Path) -> None:
        # local.conf names a distro; the distro conf requires
        # security_flags.inc. Detection follows the chain one level
        # deep.
        _write_conf(tmp_path, "local.conf", 'DISTRO = "mydistro"\n')
        _write_conf(
            tmp_path,
            "distro/mydistro.conf",
            'DISTRO_NAME = "My Distro"\nrequire conf/distro/include/security_flags.inc\n',
        )
        result = detect_signal_a(tmp_path)
        assert result.present is True
        assert any(p.name == "mydistro.conf" for p in result.including_files), (
            f"expected mydistro.conf in including_files, got {result.including_files}"
        )

    def test_signal_a_absent(self, tmp_path: Path) -> None:
        _write_conf(tmp_path, "local.conf", 'MACHINE = "qemux86-64"\n')
        _write_conf(tmp_path, "auto.conf", 'DISTRO = "poky"\n')
        result = detect_signal_a(tmp_path)
        assert result.present is False
        assert result.including_files == []

    def test_signal_a_basename_match_only(self, tmp_path: Path) -> None:
        # The spec says any file whose basename matches
        # ``security_flags.inc`` qualifies. A vendored copy under a
        # different prefix should still be detected.
        _write_conf(
            tmp_path,
            "local.conf",
            "require ${LAYERDIR}/some/path/security_flags.inc\n",
        )
        result = detect_signal_a(tmp_path)
        assert result.present is True


class TestSignalB:
    """Parse ``TUNE_CCARGS`` / ``SELECTED_OPTIMIZATION`` for hardening flags."""

    def test_signal_b_all_four_classes(self, tmp_path: Path) -> None:
        _write_conf(
            tmp_path,
            "local.conf",
            'TUNE_CCARGS = "-D_FORTIFY_SOURCE=2 -fstack-protector-strong '
            '-fPIE -Wl,-z,relro -Wl,-z,now"\n',
        )
        result = detect_signal_b(tmp_path)
        assert result.fortify_source is True
        assert result.stack_protector is True
        assert result.pie is True
        assert result.relro_now is True
        # Convenience: at least one flag class present.
        assert result.any_present is True

    def test_signal_b_fortify_source_3_also_recognised(self, tmp_path: Path) -> None:
        _write_conf(
            tmp_path,
            "local.conf",
            'TUNE_CCARGS = "-D_FORTIFY_SOURCE=3"\n',
        )
        result = detect_signal_b(tmp_path)
        assert result.fortify_source is True

    def test_signal_b_subset_via_selected_optimization(self, tmp_path: Path) -> None:
        # Only -fstack-protector-strong; the rest are absent.
        _write_conf(
            tmp_path,
            "local.conf",
            'SELECTED_OPTIMIZATION = "-O2 -fstack-protector-strong"\n',
        )
        result = detect_signal_b(tmp_path)
        assert result.stack_protector is True
        assert result.fortify_source is False
        assert result.pie is False
        assert result.relro_now is False
        assert result.any_present is True

    def test_signal_b_relro_without_now_is_not_relro_now(self, tmp_path: Path) -> None:
        # The RELRO+now class requires *both* flags. ``relro`` alone
        # leaves the GOT writable after relocation and is the weaker
        # form; the spec scenario ``All four classes`` lists
        # ``-Wl,-z,relro -Wl,-z,now`` together.
        _write_conf(
            tmp_path,
            "local.conf",
            'TUNE_CCARGS = "-Wl,-z,relro"\n',
        )
        result = detect_signal_b(tmp_path)
        assert result.relro_now is False

    def test_signal_b_none(self, tmp_path: Path) -> None:
        _write_conf(tmp_path, "local.conf", 'MACHINE = "qemux86-64"\n')
        result = detect_signal_b(tmp_path)
        assert result.fortify_source is False
        assert result.stack_protector is False
        assert result.pie is False
        assert result.relro_now is False
        assert result.any_present is False

    def test_signal_b_none_when_vars_set_without_hardening_flags(self, tmp_path: Path) -> None:
        _write_conf(
            tmp_path,
            "local.conf",
            'TUNE_CCARGS = "-march=armv8-a -mtune=cortex-a53"\n'
            'SELECTED_OPTIMIZATION = "-O2 -pipe"\n',
        )
        result = detect_signal_b(tmp_path)
        assert result.any_present is False

    def test_signal_b_reads_auto_conf(self, tmp_path: Path) -> None:
        _write_conf(
            tmp_path,
            "auto.conf",
            'TUNE_CCARGS = "-D_FORTIFY_SOURCE=2"\n',
        )
        result = detect_signal_b(tmp_path)
        assert result.fortify_source is True


class TestPerRecipeOverrideIgnored:
    """Per-recipe override syntax must not contribute to the global signal.

    Per ``specs/hardening-flags/spec.md`` Requirement: Global
    build-config scope only.
    """

    def test_tune_ccargs_pn_override_ignored(self, tmp_path: Path) -> None:
        # No global TUNE_CCARGS; only a per-recipe override.
        _write_conf(
            tmp_path,
            "local.conf",
            'TUNE_CCARGS:append:pn-openssl = " -fstack-protector-strong"\n',
        )
        result = detect_signal_b(tmp_path)
        assert result.stack_protector is False
        assert result.any_present is False

    def test_selected_optimization_pn_override_ignored(self, tmp_path: Path) -> None:
        _write_conf(
            tmp_path,
            "local.conf",
            'SELECTED_OPTIMIZATION:pn-foo = "-O2 -fPIE"\n',
        )
        result = detect_signal_b(tmp_path)
        assert result.pie is False

    def test_global_assignment_alongside_pn_override(self, tmp_path: Path) -> None:
        # Global and per-recipe both present: only the global counts.
        _write_conf(
            tmp_path,
            "local.conf",
            'TUNE_CCARGS = "-fPIE"\nTUNE_CCARGS:append:pn-openssl = " -fstack-protector-strong"\n',
        )
        result = detect_signal_b(tmp_path)
        assert result.pie is True
        assert result.stack_protector is False


class TestRunSmoke:
    """Smoke test ``run`` returns a populated ``CheckResult``.

    Status semantics belong to task 3.2; this guard only confirms
    ``run()`` does not raise and returns a result tagged with the
    expected check id and CRA mapping.
    """

    def test_run_returns_check_result_with_id_and_cra_mapping(self, tmp_path: Path) -> None:
        _write_conf(tmp_path, "local.conf", 'MACHINE = "qemux86-64"\n')
        result = HardeningFlagsCheck().run(tmp_path, {})
        assert result.check_id == "hardening-flags"
        assert result.cra_mapping == ["I.P2.c", "I.P2.j"]

    def test_run_no_conf_files(self, tmp_path: Path) -> None:
        # No conf/ directory at all: must not raise.
        result = HardeningFlagsCheck().run(tmp_path, {})
        assert result.check_id == "hardening-flags"

    def test_run_summary_mentions_signal_a_when_present(self, tmp_path: Path) -> None:
        _write_conf(
            tmp_path,
            "local.conf",
            "require conf/distro/include/security_flags.inc\n",
        )
        result = HardeningFlagsCheck().run(tmp_path, {})
        assert "security_flags.inc" in result.summary

    def test_run_summary_mentions_signal_b_classes_when_present(self, tmp_path: Path) -> None:
        _write_conf(
            tmp_path,
            "local.conf",
            'TUNE_CCARGS = "-fPIE -fstack-protector-strong"\n',
        )
        result = HardeningFlagsCheck().run(tmp_path, {})
        assert "PIE" in result.summary
        assert "stack-protector" in result.summary

    def test_run_summary_when_no_evidence(self, tmp_path: Path) -> None:
        _write_conf(tmp_path, "local.conf", 'MACHINE = "qemux86-64"\n')
        result = HardeningFlagsCheck().run(tmp_path, {})
        assert "No compile-time hardening evidence" in result.summary

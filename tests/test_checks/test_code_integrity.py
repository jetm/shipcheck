"""Scaffold tests for the unified code-integrity check.

Task 1.2 (RED phase). These tests pin the public surface of the new
package: the ``CodeIntegrityCheck`` class identity and the
``MechanismResult`` dataclass shape. Detector and aggregator behavior is
exercised by later tasks (1.3 - 1.7) under separate test classes in this
same file.
"""

from __future__ import annotations

from dataclasses import fields
from typing import TYPE_CHECKING

import pytest

from shipcheck.checks.code_integrity import CodeIntegrityCheck, MechanismResult
from shipcheck.models import BaseCheck, Finding

if TYPE_CHECKING:
    from pathlib import Path


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


# ---------------------------------------------------------------------------
# UEFI Secure Boot detector (task 1.3)
# ---------------------------------------------------------------------------


def _write_conf(build_dir: Path, filename: str, content: str) -> Path:
    """Write a config file under build_dir/conf/."""
    conf_dir = build_dir / "conf"
    conf_dir.mkdir(parents=True, exist_ok=True)
    path = conf_dir / filename
    path.write_text(content)
    return path


def _create_efi_artifacts(build_dir: Path, *names: str) -> list[Path]:
    """Create dummy .efi files under tmp/deploy/images/<machine>/."""
    deploy = build_dir / "tmp" / "deploy" / "images" / "machine"
    deploy.mkdir(parents=True, exist_ok=True)
    paths: list[Path] = []
    for name in names or ("bootx64.efi",):
        path = deploy / name
        path.write_bytes(b"\x00" * 16)
        paths.append(path)
    return paths


def _create_key_files(build_dir: Path, *names: str) -> list[Path]:
    """Create dummy key files under build_dir/keys/."""
    key_dir = build_dir / "keys"
    key_dir.mkdir(parents=True, exist_ok=True)
    paths: list[Path] = []
    for name in names:
        path = key_dir / name
        path.write_bytes(b"\x00" * 32)
        paths.append(path)
    return paths


class TestUefiDetector:
    """UEFI Secure Boot detector returning ``MechanismResult``.

    Covers the four behaviors named in task 1.3:
    1. Signing class detection in ``IMAGE_CLASSES``.
    2. Key-variable extraction (``SECURE_BOOT_SIGNING_KEY`` etc.).
    3. Test/development key flagging.
    4. EFI artifact discovery under ``tmp/deploy/images/``.

    The detector lives at ``shipcheck.checks.code_integrity.uefi`` and
    exposes a ``detect(build_dir, config)`` callable that returns a
    ``MechanismResult``.
    """

    def _detect(self, build_dir: Path, config: dict | None = None) -> MechanismResult:
        from shipcheck.checks.code_integrity.uefi import detect

        return detect(build_dir, config or {})

    # --- Scenario: signing-class detection ----------------------------------

    @pytest.mark.parametrize(
        "signing_class",
        ["uefi-sign", "sbsign", "image-uefi-sign", "secureboot"],
    )
    def test_present_when_signing_class_in_image_classes(
        self, tmp_path: Path, signing_class: str
    ) -> None:
        _write_conf(tmp_path, "local.conf", f'IMAGE_CLASSES += "{signing_class}"\n')
        result = self._detect(tmp_path)
        assert result.present is True
        # The matched class name must appear in evidence so the aggregator
        # can mention it in its summary.
        assert any(signing_class in ev for ev in result.evidence)

    def test_present_returns_mechanism_result(self, tmp_path: Path) -> None:
        _write_conf(tmp_path, "local.conf", 'IMAGE_CLASSES += "uefi-sign"\n')
        result = self._detect(tmp_path)
        assert isinstance(result, MechanismResult)

    def test_absent_when_no_signing_class(self, tmp_path: Path) -> None:
        _write_conf(tmp_path, "local.conf", 'MACHINE = "qemux86-64"\n')
        result = self._detect(tmp_path)
        assert result.present is False
        assert result.evidence == []
        assert result.misconfigurations == []

    def test_absent_when_no_config_files(self, tmp_path: Path) -> None:
        result = self._detect(tmp_path)
        assert result.present is False

    def test_absent_when_signing_class_commented(self, tmp_path: Path) -> None:
        _write_conf(tmp_path, "local.conf", '# IMAGE_CLASSES += "uefi-sign"\n')
        result = self._detect(tmp_path)
        assert result.present is False

    def test_detects_in_auto_conf(self, tmp_path: Path) -> None:
        _write_conf(tmp_path, "auto.conf", 'IMAGE_CLASSES += "sbsign"\n')
        result = self._detect(tmp_path)
        assert result.present is True

    def test_detects_append_syntax(self, tmp_path: Path) -> None:
        _write_conf(tmp_path, "local.conf", 'IMAGE_CLASSES:append = " uefi-sign"\n')
        result = self._detect(tmp_path)
        assert result.present is True

    # --- Scenario: key-variable extraction ---------------------------------

    def test_key_variable_extracted_when_signing_present(self, tmp_path: Path) -> None:
        keys = _create_key_files(tmp_path, "production.key")
        _write_conf(
            tmp_path,
            "local.conf",
            f'IMAGE_CLASSES += "uefi-sign"\nSECURE_BOOT_SIGNING_KEY = "{keys[0]}"\n',
        )
        result = self._detect(tmp_path)
        assert result.present is True
        assert any(str(keys[0]) in ev or "SECURE_BOOT_SIGNING_KEY" in ev for ev in result.evidence)
        # No misconfigurations when key file exists and name is clean.
        assert all(
            "missing" not in f.message.lower() and "test/development" not in f.message.lower()
            for f in result.misconfigurations
        )

    def test_signing_without_key_variable_emits_finding(self, tmp_path: Path) -> None:
        _write_conf(tmp_path, "local.conf", 'IMAGE_CLASSES += "uefi-sign"\n')
        result = self._detect(tmp_path)
        assert result.present is True
        assert result.misconfigurations, "expected a finding when keys are absent"
        assert any(f.severity == "high" for f in result.misconfigurations)

    def test_missing_key_file_emits_finding(self, tmp_path: Path) -> None:
        _write_conf(
            tmp_path,
            "local.conf",
            'IMAGE_CLASSES += "uefi-sign"\nSECURE_BOOT_SIGNING_KEY = "/nonexistent/key.pem"\n',
        )
        result = self._detect(tmp_path)
        assert result.present is True
        msg_text = " ".join(f.message.lower() for f in result.misconfigurations)
        assert "key file not found" in msg_text or "missing" in msg_text

    def test_db_and_uefi_sign_keys_are_extracted(self, tmp_path: Path) -> None:
        keys = _create_key_files(tmp_path, "production.key", "db.key", "uefi.key")
        _write_conf(
            tmp_path,
            "local.conf",
            (
                'IMAGE_CLASSES += "uefi-sign"\n'
                f'SECURE_BOOT_SIGNING_KEY = "{keys[0]}"\n'
                f'SECURE_BOOT_DB_KEY = "{keys[1]}"\n'
                f'UEFI_SIGN_KEY = "{keys[2]}"\n'
            ),
        )
        result = self._detect(tmp_path)
        assert result.present is True
        # All three key vars should drive evidence.
        joined = " ".join(result.evidence)
        assert "SECURE_BOOT_SIGNING_KEY" in joined
        assert "SECURE_BOOT_DB_KEY" in joined
        assert "UEFI_SIGN_KEY" in joined

    # --- Scenario: test/development key flagging ----------------------------

    def test_test_key_in_name_flags_high_severity_finding(self, tmp_path: Path) -> None:
        keys = _create_key_files(tmp_path, "test-signing.key")
        _write_conf(
            tmp_path,
            "local.conf",
            f'IMAGE_CLASSES += "uefi-sign"\nSECURE_BOOT_SIGNING_KEY = "{keys[0]}"\n',
        )
        result = self._detect(tmp_path)
        assert result.present is True
        flagged = [
            f
            for f in result.misconfigurations
            if "test" in f.message.lower() or "development" in f.message.lower()
        ]
        assert flagged, "expected a test/development key finding"
        assert all(f.severity == "high" for f in flagged)

    def test_dev_key_in_path_flags_finding(self, tmp_path: Path) -> None:
        test_dir = tmp_path / "test-keys"
        test_dir.mkdir()
        key_path = test_dir / "signing.key"
        key_path.write_bytes(b"\x00" * 32)
        _write_conf(
            tmp_path,
            "local.conf",
            f'IMAGE_CLASSES += "uefi-sign"\nSECURE_BOOT_SIGNING_KEY = "{key_path}"\n',
        )
        result = self._detect(tmp_path)
        flagged = [
            f
            for f in result.misconfigurations
            if "test" in f.message.lower() or "development" in f.message.lower()
        ]
        assert flagged, "expected a finding when key sits under a test directory"

    def test_production_key_does_not_flag(self, tmp_path: Path) -> None:
        keys = _create_key_files(tmp_path, "production-signing.key")
        _write_conf(
            tmp_path,
            "local.conf",
            f'IMAGE_CLASSES += "uefi-sign"\nSECURE_BOOT_SIGNING_KEY = "{keys[0]}"\n',
        )
        result = self._detect(tmp_path)
        flagged = [
            f
            for f in result.misconfigurations
            if "test" in f.message.lower() or "development" in f.message.lower()
        ]
        assert flagged == []

    def test_custom_known_test_key_pattern_via_config(self, tmp_path: Path) -> None:
        keys = _create_key_files(tmp_path, "staging-db.key")
        _write_conf(
            tmp_path,
            "local.conf",
            f'IMAGE_CLASSES += "uefi-sign"\nSECURE_BOOT_SIGNING_KEY = "{keys[0]}"\n',
        )
        result = self._detect(tmp_path, {"known_test_keys": ["staging"]})
        flagged = [
            f
            for f in result.misconfigurations
            if "staging" in f.message.lower()
            or "test" in f.message.lower()
            or "development" in f.message.lower()
        ]
        assert flagged, "expected staging key to be flagged via known_test_keys"

    def test_test_key_finding_carries_uefi_cra_mapping(self, tmp_path: Path) -> None:
        keys = _create_key_files(tmp_path, "test-signing.key")
        _write_conf(
            tmp_path,
            "local.conf",
            f'IMAGE_CLASSES += "uefi-sign"\nSECURE_BOOT_SIGNING_KEY = "{keys[0]}"\n',
        )
        result = self._detect(tmp_path)
        flagged = [
            f
            for f in result.misconfigurations
            if "test" in f.message.lower() or "development" in f.message.lower()
        ]
        assert flagged
        # Per spec: UEFI test-key findings carry I.P1.c, I.P1.d, I.P1.f.
        for f in flagged:
            assert "I.P1.c" in f.cra_mapping
            assert "I.P1.d" in f.cra_mapping
            assert "I.P1.f" in f.cra_mapping

    # --- Scenario: EFI-artifact discovery ----------------------------------

    def test_efi_artifacts_without_signing_emits_finding(self, tmp_path: Path) -> None:
        _create_efi_artifacts(tmp_path, "bootx64.efi", "grubx64.efi")
        _write_conf(tmp_path, "local.conf", 'MACHINE = "qemux86-64"\n')
        result = self._detect(tmp_path)
        # Detector should still report `present=False` because no signing
        # class is configured, but it should surface the inconsistency as
        # a misconfiguration the aggregator can lift up.
        assert result.misconfigurations, "expected a finding for unsigned EFI artifacts"
        joined = " ".join(f.message.lower() for f in result.misconfigurations)
        assert "efi" in joined

    def test_efi_artifacts_with_signing_no_artifact_finding(self, tmp_path: Path) -> None:
        keys = _create_key_files(tmp_path, "production.key")
        _create_efi_artifacts(tmp_path, "bootx64.efi")
        _write_conf(
            tmp_path,
            "local.conf",
            f'IMAGE_CLASSES += "uefi-sign"\nSECURE_BOOT_SIGNING_KEY = "{keys[0]}"\n',
        )
        result = self._detect(tmp_path)
        # No "EFI without signing" finding when signing is configured.
        unsigned = [
            f
            for f in result.misconfigurations
            if "efi" in f.message.lower() and "without" in f.message.lower()
        ]
        assert unsigned == []

    def test_efi_artifacts_in_evidence_when_signing_present(self, tmp_path: Path) -> None:
        keys = _create_key_files(tmp_path, "production.key")
        _create_efi_artifacts(tmp_path, "bootx64.efi", "grubx64.efi")
        _write_conf(
            tmp_path,
            "local.conf",
            f'IMAGE_CLASSES += "uefi-sign"\nSECURE_BOOT_SIGNING_KEY = "{keys[0]}"\n',
        )
        result = self._detect(tmp_path)
        # The two EFI files should be reflected in evidence so the
        # aggregator can summarize them.
        joined = " ".join(result.evidence).lower()
        assert ".efi" in joined or "efi artifact" in joined

    # --- Edge cases --------------------------------------------------------

    def test_binary_conf_file_does_not_crash(self, tmp_path: Path) -> None:
        conf_dir = tmp_path / "conf"
        conf_dir.mkdir()
        (conf_dir / "local.conf").write_bytes(b"\x00\xff\xfe" * 100)
        result = self._detect(tmp_path)
        assert isinstance(result, MechanismResult)
        assert result.present is False

    def test_confidence_high_when_present(self, tmp_path: Path) -> None:
        _write_conf(tmp_path, "local.conf", 'IMAGE_CLASSES += "uefi-sign"\n')
        result = self._detect(tmp_path)
        # UEFI signing class detection is a deterministic config-file
        # signal -- when present, confidence is high.
        assert result.confidence == "high"


# ---------------------------------------------------------------------------
# FIT signature detector (task 1.4)
# ---------------------------------------------------------------------------


# FIT image signature marker: FDT magic + "signature" node indicator.
FIT_SIGNATURE_MARKER = b"\xd0\x0d\xfe\xed" + b"\x00" * 32 + b"signature"
FIT_UNSIGNED_CONTENT = b"\xd0\x0d\xfe\xed" + b"\x00" * 64


def _create_deploy_dir(build_dir: Path) -> Path:
    """Create tmp/deploy/images/<machine>/ and return it."""
    deploy = build_dir / "tmp" / "deploy" / "images" / "machine"
    deploy.mkdir(parents=True, exist_ok=True)
    return deploy


class TestFitDetector:
    """Signed FIT detector returning ``MechanismResult``.

    Covers the FIT scenario in ``specs/code-integrity/spec.md``:
    a ``.itb`` or ``.fit`` file under ``tmp/deploy/images/`` whose
    first four bytes are FDT magic (``0xD00DFEED``) and whose body
    contains the literal byte string ``signature`` -> ``present=True``.
    Also covers the ``UBOOT_SIGN_ENABLE`` config-only path and the
    unsigned-FIT misconfiguration path.

    The detector lives at ``shipcheck.checks.code_integrity.fit`` and
    exposes a ``detect(build_dir, config)`` callable that returns a
    ``MechanismResult``.
    """

    def _detect(self, build_dir: Path, config: dict | None = None) -> MechanismResult:
        from shipcheck.checks.code_integrity.fit import detect

        return detect(build_dir, config or {})

    # --- Scenario: signed FIT artifact detection ---------------------------

    def test_signed_itb_marks_present(self, tmp_path: Path) -> None:
        deploy = _create_deploy_dir(tmp_path)
        itb = deploy / "fitImage.itb"
        itb.write_bytes(FIT_SIGNATURE_MARKER)
        result = self._detect(tmp_path)
        assert result.present is True
        # The artifact path (or its name) must appear in evidence so the
        # aggregator can mention it in its summary.
        joined = " ".join(result.evidence)
        assert "fitImage.itb" in joined or str(itb) in joined

    def test_signed_fit_extension_marks_present(self, tmp_path: Path) -> None:
        deploy = _create_deploy_dir(tmp_path)
        fit = deploy / "image.fit"
        fit.write_bytes(FIT_SIGNATURE_MARKER)
        result = self._detect(tmp_path)
        assert result.present is True
        joined = " ".join(result.evidence)
        assert "image.fit" in joined or str(fit) in joined

    def test_returns_mechanism_result(self, tmp_path: Path) -> None:
        deploy = _create_deploy_dir(tmp_path)
        (deploy / "fitImage.itb").write_bytes(FIT_SIGNATURE_MARKER)
        result = self._detect(tmp_path)
        assert isinstance(result, MechanismResult)

    def test_signed_fit_no_misconfiguration(self, tmp_path: Path) -> None:
        deploy = _create_deploy_dir(tmp_path)
        (deploy / "fitImage.itb").write_bytes(FIT_SIGNATURE_MARKER)
        result = self._detect(tmp_path)
        # A signed FIT is the happy path: present, no findings.
        assert result.present is True
        assert result.misconfigurations == []

    def test_confidence_high_when_signed_artifact_present(self, tmp_path: Path) -> None:
        deploy = _create_deploy_dir(tmp_path)
        (deploy / "fitImage.itb").write_bytes(FIT_SIGNATURE_MARKER)
        result = self._detect(tmp_path)
        # A signed FIT artifact on disk is the strongest signal.
        assert result.confidence == "high"

    # --- Scenario: unsigned FIT artifact -----------------------------------

    def test_unsigned_fit_emits_finding(self, tmp_path: Path) -> None:
        deploy = _create_deploy_dir(tmp_path)
        (deploy / "fitImage.itb").write_bytes(FIT_UNSIGNED_CONTENT)
        result = self._detect(tmp_path)
        # Unsigned FIT with FDT magic but no signature node is a
        # misconfiguration -- present is False (no integrity mechanism)
        # but the aggregator should see the finding.
        assert result.present is False
        assert result.misconfigurations, "expected a finding for unsigned FIT artifact"
        assert any(f.severity == "high" for f in result.misconfigurations)
        joined = " ".join(f.message.lower() for f in result.misconfigurations)
        assert "unsigned" in joined and "fit" in joined

    def test_unsigned_fit_finding_carries_cra_mapping(self, tmp_path: Path) -> None:
        deploy = _create_deploy_dir(tmp_path)
        (deploy / "fitImage.itb").write_bytes(FIT_UNSIGNED_CONTENT)
        result = self._detect(tmp_path)
        unsigned = [f for f in result.misconfigurations if "unsigned" in f.message.lower()]
        assert unsigned
        for f in unsigned:
            assert "I.P1.f" in f.cra_mapping

    def test_short_file_not_treated_as_unsigned(self, tmp_path: Path) -> None:
        deploy = _create_deploy_dir(tmp_path)
        (deploy / "fitImage.itb").write_bytes(b"\x00")
        result = self._detect(tmp_path)
        # File too short to carry FDT magic -- no FIT signal at all.
        assert result.present is False
        assert all("unsigned" not in f.message.lower() for f in result.misconfigurations)

    def test_wrong_magic_not_treated_as_unsigned(self, tmp_path: Path) -> None:
        deploy = _create_deploy_dir(tmp_path)
        (deploy / "fitImage.itb").write_bytes(b"\xde\xad\xbe\xef" + b"\x00" * 32)
        result = self._detect(tmp_path)
        # Wrong magic means it is not a FIT image; not our problem.
        assert result.present is False
        assert all("unsigned" not in f.message.lower() for f in result.misconfigurations)

    # --- Scenario: UBOOT_SIGN_ENABLE config-only --------------------------

    def test_uboot_sign_enable_in_local_conf(self, tmp_path: Path) -> None:
        _create_deploy_dir(tmp_path)
        _write_conf(
            tmp_path,
            "local.conf",
            'UBOOT_SIGN_ENABLE = "1"\nUBOOT_SIGN_KEYDIR = "/path/to/keys"\n',
        )
        result = self._detect(tmp_path)
        assert result.present is True
        joined = " ".join(result.evidence)
        assert "UBOOT_SIGN_ENABLE" in joined

    def test_uboot_sign_enable_in_auto_conf(self, tmp_path: Path) -> None:
        _create_deploy_dir(tmp_path)
        _write_conf(tmp_path, "auto.conf", 'UBOOT_SIGN_ENABLE = "1"\n')
        result = self._detect(tmp_path)
        assert result.present is True

    def test_commented_uboot_sign_enable_ignored(self, tmp_path: Path) -> None:
        _create_deploy_dir(tmp_path)
        _write_conf(tmp_path, "local.conf", '# UBOOT_SIGN_ENABLE = "1"\n')
        result = self._detect(tmp_path)
        assert result.present is False

    def test_config_only_without_artifacts_marks_medium_confidence(self, tmp_path: Path) -> None:
        _create_deploy_dir(tmp_path)
        _write_conf(tmp_path, "local.conf", 'UBOOT_SIGN_ENABLE = "1"\n')
        result = self._detect(tmp_path)
        # Config alone (no signed artifact yet on disk) is a weaker
        # signal than a signed FIT file: medium confidence.
        assert result.present is True
        assert result.confidence == "medium"

    # --- Scenario: absence -------------------------------------------------

    def test_absent_when_no_config_and_no_artifacts(self, tmp_path: Path) -> None:
        result = self._detect(tmp_path)
        assert result.present is False
        assert result.evidence == []
        assert result.misconfigurations == []

    def test_absent_when_only_unrelated_files_in_deploy(self, tmp_path: Path) -> None:
        deploy = _create_deploy_dir(tmp_path)
        (deploy / "image.ext4").write_bytes(b"\x00" * 16)
        (deploy / "image.cpio").write_bytes(b"\x00" * 16)
        result = self._detect(tmp_path)
        assert result.present is False

    def test_signed_fit_anywhere_under_images(self, tmp_path: Path) -> None:
        # FIT artifacts may sit under per-machine subdirectories; the
        # detector must recurse into tmp/deploy/images/.
        nested = tmp_path / "tmp" / "deploy" / "images" / "qemux86-64"
        nested.mkdir(parents=True)
        (nested / "fitImage.itb").write_bytes(FIT_SIGNATURE_MARKER)
        result = self._detect(tmp_path)
        assert result.present is True

    # --- Edge cases --------------------------------------------------------

    def test_empty_fit_file_does_not_crash(self, tmp_path: Path) -> None:
        deploy = _create_deploy_dir(tmp_path)
        # Empty file: open succeeds but read returns no bytes.
        (deploy / "empty.itb").write_bytes(b"")
        result = self._detect(tmp_path)
        assert isinstance(result, MechanismResult)
        assert result.present is False

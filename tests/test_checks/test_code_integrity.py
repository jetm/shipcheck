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


# ---------------------------------------------------------------------------
# dm-verity detector (task 1.5)
# ---------------------------------------------------------------------------


class TestDmVerityDetector:
    """dm-verity detector returning ``MechanismResult``.

    Covers the dm-verity scenario in ``specs/code-integrity/spec.md``:
    ``conf/local.conf`` or ``conf/auto.conf`` containing
    ``DM_VERITY_IMAGE`` or ``DM_VERITY_IMAGE_TYPE``, or
    ``tmp/deploy/images/`` containing files with ``.verity`` or
    ``.hashtree`` extensions -> ``present=True``.

    The detector lives at ``shipcheck.checks.code_integrity.dm_verity``
    and exposes a ``detect(build_dir, config)`` callable that returns a
    ``MechanismResult``.
    """

    def _detect(self, build_dir: Path, config: dict | None = None) -> MechanismResult:
        from shipcheck.checks.code_integrity.dm_verity import detect

        return detect(build_dir, config or {})

    # --- Scenario: config-variable detection -------------------------------

    def test_dm_verity_image_in_local_conf(self, tmp_path: Path) -> None:
        _write_conf(tmp_path, "local.conf", 'DM_VERITY_IMAGE = "core-image-minimal"\n')
        result = self._detect(tmp_path)
        assert result.present is True
        joined = " ".join(result.evidence)
        assert "DM_VERITY_IMAGE" in joined

    def test_dm_verity_image_type_in_local_conf(self, tmp_path: Path) -> None:
        _write_conf(tmp_path, "local.conf", 'DM_VERITY_IMAGE_TYPE = "ext4"\n')
        result = self._detect(tmp_path)
        assert result.present is True
        joined = " ".join(result.evidence)
        assert "DM_VERITY_IMAGE_TYPE" in joined

    def test_dm_verity_image_in_auto_conf(self, tmp_path: Path) -> None:
        _write_conf(tmp_path, "auto.conf", 'DM_VERITY_IMAGE = "core-image-full"\n')
        result = self._detect(tmp_path)
        assert result.present is True

    def test_returns_mechanism_result(self, tmp_path: Path) -> None:
        _write_conf(tmp_path, "local.conf", 'DM_VERITY_IMAGE = "core-image-minimal"\n')
        result = self._detect(tmp_path)
        assert isinstance(result, MechanismResult)

    def test_commented_dm_verity_image_ignored(self, tmp_path: Path) -> None:
        _write_conf(tmp_path, "local.conf", '# DM_VERITY_IMAGE = "core-image-minimal"\n')
        result = self._detect(tmp_path)
        assert result.present is False

    def test_commented_dm_verity_image_type_ignored(self, tmp_path: Path) -> None:
        _write_conf(tmp_path, "local.conf", '# DM_VERITY_IMAGE_TYPE = "ext4"\n')
        result = self._detect(tmp_path)
        assert result.present is False

    # --- Scenario: artifact detection --------------------------------------

    def test_verity_file_marks_present(self, tmp_path: Path) -> None:
        deploy = _create_deploy_dir(tmp_path)
        verity = deploy / "core-image-minimal.verity"
        verity.write_bytes(b"\x00" * 32)
        result = self._detect(tmp_path)
        assert result.present is True
        joined = " ".join(result.evidence)
        assert "core-image-minimal.verity" in joined or str(verity) in joined

    def test_hashtree_file_marks_present(self, tmp_path: Path) -> None:
        deploy = _create_deploy_dir(tmp_path)
        ht = deploy / "core-image-minimal.hashtree"
        ht.write_bytes(b"\x00" * 32)
        result = self._detect(tmp_path)
        assert result.present is True
        joined = " ".join(result.evidence)
        assert "core-image-minimal.hashtree" in joined or str(ht) in joined

    def test_verity_artifact_anywhere_under_images(self, tmp_path: Path) -> None:
        # Verity artifacts may sit under per-machine subdirectories; the
        # detector must recurse into tmp/deploy/images/.
        nested = tmp_path / "tmp" / "deploy" / "images" / "qemux86-64"
        nested.mkdir(parents=True)
        (nested / "core-image-minimal.verity").write_bytes(b"\x00" * 32)
        result = self._detect(tmp_path)
        assert result.present is True

    def test_present_when_both_config_and_artifact(self, tmp_path: Path) -> None:
        deploy = _create_deploy_dir(tmp_path)
        (deploy / "core-image-minimal.verity").write_bytes(b"\x00" * 32)
        _write_conf(tmp_path, "local.conf", 'DM_VERITY_IMAGE = "core-image-minimal"\n')
        result = self._detect(tmp_path)
        assert result.present is True
        # Both signals should be reflected in evidence.
        joined = " ".join(result.evidence)
        assert "DM_VERITY_IMAGE" in joined
        assert ".verity" in joined or "core-image-minimal.verity" in joined

    # --- Scenario: absence -------------------------------------------------

    def test_absent_when_no_config_and_no_artifacts(self, tmp_path: Path) -> None:
        result = self._detect(tmp_path)
        assert result.present is False
        assert result.evidence == []
        assert result.misconfigurations == []

    def test_absent_when_unrelated_conf(self, tmp_path: Path) -> None:
        _write_conf(tmp_path, "local.conf", 'MACHINE = "qemux86-64"\n')
        result = self._detect(tmp_path)
        assert result.present is False

    def test_absent_when_only_unrelated_files_in_deploy(self, tmp_path: Path) -> None:
        deploy = _create_deploy_dir(tmp_path)
        (deploy / "image.ext4").write_bytes(b"\x00" * 16)
        (deploy / "image.cpio").write_bytes(b"\x00" * 16)
        result = self._detect(tmp_path)
        assert result.present is False

    # --- Confidence --------------------------------------------------------

    def test_confidence_high_when_present(self, tmp_path: Path) -> None:
        _write_conf(tmp_path, "local.conf", 'DM_VERITY_IMAGE = "core-image-minimal"\n')
        result = self._detect(tmp_path)
        # dm-verity detection is a deterministic config / file-extension
        # signal -- when present, confidence is high.
        assert result.confidence == "high"

    # --- Edge cases --------------------------------------------------------

    def test_binary_conf_file_does_not_crash(self, tmp_path: Path) -> None:
        conf_dir = tmp_path / "conf"
        conf_dir.mkdir()
        (conf_dir / "local.conf").write_bytes(b"\x00\xff\xfe" * 100)
        result = self._detect(tmp_path)
        assert isinstance(result, MechanismResult)
        assert result.present is False


# ---------------------------------------------------------------------------
# IMA/EVM detector (task 1.6)
# ---------------------------------------------------------------------------


def _write_kernel_config(build_dir: Path, content: str, *, recipe: str = "linux-yocto") -> Path:
    """Write a kernel ``.config`` under tmp/work/<arch>/<recipe>/<ver>/.config."""
    work = build_dir / "tmp" / "work" / "qemux86_64-poky-linux" / recipe / "6.6.30+git0+abc-r0"
    work.mkdir(parents=True, exist_ok=True)
    cfg = work / ".config"
    cfg.write_text(content)
    return cfg


def _write_license_manifest(
    build_dir: Path, content: str, *, image: str = "core-image-minimal"
) -> Path:
    """Write a license.manifest under tmp/deploy/licenses/<image>/license.manifest."""
    lic_dir = build_dir / "tmp" / "deploy" / "licenses" / image
    lic_dir.mkdir(parents=True, exist_ok=True)
    manifest = lic_dir / "license.manifest"
    manifest.write_text(content)
    return manifest


def _write_bootargs(build_dir: Path, content: str, *, machine: str = "machine") -> Path:
    """Write a bootargs file under tmp/deploy/images/<machine>/bootargs."""
    deploy = build_dir / "tmp" / "deploy" / "images" / machine
    deploy.mkdir(parents=True, exist_ok=True)
    bootargs = deploy / "bootargs"
    bootargs.write_text(content)
    return bootargs


class TestImaEvmDetector:
    """IMA/EVM detector returning ``MechanismResult``.

    Covers the four-signal hierarchy in design.md "IMA/EVM detection
    signal hierarchy":

    1. Kernel ``.config`` symbols (``CONFIG_IMA=y``,
       ``CONFIG_IMA_APPRAISE=y``, ``CONFIG_EVM=y``) under
       ``tmp/work/.../linux-yocto*/.config``. Two or more → high; single → medium.
    2. License manifest entry ``ima-evm-utils`` under
       ``tmp/deploy/licenses/*/license.manifest``. Combined with kernel
       config → high; alone → medium.
    3. ``IMAGE_INSTALL`` reference to ``ima-evm-utils`` or
       ``ima-policy-*`` in ``conf/local.conf`` / ``conf/auto.conf``.
       Reported as low confidence when no other signal is present.
    4. Boot-arg evidence (``ima_policy=`` in
       ``tmp/deploy/images/*/bootargs``). Best-effort supplementary;
       raises confidence one tier when combined with another signal but
       does not stand alone.

    The detector lives at ``shipcheck.checks.code_integrity.ima_evm`` and
    exposes a ``detect(build_dir, config)`` callable that returns a
    ``MechanismResult``.
    """

    def _detect(self, build_dir: Path, config: dict | None = None) -> MechanismResult:
        from shipcheck.checks.code_integrity.ima_evm import detect

        return detect(build_dir, config or {})

    # --- Scenario: absence -------------------------------------------------

    def test_returns_mechanism_result(self, tmp_path: Path) -> None:
        result = self._detect(tmp_path)
        assert isinstance(result, MechanismResult)

    def test_absent_when_no_signals(self, tmp_path: Path) -> None:
        result = self._detect(tmp_path)
        assert result.present is False
        assert result.evidence == []
        assert result.misconfigurations == []

    def test_absent_when_unrelated_conf_only(self, tmp_path: Path) -> None:
        _write_conf(tmp_path, "local.conf", 'MACHINE = "qemux86-64"\n')
        result = self._detect(tmp_path)
        assert result.present is False

    # --- Scenario 1: kernel .config symbols --------------------------------

    def test_two_kernel_symbols_high_confidence(self, tmp_path: Path) -> None:
        _write_kernel_config(
            tmp_path,
            "CONFIG_IMA=y\nCONFIG_IMA_APPRAISE=y\n# CONFIG_EVM is not set\n",
        )
        result = self._detect(tmp_path)
        assert result.present is True
        assert result.confidence == "high"

    def test_three_kernel_symbols_high_confidence(self, tmp_path: Path) -> None:
        _write_kernel_config(
            tmp_path,
            "CONFIG_IMA=y\nCONFIG_IMA_APPRAISE=y\nCONFIG_EVM=y\n",
        )
        result = self._detect(tmp_path)
        assert result.present is True
        assert result.confidence == "high"

    def test_single_kernel_symbol_medium_confidence(self, tmp_path: Path) -> None:
        _write_kernel_config(tmp_path, "CONFIG_IMA=y\n")
        result = self._detect(tmp_path)
        assert result.present is True
        assert result.confidence == "medium"

    def test_kernel_config_evidence_lists_matched_symbols(self, tmp_path: Path) -> None:
        _write_kernel_config(tmp_path, "CONFIG_IMA=y\nCONFIG_EVM=y\n")
        result = self._detect(tmp_path)
        joined = " ".join(result.evidence)
        assert "CONFIG_IMA" in joined
        assert "CONFIG_EVM" in joined

    def test_kernel_config_not_set_lines_ignored(self, tmp_path: Path) -> None:
        _write_kernel_config(
            tmp_path,
            "# CONFIG_IMA is not set\n# CONFIG_EVM is not set\n",
        )
        result = self._detect(tmp_path)
        assert result.present is False

    def test_kernel_config_n_value_ignored(self, tmp_path: Path) -> None:
        _write_kernel_config(tmp_path, "CONFIG_IMA=n\nCONFIG_EVM=n\n")
        result = self._detect(tmp_path)
        assert result.present is False

    def test_kernel_config_module_value_counts(self, tmp_path: Path) -> None:
        # ``=m`` (module) is a valid enable in Kconfig and should count.
        _write_kernel_config(tmp_path, "CONFIG_IMA=m\nCONFIG_EVM=m\n")
        result = self._detect(tmp_path)
        assert result.present is True

    def test_kernel_config_under_other_recipe_directory(self, tmp_path: Path) -> None:
        # The detector globs ``linux-yocto*`` so ``linux-yocto-rt`` should
        # also be found.
        _write_kernel_config(
            tmp_path,
            "CONFIG_IMA=y\nCONFIG_EVM=y\n",
            recipe="linux-yocto-rt",
        )
        result = self._detect(tmp_path)
        assert result.present is True

    # --- Scenario 2: license manifest --------------------------------------

    def test_license_manifest_alone_medium_confidence(self, tmp_path: Path) -> None:
        _write_license_manifest(
            tmp_path,
            "PACKAGE NAME: ima-evm-utils\nPACKAGE VERSION: 1.5\nLICENSE: GPL-2.0-only\n\n",
        )
        result = self._detect(tmp_path)
        assert result.present is True
        assert result.confidence == "medium"

    def test_license_manifest_evidence_includes_package(self, tmp_path: Path) -> None:
        _write_license_manifest(
            tmp_path,
            "PACKAGE NAME: ima-evm-utils\nPACKAGE VERSION: 1.5\nLICENSE: GPL-2.0-only\n\n",
        )
        result = self._detect(tmp_path)
        joined = " ".join(result.evidence)
        assert "ima-evm-utils" in joined

    def test_license_manifest_with_kernel_config_high_confidence(self, tmp_path: Path) -> None:
        # license manifest + single kernel symbol → high
        # (combining license manifest with kernel config raises confidence).
        _write_kernel_config(tmp_path, "CONFIG_IMA=y\n")
        _write_license_manifest(
            tmp_path,
            "PACKAGE NAME: ima-evm-utils\nPACKAGE VERSION: 1.5\nLICENSE: GPL-2.0-only\n\n",
        )
        result = self._detect(tmp_path)
        assert result.present is True
        assert result.confidence == "high"

    def test_license_manifest_unrelated_package_ignored(self, tmp_path: Path) -> None:
        _write_license_manifest(
            tmp_path,
            "PACKAGE NAME: openssl\nPACKAGE VERSION: 3.0\nLICENSE: Apache-2.0\n\n",
        )
        result = self._detect(tmp_path)
        assert result.present is False

    # --- Scenario 3: IMAGE_INSTALL references ------------------------------

    def test_image_install_ima_evm_utils_low_confidence(self, tmp_path: Path) -> None:
        _write_conf(tmp_path, "local.conf", 'IMAGE_INSTALL:append = " ima-evm-utils"\n')
        result = self._detect(tmp_path)
        assert result.present is True
        assert result.confidence == "low"

    def test_image_install_ima_policy_pattern(self, tmp_path: Path) -> None:
        _write_conf(tmp_path, "local.conf", 'IMAGE_INSTALL:append = " ima-policy-hashed"\n')
        result = self._detect(tmp_path)
        assert result.present is True
        assert result.confidence == "low"

    def test_image_install_in_auto_conf(self, tmp_path: Path) -> None:
        _write_conf(tmp_path, "auto.conf", 'IMAGE_INSTALL += "ima-evm-utils"\n')
        result = self._detect(tmp_path)
        assert result.present is True

    def test_commented_image_install_ignored(self, tmp_path: Path) -> None:
        _write_conf(tmp_path, "local.conf", '# IMAGE_INSTALL:append = " ima-evm-utils"\n')
        result = self._detect(tmp_path)
        assert result.present is False

    def test_image_install_evidence_mentions_package(self, tmp_path: Path) -> None:
        _write_conf(tmp_path, "local.conf", 'IMAGE_INSTALL:append = " ima-evm-utils"\n')
        result = self._detect(tmp_path)
        joined = " ".join(result.evidence)
        assert "ima-evm-utils" in joined or "IMAGE_INSTALL" in joined

    # --- Scenario 4: boot-arg evidence -------------------------------------

    def test_boot_arg_alone_does_not_mark_present(self, tmp_path: Path) -> None:
        # Boot args are supplementary -- they cannot stand alone.
        _write_bootargs(tmp_path, "console=ttyS0 ima_policy=tcb\n")
        result = self._detect(tmp_path)
        assert result.present is False

    def test_boot_arg_raises_confidence_one_tier(self, tmp_path: Path) -> None:
        # IMAGE_INSTALL alone is low; with a boot-arg signal it should
        # rise to medium.
        _write_conf(tmp_path, "local.conf", 'IMAGE_INSTALL:append = " ima-evm-utils"\n')
        _write_bootargs(tmp_path, "console=ttyS0 ima_policy=tcb\n")
        result = self._detect(tmp_path)
        assert result.present is True
        assert result.confidence == "medium"

    def test_boot_arg_does_not_exceed_high(self, tmp_path: Path) -> None:
        # Already-high confidence stays at high when a boot-arg is added.
        _write_kernel_config(
            tmp_path,
            "CONFIG_IMA=y\nCONFIG_IMA_APPRAISE=y\nCONFIG_EVM=y\n",
        )
        _write_bootargs(tmp_path, "ima_policy=appraise_tcb\n")
        result = self._detect(tmp_path)
        assert result.present is True
        assert result.confidence == "high"

    # --- Combined scenarios ------------------------------------------------

    def test_all_four_signals_high_confidence(self, tmp_path: Path) -> None:
        _write_kernel_config(
            tmp_path,
            "CONFIG_IMA=y\nCONFIG_IMA_APPRAISE=y\nCONFIG_EVM=y\n",
        )
        _write_license_manifest(
            tmp_path,
            "PACKAGE NAME: ima-evm-utils\nPACKAGE VERSION: 1.5\nLICENSE: GPL-2.0-only\n\n",
        )
        _write_conf(tmp_path, "local.conf", 'IMAGE_INSTALL:append = " ima-evm-utils"\n')
        _write_bootargs(tmp_path, "ima_policy=appraise_tcb\n")
        result = self._detect(tmp_path)
        assert result.present is True
        assert result.confidence == "high"

    def test_misconfigurations_always_empty(self, tmp_path: Path) -> None:
        # The IMA/EVM detector emits no per-mechanism findings; absence is
        # surfaced by the aggregator (task 1.7).
        _write_kernel_config(tmp_path, "CONFIG_IMA=y\nCONFIG_EVM=y\n")
        result = self._detect(tmp_path)
        assert result.misconfigurations == []

    # --- Edge cases --------------------------------------------------------

    def test_binary_kernel_config_does_not_crash(self, tmp_path: Path) -> None:
        work = tmp_path / "tmp" / "work" / "arch" / "linux-yocto" / "v"
        work.mkdir(parents=True)
        (work / ".config").write_bytes(b"\x00\xff\xfe" * 100)
        result = self._detect(tmp_path)
        assert isinstance(result, MechanismResult)
        assert result.present is False

    def test_binary_license_manifest_does_not_crash(self, tmp_path: Path) -> None:
        lic_dir = tmp_path / "tmp" / "deploy" / "licenses" / "core-image-minimal"
        lic_dir.mkdir(parents=True)
        (lic_dir / "license.manifest").write_bytes(b"\x00\xff\xfe" * 100)
        result = self._detect(tmp_path)
        assert isinstance(result, MechanismResult)
        assert result.present is False

    def test_binary_bootargs_does_not_crash(self, tmp_path: Path) -> None:
        deploy = tmp_path / "tmp" / "deploy" / "images" / "machine"
        deploy.mkdir(parents=True)
        (deploy / "bootargs").write_bytes(b"\x00\xff\xfe" * 100)
        # Add another signal so present=True can be evaluated.
        _write_kernel_config(tmp_path, "CONFIG_IMA=y\n")
        result = self._detect(tmp_path)
        assert isinstance(result, MechanismResult)

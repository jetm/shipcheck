"""Secure Boot configuration check for Yocto builds."""

from __future__ import annotations

import logging
import re
from pathlib import Path

from shipcheck.models import BaseCheck, CheckResult, Finding, determine_status

logger = logging.getLogger(__name__)

_SIGNING_CLASSES = {"uefi-sign", "sbsign", "image-uefi-sign", "secureboot"}

_KEY_VARIABLES = {"SECURE_BOOT_SIGNING_KEY", "SECURE_BOOT_DB_KEY", "UEFI_SIGN_KEY"}

_DEFAULT_TEST_KEY_PATTERNS = {"test", "development", "sample", "example", "debug"}

_OVMF_TEST_PATTERNS = {"ovmf", "edk2"}

_REMEDIATION_NO_SIGNING = (
    "Add a signing class to IMAGE_CLASSES in conf/local.conf. "
    "For UEFI Secure Boot, use 'image-uefi-sign' or 'sbsign' from meta-arm/meta-secure-core."
)

_REMEDIATION_MISSING_KEY = "Set {var} in conf/local.conf to point to a valid signing key file."

_REMEDIATION_TEST_KEY = (
    "Replace development/test keys with production keys before shipping. "
    "Test keys are publicly known and provide no security."
)

_REMEDIATION_MISCONFIGURATION = (
    "EFI artifacts found without signing configuration, or signing configured "
    "without key files. Review your Secure Boot setup for consistency."
)


def _read_config_files(build_dir: Path) -> list[tuple[Path, str]]:
    """Read conf/local.conf and conf/auto.conf if they exist."""
    configs = []
    for name in ("conf/local.conf", "conf/auto.conf"):
        path = build_dir / name
        if path.is_file():
            try:
                configs.append((path, path.read_text()))
            except (OSError, UnicodeDecodeError):
                logger.warning("Could not read %s", path)
    return configs


def _parse_variable(content: str, var_name: str) -> list[str]:
    """Extract all values assigned to a variable across all assignments.

    Handles:
    - Simple: VAR = "value"
    - Append: VAR += "value"
    - Multi-line: VAR = "value1 \\
                         value2"
    """
    values: list[str] = []
    # Normalize continuation lines: replace backslash-newline with space
    normalized = re.sub(r"\\\n\s*", " ", content)
    # Standard assignments: VAR = "val", VAR += "val", VAR ?= "val", VAR ??= "val"
    for match in re.finditer(
        rf'^[ \t]*{re.escape(var_name)}\s*(?:\?\??=|\+?=)\s*"([^"]*)"',
        normalized,
        re.MULTILINE,
    ):
        values.extend(match.group(1).split())
    # BitBake override-style append: VAR:append = " val"
    for match in re.finditer(
        rf'^[ \t]*{re.escape(var_name)}:append\s*=\s*"([^"]*)"',
        normalized,
        re.MULTILINE,
    ):
        values.extend(match.group(1).split())
    return values


def _detect_signing_class(configs: list[tuple[Path, str]]) -> list[str]:
    """Detect signing classes in IMAGE_CLASSES from config files."""
    found = []
    for _path, content in configs:
        classes = _parse_variable(content, "IMAGE_CLASSES")
        for cls in classes:
            if cls in _SIGNING_CLASSES:
                found.append(cls)
    return found


def _find_key_paths(configs: list[tuple[Path, str]]) -> dict[str, str]:
    """Extract key file paths from config variables."""
    keys: dict[str, str] = {}
    for _path, content in configs:
        for var in _KEY_VARIABLES:
            values = _parse_variable(content, var)
            if values:
                # Take the last assignment (override semantics)
                keys[var] = values[-1]
    return keys


def _validate_keys(key_paths: dict[str, str], build_dir: Path) -> tuple[int, list[Finding]]:
    """Validate that key files exist. Returns (valid_count, findings)."""
    findings: list[Finding] = []
    valid = 0
    for var, raw_path in key_paths.items():
        path = Path(raw_path)
        if not path.is_absolute():
            path = build_dir / path
        if path.is_file():
            valid += 1
        else:
            findings.append(
                Finding(
                    message=f"Key file not found: {var} = {raw_path}",
                    severity="high",
                    remediation=_REMEDIATION_MISSING_KEY.format(var=var),
                )
            )
    return valid, findings


def _check_test_keys(
    key_paths: dict[str, str],
    build_dir: Path,
    extra_patterns: list[str],
) -> list[Finding]:
    """Flag test/development keys that must not ship."""
    findings: list[Finding] = []
    patterns = _DEFAULT_TEST_KEY_PATTERNS | {p.lower() for p in extra_patterns}

    for var, raw_path in key_paths.items():
        path = Path(raw_path)
        if not path.is_absolute():
            path = build_dir / path
        name_lower = path.name.lower()
        stem_lower = path.stem.lower()
        path_str_lower = str(path).lower()

        flagged = False
        for pattern in patterns:
            if pattern in name_lower or pattern in stem_lower:
                flagged = True
                break

        if not flagged:
            # Check directory path components relative to build_dir
            try:
                rel = path.relative_to(build_dir)
            except ValueError:
                rel = path
            for part in rel.parts[:-1]:
                part_lower = part.lower()
                for pattern in patterns:
                    if pattern in part_lower:
                        flagged = True
                        break
                if flagged:
                    break

        if not flagged:
            for ovmf_pattern in _OVMF_TEST_PATTERNS:
                if ovmf_pattern in path_str_lower:
                    flagged = True
                    break

        if flagged:
            findings.append(
                Finding(
                    message=(f"Test/development key detected: {var} = {raw_path}"),
                    severity="high",
                    remediation=_REMEDIATION_TEST_KEY,
                )
            )
    return findings


def _find_efi_artifacts(build_dir: Path) -> list[Path]:
    """Find .efi files in tmp/deploy/images/ (recursive)."""
    images_dir = build_dir / "tmp" / "deploy" / "images"
    if not images_dir.is_dir():
        return []
    return list(images_dir.rglob("*.efi"))


class SecureBootCheck(BaseCheck):
    """Validate Secure Boot configuration in a Yocto build directory."""

    id = "secure-boot"
    name = "Secure Boot"
    framework = ["CRA"]
    severity = "critical"

    def run(self, build_dir: Path, config: dict) -> CheckResult:
        findings: list[Finding] = []
        score = 0
        max_score = 50
        known_test_keys: list[str] = config.get("known_test_keys", [])

        configs = _read_config_files(build_dir)

        if not configs:
            findings.append(
                Finding(
                    message=("No Yocto config files found (conf/local.conf, conf/auto.conf)"),
                    severity="medium",
                    remediation=_REMEDIATION_NO_SIGNING,
                )
            )
            efi_files = _find_efi_artifacts(build_dir)
            if efi_files:
                findings.append(
                    Finding(
                        message=(
                            f"EFI artifacts found ({len(efi_files)} .efi "
                            "files) but no signing configuration detected"
                        ),
                        severity="high",
                        remediation=_REMEDIATION_MISCONFIGURATION,
                    )
                )
            return CheckResult(
                check_id=self.id,
                check_name=self.name,
                status=determine_status(findings),
                score=0,
                max_score=max_score,
                findings=findings,
                summary="No configuration files found",
            )

        # 1. Signing class detection (20 pts)
        signing_classes = _detect_signing_class(configs)
        has_signing = len(signing_classes) > 0
        if has_signing:
            score += 20
        else:
            findings.append(
                Finding(
                    message=("No Secure Boot signing class found in IMAGE_CLASSES"),
                    severity="medium",
                    remediation=_REMEDIATION_NO_SIGNING,
                )
            )

        # 2. Key file validation (15 pts)
        key_paths = _find_key_paths(configs)
        has_missing_keys = False
        if key_paths:
            valid_count, key_findings = _validate_keys(key_paths, build_dir)
            findings.extend(key_findings)
            has_missing_keys = len(key_findings) > 0
            if valid_count > 0 and not key_findings:
                score += 15
            elif valid_count > 0:
                score += round(15 * valid_count / len(key_paths))
        elif has_signing:
            findings.append(
                Finding(
                    message=("Signing class configured but no key variables found"),
                    severity="high",
                    remediation=_REMEDIATION_MISSING_KEY.format(var="SECURE_BOOT_SIGNING_KEY"),
                )
            )

        # 3. Test/dev key detection (10 pts)
        if key_paths:
            test_key_findings = _check_test_keys(key_paths, build_dir, known_test_keys)
            findings.extend(test_key_findings)
            if not test_key_findings:
                score += 10
        elif not has_signing:
            pass

        # 4. Misconfiguration detection (5 pts)
        efi_files = _find_efi_artifacts(build_dir)
        misconfigured = False

        if efi_files and not has_signing:
            findings.append(
                Finding(
                    message=(
                        f"EFI artifacts found ({len(efi_files)} .efi "
                        "files) but no signing class configured"
                    ),
                    severity="high",
                    remediation=_REMEDIATION_MISCONFIGURATION,
                )
            )
            misconfigured = True

        if has_signing and has_missing_keys:
            misconfigured = True

        if not misconfigured:
            score += 5

        # Build summary
        parts = []
        if has_signing:
            parts.append(f"signing class: {', '.join(signing_classes)}")
        if key_paths:
            parts.append(f"{len(key_paths)} key variable(s) configured")
        if efi_files:
            parts.append(f"{len(efi_files)} EFI artifact(s)")

        summary = "; ".join(parts) if parts else "No Secure Boot configuration detected"

        return CheckResult(
            check_id=self.id,
            check_name=self.name,
            status=determine_status(findings),
            score=score,
            max_score=max_score,
            findings=findings,
            summary=summary,
        )

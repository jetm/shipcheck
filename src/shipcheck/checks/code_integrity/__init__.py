"""Unified code-integrity check.

This package replaces the retired ``secure-boot`` and ``image-signing``
checks. ``CodeIntegrityCheck`` aggregates four mechanism detectors
(UEFI Secure Boot, signed FIT, dm-verity, IMA/EVM) into a single
registered check that maps to CRA Annex I Part I §c, §d, §f, and §k.

The aggregator's contract per ``specs/code-integrity/spec.md``:

- FAIL only when every detector reports ``present=False``.
- Otherwise, status is determined by ``determine_status`` over the
  union of every detector's ``misconfigurations``.
- ``CheckResult.cra_mapping`` is always the union
  ``["I.P1.c", "I.P1.d", "I.P1.f", "I.P1.k"]``; per-finding
  ``cra_mapping`` may be narrower and is preserved as the detector
  emitted it.
- The summary names which mechanism(s) were detected so report
  consumers can show evidence at a glance.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from shipcheck.models import BaseCheck, CheckResult, CheckStatus, Finding, determine_status

if TYPE_CHECKING:
    from pathlib import Path


# CRA catalog IDs covered by this check, equal to the union of the
# retired ``secure-boot`` and ``image-signing`` mappings. Per the spec
# requirement ``cra_mapping union covers prior checks``, this list is
# the value of ``CheckResult.cra_mapping`` regardless of which
# mechanism is detected.
CRA_MAPPING: list[str] = ["I.P1.c", "I.P1.d", "I.P1.f", "I.P1.k"]

# Human-friendly mechanism labels used in the summary string. Order
# matches the detector dispatch order so the summary reads consistently
# across runs.
_MECHANISM_LABELS: tuple[tuple[str, str], ...] = (
    ("uefi", "UEFI Secure Boot"),
    ("fit", "signed FIT"),
    ("dm_verity", "dm-verity"),
    ("ima_evm", "IMA/EVM"),
)

_NO_MECHANISM_MESSAGE = (
    "No software-integrity mechanism detected (UEFI Secure Boot, signed FIT, dm-verity, or IMA/EVM)"
)

_NO_MECHANISM_REMEDIATION = (
    "Configure at least one code-integrity mechanism for the build: "
    "a UEFI signing class in IMAGE_CLASSES (uefi-sign / sbsign / "
    "image-uefi-sign / secureboot), UBOOT_SIGN_ENABLE for signed FIT "
    "images, DM_VERITY_IMAGE for dm-verity, or IMA/EVM via kernel "
    "config and ima-evm-utils."
)


@dataclass
class MechanismResult:
    """Structured result from one mechanism detector.

    Each of the four detectors (UEFI Secure Boot, signed FIT, dm-verity,
    IMA/EVM) returns one of these. ``CodeIntegrityCheck.run`` aggregates
    them into the final ``CheckResult``.

    Attributes:
        present: True when the detector found evidence the mechanism is
            configured. False means "shipcheck saw no signal for this
            mechanism in this build".
        confidence: ``"high"`` / ``"medium"`` / ``"low"``. Detectors
            with a single deterministic signal (e.g. UEFI signing class
            in IMAGE_CLASSES) report ``"high"``; detectors with weaker
            heuristics (e.g. IMA/EVM via IMAGE_INSTALL alone) report
            ``"low"``. The default is ``"low"`` so that a "not present"
            result still carries a defined confidence value.
        evidence: Paths or config keys that drove the determination.
            Used by the aggregator's summary string and by report
            renderers; never empty when ``present`` is True.
        misconfigurations: ``Finding`` objects for invalid configuration
            (test keys, missing key files, unsigned FIT artifacts, etc.).
            Always empty when ``present`` is False -- absence is its own
            top-level finding emitted by the aggregator.
    """

    present: bool = False
    confidence: str = "low"
    evidence: list[str] = field(default_factory=list)
    misconfigurations: list[Finding] = field(default_factory=list)


class CodeIntegrityCheck(BaseCheck):
    """Validate software-integrity protection in a Yocto build.

    Detects whichever of UEFI Secure Boot, signed FIT, dm-verity, or
    IMA/EVM is configured and FAILs only when none are present. Status
    delegates to ``determine_status`` over the union of every detector's
    findings; ``CheckResult.cra_mapping`` is always the four-entry union
    even when a single mechanism is the only one present.
    """

    id = "code-integrity"
    name = "Code Integrity"
    framework = ["CRA"]
    severity = "critical"

    def run(self, build_dir: Path, config: dict) -> CheckResult:
        # Local imports avoid a package-level circular dependency: each
        # detector module imports ``MechanismResult`` from this package.
        from shipcheck.checks.code_integrity import dm_verity, fit, ima_evm, uefi

        results: dict[str, MechanismResult] = {
            "uefi": uefi.detect(build_dir, config),
            "fit": fit.detect(build_dir, config),
            "dm_verity": dm_verity.detect(build_dir, config),
            "ima_evm": ima_evm.detect(build_dir, config),
        }

        present_keys = [key for key, result in results.items() if result.present]
        findings: list[Finding] = []
        for result in results.values():
            findings.extend(result.misconfigurations)

        if not present_keys:
            findings.append(
                Finding(
                    message=_NO_MECHANISM_MESSAGE,
                    severity="high",
                    remediation=_NO_MECHANISM_REMEDIATION,
                    cra_mapping=list(CRA_MAPPING),
                )
            )
            status = CheckStatus.FAIL
            summary = _NO_MECHANISM_MESSAGE
        else:
            status = determine_status(findings)
            label_lookup = dict(_MECHANISM_LABELS)
            present_labels = [
                label_lookup[key] for key, _ in _MECHANISM_LABELS if key in present_keys
            ]
            summary = "Detected: " + ", ".join(present_labels)

        return CheckResult(
            check_id=self.id,
            check_name=self.name,
            status=status,
            score=0,
            max_score=0,
            findings=findings,
            summary=summary,
            cra_mapping=list(CRA_MAPPING),
        )


__all__ = ["CRA_MAPPING", "CodeIntegrityCheck", "MechanismResult"]

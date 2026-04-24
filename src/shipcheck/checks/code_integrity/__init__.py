"""Unified code-integrity check.

This package replaces the retired ``secure-boot`` and ``image-signing``
checks. ``CodeIntegrityCheck`` aggregates four mechanism detectors
(UEFI Secure Boot, signed FIT, dm-verity, IMA/EVM) into a single
registered check that maps to CRA Annex I Part I §c, §d, §f, and §k.

Task 1.2 lays the package skeleton: the public ``CodeIntegrityCheck``
class identity, the ``MechanismResult`` dataclass each detector returns,
and a placeholder ``run`` that later tasks (1.3 - 1.7) replace with the
real per-detector dispatch and aggregator.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from shipcheck.models import BaseCheck, CheckResult, CheckStatus, Finding

if TYPE_CHECKING:
    from pathlib import Path


# CRA catalog IDs covered by this check, equal to the union of the
# retired ``secure-boot`` and ``image-signing`` mappings. Per the spec
# requirement ``cra_mapping union covers prior checks``, this list is
# the value of ``CheckResult.cra_mapping`` regardless of which
# mechanism is detected.
CRA_MAPPING: list[str] = ["I.P1.c", "I.P1.d", "I.P1.f", "I.P1.k"]


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
    IMA/EVM is configured and FAILs only when none are present. The
    actual detector dispatch and aggregation logic lands in task 1.7;
    this skeleton exists so downstream tasks can import the class while
    detectors are implemented incrementally.
    """

    id = "code-integrity"
    name = "Code Integrity"
    framework = ["CRA"]
    severity = "critical"

    def run(self, build_dir: Path, config: dict) -> CheckResult:
        # Skeleton implementation. Task 1.7 replaces this with the full
        # four-detector aggregator. Returning SKIP here keeps any caller
        # that imports the class before task 1.7 lands from receiving a
        # misleading PASS or FAIL.
        return CheckResult(
            check_id=self.id,
            check_name=self.name,
            status=CheckStatus.SKIP,
            score=0,
            max_score=0,
            findings=[],
            summary="code-integrity check not yet implemented",
            cra_mapping=list(CRA_MAPPING),
        )


__all__ = ["CRA_MAPPING", "CodeIntegrityCheck", "MechanismResult"]

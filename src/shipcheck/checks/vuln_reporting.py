"""Vulnerability reporting check - Article 14 / Annex I Part II documentation.

This check validates that ``product.yaml`` declares the paperwork the CRA
requires manufacturers to put in place around vulnerability handling:

- A coordinated vulnerability disclosure policy URL (Annex I Part II §5).
- A single point of contact for reporting vulnerabilities (Annex II §2).
- A support period end date, present and not yet elapsed (Annex II §7).
- A declared update distribution mechanism (Annex I Part II §7).

The check parses ``product.yaml`` directly with ``yaml.safe_load`` rather than
going through :func:`shipcheck.product.load_product_config`, because that
loader raises on the very fields the check needs to report as findings.
"""

from __future__ import annotations

from datetime import date
from pathlib import Path
from typing import Any

import yaml

from shipcheck.models import BaseCheck, CheckResult, CheckStatus, Finding, determine_status

# Default mapping reported on the CheckResult itself. The union of finding
# mappings drives the actual surface; this default covers the case where
# ``product.yaml`` is missing or unparseable and no findings are emitted.
_DEFAULT_CRA_MAPPING: tuple[str, ...] = ("I.P2.4", "I.P2.5", "II.2", "II.7")

_MAX_SCORE = 50


def _lookup(data: dict[str, Any], dotted: str) -> Any:
    """Return the value at ``dotted`` inside ``data`` or ``None`` if absent."""
    node: Any = data
    for part in dotted.split("."):
        if not isinstance(node, dict):
            return None
        node = node.get(part)
        if node is None:
            return None
    return node


def _is_missing(value: Any) -> bool:
    """Treat ``None`` and empty / whitespace-only strings as missing."""
    if value is None:
        return True
    return bool(isinstance(value, str) and not value.strip())


def _parse_iso_date(value: str) -> date | None:
    """Return ``date`` for an ISO 8601 ``YYYY-MM-DD`` string, else ``None``."""
    try:
        return date.fromisoformat(value.strip())
    except (ValueError, AttributeError):
        return None


class VulnerabilityReportingCheck(BaseCheck):
    """Verify product.yaml declares the Article 14 / Annex I Part II paperwork."""

    id = "vuln-reporting"
    name = "Vulnerability Reporting"
    framework = ["CRA"]
    severity = "high"

    def run(self, build_dir: Path, config: dict) -> CheckResult:  # noqa: ARG002
        product_config_path = config.get("product_config_path")

        if not product_config_path:
            return CheckResult(
                check_id=self.id,
                check_name=self.name,
                status=CheckStatus.SKIP,
                score=0,
                max_score=_MAX_SCORE,
                findings=[],
                summary="product_config_path not configured; skipping vuln-reporting check",
                cra_mapping=list(_DEFAULT_CRA_MAPPING),
            )

        path = Path(product_config_path)
        if not path.exists():
            return CheckResult(
                check_id=self.id,
                check_name=self.name,
                status=CheckStatus.ERROR,
                score=0,
                max_score=_MAX_SCORE,
                findings=[],
                summary=f"product.yaml not found: {path}",
                cra_mapping=list(_DEFAULT_CRA_MAPPING),
            )

        try:
            with path.open() as fh:
                raw = yaml.safe_load(fh)
        except yaml.YAMLError as exc:
            return CheckResult(
                check_id=self.id,
                check_name=self.name,
                status=CheckStatus.ERROR,
                score=0,
                max_score=_MAX_SCORE,
                findings=[],
                summary=f"failed to parse {path}: {exc}",
                cra_mapping=list(_DEFAULT_CRA_MAPPING),
            )

        if not isinstance(raw, dict):
            return CheckResult(
                check_id=self.id,
                check_name=self.name,
                status=CheckStatus.ERROR,
                score=0,
                max_score=_MAX_SCORE,
                findings=[],
                summary=f"product.yaml must be a mapping: {path}",
                cra_mapping=list(_DEFAULT_CRA_MAPPING),
            )

        findings = self._evaluate(raw)
        status = determine_status(findings)
        if status == CheckStatus.PASS:
            score = _MAX_SCORE
        else:
            score = max(0, _MAX_SCORE - 10 * len(findings))

        # Union of every finding's mapping, preserving first-seen order.
        seen: set[str] = set()
        result_mapping: list[str] = []
        for finding in findings:
            for entry in finding.cra_mapping:
                if entry not in seen:
                    seen.add(entry)
                    result_mapping.append(entry)
        if not result_mapping:
            result_mapping = list(_DEFAULT_CRA_MAPPING)

        summary = (
            f"Vulnerability reporting: {len(findings)} finding(s), score {score}/{_MAX_SCORE}"
        )

        return CheckResult(
            check_id=self.id,
            check_name=self.name,
            status=status,
            score=score,
            max_score=_MAX_SCORE,
            findings=findings,
            summary=summary,
            cra_mapping=result_mapping,
        )

    def _evaluate(self, raw: dict[str, Any]) -> list[Finding]:
        """Produce the finding list for a parsed ``product.yaml`` mapping."""
        findings: list[Finding] = []

        if _is_missing(_lookup(raw, "cvd.policy_url")):
            findings.append(
                Finding(
                    message=(
                        "product.yaml is missing cvd.policy_url (Annex I Part II §5): "
                        "a coordinated vulnerability disclosure policy URL must be declared"
                    ),
                    severity="high",
                    remediation=(
                        "Add a cvd.policy_url entry to product.yaml pointing to the "
                        "published coordinated vulnerability disclosure policy."
                    ),
                    cra_mapping=["I.P2.5"],
                )
            )

        if _is_missing(_lookup(raw, "cvd.contact")):
            findings.append(
                Finding(
                    message=(
                        "product.yaml is missing cvd.contact (Annex II §2): "
                        "a single point of contact for vulnerability reports is required"
                    ),
                    severity="high",
                    remediation=(
                        "Add a cvd.contact entry to product.yaml (email or URL) "
                        "where security researchers can report vulnerabilities."
                    ),
                    cra_mapping=["II.2"],
                )
            )

        end_date_raw = _lookup(raw, "support_period.end_date")
        if _is_missing(end_date_raw):
            findings.append(
                Finding(
                    message=(
                        "product.yaml is missing support_period.end_date (Annex II §7): "
                        "the support period end date must be declared"
                    ),
                    severity="high",
                    remediation=(
                        "Add support_period.end_date in ISO 8601 YYYY-MM-DD form to "
                        "product.yaml; it must not be in the past."
                    ),
                    cra_mapping=["II.7"],
                )
            )
        else:
            parsed = _parse_iso_date(str(end_date_raw))
            if parsed is not None and parsed < date.today():
                findings.append(
                    Finding(
                        message=(
                            f"support_period.end_date {parsed.isoformat()} is in the past; "
                            "the declared support period has expired (Annex II §7)"
                        ),
                        severity="medium",
                        remediation=(
                            "Extend support_period.end_date in product.yaml or confirm "
                            "end-of-support status with downstream consumers."
                        ),
                        cra_mapping=["II.7"],
                    )
                )

        if _is_missing(_lookup(raw, "update_distribution.mechanism")):
            findings.append(
                Finding(
                    message=(
                        "product.yaml is missing update_distribution.mechanism "
                        "(Annex I Part II §7): the secure update distribution "
                        "mechanism must be declared"
                    ),
                    severity="medium",
                    remediation=(
                        "Add update_distribution.mechanism to product.yaml "
                        "(e.g. 'swupdate', 'RAUC', 'capsule-update', 'manual')."
                    ),
                    cra_mapping=["I.P2.7"],
                )
            )

        return findings

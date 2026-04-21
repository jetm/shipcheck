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

Each required field runs the evaluation pipeline ``missing -> placeholder ->
malformed`` with first-match-wins semantics (one finding per field).
"""

from __future__ import annotations

import re
from datetime import date
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

from shipcheck.models import BaseCheck, CheckResult, CheckStatus, Finding, determine_status

# Default mapping reported on the CheckResult itself. The union of finding
# mappings drives the actual surface; this default covers the case where
# ``product.yaml`` is missing or unparseable and no findings are emitted.
_DEFAULT_CRA_MAPPING: tuple[str, ...] = ("I.P2.4", "I.P2.5", "II.2", "II.7")

_MAX_SCORE = 50

# Case-folded tokens that indicate a field has been left as a template
# placeholder (for example ``VENDOR`` or ``[TO BE FILLED]``). Entries are
# stored pre-folded so ``_is_placeholder`` only has to fold the input once.
_PLACEHOLDER_TOKENS: frozenset[str] = frozenset(
    {token.casefold() for token in ("VENDOR", "TODO", "FIXME", "[TO BE FILLED]", "[VENDOR]")}
)

_EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


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


def _is_placeholder(value: str) -> bool:
    """Return True iff ``value`` (trimmed, case-folded) is a known placeholder token."""
    return value.strip().casefold() in _PLACEHOLDER_TOKENS


def _is_valid_url(value: str) -> bool:
    """Return True for a non-empty http/https URL with netloc, or mailto with path."""
    try:
        parsed = urlparse(value.strip())
    except ValueError:
        return False
    scheme = parsed.scheme.lower()
    if scheme in {"http", "https"}:
        return bool(parsed.netloc)
    if scheme == "mailto":
        return bool(parsed.path)
    return False


def _is_valid_email(value: str) -> bool:
    """Return True iff the trimmed value matches ``local@domain.tld``."""
    return bool(_EMAIL_RE.match(value.strip()))


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

        summary = f"Vulnerability reporting: {len(findings)} finding(s), score {score}/{_MAX_SCORE}"

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
        """Produce the finding list for a parsed ``product.yaml`` mapping.

        Each required field runs the pipeline ``missing -> placeholder ->
        malformed`` with first-match-wins semantics (design D4): a field that
        is both missing and whitespace-only short-circuits at "missing" and
        emits exactly one finding.
        """
        findings: list[Finding] = []

        # --- cvd.policy_url (Annex I Part II §5) ---------------------------
        policy_url = _lookup(raw, "cvd.policy_url")
        policy_remediation = (
            "Add a cvd.policy_url entry to product.yaml pointing to the "
            "published coordinated vulnerability disclosure policy."
        )
        if _is_missing(policy_url):
            findings.append(
                Finding(
                    message=(
                        "product.yaml is missing cvd.policy_url (Annex I Part II §5): "
                        "a coordinated vulnerability disclosure policy URL must be declared"
                    ),
                    severity="high",
                    remediation=policy_remediation,
                    cra_mapping=["I.P2.5"],
                )
            )
        else:
            policy_str = str(policy_url)
            if _is_placeholder(policy_str):
                findings.append(
                    Finding(
                        message=(
                            f"product.yaml cvd.policy_url is a placeholder token "
                            f"{policy_str.strip()!r} (Annex I Part II §5): "
                            "a real coordinated vulnerability disclosure policy URL "
                            "must be declared"
                        ),
                        severity="high",
                        remediation=policy_remediation,
                        cra_mapping=["I.P2.5"],
                    )
                )
            elif not _is_valid_url(policy_str):
                findings.append(
                    Finding(
                        message=(
                            f"product.yaml cvd.policy_url {policy_str!r} is not a valid "
                            "http://, https://, or mailto: URL (Annex I Part II §5)"
                        ),
                        severity="high",
                        remediation=policy_remediation,
                        cra_mapping=["I.P2.5"],
                    )
                )

        # --- cvd.contact (Annex II §2) -------------------------------------
        contact = _lookup(raw, "cvd.contact")
        contact_remediation = (
            "Add a cvd.contact entry to product.yaml (email or URL) "
            "where security researchers can report vulnerabilities."
        )
        if _is_missing(contact):
            findings.append(
                Finding(
                    message=(
                        "product.yaml is missing cvd.contact (Annex II §2): "
                        "a single point of contact for vulnerability reports is required"
                    ),
                    severity="high",
                    remediation=contact_remediation,
                    cra_mapping=["II.2"],
                )
            )
        else:
            contact_str = str(contact)
            if _is_placeholder(contact_str):
                findings.append(
                    Finding(
                        message=(
                            f"product.yaml cvd.contact is a placeholder token "
                            f"{contact_str.strip()!r} (Annex II §2): "
                            "a real single point of contact for vulnerability reports is required"
                        ),
                        severity="high",
                        remediation=contact_remediation,
                        cra_mapping=["II.2"],
                    )
                )
            elif not (_is_valid_email(contact_str) or _is_valid_url(contact_str)):
                findings.append(
                    Finding(
                        message=(
                            f"product.yaml cvd.contact {contact_str!r} is neither an email "
                            "address nor a valid URL (Annex II §2)"
                        ),
                        severity="high",
                        remediation=contact_remediation,
                        cra_mapping=["II.2"],
                    )
                )

        # --- support_period.end_date (Annex II §7) -------------------------
        end_date_raw = _lookup(raw, "support_period.end_date")
        end_date_remediation = (
            "Add support_period.end_date in ISO 8601 YYYY-MM-DD form to "
            "product.yaml; it must not be in the past."
        )
        if _is_missing(end_date_raw):
            findings.append(
                Finding(
                    message=(
                        "product.yaml is missing support_period.end_date (Annex II §7): "
                        "the support period end date must be declared"
                    ),
                    severity="high",
                    remediation=end_date_remediation,
                    cra_mapping=["II.7"],
                )
            )
        else:
            end_date_str = str(end_date_raw)
            if _is_placeholder(end_date_str):
                findings.append(
                    Finding(
                        message=(
                            f"product.yaml support_period.end_date is a placeholder token "
                            f"{end_date_str.strip()!r} (Annex II §7): "
                            "a real ISO 8601 YYYY-MM-DD support period end date must be declared"
                        ),
                        severity="high",
                        remediation=end_date_remediation,
                        cra_mapping=["II.7"],
                    )
                )
            else:
                parsed = _parse_iso_date(end_date_str)
                if parsed is None:
                    findings.append(
                        Finding(
                            message=(
                                f"product.yaml support_period.end_date {end_date_str!r} "
                                "is not parseable as an ISO 8601 YYYY-MM-DD date (Annex II §7)"
                            ),
                            severity="high",
                            remediation=end_date_remediation,
                            cra_mapping=["II.7"],
                        )
                    )
                elif parsed < date.today():
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

        # --- update_distribution.mechanism (Annex I Part II §7) ------------
        mechanism = _lookup(raw, "update_distribution.mechanism")
        mechanism_remediation = (
            "Add update_distribution.mechanism to product.yaml "
            "(e.g. 'swupdate', 'RAUC', 'capsule-update', 'manual')."
        )
        if _is_missing(mechanism):
            findings.append(
                Finding(
                    message=(
                        "product.yaml is missing update_distribution.mechanism "
                        "(Annex I Part II §7): the secure update distribution "
                        "mechanism must be declared"
                    ),
                    severity="medium",
                    remediation=mechanism_remediation,
                    cra_mapping=["I.P2.7"],
                )
            )
        else:
            mechanism_str = str(mechanism)
            if _is_placeholder(mechanism_str):
                findings.append(
                    Finding(
                        message=(
                            f"product.yaml update_distribution.mechanism is a placeholder token "
                            f"{mechanism_str.strip()!r} (Annex I Part II §7): "
                            "a real secure update distribution mechanism must be declared"
                        ),
                        severity="medium",
                        remediation=mechanism_remediation,
                        cra_mapping=["I.P2.7"],
                    )
                )

        return findings

"""Tests for VulnerabilityReportingCheck (Article 14 / Annex I Part II documentation).

These tests drive task 7.2 which implements
``shipcheck.checks.vuln_reporting.VulnerabilityReportingCheck``. The module does
not yet exist, so collection fails with ``ModuleNotFoundError`` until the
implementation lands - that ModuleNotFoundError is the expected RED state.

The check loads ``product.yaml`` (path supplied via ``product_config_path``
in per-check config) and emits findings whenever Article 14 / Annex I Part II
documentation obligations are unmet.

Fixtures live under ``tests/fixtures/product/``:

- ``complete.yaml`` - every required and optional field populated, end_date future.
- ``missing_cvd.yaml`` - ``cvd.policy_url`` absent.
- ``missing_cvd_contact.yaml`` - ``cvd.contact`` absent.
- ``missing_end_date.yaml`` - ``support_period.end_date`` absent.
- ``no_update_mechanism.yaml`` - ``update_distribution.mechanism`` absent.
- ``expired_support.yaml`` - end_date ``2020-01-01``.
- ``future_support.yaml`` - end_date ``2030-12-31``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from shipcheck.checks.vuln_reporting import VulnerabilityReportingCheck
from shipcheck.models import CheckStatus, Finding

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "product"

# Allowed CRA requirement IDs for findings from this check. Taken verbatim from
# the task spec so drift in the check's mapping surface is caught here.
ALLOWED_CRA_IDS: frozenset[str] = frozenset(
    {"I.P2.4", "I.P2.5", "I.P2.6", "I.P2.7", "I.P2.8", "II.2", "II.7"}
)


def _run(product_fixture: str, tmp_path: Path) -> object:
    """Instantiate the check and run it against a product.yaml fixture.

    ``product_config_path`` is passed via the per-check config dict so that the
    check does not need to discover a sibling file in ``build_dir``.
    """
    check = VulnerabilityReportingCheck()
    cfg = {"product_config_path": str(FIXTURES_DIR / product_fixture)}
    return check.run(tmp_path, cfg)


def _flatten_text(finding: Finding) -> str:
    """Return a lowercase blob containing the finding's human-readable text."""
    parts: list[str] = [finding.message or ""]
    if finding.details:
        parts.append(str(finding.details))
    if finding.remediation:
        parts.append(finding.remediation)
    return " ".join(parts).lower()


def _has_finding_about(result, needles: tuple[str, ...]) -> bool:
    """True iff any finding's flattened text mentions all given substrings."""
    for finding in result.findings:
        blob = _flatten_text(finding)
        if all(needle.lower() in blob for needle in needles):
            return True
    return False


# --- (a) FAIL when cvd.policy_url is missing --------------------------------


class TestMissingCvdPolicyUrl:
    """A product.yaml without ``cvd.policy_url`` must produce a FAIL finding."""

    def test_status_is_fail(self, tmp_path: Path) -> None:
        result = _run("missing_cvd.yaml", tmp_path)
        assert result.status == CheckStatus.FAIL

    def test_high_or_critical_finding_names_policy_url(self, tmp_path: Path) -> None:
        result = _run("missing_cvd.yaml", tmp_path)

        high_sev = [f for f in result.findings if f.severity in {"critical", "high"}]
        assert high_sev, "missing cvd.policy_url must emit at least one high-severity finding"
        assert _has_finding_about(result, ("policy_url",)) or _has_finding_about(
            result, ("cvd", "policy")
        ), f"no finding names the missing cvd.policy_url field; findings={result.findings!r}"


# --- (b) FAIL when cvd.contact is missing -----------------------------------


class TestMissingCvdContact:
    """A product.yaml without ``cvd.contact`` must produce a FAIL finding."""

    def test_status_is_fail(self, tmp_path: Path) -> None:
        result = _run("missing_cvd_contact.yaml", tmp_path)
        assert result.status == CheckStatus.FAIL

    def test_high_or_critical_finding_names_contact(self, tmp_path: Path) -> None:
        result = _run("missing_cvd_contact.yaml", tmp_path)

        high_sev = [f for f in result.findings if f.severity in {"critical", "high"}]
        assert high_sev, "missing cvd.contact must emit at least one high-severity finding"
        assert _has_finding_about(result, ("cvd", "contact")) or _has_finding_about(
            result, ("contact",)
        ), f"no finding names the missing cvd.contact field; findings={result.findings!r}"


# --- (c) FAIL when support_period.end_date is missing -----------------------


class TestMissingSupportEndDate:
    """A product.yaml without ``support_period.end_date`` must produce a FAIL finding."""

    def test_status_is_fail(self, tmp_path: Path) -> None:
        result = _run("missing_end_date.yaml", tmp_path)
        assert result.status == CheckStatus.FAIL

    def test_high_or_critical_finding_names_end_date(self, tmp_path: Path) -> None:
        result = _run("missing_end_date.yaml", tmp_path)

        high_sev = [f for f in result.findings if f.severity in {"critical", "high"}]
        assert high_sev, (
            "missing support_period.end_date must emit at least one high-severity finding"
        )
        assert _has_finding_about(result, ("end_date",)) or _has_finding_about(
            result, ("support", "period")
        ), f"no finding names the missing support_period.end_date; findings={result.findings!r}"


# --- (d) WARN when end_date is in the past ----------------------------------


class TestExpiredSupportPeriod:
    """An end_date in the past is a documentation-layer WARN, not a FAIL.

    The product is out of support; that is an obligation-state observation, not
    a configuration defect.
    """

    def test_status_is_warn(self, tmp_path: Path) -> None:
        result = _run("expired_support.yaml", tmp_path)
        assert result.status == CheckStatus.WARN

    def test_finding_severity_is_medium_or_low(self, tmp_path: Path) -> None:
        result = _run("expired_support.yaml", tmp_path)

        related = [
            f
            for f in result.findings
            if "expir" in _flatten_text(f)
            or "past" in _flatten_text(f)
            or "end_date" in _flatten_text(f)
            or "support" in _flatten_text(f)
        ]
        assert related, (
            "expected at least one finding about the expired support period; "
            f"got {result.findings!r}"
        )
        for finding in related:
            assert finding.severity in {"medium", "low"}, (
                f"expected medium/low severity for expired support; got {finding.severity} "
                f"on {finding.message!r}"
            )


# --- (e) No finding when end_date is in the future --------------------------


class TestFutureSupportPeriod:
    """A future end_date is compliant: no expiration-related finding."""

    def test_no_expiry_finding(self, tmp_path: Path) -> None:
        result = _run("future_support.yaml", tmp_path)

        for finding in result.findings:
            blob = _flatten_text(finding)
            assert "expir" not in blob, (
                f"unexpected expiry finding on future support period: {finding.message!r}"
            )
            assert "past" not in blob, (
                f"unexpected 'in the past' finding on future support period: {finding.message!r}"
            )

    def test_end_date_is_not_flagged_as_missing(self, tmp_path: Path) -> None:
        """A present, future end_date must not trigger the missing-field branch."""
        result = _run("future_support.yaml", tmp_path)

        for finding in result.findings:
            blob = _flatten_text(finding)
            # A "missing end_date" finding would name both 'end_date' and
            # 'missing'/'absent' in the same message. Future end_date is
            # present, so such a finding must not exist.
            if "end_date" in blob:
                assert not ("missing" in blob or "absent" in blob or "not set" in blob), (
                    f"future end_date wrongly flagged as missing: {finding.message!r}"
                )


# --- (f) WARN when update_distribution.mechanism is missing -----------------


class TestMissingUpdateMechanism:
    """No declared update mechanism is WARN, not FAIL (Annex I Part II §7 doc)."""

    def test_status_is_warn(self, tmp_path: Path) -> None:
        result = _run("no_update_mechanism.yaml", tmp_path)
        assert result.status == CheckStatus.WARN

    def test_finding_severity_is_medium_or_low(self, tmp_path: Path) -> None:
        result = _run("no_update_mechanism.yaml", tmp_path)

        related = [
            f
            for f in result.findings
            if "update" in _flatten_text(f) or "mechanism" in _flatten_text(f)
        ]
        assert related, (
            "expected at least one finding about the missing update mechanism; "
            f"got {result.findings!r}"
        )
        for finding in related:
            assert finding.severity in {"medium", "low"}, (
                "expected medium/low severity for missing update mechanism; "
                f"got {finding.severity} "
                f"on {finding.message!r}"
            )


# --- (g) Every finding's cra_mapping is non-empty and allow-listed ----------


class TestCraMappingCoverage:
    """Every finding must carry a cra_mapping drawn from the task spec set."""

    @pytest.mark.parametrize(
        "fixture",
        [
            "missing_cvd.yaml",
            "missing_cvd_contact.yaml",
            "missing_end_date.yaml",
            "expired_support.yaml",
            "no_update_mechanism.yaml",
        ],
    )
    def test_every_finding_has_allowed_cra_mapping(self, tmp_path: Path, fixture: str) -> None:
        result = _run(fixture, tmp_path)

        assert result.findings, (
            f"fixture {fixture!r} should produce at least one finding "
            "for this test to mean anything"
        )
        for finding in result.findings:
            mapping = finding.cra_mapping
            assert mapping, (
                f"finding {finding.message!r} has empty cra_mapping; expected at least one entry"
            )
            for entry in mapping:
                assert entry in ALLOWED_CRA_IDS, (
                    f"finding {finding.message!r} has cra_mapping entry {entry!r} "
                    f"outside the allowed set {sorted(ALLOWED_CRA_IDS)}"
                )

    def test_check_result_cra_mapping_is_allowed(self, tmp_path: Path) -> None:
        """The CheckResult-level mapping must also stay within the allowed set."""
        result = _run("missing_cvd.yaml", tmp_path)

        assert result.cra_mapping, "CheckResult.cra_mapping should not be empty"
        for entry in result.cra_mapping:
            assert entry in ALLOWED_CRA_IDS, (
                f"CheckResult.cra_mapping entry {entry!r} outside allowed set "
                f"{sorted(ALLOWED_CRA_IDS)}"
            )


# --- (h) Placeholder token detection ----------------------------------------


class TestPlaceholderDetection:
    """Placeholder tokens in required fields must be reported as findings."""

    # Single-field placeholder fixtures: one finding each.

    def test_placeholder_policy_url_produces_one_finding(self, tmp_path: Path) -> None:
        result = _run("placeholder_policy_url.yaml", tmp_path)

        ph_findings = [f for f in result.findings if "cvd.policy_url" in _flatten_text(f)]
        assert len(ph_findings) == 1, (
            f"expected exactly one finding about cvd.policy_url; got {result.findings!r}"
        )

    def test_placeholder_policy_url_severity_is_high(self, tmp_path: Path) -> None:
        result = _run("placeholder_policy_url.yaml", tmp_path)

        ph_findings = [f for f in result.findings if "cvd.policy_url" in _flatten_text(f)]
        assert ph_findings, "placeholder_policy_url.yaml must produce a cvd.policy_url finding"
        assert ph_findings[0].severity == "high", (
            f"expected high severity for cvd.policy_url placeholder; got {ph_findings[0].severity}"
        )

    def test_placeholder_policy_url_cra_mapping(self, tmp_path: Path) -> None:
        result = _run("placeholder_policy_url.yaml", tmp_path)

        ph_findings = [f for f in result.findings if "cvd.policy_url" in _flatten_text(f)]
        assert ph_findings, "placeholder_policy_url.yaml must produce a cvd.policy_url finding"
        assert "I.P2.5" in ph_findings[0].cra_mapping, (
            f"expected I.P2.5 in cra_mapping; got {ph_findings[0].cra_mapping}"
        )

    def test_placeholder_contact_produces_one_finding(self, tmp_path: Path) -> None:
        result = _run("placeholder_contact.yaml", tmp_path)

        ph_findings = [
            f
            for f in result.findings
            if "cvd.contact" in _flatten_text(f)
            or ("cvd" in _flatten_text(f) and "contact" in _flatten_text(f))
        ]
        assert len(ph_findings) == 1, (
            f"expected exactly one finding about cvd.contact; got {result.findings!r}"
        )

    def test_placeholder_contact_severity_is_high(self, tmp_path: Path) -> None:
        result = _run("placeholder_contact.yaml", tmp_path)

        ph_findings = [
            f
            for f in result.findings
            if "cvd.contact" in _flatten_text(f)
            or ("cvd" in _flatten_text(f) and "contact" in _flatten_text(f))
        ]
        assert ph_findings, "placeholder_contact.yaml must produce a cvd.contact finding"
        assert ph_findings[0].severity == "high", (
            f"expected high severity for cvd.contact placeholder; got {ph_findings[0].severity}"
        )

    def test_placeholder_contact_cra_mapping(self, tmp_path: Path) -> None:
        result = _run("placeholder_contact.yaml", tmp_path)

        ph_findings = [
            f
            for f in result.findings
            if "cvd.contact" in _flatten_text(f)
            or ("cvd" in _flatten_text(f) and "contact" in _flatten_text(f))
        ]
        assert ph_findings, "placeholder_contact.yaml must produce a cvd.contact finding"
        assert "II.2" in ph_findings[0].cra_mapping, (
            f"expected II.2 in cra_mapping; got {ph_findings[0].cra_mapping}"
        )

    def test_placeholder_end_date_produces_one_finding(self, tmp_path: Path) -> None:
        result = _run("placeholder_end_date.yaml", tmp_path)

        ph_findings = [f for f in result.findings if "end_date" in _flatten_text(f)]
        assert len(ph_findings) == 1, (
            f"expected exactly one finding about end_date; got {result.findings!r}"
        )

    def test_placeholder_end_date_severity_is_high(self, tmp_path: Path) -> None:
        result = _run("placeholder_end_date.yaml", tmp_path)

        ph_findings = [f for f in result.findings if "end_date" in _flatten_text(f)]
        assert ph_findings, "placeholder_end_date.yaml must produce an end_date finding"
        assert ph_findings[0].severity == "high", (
            f"expected high severity for end_date placeholder; got {ph_findings[0].severity}"
        )

    def test_placeholder_end_date_cra_mapping(self, tmp_path: Path) -> None:
        result = _run("placeholder_end_date.yaml", tmp_path)

        ph_findings = [f for f in result.findings if "end_date" in _flatten_text(f)]
        assert ph_findings, "placeholder_end_date.yaml must produce an end_date finding"
        assert "II.7" in ph_findings[0].cra_mapping, (
            f"expected II.7 in cra_mapping; got {ph_findings[0].cra_mapping}"
        )

    def test_placeholder_mechanism_produces_one_finding(self, tmp_path: Path) -> None:
        result = _run("placeholder_mechanism.yaml", tmp_path)

        ph_findings = [f for f in result.findings if "mechanism" in _flatten_text(f)]
        assert len(ph_findings) == 1, (
            f"expected exactly one finding about mechanism; got {result.findings!r}"
        )

    def test_placeholder_mechanism_severity_is_medium(self, tmp_path: Path) -> None:
        result = _run("placeholder_mechanism.yaml", tmp_path)

        ph_findings = [f for f in result.findings if "mechanism" in _flatten_text(f)]
        assert ph_findings, "placeholder_mechanism.yaml must produce a mechanism finding"
        assert ph_findings[0].severity == "medium", (
            f"expected medium severity for mechanism placeholder; got {ph_findings[0].severity}"
        )

    def test_placeholder_mechanism_cra_mapping(self, tmp_path: Path) -> None:
        result = _run("placeholder_mechanism.yaml", tmp_path)

        ph_findings = [f for f in result.findings if "mechanism" in _flatten_text(f)]
        assert ph_findings, "placeholder_mechanism.yaml must produce a mechanism finding"
        assert "I.P2.7" in ph_findings[0].cra_mapping, (
            f"expected I.P2.7 in cra_mapping; got {ph_findings[0].cra_mapping}"
        )

    # all_placeholders.yaml: four findings, FAIL status, score 10/50.

    def test_all_placeholders_finding_count(self, tmp_path: Path) -> None:
        result = _run("all_placeholders.yaml", tmp_path)

        assert len(result.findings) == 4, (
            f"all_placeholders.yaml must produce exactly 4 findings; got {result.findings!r}"
        )

    def test_all_placeholders_status_is_fail(self, tmp_path: Path) -> None:
        result = _run("all_placeholders.yaml", tmp_path)

        assert result.status == CheckStatus.FAIL, (
            f"expected FAIL status for all_placeholders.yaml; got {result.status}"
        )

    def test_all_placeholders_score(self, tmp_path: Path) -> None:
        result = _run("all_placeholders.yaml", tmp_path)

        assert result.score == 10, (
            f"expected score 10 (50 - 4*10) for all_placeholders.yaml; got {result.score}"
        )
        assert result.max_score == 50, f"expected max_score 50; got {result.max_score}"

    # Case-insensitivity: vendor / Vendor / "  VENDOR  " all fire the same finding.

    @pytest.mark.parametrize(
        "contact_value",
        ["vendor", "Vendor", "  VENDOR  "],
        ids=["lowercase", "capitalized", "whitespace_padded"],
    )
    def test_placeholder_case_insensitivity(self, tmp_path: Path, contact_value: str) -> None:
        product_yaml = tmp_path / "product.yaml"
        product_yaml.write_text(
            f"""schema_version: 1
product:
  name: "Acme Gateway GW-100"
  type: "Industrial IoT edge gateway"
  version: "2.4.1"
manufacturer:
  name: "Acme Embedded Systems GmbH"
  address: "Karlstrasse 42, 80333 Munich, Germany"
  contact: "compliance@acme-embedded.example"
support_period:
  end_date: "2031-12-31"
cvd:
  policy_url: "https://acme-embedded.example/security/cvd-policy"
  contact: {contact_value!r}
update_distribution:
  mechanism: "Signed OTA updates over HTTPS via the Acme Update Service"
"""
        )
        check = VulnerabilityReportingCheck()
        cfg = {"product_config_path": str(product_yaml)}
        result = check.run(tmp_path, cfg)

        contact_findings = [
            f
            for f in result.findings
            if "cvd.contact" in _flatten_text(f)
            or ("cvd" in _flatten_text(f) and "contact" in _flatten_text(f))
        ]
        assert len(contact_findings) == 1, (
            f"contact value {contact_value!r} must produce exactly one finding; "
            f"got {result.findings!r}"
        )
        assert contact_findings[0].severity == "high", (
            f"expected high severity for contact placeholder {contact_value!r}; "
            f"got {contact_findings[0].severity}"
        )
        assert "II.2" in contact_findings[0].cra_mapping, (
            f"expected II.2 in cra_mapping for contact placeholder {contact_value!r}; "
            f"got {contact_findings[0].cra_mapping}"
        )


# --- (i) Shape validation (malformed values, not missing) -------------------


class TestShapeValidation:
    """Malformed field values must produce findings even if the field is non-empty."""

    # --- negative path: malformed fixtures ---

    def test_malformed_policy_url_exactly_one_finding(self, tmp_path: Path) -> None:
        result = _run("malformed_policy_url.yaml", tmp_path)

        ph_findings = [f for f in result.findings if "cvd.policy_url" in _flatten_text(f)]
        assert len(ph_findings) == 1, (
            f"expected exactly one finding about cvd.policy_url; got {result.findings!r}"
        )

    def test_malformed_policy_url_severity_is_high(self, tmp_path: Path) -> None:
        result = _run("malformed_policy_url.yaml", tmp_path)

        ph_findings = [f for f in result.findings if "cvd.policy_url" in _flatten_text(f)]
        assert ph_findings, "malformed_policy_url.yaml must produce a cvd.policy_url finding"
        assert ph_findings[0].severity == "high", (
            f"expected high severity; got {ph_findings[0].severity}"
        )

    def test_malformed_policy_url_cra_mapping_includes_i_p2_5(self, tmp_path: Path) -> None:
        result = _run("malformed_policy_url.yaml", tmp_path)

        ph_findings = [f for f in result.findings if "cvd.policy_url" in _flatten_text(f)]
        assert ph_findings, "malformed_policy_url.yaml must produce a cvd.policy_url finding"
        assert "I.P2.5" in ph_findings[0].cra_mapping, (
            f"expected I.P2.5 in cra_mapping; got {ph_findings[0].cra_mapping}"
        )

    def test_malformed_contact_exactly_one_finding(self, tmp_path: Path) -> None:
        result = _run("malformed_contact.yaml", tmp_path)

        ph_findings = [
            f
            for f in result.findings
            if "cvd.contact" in _flatten_text(f)
            or ("cvd" in _flatten_text(f) and "contact" in _flatten_text(f))
        ]
        assert len(ph_findings) == 1, (
            f"expected exactly one finding about cvd.contact; got {result.findings!r}"
        )

    def test_malformed_contact_severity_is_high(self, tmp_path: Path) -> None:
        result = _run("malformed_contact.yaml", tmp_path)

        ph_findings = [
            f
            for f in result.findings
            if "cvd.contact" in _flatten_text(f)
            or ("cvd" in _flatten_text(f) and "contact" in _flatten_text(f))
        ]
        assert ph_findings, "malformed_contact.yaml must produce a cvd.contact finding"
        assert ph_findings[0].severity == "high", (
            f"expected high severity; got {ph_findings[0].severity}"
        )

    def test_malformed_contact_cra_mapping_includes_ii_2(self, tmp_path: Path) -> None:
        result = _run("malformed_contact.yaml", tmp_path)

        ph_findings = [
            f
            for f in result.findings
            if "cvd.contact" in _flatten_text(f)
            or ("cvd" in _flatten_text(f) and "contact" in _flatten_text(f))
        ]
        assert ph_findings, "malformed_contact.yaml must produce a cvd.contact finding"
        assert "II.2" in ph_findings[0].cra_mapping, (
            f"expected II.2 in cra_mapping; got {ph_findings[0].cra_mapping}"
        )

    def test_unparseable_end_date_exactly_one_finding(self, tmp_path: Path) -> None:
        """Unparseable end_date must emit a finding (not silently skip)."""
        result = _run("unparseable_end_date.yaml", tmp_path)

        ph_findings = [f for f in result.findings if "end_date" in _flatten_text(f)]
        assert len(ph_findings) == 1, (
            f"expected exactly one finding about end_date; got {result.findings!r}"
        )

    def test_unparseable_end_date_severity_is_high(self, tmp_path: Path) -> None:
        result = _run("unparseable_end_date.yaml", tmp_path)

        ph_findings = [f for f in result.findings if "end_date" in _flatten_text(f)]
        assert ph_findings, "unparseable_end_date.yaml must produce an end_date finding"
        assert ph_findings[0].severity == "high", (
            f"expected high severity for unparseable end_date; got {ph_findings[0].severity}"
        )

    def test_unparseable_end_date_cra_mapping_includes_ii_7(self, tmp_path: Path) -> None:
        result = _run("unparseable_end_date.yaml", tmp_path)

        ph_findings = [f for f in result.findings if "end_date" in _flatten_text(f)]
        assert ph_findings, "unparseable_end_date.yaml must produce an end_date finding"
        assert "II.7" in ph_findings[0].cra_mapping, (
            f"expected II.7 in cra_mapping; got {ph_findings[0].cra_mapping}"
        )

    # --- positive path: valid alternative shapes ---

    def test_mailto_url_in_policy_url_passes(self, tmp_path: Path) -> None:
        """A mailto: URL is a valid policy_url shape."""
        product_yaml = tmp_path / "product.yaml"
        product_yaml.write_text(
            """schema_version: 1
product:
  name: "Acme Gateway GW-100"
  type: "Industrial IoT edge gateway"
  version: "2.4.1"
manufacturer:
  name: "Acme Embedded Systems GmbH"
  address: "Karlstrasse 42, 80333 Munich, Germany"
  contact: "compliance@acme-embedded.example"
support_period:
  end_date: "2031-12-31"
cvd:
  policy_url: "mailto:security@acme.example"
  contact: "security@acme-embedded.example"
update_distribution:
  mechanism: "Signed OTA updates over HTTPS via the Acme Update Service"
"""
        )
        check = VulnerabilityReportingCheck()
        result = check.run(tmp_path, {"product_config_path": str(product_yaml)})

        policy_url_findings = [f for f in result.findings if "cvd.policy_url" in _flatten_text(f)]
        assert not policy_url_findings, (
            f"mailto: policy_url must not produce a finding; got {policy_url_findings!r}"
        )

    def test_url_shaped_contact_passes(self, tmp_path: Path) -> None:
        """An https:// URL in cvd.contact is accepted."""
        product_yaml = tmp_path / "product.yaml"
        product_yaml.write_text(
            """schema_version: 1
product:
  name: "Acme Gateway GW-100"
  type: "Industrial IoT edge gateway"
  version: "2.4.1"
manufacturer:
  name: "Acme Embedded Systems GmbH"
  address: "Karlstrasse 42, 80333 Munich, Germany"
  contact: "compliance@acme-embedded.example"
support_period:
  end_date: "2031-12-31"
cvd:
  policy_url: "https://acme-embedded.example/security/cvd-policy"
  contact: "https://acme.example/security"
update_distribution:
  mechanism: "Signed OTA updates over HTTPS via the Acme Update Service"
"""
        )
        check = VulnerabilityReportingCheck()
        result = check.run(tmp_path, {"product_config_path": str(product_yaml)})

        contact_findings = [
            f
            for f in result.findings
            if "cvd.contact" in _flatten_text(f)
            or ("cvd" in _flatten_text(f) and "contact" in _flatten_text(f))
        ]
        assert not contact_findings, (
            f"URL-shaped contact must not produce a finding; got {contact_findings!r}"
        )

    def test_email_shaped_contact_passes(self, tmp_path: Path) -> None:
        """An email address in cvd.contact is accepted (default case from complete.yaml)."""
        result = _run("complete.yaml", tmp_path)

        contact_findings = [
            f
            for f in result.findings
            if "cvd.contact" in _flatten_text(f)
            or ("cvd" in _flatten_text(f) and "contact" in _flatten_text(f))
        ]
        assert not contact_findings, (
            f"email-shaped contact must not produce a finding; got {contact_findings!r}"
        )

    # --- regression guard: complete.yaml must still pass at full score ---

    def test_complete_yaml_status_is_pass(self, tmp_path: Path) -> None:
        result = _run("complete.yaml", tmp_path)

        assert result.status == CheckStatus.PASS, (
            f"complete.yaml must return PASS; got {result.status}"
        )

    def test_complete_yaml_score_is_50(self, tmp_path: Path) -> None:
        result = _run("complete.yaml", tmp_path)

        assert result.score == 50, (
            f"complete.yaml must score 50/50; got {result.score}/{result.max_score}"
        )

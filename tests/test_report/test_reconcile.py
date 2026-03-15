"""Tests for CVE finding reconciliation across scanner sources.

Task 5.4 of devspec change ``shipcheck-v03-cra-evidence``. Pins the
contract of :mod:`shipcheck.report.reconcile`:

* Two findings with the same ``(cve_id, package, version)`` identity
  taken from ``Finding.details`` merge into a single finding whose
  ``sources`` list is the union of the inputs.
* Two findings with the same CVE ID but different package names do
  NOT merge - they remain independent.
* When inputs disagree on severity, the merged finding keeps the
  highest severity in the ordering
  ``critical > high > medium > low > info``.
* Output ordering is deterministic: running reconciliation twice on
  the same input yields the same finding sequence.

The import target ``shipcheck.report.reconcile.reconcile_findings`` is
deliberately absent until task 5.5 - the whole module should fail with
``ModuleNotFoundError`` at collection time, which is the valid RED for
TDD.

Tests aggregate findings across every returned ``CheckResult`` rather
than asserting on which result a merged finding ends up in. Task 5.5
pins the merge semantics (keyed identity, unioned sources, max
severity) but not the result-level distribution; aggregating keeps the
tests honest to the spec without over-constraining the implementation.
"""

from __future__ import annotations

from shipcheck.models import CheckResult, CheckStatus, Finding
from shipcheck.report.reconcile import reconcile_findings


def _cve_finding(
    *,
    cve: str,
    package: str,
    version: str,
    severity: str,
    source: str,
    message: str | None = None,
) -> Finding:
    return Finding(
        message=message or f"{cve} affects {package} {version}",
        severity=severity,
        details={"cve": cve, "package": package, "version": version},
        sources=[source],
        cra_mapping=["I.P2.2"],
    )


def _result(check_id: str, findings: list[Finding]) -> CheckResult:
    return CheckResult(
        check_id=check_id,
        check_name=check_id,
        status=CheckStatus.WARN if findings else CheckStatus.PASS,
        score=0,
        max_score=50,
        findings=findings,
        summary="synthetic",
        cra_mapping=["I.P2.2"],
    )


def _all_findings(results: list[CheckResult]) -> list[Finding]:
    """Flatten findings across every returned CheckResult."""

    out: list[Finding] = []
    for r in results:
        out.extend(r.findings)
    return out


def _cve_findings(results: list[CheckResult]) -> list[Finding]:
    return [f for f in _all_findings(results) if f.details and "cve" in f.details]


def _find(findings: list[Finding], *, cve: str, package: str) -> Finding:
    matches = [
        f
        for f in findings
        if f.details and f.details.get("cve") == cve and f.details.get("package") == package
    ]
    assert len(matches) == 1, (
        f"expected exactly one finding for {cve}/{package}, got {len(matches)}"
    )
    return matches[0]


class TestMergeSameCVESamePackage:
    def test_same_cve_same_package_same_version_merges(self):
        a = _result(
            "cve-scan",
            [
                _cve_finding(
                    cve="CVE-2024-1234",
                    package="openssl",
                    version="3.0.12",
                    severity="high",
                    source="cve-scan",
                )
            ],
        )
        b = _result(
            "yocto-cve-check",
            [
                _cve_finding(
                    cve="CVE-2024-1234",
                    package="openssl",
                    version="3.0.12",
                    severity="high",
                    source="yocto-cve-check",
                )
            ],
        )

        merged = _cve_findings(reconcile_findings([a, b]))

        assert len(merged) == 1, f"expected exactly one merged finding, got {len(merged)}"

    def test_merged_finding_unions_sources(self):
        a = _result(
            "cve-scan",
            [
                _cve_finding(
                    cve="CVE-2024-1234",
                    package="openssl",
                    version="3.0.12",
                    severity="high",
                    source="cve-scan",
                )
            ],
        )
        b = _result(
            "yocto-cve-check",
            [
                _cve_finding(
                    cve="CVE-2024-1234",
                    package="openssl",
                    version="3.0.12",
                    severity="high",
                    source="yocto-cve-check",
                )
            ],
        )

        merged = _find(
            _cve_findings(reconcile_findings([a, b])),
            cve="CVE-2024-1234",
            package="openssl",
        )

        assert set(merged.sources) == {"cve-scan", "yocto-cve-check"}


class TestDifferentPackagesRemainIndependent:
    def test_same_cve_different_packages_do_not_merge(self):
        # Same CVE ID, two different affected packages - these must stay
        # as separate findings because they are separate vulnerabilities
        # against separate components.
        a = _result(
            "cve-scan",
            [
                _cve_finding(
                    cve="CVE-2024-9999",
                    package="openssl",
                    version="3.0.12",
                    severity="high",
                    source="cve-scan",
                )
            ],
        )
        b = _result(
            "yocto-cve-check",
            [
                _cve_finding(
                    cve="CVE-2024-9999",
                    package="curl",
                    version="8.5.0",
                    severity="high",
                    source="yocto-cve-check",
                )
            ],
        )

        findings = _cve_findings(reconcile_findings([a, b]))

        assert len(findings) == 2

        openssl = _find(findings, cve="CVE-2024-9999", package="openssl")
        curl = _find(findings, cve="CVE-2024-9999", package="curl")

        assert openssl.sources == ["cve-scan"]
        assert curl.sources == ["yocto-cve-check"]


class TestSeverityReconciliation:
    def test_merged_finding_keeps_highest_severity_critical_over_low(self):
        a = _result(
            "cve-scan",
            [
                _cve_finding(
                    cve="CVE-2024-5555",
                    package="glibc",
                    version="2.39",
                    severity="low",
                    source="cve-scan",
                )
            ],
        )
        b = _result(
            "yocto-cve-check",
            [
                _cve_finding(
                    cve="CVE-2024-5555",
                    package="glibc",
                    version="2.39",
                    severity="critical",
                    source="yocto-cve-check",
                )
            ],
        )

        merged = _find(
            _cve_findings(reconcile_findings([a, b])),
            cve="CVE-2024-5555",
            package="glibc",
        )

        assert merged.severity == "critical"

    def test_merged_finding_keeps_highest_severity_high_over_medium(self):
        a = _result(
            "cve-scan",
            [
                _cve_finding(
                    cve="CVE-2024-6666",
                    package="busybox",
                    version="1.36.1",
                    severity="medium",
                    source="cve-scan",
                )
            ],
        )
        b = _result(
            "yocto-cve-check",
            [
                _cve_finding(
                    cve="CVE-2024-6666",
                    package="busybox",
                    version="1.36.1",
                    severity="high",
                    source="yocto-cve-check",
                )
            ],
        )

        merged = _find(
            _cve_findings(reconcile_findings([a, b])),
            cve="CVE-2024-6666",
            package="busybox",
        )

        assert merged.severity == "high"


class TestDeterministicOrdering:
    def test_same_input_yields_same_output_ordering(self):
        def build() -> list[CheckResult]:
            return [
                _result(
                    "cve-scan",
                    [
                        _cve_finding(
                            cve="CVE-2024-0001",
                            package="openssl",
                            version="3.0.12",
                            severity="high",
                            source="cve-scan",
                        ),
                        _cve_finding(
                            cve="CVE-2024-0002",
                            package="curl",
                            version="8.5.0",
                            severity="medium",
                            source="cve-scan",
                        ),
                        _cve_finding(
                            cve="CVE-2024-0003",
                            package="glibc",
                            version="2.39",
                            severity="critical",
                            source="cve-scan",
                        ),
                    ],
                ),
                _result(
                    "yocto-cve-check",
                    [
                        _cve_finding(
                            cve="CVE-2024-0002",
                            package="curl",
                            version="8.5.0",
                            severity="high",
                            source="yocto-cve-check",
                        ),
                        _cve_finding(
                            cve="CVE-2024-0004",
                            package="busybox",
                            version="1.36.1",
                            severity="low",
                            source="yocto-cve-check",
                        ),
                    ],
                ),
            ]

        first = reconcile_findings(build())
        second = reconcile_findings(build())

        def signature(results: list[CheckResult]) -> list[tuple]:
            sig: list[tuple] = []
            for r in results:
                sig.append(("result", r.check_id))
                for f in r.findings:
                    details = f.details or {}
                    sig.append(
                        (
                            "finding",
                            details.get("cve"),
                            details.get("package"),
                            details.get("version"),
                            f.severity,
                            tuple(f.sources),
                        )
                    )
            return sig

        assert signature(first) == signature(second)

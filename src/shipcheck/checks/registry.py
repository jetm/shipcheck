"""Check registry: registration, execution, and filtering."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

    from shipcheck.models import BaseCheck, CheckResult


class CheckRegistry:
    """Registry of checks that can be executed against a build directory.

    Checks run in registration order. Use ``check_ids`` in ``run_checks``
    to filter which checks execute (``--checks`` CLI flag).
    """

    def __init__(self) -> None:
        self._checks: list[BaseCheck] = []
        self._ids: set[str] = set()

    @property
    def checks(self) -> list[BaseCheck]:
        """Return a copy of the registered checks list."""
        return list(self._checks)

    def register(self, check: BaseCheck) -> None:
        """Register a check instance.

        Raises:
            ValueError: If a check with the same ``id`` is already registered.
        """
        if check.id in self._ids:
            msg = f"Check '{check.id}' already registered"
            raise ValueError(msg)
        self._checks.append(check)
        self._ids.add(check.id)

    def run_checks(
        self,
        *,
        build_dir: Path,
        config: dict,
        check_ids: list[str] | None = None,
    ) -> list[CheckResult]:
        """Execute registered checks and return results in registration order.

        Args:
            build_dir: Path to the Yocto build directory.
            config: Full configuration dict. Per-check config is extracted
                by check ``id`` (e.g. ``config["sbom-generation"]``).
            check_ids: Optional list of check IDs to run. When ``None``,
                all registered checks run. Unknown IDs raise ``ValueError``.

        Returns:
            List of CheckResult objects in registration order.

        Raises:
            ValueError: If ``check_ids`` contains an unknown check ID.
        """
        if check_ids is not None:
            unknown = set(check_ids) - self._ids
            if unknown:
                unknown_str = ", ".join(sorted(unknown))
                msg = f"Unknown check ID(s): {unknown_str}"
                raise ValueError(msg)

        results: list[CheckResult] = []
        for check in self._checks:
            if check_ids is not None and check.id not in check_ids:
                continue
            per_check_config = config.get(check.id, {})
            result = check.run(build_dir, per_check_config)
            results.append(result)
        return results


def get_default_registry() -> CheckRegistry:
    """Create a new registry with built-in checks registered in order.

    Returns a fresh instance each call so callers cannot pollute each other.
    """
    from shipcheck.checks.cve import CVECheck
    from shipcheck.checks.image_signing import ImageSigningCheck
    from shipcheck.checks.license_audit import LicenseAuditCheck
    from shipcheck.checks.sbom import SBOMCheck
    from shipcheck.checks.secureboot import SecureBootCheck
    from shipcheck.checks.vuln_reporting import VulnerabilityReportingCheck
    from shipcheck.checks.yocto_cve import YoctoCVECheck

    registry = CheckRegistry()
    registry.register(SBOMCheck())
    registry.register(CVECheck())
    registry.register(SecureBootCheck())
    registry.register(ImageSigningCheck())
    registry.register(LicenseAuditCheck())
    registry.register(YoctoCVECheck())
    registry.register(VulnerabilityReportingCheck())
    return registry

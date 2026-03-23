"""Shared CVE scan-output discovery for cve-tracking and yocto-cve-check.

Both checks consume the same evidence files; this module is the single source
of truth for where those files live in a Yocto build tree.  Extracted as part
of pilot-0001 fix  so the two checks cannot diverge on the same build
(see specs/shipcheck-v01-pilot/design.md, decision D2).

The lookup order matches design D2, priority 1 = highest:

1. ``tmp/deploy/images/*.sbom-cve-check.yocto.json``
2. ``tmp/deploy/images/*.rootfs.json``
3. ``tmp/deploy/images/*/cve_check_summary*.json``
4. ``tmp/log/cve/cve-summary.json``

Entries 1-3 are globs evaluated relative to ``tmp/deploy/images/``; entry 4 is
a direct relative path from the build root for the ``cve-check.bbclass``
aggregate summary.  Callers that want to introspect the priority order should
read :data:`CVE_DISCOVERY_PATTERNS`.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger(__name__)

IMAGES_SUBDIR = "tmp/deploy/images"
CVE_SUMMARY_RELPATH = "tmp/log/cve/cve-summary.json"

_IMAGES_GLOB_PATTERNS: tuple[str, ...] = (
    "*.sbom-cve-check.yocto.json",
    "*.rootfs.json",
    "*/cve_check_summary*.json",
)

CVE_DISCOVERY_PATTERNS: tuple[str, ...] = (
    *(f"{IMAGES_SUBDIR}/{pattern}" for pattern in _IMAGES_GLOB_PATTERNS),
    CVE_SUMMARY_RELPATH,
)
"""Priority-ordered discovery patterns relative to the build root.

Priority 1 = highest.  Indices 0-2 are globs; index 3 is a direct relative
path (no glob metacharacters) for the ``cve-check.bbclass`` aggregate summary.
Exposed so callers and tests can introspect the exact search order without
re-reading :func:`discover_cve_output`.
"""


def discover_cve_output(build_dir: Path) -> Path | None:
    """Search a Yocto build tree for CVE scan output in priority order.

    The function is pure: it only reads directory entries via
    :meth:`pathlib.Path.glob` and :meth:`pathlib.Path.is_file`, never writes,
    and emits only debug-level log records.

    Args:
        build_dir: Root of the Yocto build (the directory containing ``tmp/``).

    Returns:
        The first matching path from the four-tier priority order defined by
        :data:`CVE_DISCOVERY_PATTERNS`, or ``None`` if no candidate exists.
    """
    images_dir = build_dir / IMAGES_SUBDIR
    if images_dir.is_dir():
        for pattern in _IMAGES_GLOB_PATTERNS:
            matches = sorted(images_dir.glob(pattern))
            if matches:
                logger.debug(
                    "cve-discovery: matched %s via %s/%s",
                    matches[0],
                    IMAGES_SUBDIR,
                    pattern,
                )
                return matches[0]

    summary_path = build_dir / CVE_SUMMARY_RELPATH
    if summary_path.is_file():
        logger.debug("cve-discovery: matched aggregate summary %s", summary_path)
        return summary_path

    logger.debug("cve-discovery: no CVE output under %s", build_dir)
    return None

"""Scan history persistence and dossier reporting.

The :mod:`shipcheck.history.store` module exposes :class:`HistoryStore`,
a SQLite-backed log of every ``shipcheck check`` invocation. The
:mod:`shipcheck.history.dossier` module pivots that log into a
multi-scan compliance dossier (scan cadence, score trend, CVE velocity,
licence drift) suitable for CRA Annex VII §6 test-report evidence.
"""

from shipcheck.history.schema import SCHEMA_VERSION
from shipcheck.history.store import HistoryStore, HistoryStoreError

__all__ = ["HistoryStore", "HistoryStoreError", "SCHEMA_VERSION"]

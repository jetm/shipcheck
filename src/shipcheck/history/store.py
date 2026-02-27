"""SQLite-backed scan history store.

Task 6.2 of devspec change ``shipcheck-v03-cra-evidence``. The store
persists one row per ``shipcheck check`` invocation and exposes
indexed queries used by the dossier generator (task 6.4) and the CLI
``dossier`` subcommand (task group 10).

Contract pinned by ``tests/test_history/test_store.py``:

* ``HistoryStore(path)`` creates the SQLite DB and any missing parent
  directories on first use, stamps a ``schema_version`` row in the
  ``meta`` table with value :data:`~shipcheck.history.schema.SCHEMA_VERSION`,
  and tolerates re-opening an existing DB.
* ``HistoryStore(path)`` raises :class:`HistoryStoreError` when the
  stored schema version does not match :data:`SCHEMA_VERSION`, with a
  message that names the stored version and suggests ``delete`` or
  ``migrate``.
* ``store.persist(report)`` writes one row per scan with columns
  ``timestamp`` (ISO 8601, taken verbatim from ``report.timestamp``),
  ``build_dir`` (original path, for dossier rendering),
  ``build_dir_hash`` (SHA-256 of the absolute path, for indexed
  lookups), ``checks`` (JSON-encoded per-check status/score payload),
  ``finding_count`` (sum across all checks), ``total_score`` and
  ``max_total_score``. The insert is wrapped in a ``with conn:``
  transaction so a mid-write crash rolls back via SQLite's journal.
* ``store.query(since=None, build_dir=None)`` returns a list of dict
  rows sorted by timestamp ascending; ``since`` is an inclusive lower
  bound on ``timestamp`` and ``build_dir`` is matched against the
  SHA-256 hash of the absolute path.
* ``HistoryStore.disabled()`` returns a no-op store for
  ``history.enabled: false``.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path
from typing import TYPE_CHECKING, Any

from shipcheck.history.schema import SCHEMA_DDL, SCHEMA_VERSION

if TYPE_CHECKING:
    from shipcheck.models import ReportData

__all__ = ["HistoryStore", "HistoryStoreError", "SCHEMA_VERSION"]


class HistoryStoreError(Exception):
    """Raised on schema-version mismatch or DB-level persistence errors."""


def _hash_build_dir(build_dir: str | Path) -> str:
    """Return the SHA-256 hash of the absolute form of ``build_dir``."""
    abs_path = str(Path(build_dir).resolve())
    return hashlib.sha256(abs_path.encode("utf-8")).hexdigest()


class HistoryStore:
    """Persist and query compliance scan history.

    The store is created on construction; calling it on an existing DB
    reopens without re-initialising. Schema version mismatches are
    surfaced as :class:`HistoryStoreError` rather than silent upgrades,
    so a user who downgraded shipcheck cannot silently corrupt their
    dossier inputs.
    """

    def __init__(self, path: Path | str):
        self._path: Path | None = Path(path) if path is not None else None
        self._disabled = False
        if self._path is None:
            return
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._initialise()

    @classmethod
    def disabled(cls) -> HistoryStore:
        """Return a no-op store honouring ``history.enabled: false``.

        The returned instance silently swallows :meth:`persist` calls
        and returns an empty list from :meth:`query`. It never opens a
        connection or touches the filesystem, so users who have
        disabled history incur zero I/O.
        """
        instance = cls.__new__(cls)
        instance._path = None
        instance._disabled = True
        return instance

    def _connect(self) -> sqlite3.Connection:
        if self._path is None:
            raise HistoryStoreError("disabled store has no database connection")
        conn = sqlite3.connect(self._path)
        conn.row_factory = sqlite3.Row
        return conn

    def _initialise(self) -> None:
        conn = self._connect()
        try:
            conn.executescript(SCHEMA_DDL)
            cursor = conn.execute(
                "SELECT value FROM meta WHERE key = 'schema_version'"
            )
            row = cursor.fetchone()
            if row is None:
                with conn:
                    conn.execute(
                        "INSERT INTO meta(key, value) VALUES ('schema_version', ?)",
                        (str(SCHEMA_VERSION),),
                    )
                return
            stored = row[0]
            if str(stored) != str(SCHEMA_VERSION):
                raise HistoryStoreError(
                    f"shipcheck history database at {self._path} has schema "
                    f"version {stored}, expected {SCHEMA_VERSION}. Delete the "
                    f"store at {self._path} or migrate it manually before "
                    "re-running shipcheck."
                )
        finally:
            conn.close()

    def persist(self, report: ReportData) -> None:
        """Persist a :class:`~shipcheck.models.ReportData` as one scan row.

        The insert is wrapped in a ``with conn:`` transaction so a
        mid-write crash rolls back via SQLite's journal per the design
        risks section.
        """
        if self._disabled:
            return
        checks_payload = [
            {
                "check_id": check.check_id,
                "check_name": check.check_name,
                "status": check.status.value,
                "score": check.score,
                "max_score": check.max_score,
                "finding_count": len(check.findings),
            }
            for check in report.checks
        ]
        finding_count = sum(entry["finding_count"] for entry in checks_payload)

        conn = self._connect()
        try:
            with conn:
                conn.execute(
                    "INSERT INTO scans("
                    "timestamp, build_dir, build_dir_hash, checks, "
                    "finding_count, total_score, max_total_score"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        report.timestamp,
                        report.build_dir,
                        _hash_build_dir(report.build_dir),
                        json.dumps(checks_payload),
                        finding_count,
                        report.total_score,
                        report.max_total_score,
                    ),
                )
        finally:
            conn.close()

    def query(
        self,
        since: str | None = None,
        build_dir: str | Path | None = None,
    ) -> list[dict[str, Any]]:
        """Return the scan rows matching the optional filters.

        Args:
            since: Inclusive ISO-8601 lower bound on ``timestamp``. Rows
                with a strictly earlier timestamp are excluded.
            build_dir: Optional build-directory path. Matched against
                the SHA-256 hash of the absolute path stored on each
                row.

        Returns:
            Rows as ``dict`` objects ordered by ``timestamp`` ascending.
            Disabled stores always return an empty list.
        """
        if self._disabled:
            return []
        clauses: list[str] = []
        params: list[Any] = []
        if since is not None:
            clauses.append("timestamp >= ?")
            params.append(since)
        if build_dir is not None:
            clauses.append("build_dir_hash = ?")
            params.append(_hash_build_dir(build_dir))
        sql = "SELECT * FROM scans"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY timestamp ASC"

        conn = self._connect()
        try:
            cursor = conn.execute(sql, params)
            return [dict(row) for row in cursor.fetchall()]
        finally:
            conn.close()

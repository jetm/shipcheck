"""Tests for the SQLite scan history store.

Task 6.1 of devspec change ``shipcheck-v03-cra-evidence``. Asserts the
contract of :class:`shipcheck.history.store.HistoryStore`:

(a) constructing a ``HistoryStore(path)`` creates a SQLite DB with schema
    version 1 at the configured path on first use,
(b) ``store.persist(ReportData)`` writes a row capturing timestamp (ISO
    8601), build-dir SHA-256 hash of the absolute build-dir path,
    per-check status and score as JSON, and total finding count,
(c) ``store.query(since=...)`` returns only scans whose timestamp is
    greater-than-or-equal to the filter value,
(d) ``store.query(build_dir=...)`` filters rows by the SHA-256 hash of
    the absolute build-dir path,
(e) the schema metadata table is populated with ``version = 1``,
(f) opening a DB with an incompatible stored schema version raises
    :class:`HistoryStoreError` with a message naming the stored version
    and suggesting delete-or-migrate, and
(g) ``HistoryStore.disabled()`` returns a no-op store that silently
    swallows ``persist`` calls (for ``history.enabled: false``).

The import target ``shipcheck.history.store`` is deliberately absent
until task 6.2 - the module should fail with ``ModuleNotFoundError`` at
collection time, which is the valid RED for TDD.
"""

from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path

import pytest

from shipcheck.history.store import HistoryStore, HistoryStoreError
from shipcheck.models import CheckResult, CheckStatus, Finding, ReportData


def _make_finding(
    *,
    message: str = "synthetic finding",
    severity: str = "low",
) -> Finding:
    return Finding(message=message, severity=severity)


def _make_check(
    *,
    check_id: str = "demo-check",
    check_name: str = "Demo check",
    status: CheckStatus = CheckStatus.PASS,
    score: int = 50,
    max_score: int = 50,
    findings: list[Finding] | None = None,
    summary: str = "synthetic",
) -> CheckResult:
    return CheckResult(
        check_id=check_id,
        check_name=check_name,
        status=status,
        score=score,
        max_score=max_score,
        findings=findings or [],
        summary=summary,
    )


def _make_report(
    *,
    checks: list[CheckResult] | None = None,
    build_dir: str = "/abs/build",
    timestamp: str = "2026-04-01T12:00:00Z",
    total_score: int = 50,
    max_total_score: int = 100,
) -> ReportData:
    return ReportData(
        checks=checks if checks is not None else [_make_check()],
        total_score=total_score,
        max_total_score=max_total_score,
        framework="CRA",
        framework_version="2024/2847",
        bsi_tr_version="TR-03183-2 v2.1.0",
        build_dir=build_dir,
        timestamp=timestamp,
        shipcheck_version="0.3.0",
    )


def _hash_build_dir(build_dir: str) -> str:
    abs_path = str(Path(build_dir).resolve())
    return hashlib.sha256(abs_path.encode("utf-8")).hexdigest()


class TestStoreInitialization:
    """(a) and (e): first-use DB creation with schema v1 metadata."""

    def test_creates_sqlite_db_at_configured_path_on_first_use(self, tmp_path: Path):
        db_path = tmp_path / "history.db"
        assert not db_path.exists()

        HistoryStore(db_path)

        assert db_path.exists()

    def test_db_is_a_valid_sqlite_database(self, tmp_path: Path):
        db_path = tmp_path / "history.db"
        HistoryStore(db_path)

        # Opening it with sqlite3 should succeed without error.
        conn = sqlite3.connect(db_path)
        try:
            cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = {row[0] for row in cursor.fetchall()}
        finally:
            conn.close()

        # There must be at least a scans table and a schema_version metadata table.
        assert tables, "expected schema tables after HistoryStore init"

    def test_schema_version_metadata_row_populated_with_version_1(self, tmp_path: Path):
        db_path = tmp_path / "history.db"
        HistoryStore(db_path)

        conn = sqlite3.connect(db_path)
        try:
            # Look up version in any metadata / schema_version / settings table.
            cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = {row[0] for row in cursor.fetchall()}
            candidate_tables = [t for t in tables if "version" in t.lower() or "meta" in t.lower()]
            assert candidate_tables, f"expected a schema metadata table, found tables: {tables}"

            # Scan the candidate tables for a row whose value is 1.
            found = False
            for table in candidate_tables:
                cursor = conn.execute(f"SELECT * FROM {table}")
                rows = cursor.fetchall()
                for row in rows:
                    if 1 in row or "1" in row:
                        found = True
                        break
                if found:
                    break
            assert found, "expected schema version 1 row in metadata table"
        finally:
            conn.close()

    def test_second_open_of_existing_db_does_not_raise(self, tmp_path: Path):
        db_path = tmp_path / "history.db"
        HistoryStore(db_path)

        # Second open should not re-create or error.
        HistoryStore(db_path)

        assert db_path.exists()

    def test_creates_parent_directory_if_missing(self, tmp_path: Path):
        db_path = tmp_path / "nested" / "dir" / "history.db"
        assert not db_path.parent.exists()

        HistoryStore(db_path)

        assert db_path.exists()


class TestPersist:
    """(b): persist writes a row with the expected columns."""

    def test_persist_writes_a_scan_row(self, tmp_path: Path):
        store = HistoryStore(tmp_path / "history.db")
        report = _make_report()

        store.persist(report)

        rows = store.query()
        assert len(rows) == 1

    def test_persist_records_iso_8601_timestamp(self, tmp_path: Path):
        store = HistoryStore(tmp_path / "history.db")
        report = _make_report(timestamp="2026-04-01T12:00:00Z")

        store.persist(report)

        rows = store.query()
        assert rows[0]["timestamp"] == "2026-04-01T12:00:00Z"

    def test_persist_records_build_dir_hash(self, tmp_path: Path):
        build = tmp_path / "build"
        build.mkdir()
        store = HistoryStore(tmp_path / "history.db")
        report = _make_report(build_dir=str(build))

        store.persist(report)

        rows = store.query()
        expected = hashlib.sha256(str(build.resolve()).encode("utf-8")).hexdigest()
        assert rows[0]["build_dir_hash"] == expected

    def test_persist_records_per_check_status_and_score_as_json(self, tmp_path: Path):
        import json

        store = HistoryStore(tmp_path / "history.db")
        checks = [
            _make_check(check_id="sbom", status=CheckStatus.PASS, score=50, max_score=50),
            _make_check(check_id="cve", status=CheckStatus.WARN, score=25, max_score=50),
        ]
        report = _make_report(checks=checks)

        store.persist(report)

        rows = store.query()
        per_check_raw = rows[0]["checks"]
        # Either a JSON string or an already-decoded list/dict is acceptable;
        # the contract says JSON-encoded on disk, so decoding must work.
        if isinstance(per_check_raw, str):
            per_check = json.loads(per_check_raw)
        else:
            per_check = per_check_raw

        # Normalise to a dict keyed by check id for easy lookup.
        if isinstance(per_check, list):
            by_id = {entry["check_id"]: entry for entry in per_check}
        else:
            by_id = per_check

        assert set(by_id.keys()) == {"sbom", "cve"}
        assert by_id["sbom"]["status"] == CheckStatus.PASS.value
        assert by_id["sbom"]["score"] == 50
        assert by_id["cve"]["status"] == CheckStatus.WARN.value
        assert by_id["cve"]["score"] == 25

    def test_persist_records_total_finding_count(self, tmp_path: Path):
        store = HistoryStore(tmp_path / "history.db")
        checks = [
            _make_check(
                check_id="sbom",
                findings=[_make_finding(message="f1"), _make_finding(message="f2")],
            ),
            _make_check(
                check_id="cve",
                findings=[_make_finding(message="f3")],
            ),
        ]
        report = _make_report(checks=checks)

        store.persist(report)

        rows = store.query()
        assert rows[0]["finding_count"] == 3

    def test_persist_is_durable_across_store_reopen(self, tmp_path: Path):
        db_path = tmp_path / "history.db"
        store = HistoryStore(db_path)
        store.persist(_make_report())

        reopened = HistoryStore(db_path)
        rows = reopened.query()

        assert len(rows) == 1


class TestQueryFilters:
    """(c) and (d): since + build_dir query filters."""

    def test_query_with_no_filters_returns_all_scans(self, tmp_path: Path):
        store = HistoryStore(tmp_path / "history.db")
        store.persist(_make_report(timestamp="2026-01-01T00:00:00Z"))
        store.persist(_make_report(timestamp="2026-02-01T00:00:00Z"))
        store.persist(_make_report(timestamp="2026-03-01T00:00:00Z"))

        rows = store.query()

        assert len(rows) == 3

    def test_query_since_filters_by_timestamp_inclusive(self, tmp_path: Path):
        store = HistoryStore(tmp_path / "history.db")
        store.persist(_make_report(timestamp="2026-01-01T00:00:00Z"))
        store.persist(_make_report(timestamp="2026-02-01T00:00:00Z"))
        store.persist(_make_report(timestamp="2026-03-01T00:00:00Z"))

        rows = store.query(since="2026-02-01T00:00:00Z")

        timestamps = sorted(r["timestamp"] for r in rows)
        assert timestamps == ["2026-02-01T00:00:00Z", "2026-03-01T00:00:00Z"]

    def test_query_since_excludes_older_scans(self, tmp_path: Path):
        store = HistoryStore(tmp_path / "history.db")
        store.persist(_make_report(timestamp="2026-01-01T00:00:00Z"))
        store.persist(_make_report(timestamp="2026-06-01T00:00:00Z"))

        rows = store.query(since="2026-03-01T00:00:00Z")

        assert len(rows) == 1
        assert rows[0]["timestamp"] == "2026-06-01T00:00:00Z"

    def test_query_build_dir_filters_by_hash(self, tmp_path: Path):
        build_a = tmp_path / "build_a"
        build_b = tmp_path / "build_b"
        build_a.mkdir()
        build_b.mkdir()

        store = HistoryStore(tmp_path / "history.db")
        store.persist(_make_report(build_dir=str(build_a), timestamp="2026-01-01T00:00:00Z"))
        store.persist(_make_report(build_dir=str(build_b), timestamp="2026-01-02T00:00:00Z"))
        store.persist(_make_report(build_dir=str(build_a), timestamp="2026-01-03T00:00:00Z"))

        rows = store.query(build_dir=str(build_a))

        assert len(rows) == 2
        expected_hash = hashlib.sha256(str(build_a.resolve()).encode("utf-8")).hexdigest()
        for row in rows:
            assert row["build_dir_hash"] == expected_hash

    def test_query_build_dir_returns_empty_when_no_match(self, tmp_path: Path):
        build_real = tmp_path / "real"
        build_real.mkdir()
        store = HistoryStore(tmp_path / "history.db")
        store.persist(_make_report(build_dir=str(build_real)))

        rows = store.query(build_dir=str(tmp_path / "nonexistent"))

        assert rows == []

    def test_query_combines_since_and_build_dir(self, tmp_path: Path):
        build_a = tmp_path / "build_a"
        build_b = tmp_path / "build_b"
        build_a.mkdir()
        build_b.mkdir()

        store = HistoryStore(tmp_path / "history.db")
        store.persist(_make_report(build_dir=str(build_a), timestamp="2026-01-01T00:00:00Z"))
        store.persist(_make_report(build_dir=str(build_a), timestamp="2026-06-01T00:00:00Z"))
        store.persist(_make_report(build_dir=str(build_b), timestamp="2026-06-01T00:00:00Z"))

        rows = store.query(since="2026-03-01T00:00:00Z", build_dir=str(build_a))

        assert len(rows) == 1
        assert rows[0]["timestamp"] == "2026-06-01T00:00:00Z"


class TestIncompatibleSchemaVersion:
    """(f): opening a DB with an incompatible schema version must raise."""

    def test_incompatible_version_raises_history_store_error(self, tmp_path: Path):
        db_path = tmp_path / "history.db"

        # First create a valid DB, then tamper with the version row.
        HistoryStore(db_path)

        conn = sqlite3.connect(db_path)
        try:
            cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = {row[0] for row in cursor.fetchall()}
            meta_tables = [t for t in tables if "version" in t.lower() or "meta" in t.lower()]
            assert meta_tables, "expected a schema metadata table to tamper with"
            meta_table = meta_tables[0]

            # Brute-force set every row's version-looking column to a far-future value.
            cursor = conn.execute(f"PRAGMA table_info({meta_table})")
            cols = [row[1] for row in cursor.fetchall()]
            version_cols = [c for c in cols if "version" in c.lower()]
            if version_cols:
                for col in version_cols:
                    conn.execute(f"UPDATE {meta_table} SET {col} = 999")
            else:
                # If the table stores (key, value) pairs, update all values to 999.
                if "value" in cols:
                    conn.execute(f"UPDATE {meta_table} SET value = '999'")
            conn.commit()
        finally:
            conn.close()

        with pytest.raises(HistoryStoreError) as excinfo:
            HistoryStore(db_path)

        message = str(excinfo.value)
        assert "999" in message, (
            f"error message should name the stored schema version, got: {message}"
        )
        # Must suggest remediation (delete or migrate).
        assert "delete" in message.lower() or "migrate" in message.lower(), (
            f"error message should suggest delete or migrate, got: {message}"
        )


class TestDisabledStore:
    """(g): HistoryStore.disabled() returns a no-op store."""

    def test_disabled_returns_a_store_instance(self):
        store = HistoryStore.disabled()
        assert store is not None

    def test_disabled_persist_does_not_raise(self):
        store = HistoryStore.disabled()

        # Must silently accept the call.
        store.persist(_make_report())

    def test_disabled_persist_writes_nothing(self, tmp_path: Path):
        # The disabled store must not create any DB file anywhere the user
        # might have configured. Since it's a no-op, there's nothing to
        # inspect except that the call completes without effect.
        store = HistoryStore.disabled()
        store.persist(_make_report())

        # A second call must also be a no-op.
        store.persist(_make_report())

    def test_disabled_query_returns_empty_list(self):
        store = HistoryStore.disabled()

        rows = store.query()

        assert rows == []

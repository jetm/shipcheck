"""SQLite schema definitions for the shipcheck scan history store.

The schema is intentionally small and append-only: one ``meta`` table for
key/value metadata (currently just the schema version) and one ``scans``
table holding one row per ``shipcheck check`` invocation.

Task 6.2 of devspec change ``shipcheck-v03-cra-evidence``. The DDL lives
in this module so the store and any future migration tool share the same
canonical schema.

Notes on column names:

* ``build_dir_hash`` is the SHA-256 of the absolute build-dir path. It is
  indexed so ``query(build_dir=...)`` filters via equality on the hash.
* ``build_dir`` retains the original path string for human-readable
  dossier rendering (task 6.4).
* ``checks`` holds a JSON-encoded list of ``{check_id, status, score,
  max_score, finding_count}`` entries - one per :class:`CheckResult`.
* ``total_score`` / ``max_total_score`` mirror
  :attr:`ReportData.total_score` and :attr:`ReportData.max_total_score`
  so dossier trend lines can be rendered without re-parsing the JSON
  blob.
"""

from __future__ import annotations

SCHEMA_VERSION = 1
"""Current on-disk schema version. Bump only via a migration."""


META_TABLE_DDL = """
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT
);
"""


SCANS_TABLE_DDL = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    build_dir TEXT NOT NULL,
    build_dir_hash TEXT NOT NULL,
    checks TEXT NOT NULL,
    finding_count INTEGER NOT NULL,
    total_score INTEGER NOT NULL,
    max_total_score INTEGER NOT NULL
);
"""


SCANS_INDEX_TIMESTAMP_DDL = "CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(timestamp);"


SCANS_INDEX_BUILD_DIR_HASH_DDL = (
    "CREATE INDEX IF NOT EXISTS idx_scans_build_dir_hash ON scans(build_dir_hash);"
)


SCHEMA_DDL = "\n".join(
    [
        META_TABLE_DDL,
        SCANS_TABLE_DDL,
        SCANS_INDEX_TIMESTAMP_DDL,
        SCANS_INDEX_BUILD_DIR_HASH_DDL,
    ]
)
"""Combined DDL applied on first-use to initialise the database."""

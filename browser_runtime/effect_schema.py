"""Exact admission for the local effect journal, never schema repair."""

import sqlite3
from pathlib import Path

# SQLite application_id: ASCII RBEJ (Runspindle Browser Effect Journal).
APPLICATION_ID = 0x5242454A
SCHEMA_VERSION = 1
MAX_OPERATIONS = 1024
MAX_BINDING_BYTES = 16384
MAX_ORIGIN_BYTES = 2048
# Preserve the original table definition, including its rowid/NULL semantics.
OPERATIONS_DDL = """CREATE TABLE IF NOT EXISTS operations (
            operation TEXT PRIMARY KEY, binding TEXT NOT NULL,
            digest TEXT NOT NULL, outcome TEXT NOT NULL,
            evidence TEXT, CHECK(outcome IN ('unknown','confirmed','rejected'))
        )"""
Inventory = list[tuple[str, str, str, str | None]]


class SchemaRejected(ValueError):
    """Unknown, unsupported or damaged state must not be initialized/adopted."""


def _inventory(db: sqlite3.Connection) -> Inventory:
    # Bound row visits before sorting or examining any schema text.
    if (
        db.execute(
            "SELECT count(*) FROM (SELECT 1 FROM sqlite_master LIMIT 17)"
        ).fetchone()[0]
        > 16
    ):
        raise SchemaRejected("journal schema capacity")
    # Reject oversized schema text before returning it to Python. No repair.
    if (
        db.execute(
            "SELECT 1 FROM sqlite_master WHERE length(CAST(name AS BLOB))>128 OR length(CAST(tbl_name AS BLOB))>128 OR length(CAST(sql AS BLOB))>16384 LIMIT 1"
        ).fetchone()
        is not None
    ):
        raise SchemaRejected("journal schema bounds")
    rows = db.execute(
        "SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name LIMIT 17"
    ).fetchall()
    if len(rows) > 16:
        raise SchemaRejected("journal schema capacity")
    return rows


def retained_count(db: sqlite3.Connection) -> int:
    # LIMIT bounds returned/count-work rows even in an externally inflated file.
    return int(
        db.execute(
            "SELECT count(*) FROM (SELECT 1 FROM operations LIMIT ?)",
            (MAX_OPERATIONS + 1,),
        ).fetchone()[0]
    )


def validate_retained(db: sqlite3.Connection) -> None:
    """SQL-only bounds before any retained text/blob is materialized in Python."""
    if retained_count(db) > MAX_OPERATIONS:
        raise SchemaRejected("journal row capacity")
    if (
        db.execute(
            """SELECT 1 FROM operations WHERE
        (operation IS NOT NULL AND (typeof(operation)!='text' OR length(CAST(operation AS BLOB)) NOT BETWEEN 1 AND 128)) OR
        typeof(binding)!='text' OR length(CAST(binding AS BLOB)) NOT BETWEEN 1 AND ? OR
        typeof(digest)!='text' OR length(CAST(digest AS BLOB))!=64 OR
        typeof(outcome)!='text' OR length(CAST(outcome AS BLOB)) NOT BETWEEN 1 AND 9 OR
        (evidence IS NOT NULL AND (typeof(evidence)!='text' OR length(CAST(evidence AS BLOB))!=64))
        LIMIT 1""",
            (MAX_BINDING_BYTES,),
        ).fetchone()
        is not None
    ):
        raise SchemaRejected("journal retained bounds")


def _inspect(db: sqlite3.Connection, expected: Inventory) -> bool:
    """Read within the caller's transaction; return whether identity is absent."""
    version = db.execute("PRAGMA user_version").fetchone()[0]
    application = db.execute("PRAGMA application_id").fetchone()[0]
    found = _inventory(db)
    if (version, application) == (SCHEMA_VERSION, APPLICATION_ID) and found == expected:
        adopt = False
    elif (version, application) == (0, 0) and (not found or found == expected):
        adopt = True
    else:
        raise SchemaRejected("journal schema rejected")
    if found:
        validate_retained(db)
    if db.execute("PRAGMA quick_check(1)").fetchmany(2) != [("ok",)]:
        raise SchemaRejected("journal integrity rejected")
    return adopt


def _close_failed(db: sqlite3.Connection, failure: BaseException) -> None:
    """Do not let an ordinary close error hide an in-flight cancellation.

    Journal's public constructor sanitizes both failures outside their handlers.
    A close is attempted once; an uncertain close is never blindly retried.
    """
    try:
        db.close()
    except BaseException:
        if not isinstance(failure, Exception):
            raise failure
        raise


def open_journal(path: str | Path) -> sqlite3.Connection:
    """Preflight existing files read-only, then recheck under the writer lock.

    Only an empty unclaimed store or the exact original unversioned schema can
    acquire this identity. No migration, salvage or implicit table repair exists.
    WAL and FULL retain the existing journal's durability/locking configuration.
    """
    model = sqlite3.connect(":memory:")
    try:
        model.execute(OPERATIONS_DDL)
        expected = _inventory(model)
    except BaseException as error:
        _close_failed(model, error)
        raise
    else:
        model.close()
    file = Path(path)
    if file.exists():
        probe = sqlite3.connect(
            file.absolute().as_uri() + "?mode=ro",
            uri=True,
            isolation_level=None,
            timeout=2,
        )
        try:
            probe.execute("BEGIN")
            _inspect(probe, expected)
        except BaseException as error:
            _close_failed(probe, error)
            raise
        else:
            probe.close()
    db = sqlite3.connect(path, isolation_level=None, timeout=2)
    try:
        # Connection-local setting, not a persistent journal-mode change.
        db.execute("PRAGMA synchronous=FULL")
        db.execute("BEGIN IMMEDIATE")
        if _inspect(db, expected):
            if not _inventory(db):
                db.execute(OPERATIONS_DDL)
            db.execute(f"PRAGMA application_id={APPLICATION_ID}")
            db.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
        db.execute("COMMIT")
        # SQLite cannot enter WAL inside the admission transaction. This is only
        # reached after admission; other writers must use the same journal API.
        db.execute("PRAGMA journal_mode=WAL")
        return db
    except BaseException as error:
        # close() rolls back an uncommitted admission and releases all locks.
        _close_failed(db, error)
        raise

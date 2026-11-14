"""Exact admission for the local effect journal, never schema repair."""

import sqlite3
from pathlib import Path

# SQLite application_id: ASCII RBEJ (Runspindle Browser Effect Journal).
APPLICATION_ID = 0x5242454A
SCHEMA_VERSION = 1
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
    return db.execute(
        "SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name"
    ).fetchall()


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
    if db.execute("PRAGMA quick_check").fetchall() != [("ok",)]:
        raise SchemaRejected("journal integrity rejected")
    return adopt


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
    finally:
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
        finally:
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
    except BaseException:
        # close() rolls back an uncommitted admission and releases all locks.
        db.close()
        raise

"""Private local SQLite checkpoint storage; no migration or salvage path."""

import os
import sqlite3
import stat
from pathlib import Path

APPLICATION_ID = 0x52425053  # RBPS
VERSION = 1
FILENAME = "profiles.sqlite3"
DDL = (
    "CREATE TABLE metadata (singleton INTEGER PRIMARY KEY CHECK(singleton=1), "
    "store_id TEXT NOT NULL)",
    "CREATE TABLE profiles (identity TEXT PRIMARY KEY NOT NULL, scope TEXT NOT NULL, "
    "owner TEXT NOT NULL, epoch INTEGER NOT NULL, forgotten INTEGER NOT NULL "
    "CHECK(forgotten IN (0,1)))",
    "CREATE TABLE key_versions (version TEXT PRIMARY KEY NOT NULL, "
    "fingerprint BLOB NOT NULL CHECK(length(fingerprint)=32))",
    "CREATE TABLE nonces (fingerprint BLOB NOT NULL, nonce BLOB NOT NULL "
    "CHECK(length(nonce)=12), PRIMARY KEY(fingerprint,nonce)) WITHOUT ROWID",
    "CREATE TABLE checkpoint_refs (reference TEXT PRIMARY KEY NOT NULL)",
    "CREATE TABLE checkpoints (reference TEXT PRIMARY KEY NOT NULL, "
    "profile TEXT NOT NULL, version TEXT NOT NULL, nonce BLOB NOT NULL "
    "CHECK(length(nonce)=12), ciphertext BLOB NOT NULL "
    "CHECK(length(ciphertext) BETWEEN 17 AND 16777232))",
    "CREATE TABLE restores (operation TEXT PRIMARY KEY NOT NULL, "
    "binding TEXT NOT NULL, result TEXT NOT NULL CHECK(result IN ('unknown','delivered')))",
)
Inventory = list[tuple[str, str, str, str | None]]


def require(condition: bool) -> None:
    if not condition:
        raise ValueError("profile store rejected")


def inventory(db: sqlite3.Connection) -> Inventory:
    return db.execute(
        "SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name"
    ).fetchall()


def expected_inventory() -> Inventory:
    db = sqlite3.connect(":memory:")
    try:
        for ddl in DDL:
            db.execute(ddl)
        return inventory(db)
    finally:
        db.close()


def inspect(db: sqlite3.Connection, expected: Inventory) -> bool:
    identity = (
        db.execute("PRAGMA application_id").fetchone()[0],
        db.execute("PRAGMA user_version").fetchone()[0],
    )
    found = inventory(db)
    empty = identity == (0, 0) and not found
    require(empty or (identity == (APPLICATION_ID, VERSION) and found == expected))
    require(db.execute("PRAGMA quick_check").fetchall() == [("ok",)])
    # This store never adopts WAL, attached databases, foreign schemas or triggers.
    require(db.execute("PRAGMA journal_mode").fetchone()[0] == "delete")
    if not empty:
        rows = db.execute("SELECT singleton,store_id FROM metadata").fetchall()
        require(len(rows) == 1 and rows[0][0] == 1)
        token(rows[0][1], hexadecimal=True)
    return empty


def token(value: str, *, hexadecimal: bool = False) -> None:
    import re

    pattern = r"[0-9a-f]{64}" if hexadecimal else r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}"
    require(type(value) is str and re.fullmatch(pattern, value) is not None)


class Location:
    """Fixed filenames in a caller-provisioned 0700 directory, local POSIX only.

    No path is accepted from a ticket/profile. Same-UID hostile filesystem mutation
    is not an isolation boundary. The directory must have a single lifecycle owner.
    """

    def __init__(self, directory: str | Path) -> None:
        raw = str(directory)
        require(
            os.name == "posix" and os.path.isabs(raw) and ".." not in raw.split("/")
        )
        self.root = Path(raw)
        self.path = self.root / FILENAME
        self._directory_identity: tuple[int, int] | None = None
        self._file_identity: tuple[int, int] | None = None
        self.check()
        try:
            fd = os.open(
                self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600
            )
        except FileExistsError:
            pass
        else:
            os.close(fd)
        self.check()

    def check(self) -> None:
        current = Path(self.root.anchor)
        for part in self.root.parts[1:]:
            current /= part
            require(stat.S_ISDIR(current.lstat().st_mode))  # Reject symlink components.
        info = self.root.lstat()
        require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700)
        identity = (info.st_dev, info.st_ino)
        require(self._directory_identity in (None, identity))
        self._directory_identity = identity
        for entry in self.root.iterdir():
            require(entry.name in (FILENAME, FILENAME + "-journal"))
            info = entry.lstat()
            require(
                stat.S_ISREG(info.st_mode)
                and info.st_uid == os.getuid()
                and info.st_nlink == 1
                and stat.S_IMODE(info.st_mode) == 0o600
            )
            if entry.name == FILENAME:
                identity = (info.st_dev, info.st_ino)
                require(self._file_identity in (None, identity))
                self._file_identity = identity
        require(self._file_identity is None or self.path.exists())


def open_store(location: Location) -> sqlite3.Connection:
    expected = expected_inventory()
    # SQLite may recover its own hot rollback journal here. Admission follows
    # recovery under the writer transaction; unknown schemas are never repaired.
    db = sqlite3.connect(location.path, isolation_level=None, timeout=0.2)
    try:
        db.execute("PRAGMA synchronous=EXTRA")
        db.execute("PRAGMA secure_delete=ON")
        db.execute("PRAGMA temp_store=MEMORY")
        db.execute("PRAGMA trusted_schema=OFF")
        require(db.execute("PRAGMA synchronous").fetchone()[0] == 3)
        require(db.execute("PRAGMA secure_delete").fetchone()[0] == 1)
        require(db.execute("PRAGMA temp_store").fetchone()[0] == 2)
        require(db.execute("PRAGMA trusted_schema").fetchone()[0] == 0)
        db.execute("BEGIN IMMEDIATE")
        if inspect(db, expected):
            for ddl in DDL:
                db.execute(ddl)
            db.execute("INSERT INTO metadata VALUES (1,?)", (os.urandom(32).hex(),))
            db.execute(f"PRAGMA application_id={APPLICATION_ID}")
            db.execute(f"PRAGMA user_version={VERSION}")
        db.execute("COMMIT")
        location.check()
        return db
    except BaseException:
        db.close()
        raise

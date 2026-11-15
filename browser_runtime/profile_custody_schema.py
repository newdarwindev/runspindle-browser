"""Pre-provisioned local custody metadata; no enrollment, keys or schema repair."""

import os
import sqlite3
import stat
from pathlib import Path

from browser_runtime.profile_schema import inventory, require

GATE = "custody.sqlite3"
LEASE = "lease.sqlite3"
GATE_ID = 0x52424347
LEASE_ID = 0x5242434C
GATE_DDL = (
    "CREATE TABLE registry (key_id TEXT PRIMARY KEY NOT NULL, config TEXT NOT NULL, disabled INTEGER NOT NULL CHECK(disabled IN (0,1)))",
    "CREATE TABLE attempts (attempt TEXT PRIMARY KEY NOT NULL, key_id TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN ('pending','issued','released','abandoned')))",
)
LEASE_DDL = ("CREATE TABLE fence (singleton INTEGER PRIMARY KEY CHECK(singleton=1))",)


class Location:
    def __init__(self, directory: str | Path) -> None:
        raw = str(directory)
        require(
            os.name == "posix" and os.path.isabs(raw) and ".." not in raw.split("/")
        )
        self.root = Path(raw)
        self.identities: dict[str, tuple[int, int]] = {}
        self.check()

    def check(self) -> None:
        current = Path(self.root.anchor)
        for part in self.root.parts[1:]:
            current /= part
            require(stat.S_ISDIR(current.lstat().st_mode))
        info = self.root.lstat()
        require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700)
        identity = (info.st_dev, info.st_ino)
        require(self.identities.get(".", identity) == identity)
        self.identities["."] = identity
        found = set()
        for entry in self.root.iterdir():
            require(entry.name in (GATE, LEASE, GATE + "-journal", LEASE + "-journal"))
            info = entry.lstat()
            require(
                stat.S_ISREG(info.st_mode)
                and info.st_uid == os.getuid()
                and stat.S_IMODE(info.st_mode) == 0o600
                and info.st_nlink == 1
            )
            if entry.name in (GATE, LEASE):
                identity = (info.st_dev, info.st_ino)
                require(self.identities.get(entry.name, identity) == identity)
                self.identities[entry.name] = identity
                found.add(entry.name)
        require(found == {GATE, LEASE})

    def connect(self, name: str) -> sqlite3.Connection:
        require(name in (GATE, LEASE))
        self.check()
        db = sqlite3.connect(
            (self.root / name).as_uri() + "?mode=rw",
            uri=True,
            isolation_level=None,
            timeout=0.2,
        )
        try:
            db.execute("PRAGMA synchronous=EXTRA")
            db.execute("PRAGMA secure_delete=ON")
            db.execute("PRAGMA temp_store=MEMORY")
            db.execute("PRAGMA trusted_schema=OFF")
            for setting, value in (
                ("synchronous", 3),
                ("secure_delete", 1),
                ("temp_store", 2),
                ("trusted_schema", 0),
            ):
                require(db.execute("PRAGMA " + setting).fetchone()[0] == value)
            require(db.execute("PRAGMA journal_mode").fetchone()[0] == "delete")
            return db
        except BaseException:
            db.close()
            raise

    def inspect(self, db: sqlite3.Connection, name: str) -> None:
        self.check()
        expected = sqlite3.connect(":memory:")
        try:
            for ddl in GATE_DDL if name == GATE else LEASE_DDL:
                expected.execute(ddl)
            require(inventory(db) == inventory(expected))
        finally:
            expected.close()
        require(
            db.execute("PRAGMA application_id").fetchone()[0]
            == (GATE_ID if name == GATE else LEASE_ID)
        )
        require(db.execute("PRAGMA user_version").fetchone()[0] == 1)
        require(db.execute("PRAGMA quick_check").fetchall() == [("ok",)])
        if name == LEASE:
            require(db.execute("SELECT * FROM fence").fetchall() == [(1,)])

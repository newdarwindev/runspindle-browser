"""Real SQLite admission/rejection evidence, never live browser/provider access."""

import hashlib
import importlib.util
import json
import os
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from dataclasses import replace
from pathlib import Path
from typing import Any
from unittest.mock import patch

from browser_runtime import effects
from browser_runtime.effects import Binding, Denied, Journal, Readback
from browser_testing.effect_site import Site

ROOT = Path(__file__).resolve().parents[1]
# Frozen original DDL, deliberately independent of the implementation constant.
LEGACY_DDL = """CREATE TABLE IF NOT EXISTS operations (
            operation TEXT PRIMARY KEY, binding TEXT NOT NULL,
            digest TEXT NOT NULL, outcome TEXT NOT NULL,
            evidence TEXT, CHECK(outcome IN ('unknown','confirmed','rejected'))
        )"""
BINDING = Binding(
    "principal",
    "account",
    "browser",
    "tab",
    "intent",
    1,
    "operation",
    7,
    "https://site.example",
)
PAYLOAD = b"synthetic submission"
DIGEST = hashlib.sha256(PAYLOAD).hexdigest()
APPLICATION_ID = 0x5242454A
SCHEMA_VERSION = 1


def inventory(db: sqlite3.Connection) -> list[tuple[Any, ...]]:
    return db.execute(
        "SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name"
    ).fetchall()


def identity(db: sqlite3.Connection) -> tuple[int, int]:
    return (
        db.execute("PRAGMA application_id").fetchone()[0],
        db.execute("PRAGMA user_version").fetchone()[0],
    )


class EffectSchemaTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.path = self.root / "journal.sqlite"
        network = patch.object(
            socket.socket, "connect", side_effect=AssertionError("network forbidden")
        )
        network.start()
        self.addCleanup(network.stop)

    def create(self, ddl: str = LEGACY_DDL, version: int = 0, family: int = 0) -> None:
        db = sqlite3.connect(self.path)
        try:
            db.executescript(ddl)
            db.execute(f"PRAGMA user_version={version}")
            db.execute(f"PRAGMA application_id={family}")
            db.commit()
        finally:
            db.close()

    def snapshot(self) -> dict[str, bytes]:
        return {p.name: p.read_bytes() for p in self.root.iterdir() if p.is_file()}

    def assert_refused(self) -> None:
        before = self.snapshot()
        callbacks: list[str] = []

        def approve(*_: object) -> bool:
            callbacks.append("approve")
            return True

        with self.assertRaises(Denied) as caught:
            journal = Journal(
                self.path,
                approve,
                lambda *_: callbacks.append("submit"),
                lambda b, d: Readback(b, d, "confirmed", "a" * 64),
            )
            # If admission regresses, expose the callback opportunity too.
            try:
                journal.dispatch(BINDING, PAYLOAD)
            finally:
                journal.close()
        self.assertIn(
            str(caught.exception), ("journal schema rejected", "journal unavailable")
        )
        self.assertEqual(callbacks, [])
        self.assertEqual(self.snapshot(), before)

    def test_future_version_is_not_repaired_or_switched_to_wal(self) -> None:
        self.create("CREATE TABLE future_only (value TEXT);", version=999)
        self.assert_refused()
        db = sqlite3.connect(self.path)
        try:
            self.assertEqual(identity(db), (0, 999))
            self.assertEqual(db.execute("PRAGMA journal_mode").fetchone(), ("delete",))
            self.assertEqual([row[1] for row in inventory(db)], ["future_only"])
        finally:
            db.close()

    def test_version_and_family_pairs_fail_closed(self) -> None:
        for version, family in (
            (-1, 0),
            (999, APPLICATION_ID),
            (1, 0),
            (0, APPLICATION_ID),
            (0, 123),
            (1, 123),
            (2, APPLICATION_ID),
        ):
            with self.subTest(version=version, family=family):
                self.path = self.root / f"journal-{version}-{family}.sqlite"
                self.create(version=version, family=family)
                self.assert_refused()

    def test_claimed_but_empty_store_cannot_be_reinitialized(self) -> None:
        self.create("", version=SCHEMA_VERSION, family=APPLICATION_ID)
        self.assert_refused()

    def test_new_and_existing_empty_stores_get_persistent_identity(self) -> None:
        for name, materialize in (("absent.sqlite", False), ("empty.sqlite", True)):
            with self.subTest(name=name):
                self.path = self.root / name
                if materialize:
                    self.create("")
                journal = Journal(self.path)
                try:
                    self.assertEqual(
                        identity(journal.db), (APPLICATION_ID, SCHEMA_VERSION)
                    )
                    self.assertEqual(
                        journal.db.execute("PRAGMA journal_mode").fetchone(), ("wal",)
                    )
                    self.assertEqual(
                        journal.db.execute("PRAGMA synchronous").fetchone(), (2,)
                    )
                finally:
                    journal.close()
                reopened = Journal(self.path)
                reopened.close()

    def test_filename_uri_metacharacters_are_literal(self) -> None:
        self.path = self.root / "synthetic?#% journal.sqlite"
        self.create()
        journal = Journal(self.path)
        journal.close()
        self.assertTrue(self.path.exists())
        self.assertEqual(len(list(self.root.iterdir())), 1)

    def test_exact_legacy_adoption_preserves_rows_schema_and_unknown_fence(
        self,
    ) -> None:
        self.create()
        db = sqlite3.connect(self.path)
        try:
            for index, outcome in enumerate(("unknown", "confirmed", "rejected")):
                binding = replace(BINDING, operation=f"operation-{index}")
                db.execute(
                    "INSERT INTO operations VALUES (?,?,?,?,?)",
                    (
                        binding.operation,
                        binding.encoded(),
                        DIGEST,
                        outcome,
                        None if outcome == "unknown" else "a" * 64,
                    ),
                )
            # The legacy non-INTEGER PRIMARY KEY permits NULL. Do not silently
            # tighten old DDL or rebuild rowids while assigning the identity.
            db.execute(
                "INSERT INTO operations VALUES (NULL,?,?,'unknown',NULL)",
                (BINDING.encoded(), DIGEST),
            )
            db.commit()
            rows = db.execute(
                "SELECT rowid,* FROM operations ORDER BY rowid"
            ).fetchall()
            schema = inventory(db)
        finally:
            db.close()
        submitted: list[bytes] = []
        journal = Journal(self.path, lambda *_: True, lambda _, p: submitted.append(p))
        try:
            self.assertEqual(identity(journal.db), (APPLICATION_ID, SCHEMA_VERSION))
            self.assertEqual(inventory(journal.db), schema)
            self.assertEqual(
                journal.db.execute(
                    "SELECT rowid,* FROM operations ORDER BY rowid"
                ).fetchall(),
                rows,
            )
            for index, outcome in enumerate(("unknown", "confirmed", "rejected")):
                self.assertEqual(
                    journal.dispatch(
                        replace(BINDING, operation=f"operation-{index}"), PAYLOAD
                    ),
                    outcome,
                )
            self.assertEqual(submitted, [])
        finally:
            journal.close()
        reopened = Journal(self.path)
        try:
            self.assertEqual(
                reopened.db.execute(
                    "SELECT rowid,* FROM operations ORDER BY rowid"
                ).fetchall(),
                rows,
            )
        finally:
            reopened.close()

    def test_semantically_similar_legacy_schema_is_not_guessed(self) -> None:
        for label, ddl in (
            ("format", LEGACY_DDL.replace("operation TEXT", "operation  TEXT")),
            (
                "constraint",
                LEGACY_DDL.replace(
                    ", CHECK(outcome IN ('unknown','confirmed','rejected'))", ""
                ),
            ),
            (
                "nullability",
                LEGACY_DDL.replace("binding TEXT NOT NULL", "binding TEXT"),
            ),
            (
                "key",
                LEGACY_DDL.replace(
                    "operation TEXT PRIMARY KEY", "operation TEXT UNIQUE"
                ),
            ),
            (
                "default",
                LEGACY_DDL.replace("evidence TEXT", "evidence TEXT DEFAULT 'x'"),
            ),
        ):
            with self.subTest(label=label):
                self.path = self.root / f"{label}.sqlite"
                self.create(ddl)
                self.assert_refused()

    def test_extra_schema_objects_are_rejected_in_legacy_and_current_stores(
        self,
    ) -> None:
        for version, family in ((0, 0), (SCHEMA_VERSION, APPLICATION_ID)):
            for label, ddl in (
                ("table", "CREATE TABLE other(value TEXT)"),
                ("index", "CREATE INDEX extra ON operations(digest)"),
                ("view", "CREATE VIEW extra AS SELECT * FROM operations"),
                (
                    "trigger",
                    "CREATE TRIGGER extra BEFORE INSERT ON operations BEGIN SELECT 1; END",
                ),
            ):
                with self.subTest(version=version, label=label):
                    self.path = self.root / f"{version}-{label}.sqlite"
                    self.create(LEGACY_DDL + ";" + ddl, version, family)
                    self.assert_refused()

    def test_wrong_store_with_zero_identity_is_rejected(self) -> None:
        site = Site(self.path)
        self.assertEqual(site.effects(), 0)
        self.assert_refused()

    def test_wal_future_store_is_read_from_wal_without_repair(self) -> None:
        db = sqlite3.connect(self.path)
        try:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("PRAGMA wal_autocheckpoint=0")
            db.execute("CREATE TABLE future_only(value TEXT)")
            db.execute("INSERT INTO future_only VALUES ('synthetic retained row')")
            db.execute("PRAGMA user_version=999")
            db.commit()
            wal = Path(str(self.path) + "-wal")
            before = (self.path.read_bytes(), wal.read_bytes())
            with self.assertRaises(Denied):
                Journal(self.path)
            # The writer stays open so there is no last-writer checkpoint. SHM
            # bookkeeping is intentionally not claimed to be byte-preserved.
            self.assertEqual((self.path.read_bytes(), wal.read_bytes()), before)
            self.assertEqual(identity(db), (0, 999))
            self.assertEqual(
                db.execute("SELECT * FROM future_only").fetchall(),
                [("synthetic retained row",)],
            )
            self.assertEqual([row[1] for row in inventory(db)], ["future_only"])
        finally:
            db.close()

    def test_genuine_btree_corruption_truncation_and_non_sqlite_are_preserved(
        self,
    ) -> None:
        for fault in ("btree", "truncated", "not-sqlite"):
            with self.subTest(fault=fault):
                self.path = self.root / f"{fault}.sqlite"
                self.create()
                data = self.path.read_bytes()
                if fault == "btree":
                    # SQLite header is valid, but the sqlite_schema root page
                    # has an impossible page type, producing actual corruption.
                    data = data[:100] + b"\x00" + data[101:]
                elif fault == "truncated":
                    data = data[:512]
                else:
                    data = b"SYNTHETIC-NON-SQLITE-CANARY"
                self.path.write_bytes(data)
                self.assert_refused()

    def test_integrity_check_failure_is_not_adopted(self) -> None:
        self.create()
        db = sqlite3.connect(self.path)
        try:
            db.execute("PRAGMA ignore_check_constraints=ON")
            db.execute(
                "INSERT INTO operations VALUES ('bad','binding','digest','invalid',NULL)"
            )
            db.commit()
            db.execute("PRAGMA ignore_check_constraints=OFF")
            self.assertNotEqual(db.execute("PRAGMA quick_check").fetchall(), [("ok",)])
        finally:
            db.close()
        self.assert_refused()

    def test_preflight_rejects_before_opening_a_writable_file_connection(self) -> None:
        self.create("CREATE TABLE other(value TEXT)", version=999)
        connect = sqlite3.connect
        writable: list[object] = []

        def tracked(path: Any, *args: Any, **kwargs: Any) -> sqlite3.Connection:
            if str(path) != ":memory:" and not kwargs.get("uri"):
                writable.append(path)
            connection: sqlite3.Connection = connect(path, *args, **kwargs)
            return connection

        with patch.object(sqlite3, "connect", side_effect=tracked):
            self.assert_refused()
        self.assertEqual(writable, [])

    def test_locked_recheck_rejects_a_change_after_readonly_preflight(self) -> None:
        self.create()
        connect = sqlite3.connect
        changed: list[dict[str, bytes]] = []

        def raced(path: Any, *args: Any, **kwargs: Any) -> sqlite3.Connection:
            if str(path) == str(self.path) and not kwargs.get("uri"):
                other = connect(self.path)
                try:
                    other.execute("CREATE TABLE future_only(value TEXT)")
                    other.execute("PRAGMA user_version=999")
                    other.commit()
                finally:
                    other.close()
                changed.append(self.snapshot())
            connection: sqlite3.Connection = connect(path, *args, **kwargs)
            return connection

        with patch.object(sqlite3, "connect", side_effect=raced):
            with self.assertRaises(Denied):
                Journal(self.path)
        self.assertEqual(len(changed), 1)
        self.assertEqual(self.snapshot(), changed[0])
        db = connect(self.path)
        try:
            self.assertEqual(identity(db), (0, 999))
            self.assertEqual(db.execute("PRAGMA journal_mode").fetchone(), ("delete",))
        finally:
            db.close()

    def test_identity_failure_rolls_back_ddl_and_releases_connection(self) -> None:
        for legacy in (False, True):
            with self.subTest(legacy=legacy):
                self.path = self.root / f"rollback-{legacy}.sqlite"
                self.create(LEGACY_DDL if legacy else "")
                before = self.snapshot()
                connect = sqlite3.connect
                connections: list[sqlite3.Connection] = []

                class FailingIdentity(sqlite3.Connection):
                    def execute(
                        self, sql: str, *args: Any, **kwargs: Any
                    ) -> sqlite3.Cursor:
                        if sql.startswith("PRAGMA user_version="):
                            raise sqlite3.OperationalError("SYNTHETIC-STORAGE-CANARY")
                        return super().execute(sql, *args, **kwargs)

                def failing(path: Any, *args: Any, **kwargs: Any) -> sqlite3.Connection:
                    if str(path) == str(self.path) and not kwargs.get("uri"):
                        kwargs["factory"] = FailingIdentity
                        connection: sqlite3.Connection = connect(path, *args, **kwargs)
                        connections.append(connection)
                        return connection
                    unmodified: sqlite3.Connection = connect(path, *args, **kwargs)
                    return unmodified

                with patch.object(sqlite3, "connect", side_effect=failing):
                    with self.assertRaisesRegex(Denied, "^journal unavailable$"):
                        Journal(self.path)
                self.assertEqual(self.snapshot(), before)
                self.assertEqual(len(connections), 1)
                with self.assertRaises(sqlite3.ProgrammingError):
                    connections[0].execute("SELECT 1")
                journal = Journal(self.path)
                journal.close()

    def test_admission_cancellation_rolls_back_and_releases_writer(self) -> None:
        self.create("")
        before = self.snapshot()
        connect = sqlite3.connect
        connections: list[sqlite3.Connection] = []

        class CancelledIdentity(sqlite3.Connection):
            def execute(self, sql: str, *args: Any, **kwargs: Any) -> sqlite3.Cursor:
                if sql.startswith("PRAGMA user_version="):
                    raise KeyboardInterrupt("synthetic cancellation")
                return super().execute(sql, *args, **kwargs)

        def cancelled(path: Any, *args: Any, **kwargs: Any) -> sqlite3.Connection:
            if str(path) == str(self.path) and not kwargs.get("uri"):
                kwargs["factory"] = CancelledIdentity
            connection: sqlite3.Connection = connect(path, *args, **kwargs)
            connections.append(connection)
            return connection

        with patch.object(sqlite3, "connect", side_effect=cancelled):
            with self.assertRaises(KeyboardInterrupt):
                Journal(self.path)
        self.assertEqual(self.snapshot(), before)
        for connection in connections:
            with self.assertRaises(sqlite3.ProgrammingError):
                connection.execute("SELECT 1")
        Journal(self.path).close()

    def test_writer_contention_denies_without_identity_or_mode_changes(self) -> None:
        self.create()
        before = self.snapshot()
        blocker = sqlite3.connect(self.path, isolation_level=None)
        blocker.execute("BEGIN IMMEDIATE")
        try:
            with self.assertRaisesRegex(Denied, "^journal unavailable$"):
                Journal(self.path)
        finally:
            blocker.close()
        self.assertEqual(self.snapshot(), before)
        Journal(self.path).close()

    def test_current_schema_tampering_is_not_repaired_on_restart(self) -> None:
        Journal(self.path).close()
        db = sqlite3.connect(self.path)
        try:
            db.execute("PRAGMA journal_mode=DELETE")
            db.execute("DROP TABLE operations")
            db.commit()
        finally:
            db.close()
        self.assert_refused()

    def test_fresh_processes_initialize_or_adopt_and_keep_one_effect(self) -> None:
        script = """
import socket,sys,time
from pathlib import Path
from unittest.mock import patch
from browser_runtime.effects import Binding,Journal
from browser_testing.effect_site import Site
with patch.object(socket.socket,'connect',side_effect=AssertionError('network forbidden')):
    Path(sys.argv[3]).write_text('ready')
    deadline=time.monotonic()+10
    while not Path(sys.argv[4]).exists():
        if time.monotonic()>deadline: raise RuntimeError('barrier timeout')
        time.sleep(0.01)
    site=Site(sys.argv[2])
    binding=Binding('principal','account','browser','tab','intent',1,'operation',7,'https://site.example')
    journal=Journal(sys.argv[1],lambda *_:True,site.submit,site.observe)
    try: print(journal.dispatch(binding,b'synthetic submission'))
    finally: journal.close()
"""
        for state in ("fresh", "legacy_empty", "legacy_unknown"):
            with self.subTest(state=state):
                self.path = self.root / f"concurrent-{state}.sqlite"
                if state != "fresh":
                    self.create()
                if state == "legacy_unknown":
                    db = sqlite3.connect(self.path)
                    try:
                        db.execute(
                            "INSERT INTO operations VALUES (?,?,?,'unknown',NULL)",
                            (BINDING.operation, BINDING.encoded(), DIGEST),
                        )
                        db.commit()
                    finally:
                        db.close()
                site = Site(self.root / f"site-{state}.sqlite")
                barrier = self.root / f"start-{state}"
                ready = [self.root / f"ready-{state}-{i}" for i in range(3)]
                children = [
                    subprocess.Popen(
                        [
                            sys.executable,
                            *(["-O"] if sys.flags.optimize else []),
                            "-c",
                            script,
                            str(self.path),
                            str(site.path),
                            str(marker),
                            str(barrier),
                        ],
                        cwd=ROOT,
                        env=dict(os.environ, PYTHONPATH=str(ROOT)),
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                    )
                    for marker in ready
                ]
                try:
                    deadline = time.monotonic() + 10
                    while not all(marker.exists() for marker in ready):
                        if time.monotonic() > deadline:
                            self.fail("child readiness timeout")
                        time.sleep(0.01)
                    barrier.write_text("go")
                    for child in children:
                        output, error = child.communicate(timeout=15)
                        self.assertEqual(child.returncode, 0, error)
                        self.assertEqual(output.strip(), "unknown")
                finally:
                    for child in children:
                        if child.poll() is None:
                            child.kill()
                        child.communicate(timeout=5)
                self.assertEqual(site.effects(), 0 if state == "legacy_unknown" else 1)
                journal = Journal(self.path)
                try:
                    self.assertEqual(
                        identity(journal.db), (APPLICATION_ID, SCHEMA_VERSION)
                    )
                    self.assertEqual(
                        journal.db.execute(
                            "SELECT COUNT(*) FROM operations"
                        ).fetchone(),
                        (1,),
                    )
                finally:
                    journal.close()

    def test_future_store_is_refused_in_a_fresh_process(self) -> None:
        self.create("CREATE TABLE future_only(value TEXT)", version=999)
        before = self.snapshot()
        script = """
import json,sys
from browser_runtime.effects import Denied,Journal
calls=[]
try:
    journal=Journal(sys.argv[1],lambda *_:calls.append('approve'),lambda *_:calls.append('submit'))
except Denied as error:
    print(json.dumps({'denied':str(error),'calls':calls}))
else:
    journal.close()
    raise RuntimeError('future store admitted')
"""
        result = subprocess.run(
            [
                sys.executable,
                *(["-O"] if sys.flags.optimize else []),
                "-c",
                script,
                str(self.path),
            ],
            cwd=ROOT,
            env=dict(os.environ, PYTHONPATH=str(ROOT)),
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            json.loads(result.stdout),
            {"denied": "journal schema rejected", "calls": []},
        )
        self.assertEqual(self.snapshot(), before)

    def test_deliberate_schema_bypass_mutation_breaks_rejection_oracle(self) -> None:
        source = (ROOT / "browser_runtime/effect_schema.py").read_text()
        anchor = 'raise SchemaRejected("journal schema rejected")'
        self.assertEqual(source.count(anchor), 1)
        mutant = self.root / "mutant_schema.py"
        mutant.write_text(source.replace(anchor, "adopt = True"))
        spec = importlib.util.spec_from_file_location("mutant_schema", mutant)
        if spec is None or spec.loader is None:
            self.fail("mutation loader unavailable")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.create(version=999)
        with patch.object(effects, "open_journal", module.open_journal):
            with self.assertRaises(AssertionError):
                self.assert_refused()
        db = sqlite3.connect(self.path)
        try:
            self.assertEqual(identity(db), (APPLICATION_ID, SCHEMA_VERSION))
            self.assertEqual(
                db.execute("SELECT COUNT(*) FROM operations").fetchone(), (1,)
            )
        finally:
            db.close()

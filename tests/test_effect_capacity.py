"""Logical journal bounds; no filesystem quota or physical-power-loss claim."""

from __future__ import annotations

import hashlib
import json
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import closing
from dataclasses import asdict, replace
from pathlib import Path

from browser_runtime.effect_schema import MAX_OPERATIONS
from browser_runtime.effects import Binding, Denied, Journal
from browser_testing.effect_site import Site

ROOT = Path(__file__).resolve().parents[1]
BINDING = Binding("p", "a", "b", "t", "i", 1, "final", 1, "https://example.invalid")
PAYLOAD = b"capacity synthetic effect"
DIGEST = hashlib.sha256(PAYLOAD).hexdigest()


class EffectCapacity(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.db = self.root / "journal.sqlite"
        self.site = Site(self.root / "site.sqlite")
        Journal(self.db).close()

    def fill(self, count: int) -> None:
        # Independent valid retained rows, no test-only capacity override.
        rows = []
        for i in range(count):
            binding = replace(BINDING, operation=f"retained-{i}")
            rows.append((binding.operation, binding.encoded(), DIGEST))
        with closing(sqlite3.connect(self.db)) as db, db:
            db.executemany("INSERT INTO operations VALUES(?,?,?,'unknown',NULL)", rows)

    def journal(self) -> Journal:
        return Journal(
            self.db, lambda b, d: d == DIGEST, self.site.submit, self.site.observe
        )

    def test_capacity_denies_new_effect_but_preserves_duplicate_and_reconcile(
        self,
    ) -> None:
        self.assertEqual(MAX_OPERATIONS, 1024)
        self.fill(1023)
        journal = self.journal()
        try:
            self.assertEqual(journal.dispatch(BINDING, PAYLOAD), "unknown")
            self.assertEqual(journal.dispatch(BINDING, PAYLOAD), "unknown")
            self.assertEqual(journal.reconcile(BINDING, DIGEST), "confirmed")
            with self.assertRaises(Denied):
                journal.dispatch(replace(BINDING, operation="overflow"), PAYLOAD)
            self.assertEqual(self.site.effects(), 1)
        finally:
            journal.close()
        reopened = self.journal()
        try:
            self.assertEqual(reopened.dispatch(BINDING, PAYLOAD), "confirmed")
            self.assertEqual(reopened.reconcile(BINDING, DIGEST), "confirmed")
            self.assertEqual(self.site.effects(), 1)
        finally:
            reopened.close()
        with closing(sqlite3.connect(self.db)) as db, db:
            self.assertEqual(
                db.execute("SELECT count(*) FROM operations").fetchone()[0], 1024
            )

    def test_origin_bound_and_control_denial_before_authority(self) -> None:
        calls: list[bool] = []

        def approve(binding: Binding, digest: str) -> bool:
            calls.append(True)
            return True

        journal = Journal(self.db, approve, self.site.submit)
        try:
            for origin in (
                "https://" + "x" * 2048,
                "https://example.invalid\x00",
                "https://example.invalid\n",
            ):
                with self.subTest(origin_length=len(origin)), self.assertRaises(Denied):
                    journal.dispatch(replace(BINDING, origin=origin), PAYLOAD)
            self.assertEqual(calls, [])
            self.assertEqual(self.site.effects(), 0)
        finally:
            journal.close()

    def test_oversized_retained_fields_deny_before_row_materialization_and_no_repair(
        self,
    ) -> None:
        for field in ("binding", "operation", "digest", "evidence"):
            with self.subTest(field=field):
                with closing(sqlite3.connect(self.db)) as db, db:
                    db.execute("DELETE FROM operations")
                    db.execute(
                        "INSERT INTO operations VALUES(?,?,?,'unknown',NULL)",
                        (BINDING.operation, BINDING.encoded(), DIGEST),
                    )
                journal = self.journal()
                with closing(sqlite3.connect(self.db)) as db, db:
                    db.execute(f"UPDATE operations SET {field}=?", ("x" * 200000,))
                traced: list[str] = []
                journal.db.set_trace_callback(traced.append)
                try:
                    with self.assertRaises(Denied):
                        journal.dispatch(BINDING, PAYLOAD)
                    with self.assertRaises(Denied):
                        journal.reconcile(BINDING, DIGEST)
                    self.assertFalse(
                        any("SELECT binding,digest,outcome" in sql for sql in traced)
                    )
                    self.assertEqual(self.site.effects(), 0)
                finally:
                    journal.close()
                before = self.db.read_bytes()
                with self.assertRaises(Denied):
                    self.journal()
                self.assertEqual(self.db.read_bytes(), before)

    def test_schema_inventory_capacity_and_text_deny_before_materialization(
        self,
    ) -> None:
        from browser_runtime.effect_schema import SchemaRejected, _inventory

        for mode in ("rows", "text"):
            with self.subTest(mode=mode), closing(sqlite3.connect(":memory:")) as db:
                if mode == "rows":
                    for i in range(17):
                        db.execute(f"CREATE TABLE t{i}(value TEXT)")
                else:
                    db.execute(
                        "CREATE TABLE oversized(value TEXT CHECK(value != '"
                        + "x" * 20000
                        + "'))"
                    )
                traced: list[str] = []
                db.set_trace_callback(traced.append)
                with self.assertRaises(SchemaRejected):
                    _inventory(db)
                self.assertFalse(
                    any("SELECT type,name,tbl_name,sql" in sql for sql in traced)
                )
                if mode == "rows":
                    self.assertFalse(any("length(CAST" in sql for sql in traced))

    def test_over_capacity_existing_database_denies_without_repair(self) -> None:
        self.fill(1025)
        before = self.db.read_bytes()
        with self.assertRaises(Denied):
            self.journal()
        self.assertEqual(self.db.read_bytes(), before)
        self.assertEqual(self.site.effects(), 0)

    def test_fresh_process_race_only_one_last_slot_and_effect(self) -> None:
        self.fill(1023)
        code = """import json,pathlib,sys,time
from browser_runtime.effects import Binding,Journal,Denied
from browser_testing.effect_site import Site
root=pathlib.Path(sys.argv[1]);binding=Binding(**json.loads(sys.argv[2]));site=Site(root/'site.sqlite')
journal=Journal(root/'journal.sqlite',lambda b,d:True,site.submit,site.observe)
(root/(binding.operation+'.ready')).touch()
end=time.monotonic()+10
while not (root/'go').exists():
    if time.monotonic()>end: raise RuntimeError('barrier deadline')
    time.sleep(.01)
try:
    try: print(journal.dispatch(binding,b'capacity synthetic effect'))
    except Denied: print('denied')
finally: journal.close()
"""
        children = []
        try:
            for operation in ("race-a", "race-b"):
                children.append(
                    subprocess.Popen(
                        [
                            sys.executable,
                            "-B",
                            *(["-O"] if sys.flags.optimize else []),
                            "-c",
                            code,
                            str(self.root),
                            json.dumps(asdict(replace(BINDING, operation=operation))),
                        ],
                        cwd=ROOT,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                    )
                )
            deadline = time.monotonic() + 10
            while not all(
                (self.root / (op + ".ready")).exists() for op in ("race-a", "race-b")
            ):
                if time.monotonic() > deadline or any(
                    child.poll() is not None for child in children
                ):
                    self.fail("race startup failed")
                time.sleep(0.01)
            (self.root / "go").touch()
            outputs = []
            for child in children:
                out, err = child.communicate(timeout=15)
                self.assertEqual(child.returncode, 0, err)
                outputs.append(out.strip())
            self.assertEqual(sorted(outputs), ["denied", "unknown"])
            self.assertEqual(self.site.effects(), 1)
            with closing(sqlite3.connect(self.db)) as db, db:
                self.assertEqual(
                    db.execute("SELECT count(*) FROM operations").fetchone()[0], 1024
                )
        finally:
            for child in children:
                if child.poll() is None:
                    child.kill()
                child.communicate(timeout=5)

    def test_capacity_bypass_mutation_exposes_forbidden_independent_effect(
        self,
    ) -> None:
        self.fill(1024)
        baseline = self.journal()
        try:
            with self.assertRaises(Denied):
                baseline.dispatch(BINDING, PAYLOAD)
        finally:
            baseline.close()
        self.assertEqual(self.site.effects(), 0)
        mutant = self.root / "mutant"
        shutil.copytree(
            ROOT / "browser_runtime",
            mutant / "browser_runtime",
            ignore=shutil.ignore_patterns("__pycache__"),
        )
        shutil.copytree(
            ROOT / "browser_testing",
            mutant / "browser_testing",
            ignore=shutil.ignore_patterns("__pycache__"),
        )
        # One policy mutation in its defining source raises the admitted bound.
        path = mutant / "browser_runtime/effect_schema.py"
        source = path.read_text()
        self.assertEqual(source.count("MAX_OPERATIONS = 1024"), 1)
        path.write_text(
            source.replace("MAX_OPERATIONS = 1024", "MAX_OPERATIONS = 1025")
        )
        code = """import json,sys
sys.path.insert(0,sys.argv[1])
from browser_runtime.effects import Binding,Journal
from browser_testing.effect_site import Site
site=Site(sys.argv[3]);j=Journal(sys.argv[2],lambda b,d:True,site.submit,site.observe)
try: print(j.dispatch(Binding(**json.loads(sys.argv[4])),b'capacity synthetic effect'))
finally:j.close()
"""
        result = subprocess.run(
            [
                sys.executable,
                "-I",
                "-B",
                *(["-O"] if sys.flags.optimize else []),
                "-c",
                code,
                str(mutant),
                str(self.db),
                str(self.site.path),
                json.dumps(asdict(BINDING)),
            ],
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "unknown")
        self.assertEqual(self.site.effects(), 1)

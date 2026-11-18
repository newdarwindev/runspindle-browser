"""Real SQLite capacity and independent fencing observations; no live browser."""

import importlib
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from browser_runtime.control_leases import Holder, LeaseStore, Transfer
from browser_runtime.effects import Denied

_fixtures = importlib.import_module("test_control_leases")
AGENT, HUMAN = _fixtures.AGENT, _fixtures.HUMAN
ControlFixture, target = _fixtures.ControlFixture, _fixtures.target


class ControlCapacityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.f = ControlFixture(self.tmp.name)
        self.store = self.f.store()
        self.addCleanup(self.store.close)

    def seed(self, count: int) -> None:
        self.f.transition("initialize", None, AGENT, 0)
        self.store.transfer("admitted")
        db = self.store._db
        row = db.execute("SELECT * FROM leases").fetchone()
        db.executemany(
            "INSERT INTO leases VALUES (?,?,?,?,?,?)",
            [(f"other-{i}", *row[1:]) for i in range(count - 1)],
        )

    def new_browser(self) -> None:
        t = target(1, "new-operation")
        t = replace(t, binding=replace(t.binding, browser="new-browser"))
        self.f.grant = Transfer(
            t, "initialize", None, Holder("agent", "new-agent"), 0, 20.0
        )
        # Fixture observations must independently follow the selected target.
        self.f.observed = t

    def test_full_store_preserves_existing_transfers_and_denies_new_fence(self) -> None:
        self.seed(1024)
        self.f.transition("takeover", AGENT, HUMAN, 1)
        self.assertEqual(self.store.transfer("admitted"), "active")
        before = self.f.fences()
        self.new_browser()
        with self.assertRaises(Denied):
            self.store.transfer("admitted")
        self.assertEqual(self.f.fences(), before)
        self.assertEqual(
            self.store._db.execute("SELECT count(*) FROM leases").fetchone()[0], 1024
        )

    def test_oversized_retained_json_rejected_before_selected_row_materializes(
        self,
    ) -> None:
        self.seed(1)
        self.store._db.execute("UPDATE leases SET transition=?", ("x" * 32769,))
        queries: list[str] = []
        self.store._db.set_trace_callback(queries.append)
        self.f.transition("takeover", AGENT, HUMAN, 1)
        with self.assertRaises(Denied):
            self.store.transfer("admitted")
        self.assertFalse(any(q.startswith("SELECT scope,epoch") for q in queries))
        self.assertEqual(self.f.fences(), 1)
        path = Path(self.tmp.name) / "leases.sqlite"
        self.store.close()
        before = path.read_bytes()
        with self.assertRaises(Denied):
            LeaseStore(path)
        self.assertEqual(path.read_bytes(), before)

    def test_overfull_store_and_excess_schema_deny_without_repair(self) -> None:
        self.seed(1025)
        self.store.close()
        path = Path(self.tmp.name) / "leases.sqlite"
        before = path.read_bytes()
        with self.assertRaises(Denied):
            LeaseStore(path)
        self.assertEqual(path.read_bytes(), before)
        other = Path(self.tmp.name) / "overschema.sqlite"
        with sqlite3.connect(other) as db:
            for i in range(17):
                db.execute(f"CREATE TABLE t{i}(x)")
        before = other.read_bytes()
        with self.assertRaises(Denied):
            LeaseStore(other)
        self.assertEqual(other.read_bytes(), before)

    def test_capacity_mutant_produces_forbidden_independent_fence(self) -> None:
        self.seed(1024)
        self.new_browser()
        before = self.f.fences()
        with self.assertRaises(Denied):
            self.store.transfer("admitted")
        self.assertEqual(self.f.fences(), before)
        with patch("browser_runtime.control_leases.MAX_LEASES", 1025):
            self.assertEqual(self.store.transfer("admitted"), "active")
        self.assertEqual(self.f.fences(), before + 1)

    def test_fresh_process_race_for_last_slot_fences_exactly_one_holder(self) -> None:
        self.seed(1023)
        self.store.close()
        script = """
import sys,time
from dataclasses import replace
from pathlib import Path
from browser_runtime.control_leases import Holder,Transfer
from browser_runtime.effects import Denied
sys.path.insert(0, str(Path.cwd()/"tests"))
from test_control_leases import ControlFixture,target
root,name=sys.argv[1:]
f=ControlFixture(root)
t=target(1,'race-'+name)
t=replace(t,binding=replace(t.binding,browser='race-'+name))
f.observed=t
f.grant=Transfer(t,'initialize',None,Holder('agent',name),0,20.0)
s=f.store()
try:
    deadline=time.monotonic()+5
    while not (Path(root)/'start').exists():
        if time.monotonic()>deadline: raise RuntimeError('start timeout')
        time.sleep(.01)
    try: print(s.transfer('admitted'))
    except Denied: print('denied')
finally: s.close()
"""
        workers = []
        try:
            for name in ("one", "two"):
                workers.append(
                    subprocess.Popen(
                        [sys.executable, "-c", script, self.tmp.name, name],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                    )
                )
            (Path(self.tmp.name) / "start").touch()
            outputs = []
            for worker in workers:
                out, err = worker.communicate(timeout=10)
                self.assertEqual(worker.returncode, 0, err)
                outputs.append(out.strip())
            self.assertEqual(sorted(outputs), ["active", "denied"])
            self.assertEqual(self.f.fences(), 2)  # Seed plus only one fresh fence.
            with sqlite3.connect(Path(self.tmp.name) / "leases.sqlite") as db:
                self.assertEqual(
                    db.execute("SELECT count(*) FROM leases").fetchone()[0], 1024
                )
        finally:
            for worker in workers:
                if worker.poll() is None:
                    worker.kill()
                worker.communicate(timeout=5)

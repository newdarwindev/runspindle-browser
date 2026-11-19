"""Actual SQLite lease/input journals; synthetic authenticated authority/backend."""

import subprocess
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from browser_runtime.control_leases import (
    FenceReceipt,
    Holder,
    Input,
    LeaseStore,
    Transfer,
)
from browser_runtime.effects import Cancelled, Denied
from browser_runtime.guarded_effects import Grant
from test_guarded_effects import DIGEST, PAYLOAD, TARGET, Fixture

AGENT = Holder("agent", "agent-one")
HUMAN = Holder("human", "human-one")


def target(epoch, operation):
    return replace(
        TARGET, binding=replace(TARGET.binding, epoch=epoch, operation=operation)
    )


class ControlFixture(Fixture):
    def __init__(self, root):
        super().__init__(root)
        self.release = True
        self.closed_inputs = True
        self.fence_error = False
        self.fence_cancel = False
        self.after_fence = lambda: None

    def submit(self, grant, payload, guard):
        if not self.active or guard.current(grant) is not True:
            raise AssertionError("no current input fence")
        return super().submit(grant, payload, self)

    def readback(self, grant, guard):
        if not self.active or guard.current(grant) is not True:
            raise AssertionError("no current readback fence")
        return super().readback(grant, self)

    def released(self, transfer):
        return self.release

    def fence(self, transfer, guard):
        if not self.active or guard is not self:
            raise AssertionError("missing authority fence")
        with (self.root / "fence-ledger").open("ab") as stream:
            stream.write(b"fenced\n")
        self.after_fence()
        if self.fence_cancel:
            raise KeyboardInterrupt("SYNTHETIC-PRIVATE-CANCEL")
        if self.fence_error:
            raise RuntimeError("SYNTHETIC-PRIVATE-ERROR")
        return FenceReceipt(transfer, self.closed_inputs)

    def fences(self):
        path = self.root / "fence-ledger"
        return len(path.read_bytes().splitlines()) if path.exists() else 0

    def store(self):
        return LeaseStore(
            self.root / "leases.sqlite",
            authority=self,
            backend=self,
            clock=lambda: self.now,
        )

    def transition(self, action, source, destination, epoch):
        self.grant = Transfer(
            target(epoch + 1, "transfer-" + str(epoch + 1)),
            action,
            source,
            destination,
            epoch,
            20.0,
        )
        return self.grant

    def input(self, holder, epoch, operation="command"):
        self.grant = Input(
            Grant(target(epoch, operation), DIGEST, "dispatch", 20.0), holder
        )


class ControlLeaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.f = ControlFixture(self.tmp.name)
        self.store = self.f.store()
        self.addCleanup(self.store.close)
        self.journal = self.store.journal(
            Path(self.tmp.name) / "effects.sqlite", self.f
        )
        self.addCleanup(self.journal.close)

    def initialize(self):
        self.f.transition("initialize", None, AGENT, 0)
        self.assertEqual(self.store.transfer("admitted"), "active")

    def test_full_agent_human_handback_fences_previous_inputs(self) -> None:
        self.initialize()
        self.f.input(AGENT, 1, "agent-command")
        self.assertEqual(self.journal.dispatch("admitted", PAYLOAD), "unknown")
        self.f.transition("takeover", AGENT, HUMAN, 1)
        self.assertEqual(self.store.transfer("admitted"), "active")
        self.f.input(AGENT, 1, "stale-agent")
        with self.assertRaises(Denied):
            self.journal.dispatch("admitted", PAYLOAD)
        self.f.input(HUMAN, 2, "human-command")
        self.assertEqual(self.journal.dispatch("admitted", PAYLOAD), "unknown")
        self.f.transition("handback", HUMAN, AGENT, 2)
        self.assertEqual(self.store.transfer("admitted"), "active")
        self.f.input(HUMAN, 2, "stale-human")
        with self.assertRaises(Denied):
            self.journal.dispatch("admitted", PAYLOAD)
        self.f.input(AGENT, 3, "resumed-agent")
        self.assertEqual(self.journal.dispatch("admitted", PAYLOAD), "unknown")
        self.assertEqual(self.f.effects(), 3)
        self.assertEqual(self.f.fences(), 3)

    def test_forged_release_does_not_call_backend_or_grant_agent(self) -> None:
        self.initialize()
        self.f.transition("takeover", AGENT, HUMAN, 1)
        self.store.transfer("admitted")
        self.f.transition("handback", HUMAN, AGENT, 2)
        self.f.release = False
        with self.assertRaises(Denied):
            self.store.transfer("admitted")
        self.f.input(AGENT, 3)
        with self.assertRaises(Denied):
            self.journal.dispatch("admitted", PAYLOAD)
        self.assertEqual(self.f.effects(), 0)
        self.assertEqual(self.f.fences(), 2)

    def test_incomplete_viewer_closure_blocks_both_after_restart(self) -> None:
        self.initialize()
        self.f.transition("takeover", AGENT, HUMAN, 1)
        self.store.transfer("admitted")
        transfer = self.f.transition("handback", HUMAN, AGENT, 2)
        self.f.closed_inputs = False
        self.assertEqual(self.store.transfer("admitted"), "unknown")
        self.store.close()
        self.store = self.f.store()
        self.addCleanup(self.store.close)
        j = self.store.journal(Path(self.tmp.name) / "effects.sqlite", self.f)
        self.addCleanup(j.close)
        for holder, epoch in ((AGENT, 3), (HUMAN, 2)):
            self.f.input(holder, epoch)
            with self.assertRaises(Denied):
                j.dispatch("admitted", PAYLOAD)
        self.f.grant = transfer
        self.f.closed_inputs = True
        self.assertEqual(self.store.transfer("admitted"), "unknown")
        self.assertEqual(self.f.fences(), 3)  # No retry of uncertain closure.
        self.assertEqual(self.f.effects(), 0)

    def test_fence_exception_or_cancellation_leaves_durable_pending(self) -> None:
        self.initialize()
        transfer = self.f.transition("takeover", AGENT, HUMAN, 1)
        self.f.fence_cancel = True
        with self.assertRaises(Cancelled) as raised:
            self.store.transfer("admitted")
        self.assertIsNone(raised.exception.__context__)
        self.f.fence_cancel = False
        self.assertEqual(self.store.transfer("admitted"), "unknown")
        self.f.input(HUMAN, 2)
        with self.assertRaises(Denied):
            self.journal.dispatch("admitted", PAYLOAD)
        self.assertEqual(self.f.fences(), 2)
        self.assertEqual(self.f.effects(), 0)

    def test_wrong_holder_account_and_epoch_deny_before_input(self) -> None:
        self.initialize()
        for holder, epoch in ((HUMAN, 1), (AGENT, 2)):
            self.f.input(holder, epoch)
            with self.assertRaises(Denied):
                self.journal.dispatch("admitted", PAYLOAD)
        self.f.input(AGENT, 1)
        changed = replace(
            self.f.grant.effect.target,
            binding=replace(self.f.grant.effect.target.binding, account="other"),
        )
        self.f.grant = replace(
            self.f.grant, effect=replace(self.f.grant.effect, target=changed)
        )
        self.f.observed = (
            changed  # Even matching physical observations cannot rebind the row.
        )
        with self.assertRaises(Denied):
            self.journal.dispatch("admitted", PAYLOAD)
        self.assertEqual(self.f.effects(), 0)

    def test_restart_never_creates_authority_and_expired_grants_deny(self) -> None:
        self.initialize()
        self.f.input(AGENT, 1)
        self.f.allowed = False
        with self.assertRaises(Denied):
            self.journal.dispatch("admitted", PAYLOAD)
        self.f.allowed = True
        self.f.now = 20.0
        with self.assertRaises(Denied):
            self.journal.dispatch("admitted", PAYLOAD)
        self.assertEqual(self.f.effects(), 0)

    def test_pending_transfer_blocks_nested_or_competing_inputs(self) -> None:
        self.initialize()
        transfer = self.f.transition("takeover", AGENT, HUMAN, 1)

        def during_fence():
            self.f.input(AGENT, 1)
            with self.assertRaises(Denied):
                self.journal.dispatch("admitted", PAYLOAD)
            self.f.grant = transfer

        self.f.after_fence = during_fence
        self.assertEqual(self.store.transfer("admitted"), "active")
        self.assertEqual(self.f.effects(), 0)

    def test_fresh_process_lost_fence_reply_never_retries_or_inputs(self) -> None:
        self.initialize()
        code = """import os,sys
sys.path.insert(0,'tests')
from test_control_leases import ControlFixture,AGENT,HUMAN
f=ControlFixture(sys.argv[1]); s=f.store()
f.transition('takeover',AGENT,HUMAN,1)
f.after_fence=lambda: os._exit(73)
s.transfer('admitted')
"""
        result = subprocess.run([sys.executable, "-c", code, self.tmp.name], timeout=10)
        self.assertEqual(result.returncode, 73)
        self.f.transition("takeover", AGENT, HUMAN, 1)
        self.assertEqual(self.store.transfer("admitted"), "unknown")
        self.f.input(HUMAN, 2)
        with self.assertRaises(Denied):
            self.journal.dispatch("admitted", PAYLOAD)
        self.assertEqual(self.f.fences(), 2)
        self.assertEqual(self.f.effects(), 0)

    def test_missing_adapters_and_foreign_schema_fail_closed(self) -> None:
        missing = LeaseStore(Path(self.tmp.name) / "missing.sqlite")
        self.addCleanup(missing.close)
        with self.assertRaises(Denied):
            missing.transfer("admitted")
        import sqlite3

        path = Path(self.tmp.name) / "foreign.sqlite"
        db = sqlite3.connect(path)
        db.execute("CREATE TABLE unrelated(value TEXT)")
        db.commit()
        db.close()
        with self.assertRaises(Denied):
            LeaseStore(path)

    def test_actual_other_process_input_blocks_transfer_until_helper_finishes(self) -> None:
        import time

        self.initialize()
        code = """import sys,time
from pathlib import Path
sys.path.insert(0,'tests')
from test_control_leases import ControlFixture,AGENT,PAYLOAD
f=ControlFixture(sys.argv[1]); s=f.store(); f.input(AGENT,1,'child-command')
original=f.submit
root=Path(sys.argv[1])
def held(grant,payload,guard):
    (root/'entered').write_text('held')
    deadline=time.monotonic()+10
    while not (root/'release').exists():
        if time.monotonic()>deadline: raise RuntimeError('bounded fixture timeout')
        time.sleep(.01)
    return original(grant,payload,guard)
f.submit=held
j=s.journal(root/'effects.sqlite',f)
try: print(j.dispatch('admitted',PAYLOAD),flush=True)
finally: j.close(); s.close()
"""
        process = subprocess.Popen(
            [sys.executable, "-c", code, self.tmp.name],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            marker = Path(self.tmp.name) / "entered"
            deadline = time.monotonic() + 5
            while not marker.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(marker.exists(), "child did not enter real helper")
            self.f.transition("takeover", AGENT, HUMAN, 1)
            with self.assertRaises(Denied):
                self.store.transfer("admitted")
            self.assertEqual(self.f.fences(), 1)
            self.assertEqual(self.f.effects(), 0)
        finally:
            (Path(self.tmp.name) / "release").write_text("release")
            try:
                out, err = process.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()  # Only the exact child started by this test.
                process.communicate(timeout=5)
                raise
        self.assertEqual(process.returncode, 0, err)
        self.assertEqual(out.strip(), "unknown")
        self.assertEqual(self.f.effects(), 1)
        self.assertEqual(self.store.transfer("admitted"), "active")
        self.assertEqual(self.f.fences(), 2)

    def test_source_mutation_exposes_wrong_holder_input(self) -> None:
        import shutil

        source = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shutil.copytree(
                source / "browser_runtime",
                root / "browser_runtime",
                ignore=shutil.ignore_patterns("__pycache__"),
            )
            for name in ("test_control_leases.py", "test_guarded_effects.py"):
                shutil.copyfile(source / "tests" / name, root / name)
            code = """from pathlib import Path
from test_control_leases import ControlFixture,AGENT,HUMAN,PAYLOAD,Denied
Path('data').mkdir(exist_ok=True)
f=ControlFixture('data'); s=f.store()
f.transition('initialize',None,AGENT,0); s.transfer('admitted')
f.input(HUMAN,1); j=s.journal(Path('data/effects.sqlite'),f)
try: j.dispatch('admitted',PAYLOAD)
except Denied: pass
print(f.effects()); j.close(); s.close()
"""

            def run():
                result = subprocess.run(
                    [sys.executable, "-c", code],
                    cwd=root,
                    capture_output=True,
                    text=True,
                    check=True,
                    timeout=10,
                )
                return result.stdout.strip()

            self.assertEqual(run(), "0")
            shutil.rmtree(root / "data")
            path = root / "browser_runtime/control_leases.py"
            original = path.read_text()
            anchor = '_encode(asdict(grant.holder)),\n            "active"'
            self.assertEqual(original.count(anchor), 1)
            path.write_text(original.replace(anchor, 'row[2],\n            "active"'))
            shutil.rmtree(root / "browser_runtime/__pycache__", ignore_errors=True)
            self.assertEqual(run(), "1")

    def test_release_callback_expiry_prevents_fence_and_new_authority(self) -> None:
        self.initialize()
        self.f.transition("takeover", AGENT, HUMAN, 1)
        self.store.transfer("admitted")
        self.f.transition("handback", HUMAN, AGENT, 2)

        def late_release(transfer):
            self.f.now = 20.0
            return True

        self.f.released = late_release
        with self.assertRaises(Denied):
            self.store.transfer("admitted")
        self.assertEqual(self.f.fences(), 2)
        self.assertEqual(self.f.effects(), 0)

    def test_process_death_after_reservation_before_fence_remains_blocked(self) -> None:
        self.initialize()
        code = """import os,sys
sys.path.insert(0,'tests')
from test_control_leases import ControlFixture,AGENT,HUMAN
f=ControlFixture(sys.argv[1]); s=f.store()
f.transition('takeover',AGENT,HUMAN,1)
def die():
    if f.current_calls == 3: os._exit(74)
f.at_current=die
s.transfer('admitted')
"""
        result = subprocess.run([sys.executable, "-c", code, self.tmp.name], timeout=10)
        self.assertEqual(result.returncode, 74)
        self.f.transition("takeover", AGENT, HUMAN, 1)
        self.assertEqual(self.store.transfer("admitted"), "unknown")
        self.f.input(AGENT, 1)
        with self.assertRaises(Denied):
            self.journal.dispatch("admitted", PAYLOAD)
        self.assertEqual(self.f.fences(), 1)
        self.assertEqual(self.f.effects(), 0)

    def test_wrong_fence_receipt_never_activates_or_retries(self) -> None:
        self.initialize()
        grant = self.f.transition("takeover", AGENT, HUMAN, 1)
        original = self.f.fence

        def wrong_receipt(transfer, guard):
            original(transfer, guard)
            return FenceReceipt(
                replace(transfer, destination=Holder("human", "other")), True
            )

        self.f.fence = wrong_receipt
        self.assertEqual(self.store.transfer("admitted"), "unknown")
        self.f.input(HUMAN, 2)
        with self.assertRaises(Denied):
            self.journal.dispatch("admitted", PAYLOAD)
        self.assertEqual(self.f.effects(), 0)
        self.f.grant = grant
        self.f.fence = original
        self.assertEqual(self.store.transfer("admitted"), "unknown")
        self.assertEqual(self.f.fences(), 2)

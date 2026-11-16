"""Recovery of actual SQLite pending rows from independent synthetic readback."""
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from dataclasses import asdict, replace
from pathlib import Path

from browser_runtime.control_leases import FenceObservation, LeaseStore, Recovery
from browser_runtime.credentials import Observation
from browser_runtime.effects import Cancelled, Denied
from test_control_leases import AGENT, HUMAN, ControlFixture, PAYLOAD


class RecoveryFixture(ControlFixture):
    def __init__(self, root):
        super().__init__(root)
        self.inspections = 0
        self.observation_age = 0.0
        self.inspect_callback = lambda: None
        self.inspect_cancel = False
        self.inspect_unknown = False
        self.inspect_wrong = False

    def observe(self):
        return Observation(self.observed, self.now)

    def fence(self, transfer, guard):
        # Independent backend state exists before the response can be lost.
        path = self.root / "closed-transfer.json"
        path.write_text(json.dumps(asdict(transfer), sort_keys=True))
        return super().fence(transfer, guard)

    def inspect(self, recovery, guard):
        if not self.active or guard is not self:
            raise AssertionError("physical guard not held for inspection")
        self.inspections += 1
        self.inspect_callback()
        if self.inspect_cancel:
            raise KeyboardInterrupt("SYNTHETIC-PRIVATE-INSPECT")
        path = self.root / "closed-transfer.json"
        if self.inspect_unknown or not path.exists():
            return None
        if json.loads(path.read_text()) != asdict(recovery.transfer):
            return None
        transfer = recovery.transfer
        if self.inspect_wrong:
            transfer = replace(transfer, expected_epoch=900)
        return FenceObservation(transfer, self.closed_inputs, self.now - self.observation_age)

    def store(self):
        return LeaseStore(self.root / "leases.sqlite", authority=self, backend=self,
                          inspector=self, clock=lambda: self.now)

    def recovery(self, transfer):
        self.grant = Recovery(transfer, self.now + 10.0)


class ControlReconciliationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.f = RecoveryFixture(self.tmp.name)
        self.store = self.f.store()
        self.addCleanup(self.store.close)
        self.journal = self.store.journal(Path(self.tmp.name) / "effects.sqlite", self.f)
        self.addCleanup(self.journal.close)
        self.f.transition("initialize", None, AGENT, 0)
        self.assertEqual(self.store.transfer("admitted"), "active")

    def pending(self, handback=False):
        transfer = self.f.transition("takeover", AGENT, HUMAN, 1)
        if handback:
            self.assertEqual(self.store.transfer("admitted"), "active")
            transfer = self.f.transition("handback", HUMAN, AGENT, 2)
        self.f.fence_error = True
        with self.assertRaises(Denied):
            self.store.transfer("admitted")
        self.f.fence_error = False
        return transfer

    def blocked(self, holder=HUMAN, epoch=2):
        self.f.input(holder, epoch)
        self.f.grant = replace(self.f.grant, effect=replace(self.f.grant.effect, deadline=self.f.now+10))
        with self.assertRaises(Denied):
            self.journal.dispatch("admitted", PAYLOAD)
        self.assertEqual(self.f.effects(), 0)

    def test_fresh_recovery_after_original_deadline_activates_without_refencing(self):
        transfer = self.pending()
        self.f.now = 30.0
        with self.assertRaises(Denied):
            self.store.transfer("admitted")  # Expired original transfer cannot act.
        self.f.recovery(transfer)
        self.assertEqual(self.store.reconcile_transfer("admitted"), "active")
        self.assertEqual(self.f.fences(), 2)
        self.assertEqual(self.f.inspections, 1)
        self.assertEqual(self.store.reconcile_transfer("admitted"), "active")
        self.assertEqual(self.f.inspections, 1)
        self.f.input(HUMAN, 2)
        self.f.grant = replace(self.f.grant, effect=replace(self.f.grant.effect, deadline=40.0))
        self.assertEqual(self.journal.dispatch("admitted", PAYLOAD), "unknown")
        self.assertEqual(self.f.effects(), 1)
        self.assertEqual(self.f.fences(), 2)

    def test_missing_incomplete_or_wrong_closure_evidence_stays_pending(self):
        transfer = self.pending()
        for kind in ("missing", "incomplete", "wrong"):
            self.f.inspect_unknown = kind == "missing"
            self.f.closed_inputs = kind != "incomplete"
            self.f.inspect_wrong = kind == "wrong"
            self.f.recovery(transfer)
            self.assertEqual(self.store.reconcile_transfer("admitted"), "unknown")
            self.blocked()
        self.assertEqual(self.f.fences(), 2)

    def test_conflicting_transfer_rejects_before_inspector(self):
        transfer = self.pending()
        for altered in (
            replace(transfer, deadline=99.0),
            replace(transfer, destination=AGENT),
            replace(transfer, target=replace(transfer.target, native_session="other")),
        ):
            self.f.recovery(altered)
            with self.assertRaises(Denied):
                self.store.reconcile_transfer("admitted")
        self.assertEqual(self.f.inspections, 0)
        self.blocked()

    def test_original_transfer_ticket_is_not_recovery_authority(self):
        self.pending()
        with self.assertRaises(Denied):
            self.store.reconcile_transfer("admitted")
        self.assertEqual(self.f.inspections, 0)
        self.blocked()

    def test_handback_requires_renewed_exact_holder_release(self):
        transfer = self.pending(handback=True)
        self.f.release = False
        self.f.recovery(transfer)
        with self.assertRaises(Denied):
            self.store.reconcile_transfer("admitted")
        self.assertEqual(self.f.inspections, 0)
        self.blocked(AGENT, 3)
        self.f.release = True
        self.f.recovery(transfer)
        self.assertEqual(self.store.reconcile_transfer("admitted"), "active")
        self.assertEqual(self.f.fences(), 3)

    def test_release_revoked_during_inspection_prevents_activation(self):
        transfer = self.pending(handback=True)
        self.f.inspect_callback = lambda: setattr(self.f, "release", False)
        self.f.recovery(transfer)
        with self.assertRaises(Denied):
            self.store.reconcile_transfer("admitted")
        self.blocked(AGENT, 3)
        self.assertEqual(self.f.fences(), 3)

    def test_stale_future_nonfinite_and_boolean_receipt_times_deny(self):
        transfer = self.pending()
        for age in (2.0, -1.0, float("nan"), float("inf")):
            self.f.observation_age = age
            self.f.recovery(transfer)
            with self.assertRaises(Denied):
                self.store.reconcile_transfer("admitted")
            self.blocked()
        self.assertEqual(self.f.fences(), 2)

    def test_inspector_delay_cannot_outlive_recovery_deadline(self):
        transfer = self.pending()
        self.f.recovery(transfer)
        self.f.inspect_callback = lambda: setattr(self.f, "now", 20.0)
        with self.assertRaises(Denied):
            self.store.reconcile_transfer("admitted")
        self.blocked()
        self.assertEqual(self.f.fences(), 2)

    def test_cancelled_inspection_preserves_pending_and_sanitizes(self):
        transfer = self.pending()
        self.f.inspect_cancel = True
        self.f.recovery(transfer)
        with self.assertRaises(Cancelled) as raised:
            self.store.reconcile_transfer("admitted")
        self.assertNotIn("SYNTHETIC", str(raised.exception))
        self.assertIsNone(raised.exception.__context__)
        self.blocked()
        self.assertEqual(self.f.fences(), 2)

    def test_fresh_process_recovery_uses_existing_exact_backend_record(self):
        transfer = self.pending()
        code = """import sys
sys.path.insert(0,'tests')
from test_control_reconciliation import RecoveryFixture
from test_control_leases import AGENT,HUMAN
f=RecoveryFixture(sys.argv[1]); s=f.store()
t=f.transition('takeover',AGENT,HUMAN,1); f.recovery(t)
try: print(s.reconcile_transfer('admitted'))
finally: s.close()
"""
        result = subprocess.run([sys.executable, "-c", code, self.tmp.name], timeout=10,
                                check=True, capture_output=True, text=True)
        self.assertEqual(result.stdout.strip(), "active")
        self.assertEqual(self.f.fences(), 2)
        self.f.recovery(transfer)
        self.assertEqual(self.store.reconcile_transfer("admitted"), "active")
        self.assertEqual(self.f.inspections, 0)

    def test_absent_inspector_denies_without_backend_effect(self):
        transfer = self.pending()
        other = LeaseStore(Path(self.tmp.name) / "leases.sqlite", authority=self.f,
                           backend=self.f, clock=lambda: self.f.now)
        self.addCleanup(other.close)
        self.f.recovery(transfer)
        with self.assertRaises(Denied):
            other.reconcile_transfer("admitted")
        self.assertEqual(self.f.fences(), 2)
        self.blocked()

    def test_source_mutation_exposes_stale_closure_activation(self):
        source = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shutil.copytree(source / "browser_runtime", root / "browser_runtime",
                            ignore=shutil.ignore_patterns("__pycache__"))
            for name in ("test_control_reconciliation.py", "test_control_leases.py", "test_guarded_effects.py"):
                shutil.copyfile(source / "tests" / name, root / name)
            code = """from pathlib import Path
from test_control_reconciliation import RecoveryFixture
from test_control_leases import AGENT,HUMAN,PAYLOAD,Denied
Path('data').mkdir()
f=RecoveryFixture('data'); s=f.store()
f.transition('initialize',None,AGENT,0); s.transfer('admitted')
t=f.transition('takeover',AGENT,HUMAN,1); f.fence_error=True
try: s.transfer('admitted')
except Denied: pass
f.fence_error=False; f.observation_age=2; f.recovery(t)
try: s.reconcile_transfer('admitted')
except Denied: pass
f.input(HUMAN,2); j=s.journal(Path('data/effects.sqlite'),f)
try: j.dispatch('admitted',PAYLOAD)
except Denied: pass
print(f.effects()); j.close(); s.close()
"""
            def run():
                result = subprocess.run([sys.executable, "-c", code], cwd=root,
                                        capture_output=True, text=True,
                                        check=True, timeout=10)
                return result.stdout.strip()
            self.assertEqual(run(), "0")
            shutil.rmtree(root / "data")
            path = root / "browser_runtime/control_leases.py"
            original = path.read_text()
            anchor = "raise ValueError  # Stale closure is not activation authority."
            self.assertEqual(original.count(anchor), 1)
            path.write_text(original.replace(anchor, "pass  # deliberate mutation"))
            shutil.rmtree(root / "browser_runtime/__pycache__", ignore_errors=True)
            self.assertEqual(run(), "1")

    def test_boolean_closure_time_is_not_a_timestamp(self):
        transfer = self.pending()
        inspect = self.f.inspect
        self.f.inspect = lambda recovery, guard: replace(inspect(recovery, guard), observed_at=True)
        self.f.recovery(transfer)
        with self.assertRaises(Denied):
            self.store.reconcile_transfer("admitted")
        self.blocked()

    def test_committed_activation_with_lost_return_is_not_repeated(self):
        transfer = self.pending()
        self.f.recovery(transfer)
        self.f.exit_error = True
        with self.assertRaises(Denied):
            self.store.reconcile_transfer("admitted")
        self.f.exit_error = False
        self.assertEqual(self.store.reconcile_transfer("admitted"), "active")
        self.assertEqual(self.f.inspections, 1)
        self.assertEqual(self.f.fences(), 2)

    def test_old_recovery_cannot_replace_a_newer_active_epoch(self):
        transfer = self.pending()
        self.f.recovery(transfer)
        self.assertEqual(self.store.reconcile_transfer("admitted"), "active")
        self.f.transition("handback", HUMAN, AGENT, 2)
        self.assertEqual(self.store.transfer("admitted"), "active")
        self.f.recovery(transfer)
        with self.assertRaises(Denied):
            self.store.reconcile_transfer("admitted")
        self.assertEqual(self.f.inspections, 1)
        self.blocked(HUMAN, 2)

    def test_reservation_without_any_fence_has_no_closure_to_infer(self):
        transfer = self.f.transition("takeover", AGENT, HUMAN, 1)
        self.f.current_calls = 0
        def fail_before_fence():
            if self.f.current_calls == 3:
                raise RuntimeError("SYNTHETIC-BEFORE-FENCE")
        self.f.at_current = fail_before_fence
        with self.assertRaises(Denied):
            self.store.transfer("admitted")
        self.f.at_current = lambda: None
        self.f.recovery(transfer)
        self.assertEqual(self.store.reconcile_transfer("admitted"), "unknown")
        self.assertEqual(self.f.fences(), 1)
        self.blocked()

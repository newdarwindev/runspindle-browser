"""Real Journal + synthetic authenticated fence/site; no browser or network."""
import hashlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path

from browser_runtime.credentials import Observation, Target
from browser_runtime.effects import Binding, Cancelled, Denied, Readback
from browser_runtime.guarded_effects import Grant, GuardedJournal

PAYLOAD = b"invented-action"
DIGEST = hashlib.sha256(PAYLOAD).hexdigest()
TARGET = Target(Binding("principal", "account", "browser", "tab", "intent", 1, "operation", 1, "https://example.invalid"), "session", "frame", "https://example.invalid")


class Fixture:
    def __init__(self, root):
        self.root = Path(root)
        self.now = 10.0
        self.grant = Grant(TARGET, DIGEST, "dispatch", 20.0)
        self.observed = TARGET
        self.current_calls = 0
        self.at_current = lambda: None
        self.allowed = True
        self.active = False
        self.reads = 0
        self.lost = False
        self.cancel = False
        self.exit_error = False

    @contextmanager
    def acquire(self):
        self.active = True
        try:
            yield self
        finally:
            self.active = False
        if self.exit_error:
            raise RuntimeError("SYNTHETIC-PRIVATE-ERROR")

    def admit(self, ticket):
        return self.grant if ticket == "admitted" else None

    def observe(self):
        return Observation(self.observed, 10.0)

    def current(self, grant):
        self.current_calls += 1
        self.at_current()
        return self.allowed

    def submit(self, grant, payload, guard):
        if not self.active or guard is not self:
            raise AssertionError("guard not held")
        with (self.root / "site-ledger").open("ab") as stream:
            stream.write(b"accepted\n")
            stream.flush()
        if self.cancel:
            raise KeyboardInterrupt("SYNTHETIC-PRIVATE-ERROR")
        if self.lost:
            raise RuntimeError("SYNTHETIC-PRIVATE-ERROR")
        return "not-an-authoritative-result"

    def readback(self, grant, guard):
        if not self.active or guard is not self:
            raise AssertionError("guard not held")
        self.reads += 1
        return Readback(grant.target.binding, grant.payload_digest, "confirmed", "a" * 64)

    def journal(self):
        return GuardedJournal(self.root / "journal.sqlite", authority=self, site=self, clock=lambda: self.now)

    def effects(self):
        path = self.root / "site-ledger"
        return len(path.read_bytes().splitlines()) if path.exists() else 0


class GuardedEffectsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.f = Fixture(self.tmp.name)
        self.j = self.f.journal()
        self.addCleanup(self.j.close)

    def test_lost_reply_fresh_process_and_authenticated_reconciliation(self):
        self.f.lost = True
        self.assertEqual(self.j.dispatch("admitted", PAYLOAD), "unknown")
        self.assertEqual(self.f.effects(), 1)
        self.j.close()
        code = """import sys
sys.path.insert(0, 'tests')
from test_guarded_effects import Fixture, PAYLOAD
f=Fixture(sys.argv[1]); j=f.journal()
print(j.dispatch('admitted',PAYLOAD)); j.close()
"""
        result = subprocess.run([sys.executable, "-c", code, self.tmp.name], check=True, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.stdout.strip(), "unknown")
        self.assertEqual(self.f.effects(), 1)
        self.j = self.f.journal()
        self.addCleanup(self.j.close)
        self.f.grant = replace(self.f.grant, action="reconcile")
        self.assertEqual(self.j.reconcile("admitted"), "confirmed")
        self.assertEqual(self.f.reads, 1)
        self.assertEqual(self.f.effects(), 1)

    def test_wrong_ticket_payload_action_and_exact_observation_deny(self):
        for mutation in [
            lambda: setattr(self.f, "observed", replace(TARGET, native_session="other")),
            lambda: setattr(self.f, "observed", replace(TARGET, frame="other")),
            lambda: setattr(self.f, "observed", replace(TARGET, binding=replace(TARGET.binding, account="other"))),
            lambda: setattr(self.f, "grant", replace(self.f.grant, action="reconcile")),
            lambda: setattr(self.f, "grant", replace(self.f.grant, payload_digest="b"*64)),
        ]:
            self.f.observed = TARGET
            self.f.grant = Grant(TARGET, DIGEST, "dispatch", 20.0)
            mutation()
            with self.assertRaises(Denied):
                self.j.dispatch("admitted", PAYLOAD)
        with self.assertRaises(Denied):
            self.j.dispatch("forged", PAYLOAD)
        self.assertEqual(self.f.effects(), 0)

    def test_authority_delay_and_deadline_are_sampled_after_callback(self):
        self.f.at_current = lambda: setattr(self.f, "now", 20.0)
        with self.assertRaises(Denied):
            self.j.dispatch("admitted", PAYLOAD)
        self.assertEqual(self.f.effects(), 0)

    def test_freshness_exact_age_is_inclusive_and_deadline_exclusive(self):
        self.f.now = 11.0
        self.assertEqual(self.j.dispatch("admitted", PAYLOAD), "unknown")
        self.f.grant = replace(self.f.grant, deadline=11.0)
        with self.assertRaises(Denied):
            self.j.dispatch("admitted", PAYLOAD)
        self.assertEqual(self.f.effects(), 1)

    def test_revocation_at_durable_dispatch_boundary_prevents_site_call(self):
        # First check is outer admission, second Journal preflight, third follows
        # reservation and the actual second writer transaction.
        def revoke():
            if self.f.current_calls == 3:
                self.f.allowed = False
        self.f.at_current = revoke
        with self.assertRaises(Denied):
            self.j.dispatch("admitted", PAYLOAD)
        self.assertEqual(self.f.effects(), 0)
        self.f.allowed = True
        self.f.at_current = lambda: None
        self.assertEqual(self.j.dispatch("admitted", PAYLOAD), "unknown")
        self.assertEqual(self.f.effects(), 0)  # Reservation never grants retry.

    def test_cancellation_after_effect_stays_cancelled_and_never_replays(self):
        self.f.cancel = True
        with self.assertRaises(Cancelled) as raised:
            self.j.dispatch("admitted", PAYLOAD)
        self.assertNotIn("SYNTHETIC", str(raised.exception))
        self.assertIsNone(raised.exception.__context__)
        self.f.cancel = False
        self.assertEqual(self.j.dispatch("admitted", PAYLOAD), "unknown")
        self.assertEqual(self.f.effects(), 1)

    def test_guard_exit_failure_cannot_return_success(self):
        self.f.exit_error = True
        with self.assertRaises(Denied) as raised:
            self.j.dispatch("admitted", PAYLOAD)
        self.assertIsNone(raised.exception.__context__)
        self.assertFalse(self.f.active)
        self.f.exit_error = False
        self.assertEqual(self.j.dispatch("admitted", PAYLOAD), "unknown")
        self.assertEqual(self.f.effects(), 1)

    def test_nested_calls_fail_before_another_site_effect(self):
        def nested():
            with self.assertRaises(Denied):
                self.j.dispatch("admitted", PAYLOAD)
        self.f.at_current = nested
        self.assertEqual(self.j.dispatch("admitted", PAYLOAD), "unknown")
        self.assertEqual(self.f.effects(), 1)

    def test_missing_adapters_deny_and_passive_read_does_not_submit(self):
        other = GuardedJournal(Path(self.tmp.name) / "empty.sqlite")
        self.addCleanup(other.close)
        with self.assertRaises(Denied):
            other.dispatch("admitted", PAYLOAD)
        self.f.grant = replace(self.f.grant, action="reconcile")
        with self.assertRaises(Denied):
            self.j.reconcile("admitted")
        self.assertEqual(self.f.effects(), 0)
        self.assertEqual(self.f.reads, 0)

    def test_source_mutation_exposes_forbidden_site_effect(self):
        source = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shutil.copytree(source / "browser_runtime", root / "browser_runtime",
                            ignore=shutil.ignore_patterns("__pycache__"))
            shutil.copyfile(Path(__file__), root / "test_guarded_effects.py")
            code = """from test_guarded_effects import Fixture, PAYLOAD
from browser_runtime.effects import Denied
from pathlib import Path
Path('data').mkdir(exist_ok=True)
f=Fixture('data'); f.allowed=False; j=f.journal()
try: j.dispatch('admitted',PAYLOAD)
except Denied: pass
print(f.effects()); j.close()
"""
            def run():
                result = subprocess.run([sys.executable, "-c", code], cwd=root,
                                        check=True, capture_output=True,
                                        text=True, timeout=10)
                return result.stdout.strip()
            self.assertEqual(run(), "0")
            module = root / "browser_runtime/guarded_effects.py"
            original = module.read_text()
            anchor = "current is not True\n            or "
            self.assertEqual(original.count(anchor), 1)
            module.write_text(original.replace(anchor, ""))
            shutil.rmtree(root / "browser_runtime/__pycache__", ignore_errors=True)
            self.assertEqual(run(), "1")

    def test_nonfinite_and_boolean_clock_fail_closed(self):
        for value in [float("nan"), float("inf"), True]:
            self.f.now = value
            with self.assertRaises(Denied):
                self.j.dispatch("admitted", PAYLOAD)
        self.assertEqual(self.f.effects(), 0)

    def test_persisted_full_target_rejects_changed_session_frame_and_origin(self):
        self.assertEqual(self.j.dispatch("admitted", PAYLOAD), "unknown")
        self.j.close()
        self.j = self.f.journal()
        self.addCleanup(self.j.close)
        for target in [replace(TARGET, native_session="different"),
                       replace(TARGET, frame="different"),
                       replace(TARGET, frame_origin="https://other.invalid")]:
            self.f.grant = Grant(target, DIGEST, "reconcile", 20.0)
            self.f.observed = target
            with self.assertRaises(Denied):
                self.j.reconcile("admitted")
        self.assertEqual(self.f.reads, 0)
        self.assertEqual(self.f.effects(), 1)
        self.f.grant = Grant(TARGET, DIGEST, "reconcile", 20.0)
        self.f.observed = TARGET
        self.assertEqual(self.j.reconcile("admitted"), "confirmed")

    def test_legacy_journal_cannot_reconcile_contextual_row(self):
        from browser_runtime.effects import Journal
        self.j.dispatch("admitted", PAYLOAD)
        legacy = Journal(Path(self.tmp.name) / "journal.sqlite", lambda *_: True,
                         observe=lambda *_: self.fail("must reject before readback"))
        self.addCleanup(legacy.close)
        with self.assertRaises(Denied):
            legacy.reconcile(TARGET.binding, DIGEST)

    def test_cancellation_survives_guard_suppression_and_exit_error(self):
        for suppress in (False, True):
            with tempfile.TemporaryDirectory() as root:
                f = Fixture(root)
                @contextmanager
                def acquire():
                    f.active = True
                    try:
                        yield f
                    except BaseException:
                        if not suppress:
                            raise RuntimeError("SYNTHETIC-PRIVATE-CLEANUP")
                    finally:
                        f.active = False
                f.acquire = acquire
                f.cancel = True
                j = f.journal()
                try:
                    with self.assertRaises(Cancelled) as raised:
                        j.dispatch("admitted", PAYLOAD)
                    self.assertIsNone(raised.exception.__context__)
                    self.assertNotIn("SYNTHETIC", str(raised.exception))
                    self.assertEqual(f.effects(), 1)
                finally:
                    j.close()

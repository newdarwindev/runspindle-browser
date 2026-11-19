"""Real read-only lease snapshots; synthetic admission, input and provider spies."""

import json
import socket
import subprocess
import sys
import tempfile
import unittest
from collections.abc import Callable
from dataclasses import asdict, replace
from pathlib import Path
from unittest.mock import Mock, patch

from browser_runtime.control_leases import (
    ControlStatus,
    CredentialInput,
    PassiveStatus,
    Recovery,
)
from browser_runtime.credentials import Denied as CredentialDenied
from browser_runtime.credentials import Grant as CredentialGrant
from browser_runtime.credentials import Target
from browser_runtime.effects import Denied
from tests.test_control_leases import AGENT, HUMAN, ControlFixture, target
from tests.test_guarded_effects import PAYLOAD
from tests.test_lease_credentials import CredentialAdapters

ROOT = Path(__file__).resolve().parents[1]


class PassiveTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.f = ControlFixture(self.root)
        self.store = self.f.store()
        self.addCleanup(self.store.close)
        network = patch.object(
            socket.socket, "connect", side_effect=AssertionError("network forbidden")
        )
        network.start()
        self.addCleanup(network.stop)

    def passive(
        self, bound: Target | None = None, deadline: float = 20.0
    ) -> PassiveStatus:
        admission = PassiveStatus(
            target(1, "passive-status") if bound is None else bound, deadline
        )
        self.f.grant = admission
        return admission

    def initialize(self) -> None:
        self.f.transition("initialize", None, AGENT, 0)
        self.assertEqual(self.store.transfer("admitted"), "active")

    def scope(self) -> str:
        physical = asdict(target(1, "passive-status"))
        for key in ("intent", "revision", "operation", "epoch"):
            del physical["binding"][key]
        return json.dumps(physical, sort_keys=True, separators=(",", ":"))

    def snapshot(self) -> ControlStatus:
        before = (self.root / "leases.sqlite").read_bytes()
        rows = self.store._db.execute("SELECT * FROM leases").fetchall()
        changes = self.store._db.total_changes
        fences = self.f.fences()
        result = self.store.status("admitted")
        self.assertEqual(
            self.store._db.execute("SELECT * FROM leases").fetchall(), rows
        )
        self.assertEqual(self.store._db.total_changes, changes)
        self.assertEqual((self.root / "leases.sqlite").read_bytes(), before)
        self.assertEqual(self.f.fences(), fences)
        self.assertEqual(self.f.effects(), 0)
        self.assertEqual(self.f.reads, 0)
        self.assertFalse(self.store._db.in_transaction)
        self.assertFalse(self.f.active)
        return result

    def test_absent_active_pending_are_read_only_and_pending_has_no_holder(
        self,
    ) -> None:
        self.passive()
        self.assertEqual(
            self.snapshot(), ControlStatus("absent", None, None, 10.0, self.scope())
        )
        self.initialize()
        self.passive()
        active = self.snapshot()
        self.assertEqual(active, ControlStatus("active", 1, AGENT, 10.0, self.scope()))
        self.f.transition("takeover", AGENT, HUMAN, 1)
        self.f.closed_inputs = False
        self.assertEqual(self.store.transfer("admitted"), "unknown")
        self.passive()
        self.assertEqual(
            self.snapshot(), ControlStatus("pending", 2, None, 10.0, self.scope())
        )
        # The earlier observation is retained history, not current ownership.
        self.assertEqual(active.holder, AGENT)
        self.f.input(AGENT, 1)
        journal = self.store.journal(self.root / "effects.sqlite", self.f)
        self.addCleanup(journal.close)
        with self.assertRaises(Denied):
            journal.dispatch("admitted", PAYLOAD)
        self.assertEqual(self.f.effects(), 0)

    def test_observation_does_not_prevent_later_transfer_or_grant_input(self) -> None:
        self.initialize()
        self.passive()
        old = self.snapshot()
        self.f.transition("takeover", AGENT, HUMAN, 1)
        self.assertEqual(self.store.transfer("admitted"), "active")
        self.passive()
        self.assertEqual(
            self.snapshot(), ControlStatus("active", 2, HUMAN, 10.0, self.scope())
        )
        with patch.object(self.f, "admit", return_value=old), self.assertRaises(Denied):
            self.store.transfer("admitted")
        self.assertEqual(self.f.fences(), 2)

    def test_passive_admission_never_enters_effect_credential_or_transition_routes(
        self,
    ) -> None:
        self.initialize()
        admission = self.passive()
        journal = self.store.journal(self.root / "effects.sqlite", self.f)
        self.addCleanup(journal.close)
        vault = CredentialAdapters(self.f)
        inspector = Mock()
        self.store._inspector = inspector
        operations: tuple[Callable[[], str], ...] = (
            lambda: self.store.transfer("admitted"),
            lambda: self.store.reconcile_transfer("admitted"),
            lambda: journal.dispatch("admitted", PAYLOAD),
            lambda: journal.reconcile("admitted"),
        )
        for operation in operations:
            with self.assertRaises(Denied):
                operation()
        with self.assertRaises(CredentialDenied):
            vault.resolver(self.store).resolve_and_inject("admitted")
        self.assertEqual((self.f.fences(), self.f.effects(), self.f.reads), (1, 0, 0))
        self.assertEqual((vault.reads, vault.injections, vault.releases), (0, 0, 0))
        inspector.inspect.assert_not_called()
        self.f.input(AGENT, 1)
        with self.assertRaises(Denied):
            self.store.status("admitted")
        transfer = self.f.transition("takeover", AGENT, HUMAN, 1)
        credential = CredentialInput(
            CredentialGrant(target(1, "credential"), "credential:one", 20.0), AGENT
        )
        for other in (
            transfer,
            Recovery(transfer, 20.0),
            credential,
            ControlStatus("active", 1, AGENT, 10.0, self.scope()),
        ):
            with (
                patch.object(self.f, "admit", return_value=other),
                self.assertRaises(Denied),
            ):
                self.store.status("admitted")
        self.f.grant = admission
        with self.assertRaises(Denied):
            self.store.status("forged")

    def test_wrong_scope_revoked_expired_and_stale_observations_deny(self) -> None:
        self.initialize()
        base = target(1, "passive-status")
        binding = base.binding
        changes = (
            ("principal", replace(base, binding=replace(binding, principal="other"))),
            ("account", replace(base, binding=replace(binding, account="other"))),
            ("browser", replace(base, binding=replace(binding, browser="other"))),
            ("tab", replace(base, binding=replace(binding, tab="other"))),
            ("native_session", replace(base, native_session="other")),
            ("frame", replace(base, frame="other")),
            ("frame_origin", replace(base, frame_origin="https://other.invalid")),
            (
                "origin",
                replace(base, binding=replace(binding, origin="https://other.invalid")),
            ),
        )
        for field, changed in changes:
            with self.subTest(field=field):
                self.passive(bound=changed)
                with self.assertRaises(Denied):
                    self.store.status("admitted")
                # Even coherent observed scope cannot reveal another row's owner.
                if field != "browser":
                    self.f.observed = changed
                    with self.assertRaises(Denied):
                        self.store.status("admitted")
                    self.f.observed = base
        self.passive(deadline=10.0)
        with self.assertRaises(Denied):
            self.store.status("admitted")
        self.passive()
        self.f.allowed = False
        with self.assertRaises(Denied):
            self.store.status("admitted")
        self.f.allowed = True
        self.f.now = 12.0
        with self.assertRaises(Denied):
            self.store.status("admitted")
        self.assertEqual(self.f.fences(), 1)

    def test_read_delay_or_revocation_cannot_preserve_admission(self) -> None:
        self.initialize()
        self.passive()
        original = self.store._row
        for mode in ("expired", "revoked"):
            self.f.now = 10.0
            self.f.allowed = True

            def delayed(selected: Target) -> tuple[object, ...] | None:
                row = original(selected)
                if mode == "expired":
                    self.f.now = 20.0
                else:
                    self.f.allowed = False
                return row

            with patch.object(self.store, "_row", side_effect=delayed):
                with self.assertRaises(Denied):
                    self.store.status("admitted")
            self.assertFalse(self.store._db.in_transaction)

    def test_scope_check_mutation_exposes_other_account_ownership(self) -> None:
        script = r"""
import pathlib, sys, unittest
import browser_runtime.control_leases as module
source=pathlib.Path(module.__file__).read_text()
needle='row[0] != _scope(grant.target)\n                    or '
assert source.count(needle)==1
source=source.replace(needle,'')
exec(compile(source,module.__file__,'exec'),module.__dict__)
sys.path.insert(0,'tests')
from test_passive_control_status import PassiveTests
result=unittest.TextTestRunner().run(unittest.TestSuite([
 PassiveTests('test_wrong_scope_revoked_expired_and_stale_observations_deny')]))
sys.exit(0 if result.wasSuccessful() else 1)
"""
        result = subprocess.run(
            [sys.executable, *(["-O"] if sys.flags.optimize else []), "-c", script],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("Denied not raised", result.stderr)
        self.assertNotIn("ERROR:", result.stderr)

    def test_timestamp_follows_final_callbacks_and_guard_exit_cannot_fake_success(
        self,
    ) -> None:
        self.initialize()
        self.passive()
        self.f.at_current = lambda: setattr(self.f, "now", 10.5)
        self.assertEqual(self.store.status("admitted").observed_at, 10.5)
        self.f.exit_error = True
        with self.assertRaises(Denied):
            self.store.status("admitted")
        self.assertFalse(self.store._db.in_transaction)

    def test_fresh_process_observes_same_row_without_backend_or_writes(self) -> None:
        self.initialize()
        self.store.close()
        path = self.root / "leases.sqlite"
        before = path.read_bytes()
        script = r"""
import sys, json, socket
sys.path.insert(0, 'tests')
from dataclasses import asdict
from unittest.mock import Mock, patch
from test_control_leases import ControlFixture, target
from browser_runtime.control_leases import PassiveStatus, LeaseStore
f=ControlFixture(sys.argv[1]); f.grant=PassiveStatus(target(1,'passive-status'),20.0)
with patch.object(socket.socket,'connect',side_effect=AssertionError('network forbidden')):
 s=LeaseStore(f.root/'leases.sqlite',authority=f,clock=lambda:10.0)
 try: print(json.dumps(asdict(s.status('admitted')),sort_keys=True))
 finally: s.close()
"""
        result = subprocess.run(
            [
                sys.executable,
                *(["-O"] if sys.flags.optimize else []),
                "-c",
                script,
                str(self.root),
            ],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(
            json.loads(result.stdout),
            asdict(ControlStatus("active", 1, AGENT, 10.0, self.scope())),
        )
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(self.f.fences(), 1)


if __name__ == "__main__":
    unittest.main()

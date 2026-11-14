"""Actual journal/site databases and process deaths, without live browser I/O."""

import hashlib
import importlib.util
import os
import socket
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from dataclasses import asdict, replace
from pathlib import Path
from typing import Any
from unittest.mock import patch

from browser_runtime.effects import Binding, Denied, Journal, Readback
from browser_testing.effect_site import Site

ROOT = Path(__file__).resolve().parents[1]
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
PAYLOAD = b"invented submission"
DIGEST = hashlib.sha256(PAYLOAD).hexdigest()
SCRIPT = """
import json,sys
from browser_runtime.effects import Binding,Journal
from browser_testing.effect_site import Site
binding=Binding(**json.loads(sys.argv[4]))
site=Site(sys.argv[2],sys.argv[3])
journal=Journal(sys.argv[1],lambda b,d: b==binding,site.submit,site.observe)
try: print(journal.dispatch(binding,b'invented submission'))
finally: journal.close()
"""


class EffectJournalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "journal.sqlite"
        self.site = Site(Path(self.tmp.name) / "site.sqlite")
        self.journal = Journal(
            self.path,
            lambda b, d: b == BINDING and d == DIGEST,
            self.site.submit,
            self.site.observe,
        )
        self.addCleanup(self.journal.close)
        self.network = patch.object(
            socket.socket, "connect", side_effect=AssertionError("network forbidden")
        )
        self.network.start()
        self.addCleanup(self.network.stop)

    def spawn(self, fault: str = "none") -> subprocess.Popen[str]:
        import json

        return subprocess.Popen(
            [
                sys.executable,
                *(["-O"] if sys.flags.optimize else []),
                "-c",
                SCRIPT,
                str(self.path),
                str(self.site.path),
                fault,
                json.dumps(asdict(BINDING)),
            ],
            env=dict(
                os.environ, PYTHONPATH=os.pathsep.join([str(ROOT), str(ROOT / "tests")])
            ),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def observe_state(self) -> list[tuple[Any, ...]]:
        with sqlite3.connect(self.path) as db:
            return db.execute(
                "SELECT operation,digest,outcome,evidence FROM operations"
            ).fetchall()

    def test_nonpersistent_sqlite_names_are_rejected(self) -> None:
        for path in ("", ":memory:", "file::memory:?cache=shared"):
            with self.assertRaises(Denied):
                Journal(path)

    def test_acknowledgment_is_unknown_until_independent_readback(self) -> None:
        self.assertEqual(self.journal.dispatch(BINDING, PAYLOAD), "unknown")
        self.assertEqual(self.site.effects(), 1)
        self.assertEqual(self.observe_state()[0][2], "unknown")
        self.assertEqual(self.journal.reconcile(BINDING, DIGEST), "confirmed")
        self.assertEqual(self.journal.dispatch(BINDING, PAYLOAD), "confirmed")
        self.assertEqual(self.site.effects(), 1)

    def test_lost_reply_and_explicit_rejection_never_resubmit(self) -> None:
        self.site.fault = "lost"
        self.assertEqual(self.journal.dispatch(BINDING, PAYLOAD), "unknown")
        self.assertEqual(self.journal.dispatch(BINDING, PAYLOAD), "unknown")
        self.assertEqual(self.site.effects(), 1)
        self.assertEqual(self.journal.reconcile(BINDING, DIGEST), "confirmed")
        binding = replace(BINDING, operation="reject-operation")
        self.journal.approve = lambda *_: True
        self.site.fault = "reject"
        self.assertEqual(self.journal.dispatch(binding, PAYLOAD), "unknown")
        self.assertEqual(self.journal.reconcile(binding, DIGEST), "rejected")
        self.assertEqual(self.journal.dispatch(binding, PAYLOAD), "rejected")
        self.assertEqual(self.site.effects(), 1)

    def test_wrong_binding_and_missing_authority_have_zero_effects(self) -> None:
        for field, value in (
            ("account", "wrong"),
            ("tab", "wrong"),
            ("epoch", 6),
            ("origin", "https://wrong.example"),
        ):
            with self.assertRaises(Denied):
                changes: dict[str, Any] = {field: value}
                self.journal.dispatch(replace(BINDING, **changes), PAYLOAD)
        self.journal.approve = None
        with self.assertRaises(Denied):
            self.journal.dispatch(BINDING, PAYLOAD)
        self.assertEqual(self.observe_state(), [])
        self.assertEqual(self.site.effects(), 0)

    def test_changed_authority_after_reservation_does_not_call_site(self) -> None:
        calls = 0

        def approve(_binding: Binding, _digest: str) -> bool:
            nonlocal calls
            calls += 1
            return calls == 1

        self.journal.approve = approve
        with self.assertRaises(Denied):
            self.journal.dispatch(BINDING, PAYLOAD)
        self.assertEqual(self.observe_state()[0][2], "unknown")
        self.assertEqual(self.site.effects(), 0)
        self.journal.approve = lambda *_: True
        self.assertEqual(self.journal.dispatch(BINDING, PAYLOAD), "unknown")
        self.assertEqual(self.site.effects(), 0)

    def test_conflicting_payload_or_identity_cannot_reuse_operation(self) -> None:
        self.journal.dispatch(BINDING, PAYLOAD)
        self.journal.approve = lambda *_: True
        for binding, payload in (
            (BINDING, b"different"),
            (replace(BINDING, revision=2), PAYLOAD),
            (replace(BINDING, epoch=8), PAYLOAD),
        ):
            with self.assertRaises(Denied):
                self.journal.dispatch(binding, payload)
        self.assertEqual(self.site.effects(), 1)

    def test_ambiguous_wrong_account_or_malformed_readback_stays_unknown(self) -> None:
        self.journal.dispatch(BINDING, PAYLOAD)
        for readback in (
            Readback(replace(BINDING, account="wrong"), DIGEST, "confirmed", "a" * 64),
            Readback(BINDING, "b" * 64, "confirmed", "a" * 64),
            Readback(BINDING, DIGEST, "unknown", "a" * 64),
            Readback(BINDING, DIGEST, "confirmed", "not-a-digest"),
        ):
            self.journal.observe = lambda *_, row=readback: row
            self.assertEqual(self.journal.reconcile(BINDING, DIGEST), "unknown")
        self.assertEqual(self.observe_state()[0][2], "unknown")
        self.assertEqual(self.journal.dispatch(BINDING, PAYLOAD), "unknown")
        self.assertEqual(self.site.effects(), 1)

    def test_authority_revoked_during_readback_keeps_unknown(self) -> None:
        self.journal.dispatch(BINDING, PAYLOAD)
        authorized = True
        self.journal.approve = lambda *_: authorized

        def readback(binding: Binding, digest: str) -> Readback:
            nonlocal authorized
            authorized = False
            return self.site.observe(binding, digest)

        self.journal.observe = readback
        with self.assertRaises(Denied):
            self.journal.reconcile(BINDING, DIGEST)
        self.assertEqual(self.observe_state()[0][2:], ("unknown", None))
        self.assertEqual(self.site.effects(), 1)
        authorized = True
        self.assertEqual(self.journal.dispatch(BINDING, PAYLOAD), "unknown")
        self.assertEqual(self.site.effects(), 1)

    def test_authority_failure_after_readback_is_redacted_and_unknown(self) -> None:
        self.journal.dispatch(BINDING, PAYLOAD)
        observed = False

        def approve(_binding: Binding, _digest: str) -> bool:
            if observed:
                raise OSError("SYNTHETIC-AUTHORITY-CANARY")
            return True

        def readback(binding: Binding, digest: str) -> Readback:
            nonlocal observed
            observed = True
            return self.site.observe(binding, digest)

        self.journal.approve = approve
        self.journal.observe = readback
        with self.assertRaises(Denied) as caught:
            self.journal.reconcile(BINDING, DIGEST)
        self.assertNotIn("SYNTHETIC-AUTHORITY-CANARY", str(caught.exception))
        self.assertEqual(self.observe_state()[0][2:], ("unknown", None))
        self.assertEqual(self.site.effects(), 1)

    def test_readback_boolean_revision_is_not_exact_binding(self) -> None:
        self.journal.dispatch(BINDING, PAYLOAD)
        malformed = replace(BINDING, revision=True)
        self.assertEqual(
            malformed,
            BINDING,
            "Python bool equality must not authorize malformed identity",
        )
        self.journal.observe = lambda *_: Readback(
            malformed, DIGEST, "confirmed", "a" * 64
        )
        self.assertEqual(self.journal.reconcile(BINDING, DIGEST), "unknown")
        self.assertEqual(self.observe_state()[0][2:], ("unknown", None))

    def test_fresh_process_crashes_before_and_after_effect_remain_fenced(self) -> None:
        for fault, count, code in (("crash_before", 0, 17), ("crash_after", 1, 18)):
            with self.subTest(fault=fault):
                self.journal.db.execute("DELETE FROM operations")
                with sqlite3.connect(self.site.path) as db:
                    db.execute("DELETE FROM events")
                child = self.spawn(fault)
                stdout, stderr = child.communicate(timeout=15)
                self.assertEqual(child.returncode, code, (stdout, stderr))
                self.assertEqual(self.observe_state()[0][2], "unknown")
                restarted = self.spawn()
                output, error = restarted.communicate(timeout=15)
                self.assertEqual(restarted.returncode, 0, error)
                self.assertEqual(output.strip(), "unknown")
                self.assertEqual(self.site.effects(), count)
                self.assertEqual(
                    self.journal.reconcile(BINDING, DIGEST),
                    "confirmed" if count else "unknown",
                )

    def test_concurrent_processes_make_one_effect(self) -> None:
        children = [self.spawn(), self.spawn()]
        try:
            for child in children:
                output, error = child.communicate(timeout=15)
                self.assertEqual(child.returncode, 0, error)
                self.assertEqual(output.strip(), "unknown")
        finally:
            for child in children:
                if child.poll() is None:
                    child.kill()
                child.wait(timeout=5)
        self.assertEqual(self.site.effects(), 1)

    def test_inflight_transaction_prevents_premature_readback(self) -> None:
        self.journal.dispatch(BINDING, PAYLOAD)
        calls: list[object] = []

        def observer(binding: Binding, digest: str) -> Readback:
            calls.append(binding)
            return Readback(binding, digest, "confirmed", "a" * 64)

        other = Journal(self.path, lambda *_: True, observe=observer)
        self.addCleanup(other.close)
        self.journal.db.execute("BEGIN IMMEDIATE")
        try:
            with self.assertRaises(Denied):
                other.reconcile(BINDING, DIGEST)
        finally:
            self.journal.db.execute("ROLLBACK")
        self.assertEqual(calls, [])

    def test_failed_durable_insert_prevents_external_effect(self) -> None:
        self.journal.db.execute(
            "CREATE TRIGGER deny_insert BEFORE INSERT ON operations BEGIN SELECT RAISE(ABORT, 'synthetic storage failure'); END"
        )
        with self.assertRaises(sqlite3.Error):
            self.journal.dispatch(BINDING, PAYLOAD)
        self.assertEqual(self.observe_state(), [])
        self.assertEqual(self.site.effects(), 0)

    def test_raw_payload_and_response_are_not_in_journal(self) -> None:
        self.journal.approve = lambda *_: True
        secret_payload = b"SYNTHETIC-PAYLOAD-CANARY"

        def lost(_binding: Binding, _payload: bytes) -> None:
            raise ValueError("SYNTHETIC-RESPONSE-CANARY")

        self.journal.submit = lost
        self.assertEqual(self.journal.dispatch(BINDING, secret_payload), "unknown")
        dumped = "\n".join(self.journal.db.iterdump())
        self.assertNotIn("SYNTHETIC-PAYLOAD-CANARY", dumped)
        self.assertNotIn("SYNTHETIC-RESPONSE-CANARY", dumped)

    def test_deliberate_duplicate_effect_mutation_is_observed(self) -> None:
        source = (ROOT / "browser_runtime/effects.py").read_text()
        anchor = "return self._outcome(row[2])"
        self.assertEqual(source.count(anchor), 1)
        mutated = source.replace(
            anchor, "self.submit(binding, payload)\n                " + anchor
        )
        path = Path(self.tmp.name) / "mutated_effects.py"
        path.write_text(mutated)
        spec = importlib.util.spec_from_file_location("mutated_effects", path)
        if spec is None or spec.loader is None:
            raise RuntimeError("mutation loader missing")
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        self.addCleanup(sys.modules.pop, spec.name)
        spec.loader.exec_module(module)
        journal = module.Journal(
            Path(self.tmp.name) / "mutant.sqlite", lambda *_: True, self.site.submit
        )
        try:
            journal.dispatch(BINDING, PAYLOAD)
            journal.dispatch(BINDING, PAYLOAD)
        finally:
            journal.close()
        self.assertEqual(
            self.site.effects(),
            2,
            "broken duplicate guard must create an independently observed extra effect",
        )

    def test_cancellation_after_effect_preserves_unknown(self) -> None:
        def cancelled(binding: Binding, payload: bytes) -> None:
            self.site.submit(binding, payload)
            raise KeyboardInterrupt("synthetic cancellation")

        self.journal.submit = cancelled
        with self.assertRaises(KeyboardInterrupt):
            self.journal.dispatch(BINDING, PAYLOAD)
        self.assertEqual(self.observe_state()[0][2], "unknown")
        self.assertEqual(self.journal.dispatch(BINDING, PAYLOAD), "unknown")
        self.assertEqual(self.site.effects(), 1)

"""Invented values, independent protocol peer; no network or browser access."""

import contextlib
import hashlib
import json
import tempfile
import subprocess
import sys
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from browser_runtime.autosave import Autosave, Login, Writer, MARKER
from browser_runtime.credentials import Observation
from browser_runtime.effects import Cancelled, Journal
from browser_runtime.openbao import Response, Vault
from test_openbao import Fixture, CANARY


class ExternalEffects:
    """Test-only external owner adapts the legacy store during relocation.

    This fixture, not Autosave, owns the path, open, close and recovery lifecycle.
    The production external owner belongs outside Browser.
    """

    def __init__(self, path):
        self.path = path

    def execute(
        self,
        *,
        binding,
        payload,
        target_digest,
        approve,
        submit,
        observe,
        reconcile_only,
    ):
        journal = Journal(self.path, approve=approve, submit=submit, observe=observe)
        try:
            if not reconcile_only:
                journal.dispatch(binding, payload, target_digest=target_digest)
            return journal.reconcile(
                binding,
                hashlib.sha256(payload).hexdigest(),
                target_digest=target_digest,
            )
        finally:
            journal.close()


class Harness(Fixture):
    def __init__(self, path):
        super().__init__()
        del self.current
        self.path = path
        self.opt_in = True
        self.expected = 0
        self.posts = 0
        self.captures = 0
        self.gets = 0
        self.records = {}
        self.login_ok = True
        self.lost = False
        self.offline = False
        self.wrong_marker = False
        self.observed = self.g.target
        self.ticket = object()
        self.callback = lambda: None
        self.username = "synthetic-user"
        self.suppress = False
        self.v = Vault(
            (self.m,),
            transport=self.transport,
            token=self.token,
            authorize=lambda g: self.allowed and g == self.g,
            clock=lambda: self.now,
        )

    @contextlib.contextmanager
    def acquire(self):
        try:
            yield self
        except Exception:
            if not self.suppress:
                raise

    def admit(self, ticket):
        return self.g if ticket is self.ticket else None

    def observe(self):
        return Observation(self.observed, self.now)

    def current(self, grant):
        return self.allowed and grant == self.g

    def consent(self, grant):
        return self.expected if self.opt_in and grant == self.g else None

    def capture(self, grant):
        self.captures += 1
        self.callback()
        return Login(self.username, CANARY, self.login_ok)

    def peer(self, method, path, token, timeout, body):
        if self.offline:
            raise RuntimeError(CANARY)
        if method == "POST":
            self.posts += 1
            data = json.loads(body)
            expected = data["options"]["cas"]
            if expected != len(self.records):
                return Response(400, b"{}")
            current = expected + 1
            self.records[current] = data["data"]
            if self.wrong_marker:
                self.records[current][MARKER] = "wrong"
            if self.lost:
                raise TimeoutError(CANARY)
            return Response(200, json.dumps({"data": {"version": current}}).encode())
        self.gets += 1
        if "/metadata/" in path:
            return Response(
                200,
                json.dumps(
                    {
                        "data": {
                            "current_version": len(self.records),
                            "versions": {
                                str(v): {"deletion_time": "", "destroyed": False}
                                for v in self.records
                            },
                        }
                    }
                ).encode(),
            )
        selected = (
            int(path.split("?version=")[1])
            if "?version=" in path
            else len(self.records)
        )
        if selected not in self.records:
            return Response(404, b"{}")
        return Response(
            200,
            json.dumps(
                {
                    "data": {
                        "data": self.records[selected],
                        "metadata": {
                            "version": selected,
                            "deletion_time": "",
                            "destroyed": False,
                        },
                    }
                }
            ).encode(),
        )

    def service(self):
        return Autosave(
            ExternalEffects(self.path),
            authority=self,
            writer=Writer(self.v, self.peer),
            consent=self.consent,
            capture=self.capture,
            clock=lambda: self.now,
        )


class AutosaveTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.f = Harness(Path(self.tmp.name) / "existing-effects.sqlite")

    def test_normal_login_saves_and_replay_does_not_recapture_or_write(self):
        f = self.f
        self.assertEqual(f.service().run(f.ticket), "saved")
        self.assertEqual(f.records[1]["password"], CANARY)
        self.assertEqual((f.posts, f.captures), (1, 1))
        self.assertEqual(f.service().run(f.ticket), "saved")
        self.assertEqual((f.posts, f.captures), (1, 1))
        self.assertNotIn(CANARY.encode(), f.path.read_bytes())
        self.assertNotIn(
            hashlib.sha256(CANARY.encode()).hexdigest().encode(), f.path.read_bytes()
        )
        self.assertNotIn(CANARY, repr(Login("u", CANARY, True)))

    def test_missing_opt_in_and_forged_ticket_have_zero_capture_token_http(self):
        f = self.f
        f.opt_in = False
        self.assertEqual(f.service().run(f.ticket), "not_saved")
        f.opt_in = True
        self.assertEqual(f.service().run(object()), "not_saved")
        self.assertEqual((f.captures, f.tokens, f.posts, f.gets), (0, 0, 0, 0))

    def test_every_target_mismatch_denies_before_capture(self):
        f = self.f
        for field, value in [
            ("account", "other"),
            ("principal", "other"),
            ("epoch", 2),
            ("origin", "https://other.invalid"),
            ("browser", "other"),
            ("tab", "other"),
        ]:
            f.observed = replace(
                f.g.target, binding=replace(f.g.target.binding, **{field: value})
            )
            self.assertEqual(f.service().run(f.ticket), "not_saved")
        for field, value in [
            ("native_session", "other"),
            ("frame", "other"),
            ("frame_origin", "https://other.invalid"),
        ]:
            f.observed = replace(f.g.target, **{field: value})
            self.assertEqual(f.service().run(f.ticket), "not_saved")
        self.assertEqual((f.posts, f.captures, f.tokens), (0, 0, 0))

    def test_expired_and_boolean_consent_deny(self):
        f = self.f
        f.now = f.g.deadline
        self.assertEqual(f.service().run(f.ticket), "not_saved")
        f.now = 10
        f.expected = True
        self.assertEqual(f.service().run(f.ticket), "not_saved")
        self.assertEqual(f.posts, 0)

    def test_capture_redirect_revocation_and_failed_login_do_not_write(self):
        for change in (
            lambda f: setattr(f, "allowed", False),
            lambda f: setattr(f, "opt_in", False),
            lambda f: setattr(f, "login_ok", False),
            lambda f: setattr(f, "observed", replace(f.g.target, frame="changed")),
        ):
            with self.subTest(change=change):
                f = Harness(Path(self.tmp.name) / str(id(change)))
                f.callback = lambda: change(f)
                self.assertIn(f.service().run(f.ticket), ("unknown", "not_saved"))
                self.assertEqual(f.posts, 0)

    def test_lost_response_reconciles_without_second_post(self):
        f = self.f
        f.lost = True
        self.assertEqual(f.service().run(f.ticket), "saved")
        self.assertEqual(f.service().run(f.ticket, reconcile_only=True), "saved")
        self.assertEqual((f.posts, f.captures), (1, 1))

    def test_outage_does_not_store_plaintext_or_retry(self):
        f = self.f
        f.offline = True
        self.assertEqual(f.service().run(f.ticket), "unknown")
        f.offline = False
        self.assertEqual(f.service().run(f.ticket), "unknown")
        self.assertEqual(f.captures, 1)
        self.assertEqual(f.posts, 0)
        for p in Path(self.tmp.name).iterdir():
            self.assertNotIn(CANARY.encode(), p.read_bytes())

    def test_wrong_operation_marker_is_not_success(self):
        f = self.f
        f.wrong_marker = True
        self.assertEqual(f.service().run(f.ticket), "unknown")
        self.assertEqual(f.posts, 1)

    def test_update_preserves_other_fields_and_checks_username(self):
        f = self.f
        f.records[1] = {"username": f.username, "password": "old", "other": "keep"}
        f.expected = 1
        self.assertEqual(f.service().run(f.ticket), "saved")
        self.assertEqual(f.records[2]["other"], "keep")
        self.assertEqual(f.records[2]["password"], CANARY)

    def test_account_change_does_not_overwrite(self):
        f = self.f
        f.records[1] = {"username": "other-account", "password": "old"}
        f.expected = 1
        self.assertEqual(f.service().run(f.ticket), "unknown")
        self.assertEqual(f.posts, 0)
        self.assertEqual(f.records[1]["password"], "old")

    def test_concurrent_version_conflict_does_not_post(self):
        f = self.f
        f.records = {1: {"username": f.username}, 2: {"username": f.username}}
        f.expected = 1
        self.assertEqual(f.service().run(f.ticket), "unknown")
        self.assertEqual(f.posts, 0)

    def test_cancellation_has_no_secret_context_and_no_replay(self):
        f = self.f

        def cancel():
            raise KeyboardInterrupt(CANARY)

        f.callback = cancel
        with self.assertRaises(Cancelled) as caught:
            f.service().run(f.ticket)
        self.assertIsNone(caught.exception.__context__)
        self.assertNotIn(CANARY, str(caught.exception))
        f.callback = lambda: None
        self.assertEqual(f.service().run(f.ticket), "unknown")
        self.assertEqual((f.posts, f.captures), (0, 1))

    def test_revocation_in_token_callback_blocks_network(self):
        f = self.f

        def revoke():
            f.opt_in = False
            return "synthetic-token"

        f.v._token = revoke
        self.assertEqual(f.service().run(f.ticket), "unknown")
        self.assertEqual((f.posts, f.gets), (0, 0))

    def test_mutation_removing_observation_check_breaks_zero_write_invariant(self):
        f = self.f
        f.observed = replace(f.g.target, frame="wrong")
        with patch.object(Autosave, "_check", return_value=None):
            self.assertEqual(f.service().run(f.ticket), "saved")
        self.assertEqual(f.posts, 1)  # Independent spy catches the deliberate bug.

    def test_suppressing_guard_cannot_turn_failed_admission_into_success(self):
        f = self.f
        f.suppress = True
        f.opt_in = False
        self.assertEqual(f.service().run(f.ticket), "not_saved")
        self.assertEqual(f.posts, 0)

    def test_final_vault_authorization_cannot_retarget_post(self):
        f = self.f
        calls = []

        def mutate(grant):
            calls.append(grant)
            if len(calls) == 3:
                f.observed = replace(f.g.target, frame="changed")
            return True

        f.v._authorize = mutate
        self.assertEqual(f.service().run(f.ticket), "unknown")
        self.assertEqual(f.posts, 0)

    def test_consent_callback_cannot_hide_target_change(self):
        f = self.f

        def consent(grant):
            f.observed = replace(f.g.target, frame="changed")
            return 0

        f.consent = consent
        self.assertEqual(f.service().run(f.ticket), "not_saved")
        self.assertEqual((f.posts, f.captures), (0, 0))

    def test_suppressed_or_replaced_cancellation_still_propagates_sanitized(self):
        for replacement in (False, True):
            with self.subTest(replacement=replacement):
                f = Harness(Path(self.tmp.name) / str(replacement))

                @contextlib.contextmanager
                def guard():
                    try:
                        yield f
                    except BaseException:
                        if replacement:
                            raise RuntimeError(CANARY)

                f.acquire = guard

                def cancel():
                    raise KeyboardInterrupt(CANARY)

                f.callback = cancel
                with self.assertRaises(Cancelled) as caught:
                    f.service().run(f.ticket)
                self.assertIsNone(caught.exception.__context__)
                self.assertNotIn(CANARY, str(caught.exception))
                self.assertEqual(f.posts, 0)

    def test_unchanged_password_does_not_add_vault_version(self):
        f = self.f
        f.records[1] = {"username": f.username, "password": CANARY}
        f.expected = 1
        self.assertEqual(f.service().run(f.ticket), "saved")
        self.assertEqual((f.posts, len(f.records)), (0, 1))

    def test_fresh_process_reopens_existing_journal_without_capture_or_post(self):
        f = self.f
        self.assertEqual(f.service().run(f.ticket), "saved")
        script = """
import json, sys
from pathlib import Path
sys.path.insert(0, 'tests')
from test_autosave import Harness
f = Harness(Path(sys.argv[1]))
f.records = {int(k): v for k, v in json.load(sys.stdin).items()}
print(json.dumps([f.service().run(f.ticket), f.posts, f.captures]))
"""
        completed = subprocess.run(
            [sys.executable, "-c", script, str(f.path)],
            input=json.dumps(f.records),
            text=True,
            capture_output=True,
            timeout=20,
            check=True,
        )
        self.assertEqual(json.loads(completed.stdout), ["saved", 0, 0])
        self.assertNotIn(CANARY, completed.stdout + completed.stderr)

    def test_saved_record_can_use_existing_vault_handle_path(self):
        f = self.f
        self.assertEqual(f.service().run(f.ticket), "saved")
        reader = Vault(
            (f.m,),
            transport=lambda p, t, d: f.peer("GET", p, t, d, None),
            token=f.token,
            authorize=lambda g: f.allowed and g == f.g,
            clock=lambda: f.now,
        )
        handle = reader.read(f.g)
        received = []

        def sink(secret):
            received.append(secret)
            return True

        self.assertTrue(reader.consume(handle, f.g, sink))
        self.assertEqual(received, [CANARY])
        self.assertFalse(reader.consume(handle, f.g, sink))

    def test_browser_does_not_open_or_own_storage(self):
        f = self.f

        class ExternalOwner:
            def execute(
                self,
                *,
                binding,
                payload,
                target_digest,
                approve,
                submit,
                observe,
                reconcile_only,
            ):
                if not approve(binding, hashlib.sha256(payload).hexdigest()):
                    return "unknown"
                submit(binding, payload)
                return observe(binding, hashlib.sha256(payload).hexdigest()).outcome

        service = f.service()
        service.effects = ExternalOwner()
        with patch(
            "sqlite3.connect", side_effect=AssertionError("Browser opened storage")
        ):
            self.assertEqual(service.run(f.ticket), "saved")
        self.assertEqual(list(Path(self.tmp.name).iterdir()), [])
        self.assertFalse(hasattr(service, "path"))

    def test_external_owner_cannot_hide_callback_cancellation(self):
        f = self.f

        class SuppressingOwner:
            def execute(self, **kwargs):
                try:
                    kwargs["submit"](kwargs["binding"], kwargs["payload"])
                except BaseException:
                    return "confirmed"

        def cancel():
            raise KeyboardInterrupt(CANARY)

        f.callback = cancel
        service = f.service()
        service.effects = SuppressingOwner()
        with self.assertRaises(Cancelled) as caught:
            service.run(f.ticket)
        self.assertIsNone(caught.exception.__context__)
        self.assertNotIn(CANARY, str(caught.exception))
        self.assertEqual(f.posts, 0)

    def test_external_owner_cannot_reuse_callbacks_after_return(self):
        f = self.f
        retained = {}

        class ExternalOwner:
            def execute(self, **kwargs):
                retained.update(kwargs)
                kwargs["submit"](kwargs["binding"], kwargs["payload"])
                return kwargs["observe"](
                    kwargs["binding"], hashlib.sha256(kwargs["payload"]).hexdigest()
                ).outcome

        service = f.service()
        service.effects = ExternalOwner()
        self.assertEqual(service.run(f.ticket), "saved")
        counts = (f.captures, f.posts, f.tokens)
        with self.assertRaises(ValueError):
            retained["submit"](retained["binding"], retained["payload"])
        with self.assertRaises(ValueError):
            retained["approve"](
                retained["binding"], hashlib.sha256(retained["payload"]).hexdigest()
            )
        self.assertEqual((f.captures, f.posts, f.tokens), counts)


if __name__ == "__main__":
    unittest.main()

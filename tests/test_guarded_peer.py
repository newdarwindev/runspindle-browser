"""Stateless peer component tests; authority/site are synthetic, no Core bridge."""

import json
import tempfile
import unittest
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import replace
from unittest.mock import patch

from browser_runtime.effect_wire import Receiver
from browser_runtime.effects import Cancelled, Denied, Readback
from browser_runtime.guarded_peer import Grant, Guard, GuardedPeer
from tests.test_effect_wire import encoded, request
from tests.test_guarded_effects import DIGEST, PAYLOAD, TARGET, Fixture


class StatelessPeerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.f = Fixture(self.tmp.name)
        self.peer = GuardedPeer(authority=self.f, site=self.f, clock=lambda: self.f.now)

    def test_wire_dispatch_unknown_reconcile_only_without_database(self) -> None:
        with patch(
            "sqlite3.connect", side_effect=AssertionError("no Browser database")
        ):
            wire = Receiver(self.peer)
            self.assertEqual(
                json.loads(wire.exchange(encoded(request()), "admitted"))["outcome"],
                "unknown",
            )
            self.f.grant = replace(self.f.grant, action="reconcile")
            self.assertEqual(
                json.loads(wire.exchange(encoded(request("reconcile")), "admitted"))[
                    "outcome"
                ],
                "confirmed",
            )
        self.assertEqual((self.f.effects(), self.f.reads), (1, 1))
        self.assertFalse(hasattr(self.peer, "_journal"))

    def test_no_authority_or_wire_supplied_target_can_authorize(self) -> None:
        with self.assertRaises(Denied):
            GuardedPeer().dispatch("admitted", PAYLOAD)
        with self.assertRaises(Denied):
            self.peer.dispatch("forged", PAYLOAD)
        with self.assertRaises(Denied):
            self.peer.dispatch(
                "admitted",
                PAYLOAD,
                expected_target=replace(TARGET, frame="other"),
                expected_digest=DIGEST,
            )
        self.assertEqual(self.f.effects(), 0)

    def test_lost_ack_does_not_claim_success_and_reconcile_never_submits(self) -> None:
        self.f.lost = True
        self.assertEqual(self.peer.dispatch("admitted", PAYLOAD), "unknown")
        self.f.grant = replace(self.f.grant, action="reconcile")
        recreated = GuardedPeer(authority=self.f, site=self.f, clock=lambda: self.f.now)
        self.assertEqual(recreated.reconcile("admitted"), "confirmed")
        self.assertEqual(self.f.effects(), 1)

    def test_replay_policy_is_external_not_hidden_peer_state(self) -> None:
        # This intentionally demonstrates why only the canonical owner may call
        # dispatch. The peer must not pretend to have a second replay ledger.
        self.assertEqual(self.peer.dispatch("admitted", PAYLOAD), "unknown")
        self.assertEqual(self.peer.dispatch("admitted", PAYLOAD), "unknown")
        self.assertEqual(self.f.effects(), 2)

    def test_wrong_readback_or_expired_authority_never_confirms(self) -> None:
        self.f.grant = replace(self.f.grant, action="reconcile")
        for readback in (
            Readback(
                replace(TARGET.binding, operation="other"),
                DIGEST,
                "confirmed",
                "a" * 64,
            ),
            Readback(TARGET.binding, DIGEST, "confirmed", "not-evidence"),
        ):
            with patch.object(self.f, "readback", return_value=readback):
                self.assertEqual(self.peer.reconcile("admitted"), "unknown")
        self.f.allowed = False
        with self.assertRaises(Denied):
            self.peer.reconcile("admitted")
        self.assertEqual(self.f.effects(), 0)

    def test_post_submit_revocation_cannot_claim_authorized_result(self) -> None:
        original = self.f.submit

        def revoke(grant: Grant, payload: bytes, guard: Guard) -> None:
            original(grant, payload, guard)
            self.f.allowed = False

        with patch.object(self.f, "submit", revoke), self.assertRaises(Denied):
            self.peer.dispatch("admitted", PAYLOAD)
        self.assertEqual(self.f.effects(), 1)  # external owner must retain unknown

    def test_suppressed_cancellation_stays_redacted(self) -> None:
        f = self.f

        @contextmanager
        def suppress() -> Iterator[Fixture]:
            f.active = True
            try:
                yield f
            except BaseException:
                pass
            finally:
                f.active = False

        f.cancel = True
        with (
            patch.object(f, "acquire", suppress),
            self.assertRaises(Cancelled) as caught,
        ):
            self.peer.dispatch("admitted", PAYLOAD)
        self.assertIsNone(caught.exception.__context__)
        self.assertNotIn("SYNTHETIC", str(caught.exception))
        self.assertEqual(f.effects(), 1)


if __name__ == "__main__":
    unittest.main()

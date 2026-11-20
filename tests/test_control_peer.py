from __future__ import annotations

import hashlib
import inspect
import json
import textwrap
import unittest
from contextlib import contextmanager
from dataclasses import asdict, replace
from pathlib import Path
from typing import Any, Callable, Iterator, cast
from unittest.mock import patch

from browser_runtime import control_peer
from browser_runtime.control_leases import (
    FenceObservation,
    FenceReceipt,
    Holder,
    Recovery,
    Transfer,
    _scope,
)
from browser_runtime.control_peer import DOMAIN, ControlPeer, core_scope
from browser_runtime.credentials import Observation, Target
from browser_runtime.effect_wire import VERSION
from browser_runtime.effects import Binding, Cancelled, Denied


def initial() -> Transfer:
    target = Target(
        Binding(
            "principal",
            "account",
            "browser",
            "tab",
            "intent",
            1,
            "operation",
            1,
            "https://example.invalid",
        ),
        "session",
        "frame",
        "https://example.invalid",
    )
    intent = "browser-control:" + hashlib.sha256(_scope(target).encode()).hexdigest()
    target = replace(target, binding=replace(target.binding, intent=intent))
    return Transfer(target, "initialize", None, Holder("agent", "agent"), 0, 20.0)


def payload(transfer: Transfer) -> bytes:
    previous = (
        None
        if transfer.action == "initialize"
        else {"operation": "previous", "payload_digest": "a" * 64, "generation": 1}
    )
    return json.dumps(
        {
            "version": DOMAIN,
            "action": transfer.action,
            "source": asdict(transfer.source) if transfer.source else None,
            "destination": asdict(transfer.destination),
            "predecessor": previous,
        },
        separators=(",", ":"),
    ).encode()


def wire(transfer: Transfer, data: bytes, action: str) -> bytes:
    return json.dumps(
        {
            "version": VERSION,
            "action": action,
            "target": asdict(transfer.target),
            "payload_digest": hashlib.sha256(data).hexdigest(),
            "payload_hex": data.hex() if action == "dispatch" else None,
        },
        separators=(",", ":"),
    ).encode()


class Harness:
    def __init__(self) -> None:
        self.transfer = initial()
        self.grant: Transfer | Recovery = self.transfer
        self.observed = Observation(self.transfer.target, 10.0)
        self.proof = self.release = self.current_value = True
        self.calls = self.reads = 0
        self.receipt: FenceObservation | None = FenceObservation(
            self.transfer, True, 10.0
        )
        self.fail: BaseException | None = None
        self.suppress = False
        self.after_fence: Callable[[], None] = lambda: None
        self.peer = ControlPeer(self, self, self, clock=lambda: 10.0)

    @contextmanager
    def acquire(self) -> Iterator[Harness]:
        try:
            yield self
        except BaseException:
            if not self.suppress:
                raise

    def admit(self, ticket: object) -> Any:
        return self.grant if ticket is self else None

    def current(self, grant: object) -> bool:
        return self.current_value

    def observe(self) -> Observation:
        return self.observed

    def initialization_proven(self, transfer: Transfer) -> bool:
        return self.proof

    def released(self, grant: object) -> bool:
        return self.release

    def fence(self, transfer: Transfer, guard: Any) -> FenceReceipt:
        self.calls += 1
        if self.fail:
            raise self.fail
        self.after_fence()
        return FenceReceipt(transfer, True)

    def inspect(self, recovery: Recovery, guard: Any) -> FenceObservation | None:
        self.reads += 1
        if self.fail:
            raise self.fail
        return self.receipt

    def exchange(self, action: str = "dispatch", data: bytes | None = None) -> str:
        data = payload(self.transfer) if data is None else data
        return cast(
            str,
            json.loads(
                self.peer.exchange(
                    wire(self.transfer, data, action), self, retained_payload=data
                )
            )["outcome"],
        )


class ControlPeerTests(unittest.TestCase):
    def test_dispatch_unknown_and_fresh_readback_confirmed(self) -> None:
        h = Harness()
        self.assertEqual(h.exchange(), "unknown")
        self.assertEqual((h.calls, h.reads), (1, 0))
        h.grant = Recovery(h.transfer, 30.0)
        self.assertEqual(h.exchange("reconcile"), "confirmed")
        self.assertEqual((h.calls, h.reads), (1, 1))

    def test_no_store_or_deduplication_is_claimed(self) -> None:
        h = Harness()
        h.exchange()
        h.peer = ControlPeer(h, h, h, clock=lambda: 10.0)
        h.exchange()
        self.assertEqual(h.calls, 2)  # Core, not this adapter, must reserve.

    def test_wire_may_not_create_ticket_or_switch_action(self) -> None:
        h = Harness()
        with self.assertRaises(Denied):
            h.peer.exchange(
                wire(h.transfer, payload(h.transfer), "dispatch"),
                object(),
                retained_payload=payload(h.transfer),
            )
        with self.assertRaises(Denied):
            h.exchange("reconcile")
        h.grant = Recovery(h.transfer, 30.0)
        with self.assertRaises(Denied):
            h.exchange()
        self.assertEqual((h.calls, h.reads), (0, 0))

    def test_wrong_owner_payload_or_scope_denied_before_fence(self) -> None:
        for change in ("destination", "version", "predecessor", "extra"):
            h = Harness()
            data = json.loads(payload(h.transfer))
            data[change] = "wrong"
            with self.assertRaises(Denied):
                h.exchange(data=json.dumps(data).encode())
            self.assertEqual(h.calls, 0)
        h = Harness()
        h.observed = replace(
            h.observed, target=replace(h.transfer.target, frame="other")
        )
        with self.assertRaises(Denied):
            h.exchange()
        self.assertEqual(h.calls, 0)

    def test_initialization_and_handback_need_distinct_proofs(self) -> None:
        h = Harness()
        h.proof = False
        with self.assertRaises(Denied):
            h.exchange()
        h = Harness()
        target = replace(
            h.transfer.target,
            binding=replace(h.transfer.target.binding, epoch=3, revision=3),
        )
        h.transfer = Transfer(
            target,
            "handback",
            Holder("human", "human"),
            Holder("agent", "agent"),
            2,
            20.0,
        )
        h.grant = h.transfer
        h.release = False
        with self.assertRaises(Denied):
            h.exchange()
        self.assertEqual(h.calls, 0)

    def test_exact_fresh_closure_required(self) -> None:
        for observation in (
            None,
            FenceObservation(initial(), False, 10.0),
            FenceObservation(initial(), True, 0.0),
            FenceObservation(replace(initial(), deadline=99.0), True, 10.0),
        ):
            h = Harness()
            h.grant = Recovery(h.transfer, 30.0)
            h.receipt = observation
            self.assertEqual(h.exchange("reconcile"), "unknown")
            self.assertEqual(h.calls, 0)

    def test_foreign_transfer_equality_cannot_confirm_closure(self) -> None:
        h = Harness()
        h.grant = Recovery(h.transfer, 30.0)
        comparisons: list[object] = []

        class Foreign:
            def __eq__(self, value: object) -> bool:
                comparisons.append(value)
                return True

        h.receipt = FenceObservation(cast(Transfer, Foreign()), True, 10.0)
        self.assertEqual(h.exchange("reconcile"), "unknown")
        self.assertEqual(comparisons, [])
        self.assertEqual((h.calls, h.reads), (0, 1))

    def test_guard_callback_cannot_replace_admitted_destination_before_fence(
        self,
    ) -> None:
        h = Harness()

        def change_destination(grant: object) -> bool:
            object.__setattr__(grant, "destination", Holder("agent", "different-agent"))
            return True

        with patch.object(h, "current", side_effect=change_destination):
            with self.assertRaises(Denied):
                h.exchange()
        self.assertEqual(h.calls, 0, "changed holder must never reach the native fence")

    def test_removing_final_grant_check_reaches_the_native_fence(self) -> None:
        source = textwrap.dedent(inspect.getsource(ControlPeer._check))
        anchor = "if asdict(grant) != admitted:"
        self.assertEqual(source.count(anchor), 2)
        before, after = source.rsplit(anchor, 1)
        scope = dict(vars(control_peer))
        exec(before + "if False:" + after, scope)
        with patch.object(ControlPeer, "_check", scope["_check"]):
            result = unittest.TestResult()
            ControlPeerTests(
                "test_guard_callback_cannot_replace_admitted_destination_before_fence"
            ).run(result)
        self.assertEqual(len(result.failures), 1)
        self.assertEqual(result.errors, [])
        self.assertIn("changed holder must never reach", result.failures[0][1])

    def test_closure_cannot_be_upgraded_by_later_authority_callback(self) -> None:
        h = Harness()
        h.grant = Recovery(h.transfer, 30.0)
        receipt = FenceObservation(h.transfer, False, 10.0)
        h.receipt = receipt

        def upgrade_closure(_: object) -> bool:
            if h.reads:
                object.__setattr__(receipt, "previous_inputs_closed", True)
            return True

        with patch.object(h, "current", side_effect=upgrade_closure):
            self.assertEqual(h.exchange("reconcile"), "unknown")
        self.assertTrue(receipt.previous_inputs_closed)
        self.assertEqual((h.calls, h.reads), (0, 1))

    def test_expired_observation_current_authority_and_deadline_denied(self) -> None:
        for kind in ("age", "authority", "deadline"):
            h = Harness()
            if kind == "age":
                h.observed = replace(h.observed, observed_at=0.0)
            elif kind == "authority":
                h.current_value = False
            else:
                h.grant = replace(h.transfer, deadline=10.0)
            with self.assertRaises(Denied):
                h.exchange()
            self.assertEqual(h.calls, 0)

    def test_suppressed_cancellation_and_exception_are_sanitized(self) -> None:
        for error in (KeyboardInterrupt("private"), RuntimeError("private")):
            for action in ("dispatch", "reconcile"):
                h = Harness()
                if action == "reconcile":
                    h.grant = Recovery(h.transfer, 30.0)
                h.fail = error
                h.suppress = True
                expected = Cancelled if isinstance(error, KeyboardInterrupt) else Denied
                with self.assertRaises(expected) as raised:
                    h.exchange(action)
                self.assertNotIn("private", str(raised.exception))
                self.assertIsNone(raised.exception.__context__)

    def test_external_retained_bytes_commitment_required(self) -> None:
        h = Harness()
        with self.assertRaises(Denied):
            h.peer.exchange(
                wire(h.transfer, payload(h.transfer), "dispatch"),
                h,
                retained_payload=b"{}",
            )
        self.assertEqual(h.calls, 0)

    def test_takeover_and_handback_mapping_with_fresh_release(self) -> None:
        for action, epoch, source, destination in (
            ("takeover", 2, Holder("agent", "agent"), Holder("human", "human")),
            ("handback", 3, Holder("human", "human"), Holder("agent", "agent")),
        ):
            h = Harness()
            target = replace(
                h.transfer.target,
                binding=replace(h.transfer.target.binding, epoch=epoch, revision=epoch),
            )
            h.transfer = Transfer(target, action, source, destination, epoch - 1, 20.0)
            h.grant = h.transfer
            self.assertEqual(h.exchange(), "unknown")
            h.grant = Recovery(h.transfer, 30.0)
            h.receipt = FenceObservation(h.transfer, True, 10.0)
            self.assertEqual(h.exchange("reconcile"), "confirmed")
            self.assertEqual((h.calls, h.reads), (1, 1))

    def test_authority_loss_after_native_effect_never_confirms(self) -> None:
        h = Harness()

        def lose_authority() -> None:
            h.current_value = False

        h.after_fence = lose_authority
        with self.assertRaises(Denied):
            h.exchange()
        self.assertEqual(h.calls, 1)
        # Core has already retained unknown; this failure grants no retry.

    def test_no_database_constructor_during_control_exchange(self) -> None:
        h = Harness()
        with patch("sqlite3.connect", side_effect=AssertionError("no Browser store")):
            self.assertEqual(h.exchange(), "unknown")
            h.grant = Recovery(h.transfer, 30.0)
            self.assertEqual(h.exchange("reconcile"), "confirmed")

    def test_literal_core_utf8_scope_vectors_preserve_legacy_scope(self) -> None:
        # Produced by Core control library 9521ba0/merged4a7bb93, not by this helper.
        fixture = json.loads(
            (Path(__file__).parent / "fixtures/core_control_scope.json").read_text()
        )
        for vector in fixture["vectors"]:
            origin = vector["origin"]
            expected = vector["intent"].split(":", 1)[1]
            h = Harness()
            target = replace(
                h.transfer.target,
                binding=replace(
                    h.transfer.target.binding,
                    origin=origin,
                    intent="browser-control:" + expected,
                ),
                frame_origin=origin,
            )
            self.assertEqual(core_scope(target).decode(), vector["canonical_scope"])
            self.assertEqual(hashlib.sha256(core_scope(target)).hexdigest(), expected)
            h.transfer = replace(h.transfer, target=target)
            h.grant = h.transfer
            h.observed = Observation(target, 10.0)
            self.assertEqual(h.exchange(), "unknown")
            if "bücher" in origin:
                self.assertIn("\\u00fc", _scope(target))
                self.assertNotEqual(
                    hashlib.sha256(_scope(target).encode()).hexdigest(), expected
                )


if __name__ == "__main__":
    unittest.main()

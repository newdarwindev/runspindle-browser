from __future__ import annotations

import hashlib
import inspect
import json
import unittest
from contextlib import contextmanager
from dataclasses import asdict, replace
from typing import Callable, Iterator, cast
from unittest.mock import patch

from browser_runtime import passive_peer
from browser_runtime.control_leases import Holder, PassiveStatus, Transfer
from browser_runtime.credentials import Observation, Target
from browser_runtime.effects import Binding, Cancelled, Denied
from browser_runtime.passive_peer import PassivePeer, selection_digest


def target() -> Target:
    return Target(
        Binding(
            "principal",
            "account",
            "browser",
            "tab",
            "task",
            2,
            "operation",
            5,
            "https://example.invalid",
        ),
        "native",
        "frame",
        "https://frame.invalid",
    )


class Guard:
    def __init__(self) -> None:
        self.ticket = object()
        self.target = target()
        self.grant: object | None = PassiveStatus(self.target, 20.0)
        self.observation: Observation | None = Observation(self.target, 10.0)
        self.time = 11.0
        self.calls: list[str] = []
        self.controls: list[str] = []
        self.current_replies = iter([True, True])
        self.suppress = False
        self.on_current: Callable[[], None] = lambda: None
        self.on_close: Callable[[], None] = lambda: None
        self.on_observe: Callable[[], None] = lambda: None
        self.peer = PassivePeer(self, clock=self.clock)

    @contextmanager
    def acquire(self) -> Iterator[Guard]:
        self.calls.append("acquire")
        try:
            yield self
        except BaseException:
            if not self.suppress:
                raise
        finally:
            self.calls.append("close")
            self.on_close()

    def admit(self, ticket: object) -> PassiveStatus | None:
        self.calls.append("admit")
        return cast(PassiveStatus | None, self.grant if ticket is self.ticket else None)

    def current(self, grant: PassiveStatus) -> bool:
        self.calls.append("current")
        self.on_current()
        return grant is self.grant and next(self.current_replies)

    def observe(self) -> Observation | None:
        self.calls.append("observe")
        self.on_observe()
        return self.observation

    def clock(self) -> float:
        self.calls.append("clock")
        return self.time

    def fence(self) -> None:
        self.controls.append("fence")
        raise AssertionError("passive peer invoked a fence")

    def released(self) -> bool:
        self.controls.append("release")
        raise AssertionError("passive peer released a viewer")

    def inject(self) -> None:
        self.controls.append("inject")
        raise AssertionError("passive peer injected control")


class PassivePeerTests(unittest.TestCase):
    def deny(
        self,
        probe: Guard,
        *,
        expected: Target | None = None,
        ticket: object | None = None,
    ) -> None:
        with self.assertRaisesRegex(Denied, "^passive observation denied$") as failure:
            probe.peer.observe(
                ticket if ticket is not None else probe.ticket,
                expected=expected if expected is not None else probe.target,
            )
        self.assertIsNone(failure.exception.__cause__)
        self.assertIsNone(failure.exception.__context__)
        self.assertEqual(probe.controls, [])

    def test_reports_original_time_and_full_selection_without_control(self) -> None:
        probe = Guard()
        old = probe.target
        probe.observation = Observation(
            replace(old, binding=replace(old.binding, operation="ignored", epoch=1)),
            10.0,
        )
        report = probe.peer.observe(probe.ticket, expected=old)
        self.assertEqual((report.observed_at, report.checked_at), (10.0, 11.0))
        values = asdict(old)
        expected = hashlib.sha256(
            json.dumps(values, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        self.assertEqual(report.selection_sha256, expected)
        selection_b = replace(old, binding=replace(old.binding, revision=3))
        self.assertNotEqual(report.selection_sha256, selection_digest(selection_b))
        for key in ("intent", "revision", "operation", "epoch"):
            del values["binding"][key]
        expected_scope = hashlib.sha256(
            json.dumps(
                values, sort_keys=True, separators=(",", ":"), ensure_ascii=False
            ).encode("utf-8")
        ).hexdigest()
        self.assertEqual(report.scope_sha256, expected_scope)
        self.assertEqual(
            set(asdict(report)),
            {"selection_sha256", "scope_sha256", "observed_at", "checked_at"},
        )
        self.assertEqual(
            probe.calls,
            [
                "acquire",
                "admit",
                "current",
                "clock",
                "observe",
                "current",
                "clock",
                "close",
                "clock",
            ],
        )
        self.assertEqual(probe.controls, [])

    def test_public_peer_opens_no_store_socket_or_process(self) -> None:
        probe = Guard()
        with (
            patch("sqlite3.connect") as store,
            patch("socket.socket") as socket,
            patch("subprocess.Popen") as process,
        ):
            probe.peer.observe(probe.ticket, expected=probe.target)
        store.assert_not_called()
        socket.assert_not_called()
        process.assert_not_called()

    def test_only_current_passive_admission_can_read_native_observation(self) -> None:
        changed = target()
        stale_selection = replace(
            changed,
            binding=replace(changed.binding, revision=changed.binding.revision + 1),
        )
        probe = Guard()
        self.deny(probe, expected=stale_selection)
        self.assertEqual(probe.calls, ["acquire", "admit", "close"])
        probe = Guard()
        self.deny(probe, ticket=object())
        self.assertNotIn("observe", probe.calls)
        probe = Guard()
        probe.grant = Transfer(
            target(), "initialize", None, Holder("agent", "a"), 0, 20.0
        )
        self.deny(probe)
        self.assertNotIn("observe", probe.calls)
        probe = Guard()
        probe.time = 20.0
        self.deny(probe)
        self.assertNotIn("observe", probe.calls)
        probe = Guard()
        probe.current_replies = iter([False])
        self.deny(probe)
        self.assertNotIn("observe", probe.calls)

    def test_unknown_time_and_wrong_physical_scope_fail_closed(self) -> None:
        original = target()
        wrong_account = replace(
            original, binding=replace(original.binding, account="other")
        )
        wrong_origin = replace(original, frame_origin="https://another.invalid")
        wrong_frame = replace(original, frame="second")
        wrong_native = replace(original, native_session="second")
        for observed in (
            None,
            Observation(original, 12.0),
            Observation(original, 5.9),
            Observation(original, float("nan")),
            Observation(original, cast(float, True)),
            Observation(wrong_account, 10.0),
            Observation(wrong_origin, 10.0),
            Observation(wrong_frame, 10.0),
            Observation(wrong_native, 10.0),
        ):
            with self.subTest(observed=observed):
                probe = Guard()
                probe.observation = observed
                probe.suppress = True
                self.deny(probe)
                self.assertEqual(probe.calls.count("observe"), 1)

    def test_revocation_and_guard_exit_fail_without_retries(self) -> None:
        probe = Guard()
        probe.current_replies = iter([True, False])
        probe.suppress = True
        self.deny(probe)
        self.assertEqual(probe.calls.count("observe"), 1)

        def fail_close() -> None:
            raise RuntimeError("synthetic-private-adapter-details")

        probe = Guard()
        probe.on_close = fail_close
        self.deny(probe)
        self.assertEqual(probe.calls.count("observe"), 1)
        probe = Guard()
        probe.observation = Observation(probe.target, 12.0)
        probe.on_close = lambda: setattr(probe, "time", 13.0)
        self.deny(probe)

        for clock in (9.0, 16.0, 20.0):
            probe = Guard()
            probe.on_close = lambda: setattr(probe, "time", clock)
            self.deny(probe)
            self.assertEqual(probe.calls.count("observe"), 1)

    def test_callback_cannot_refresh_timestamp_or_rebind_grant(self) -> None:
        probe = Guard()
        frame = probe.observation

        def refresh_timestamp() -> None:
            if "observe" in probe.calls:
                object.__setattr__(frame, "observed_at", 11.0)

        probe.on_current = refresh_timestamp
        self.deny(probe)
        probe = Guard()
        probe.on_close = lambda: object.__setattr__(probe.grant, "deadline", 99.0)
        self.deny(probe)
        probe = Guard()
        probe.on_observe = lambda: object.__setattr__(probe.grant, "deadline", 99.0)
        probe.on_current = lambda: object.__setattr__(probe.grant, "deadline", 20.0)
        self.deny(probe)
        self.assertEqual(probe.calls.count("current"), 1)

    def test_suppressed_cancellation_is_redacted(self) -> None:
        probe = Guard()
        probe.suppress = True

        def interrupt() -> None:
            raise KeyboardInterrupt("synthetic-private-adapter-details")

        probe.on_current = interrupt
        with self.assertRaisesRegex(
            Cancelled, "^passive observation cancelled$"
        ) as failure:
            probe.peer.observe(probe.ticket, expected=probe.target)
        self.assertIsNone(failure.exception.__context__)
        self.assertEqual(probe.calls, ["acquire", "admit", "current", "close"])
        self.assertEqual(probe.controls, [])

    def test_deliberate_scope_mutation_would_publish_foreign_observation(self) -> None:
        source = inspect.getsource(passive_peer)
        anchor = "scope != expected_scope"
        self.assertEqual(source.count(anchor), 1)
        namespace = vars(passive_peer).copy()
        exec(
            compile(source.replace(anchor, "False", 1), "<scope-mutant>", "exec"),
            namespace,
        )
        probe = Guard()
        foreign = replace(probe.target, native_session="foreign")
        probe.observation = Observation(foreign, 10.0)
        self.deny(probe)
        probe = Guard()
        probe.observation = Observation(foreign, 10.0)
        mutated = namespace["PassivePeer"](probe, clock=probe.clock)
        report = mutated.observe(probe.ticket, expected=probe.target)
        good = Guard()
        good_scope = good.peer.observe(good.ticket, expected=good.target).scope_sha256
        self.assertNotEqual(report.scope_sha256, good_scope)
        self.assertEqual(probe.calls.count("observe"), 1)
        self.assertEqual(probe.controls, [])


if __name__ == "__main__":
    unittest.main()

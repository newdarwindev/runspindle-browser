"""Real Resolver/Vault path, synthetic authority/transport/sink, no live provider."""

import contextlib
import math
import socket
import traceback
import unittest
from collections.abc import Iterator
from dataclasses import replace
from typing import Any, Callable, cast
from unittest.mock import patch

from browser_runtime.credentials import (
    AdapterSet,
    Denied,
    Fence,
    Grant,
    Observation,
    Resolver,
    _grant_binding,
    _GrantBinding,
    _target_binding,
    _time,
)
from tests.test_openbao import CANARY, Fixture

PIN = "d" * 64


class Probe:
    def __init__(self, *, max_age: float = 1.0) -> None:
        self.fx = Fixture()  # Actual OpenBao Vault/JSON implementation; byte transport.
        self.active = False
        self.ticket = object()
        self.observed_at: Any = 10.0
        self.observations = 0
        self.current_checks = 0
        self.current_value: object = True
        self.on_observe: Callable[[int], None] = lambda _n: None
        self.on_current: Callable[[int], None] = lambda _n: None
        self.events: list[str] = []
        self.reads = 0
        self.versions = 0
        self.helpers = 0
        self.sinks = 0
        self.releases = 0
        outer = self

        class VaultSpy:
            def read(self, grant: Grant) -> object:
                outer.reads += 1
                outer.events.append("read")
                if not outer.active:
                    raise AssertionError("missing fence")
                return outer.fx.v.read(grant)

            def current(self, handle: object, grant: Grant) -> bool:
                outer.versions += 1
                outer.events.append("version")
                valid: bool = outer.fx.v.current(handle, grant)
                return valid

            def release(self, handle: object) -> None:
                outer.releases += 1
                outer.fx.v.release(handle)

        class Helper:
            def inject(self, handle: object, grant: Grant, fence: Fence) -> bool:
                outer.helpers += 1
                outer.events.append("helper")
                if fence is not outer or not outer.active:
                    raise AssertionError("missing exact fence")

                def sink(secret: str) -> bool:
                    if secret != CANARY:
                        raise AssertionError("unexpected synthetic secret")
                    outer.sinks += 1
                    return True

                consumed: bool = outer.fx.v.consume(handle, grant, sink)
                return consumed

        self.resolver = Resolver(
            AdapterSet(PIN, self, VaultSpy(), Helper()),
            expected_digest=PIN,
            clock=self.clock,
            max_age=max_age,
        )

    def clock(self) -> float:
        self.events.append("clock")
        now: float = self.fx.now
        return now

    @contextlib.contextmanager
    def acquire(self) -> Iterator[Fence]:
        self.active = True
        try:
            yield self
        finally:
            self.active = False

    def admit(self, ticket: object) -> Grant | None:
        return self.fx.g if ticket is self.ticket else None

    def observe(self) -> Observation:
        self.observations += 1
        self.events.append("observe")
        self.on_observe(self.observations)
        return Observation(self.fx.g.target, self.observed_at)

    def current(self, grant: Grant) -> bool:
        self.current_checks += 1
        self.events.append("current")
        self.on_current(self.current_checks)
        return cast(bool, self.current_value)

    def run(self) -> str:
        return self.resolver.resolve_and_inject(self.ticket)


class ResolverFreshnessTests(unittest.TestCase):
    def setUp(self) -> None:
        network = patch.object(
            socket.socket, "connect", side_effect=AssertionError("network forbidden")
        )
        network.start()
        self.addCleanup(network.stop)

    def denied(self, probe: Probe, *, reads: int, versions: int, requests: int) -> None:
        try:
            probe.run()
        except Denied as error:
            self.assertIsNone(error.__cause__)
            self.assertIsNone(error.__context__)
            self.assertNotIn(
                CANARY, repr(error.args) + "".join(traceback.format_exception(error))
            )
        else:
            self.fail("stale admission reached a successful result")
        self.assertEqual(
            (probe.reads, probe.versions, len(probe.fx.calls)),
            (reads, versions, requests),
        )
        self.assertEqual((probe.helpers, probe.sinks), (0, 0))
        self.assertEqual(probe.releases, reads)
        self.assertFalse(probe.active)
        self.assertEqual(len(probe.fx.v._entries), 0)
        before = (
            probe.reads,
            probe.versions,
            len(probe.fx.calls),
            probe.helpers,
            probe.sinks,
        )
        with self.assertRaises(Denied):
            probe.run()
        self.assertEqual(
            (
                probe.reads,
                probe.versions,
                len(probe.fx.calls),
                probe.helpers,
                probe.sinks,
            ),
            before,
        )

    def test_current_callback_delay_blocks_each_actual_use_boundary(self) -> None:
        for stage, reads, versions, requests in (
            (1, 0, 0, 0),
            (2, 1, 0, 1),
            (3, 1, 1, 2),
        ):
            with self.subTest(stage=stage):
                probe = Probe()

                def delay(n: int) -> None:
                    if n == stage:
                        probe.fx.now = (
                            12.0  # Observation age 2 > 1; deadline 20 still valid.
                        )

                probe.on_current = delay
                self.denied(probe, reads=reads, versions=versions, requests=requests)

    def test_observe_delay_remains_fail_closed_at_each_boundary(self) -> None:
        for stage, reads, versions, requests in (
            (1, 0, 0, 0),
            (2, 1, 0, 1),
            (3, 1, 1, 2),
        ):
            with self.subTest(stage=stage):
                probe = Probe()

                def delay(n: int) -> None:
                    if n == stage:
                        probe.fx.now = 12.0

                probe.on_observe = delay
                self.denied(probe, reads=reads, versions=versions, requests=requests)

    def test_expired_grant_blocks_adapter_calls_even_with_fresh_observations(
        self,
    ) -> None:
        for stage, reads, versions, requests in (
            (1, 0, 0, 0),
            (2, 1, 0, 1),
            (3, 1, 1, 2),
        ):
            with self.subTest(stage=stage):
                probe = Probe(max_age=100.0)

                def expire(n: int) -> None:
                    if n == stage:
                        probe.fx.now = probe.fx.g.deadline

                probe.on_current = expire
                self.denied(probe, reads=reads, versions=versions, requests=requests)

    def test_exact_age_inclusive_and_deadline_exclusive_boundaries(self) -> None:
        for now, max_age, deadline, allowed in (
            (11.0, 1.0, 20.0, True),
            (math.nextafter(11.0, math.inf), 1.0, 20.0, False),
            (math.nextafter(20.0, -math.inf), 100.0, 20.0, True),
            (20.0, 100.0, 20.0, False),
            (10.0, 0.0, 20.0, True),
            (math.nextafter(10.0, math.inf), 0.0, 20.0, False),
        ):
            with self.subTest(now=now, max_age=max_age, deadline=deadline):
                probe = Probe(max_age=max_age)
                probe.fx.g = replace(probe.fx.g, deadline=deadline)
                probe.on_current = lambda _n: setattr(probe.fx, "now", now)
                if allowed:
                    self.assertEqual(probe.run(), "injected")
                    self.assertEqual(
                        (probe.reads, probe.versions, probe.helpers, probe.sinks),
                        (1, 1, 1, 1),
                    )
                    self.assertEqual(len(probe.fx.calls), 3)
                    self.assertFalse(probe.active)
                    self.assertEqual(len(probe.fx.v._entries), 0)
                else:
                    self.denied(probe, reads=0, versions=0, requests=0)

    def test_authority_order_still_observes_then_checks_current_then_time(self) -> None:
        probe = Probe()
        probe.on_observe = lambda _n: setattr(probe, "current_value", False)
        self.denied(probe, reads=0, versions=0, requests=0)
        self.assertEqual(probe.events[:3], ["observe", "current", "clock"])
        good = Probe()
        self.assertEqual(good.run(), "injected")
        self.assertEqual(
            good.events,
            [
                "observe",
                "current",
                "clock",
                "read",
                "observe",
                "current",
                "clock",
                "version",
                "observe",
                "current",
                "clock",
                "helper",
            ],
        )

    def test_malformed_or_backward_clock_after_callback_denies(self) -> None:
        for value in (True, None, "10", math.nan, math.inf, -math.inf, 9.0):
            for stage, reads, versions, requests in (
                (1, 0, 0, 0),
                (2, 1, 0, 1),
                (3, 1, 1, 2),
            ):
                with self.subTest(value=value, stage=stage):
                    probe = Probe()

                    def change(n: int) -> None:
                        if n == stage:
                            probe.fx.now = cast(float, value)

                    probe.on_current = change
                    self.denied(
                        probe, reads=reads, versions=versions, requests=requests
                    )

    def test_callback_exception_and_non_true_results_do_not_reach_use(self) -> None:
        for value in (False, None, 1, "yes"):
            probe = Probe()
            probe.current_value = value
            self.denied(probe, reads=0, versions=0, requests=0)
        for stage, reads, versions, requests in (
            (1, 0, 0, 0),
            (2, 1, 0, 1),
            (3, 1, 1, 2),
        ):
            probe = Probe()

            def failure(n: int) -> None:
                if n == stage:
                    raise OSError(CANARY)

            probe.on_current = failure
            self.denied(probe, reads=reads, versions=versions, requests=requests)

    def test_default_monotonic_clock_is_sampled_after_current_callback(self) -> None:
        probe = Probe()
        probe.on_current = lambda _n: setattr(probe.fx, "now", 12.0)
        with patch("time.monotonic", side_effect=lambda: probe.fx.now):
            probe.resolver = Resolver(probe.resolver._adapters, expected_digest=PIN)
            self.denied(probe, reads=0, versions=0, requests=0)

    def test_mutated_pre_callback_clock_is_observed_by_forbidden_effect_spies(
        self,
    ) -> None:
        def stale_sample(
            resolver: Resolver, fence: Fence, grant: Grant, binding: _GrantBinding
        ) -> None:
            if _grant_binding(grant) != binding:
                raise ValueError
            observation = fence.observe()
            if (
                type(observation) is not Observation
                or _target_binding(observation.target) != binding.target
            ):
                raise ValueError
            observed_at = _time(observation.observed_at)
            now = _time(resolver._clock())  # Deliberately broken ordering.
            current = fence.current(grant)
            if (
                not 0 <= now - observed_at <= resolver._max_age
                or now >= binding.deadline
                or current is not True
                or _grant_binding(grant) != binding
            ):
                raise ValueError

        for stage, expected in ((1, (1, 0, 1, 0, 0)), (3, (1, 1, 3, 1, 1))):
            probe = Probe()

            def delay(n: int) -> None:
                if n == stage:
                    probe.fx.now = 12.0

            probe.on_current = delay
            with patch.object(Resolver, "_check", stale_sample):
                if stage == 1:
                    with self.assertRaises(Denied):
                        probe.run()
                else:
                    self.assertEqual(probe.run(), "injected")
            observed = (
                probe.reads,
                probe.versions,
                len(probe.fx.calls),
                probe.helpers,
                probe.sinks,
            )
            self.assertEqual(observed, expected)
            self.assertFalse(probe.active)
            self.assertEqual(len(probe.fx.v._entries), 0)


if __name__ == "__main__":
    unittest.main()

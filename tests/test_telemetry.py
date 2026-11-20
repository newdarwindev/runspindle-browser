"""Content-free observation coverage with actual resolver synthetic adapters."""

import unittest
from unittest.mock import patch

from browser_runtime.credentials import Denied, Resolver
from browser_runtime.telemetry import CAPACITY, Buffer, Outcome
from tests.test_resolver_freshness import Probe


class TelemetryTests(unittest.TestCase):
    def test_default_off(self) -> None:
        self.assertIsNone(Resolver()._telemetry)

    def test_success_is_ack_not_external_acceptance(self) -> None:
        probe = Probe()
        buffer = Buffer()
        probe.resolver._telemetry = buffer
        self.assertEqual(probe.run(), "injected")
        self.assertFalse(probe.active)
        records = buffer.drain()
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].outcome, Outcome.ACKNOWLEDGED)
        self.assertEqual(set(vars(records[0])), {"outcome", "started_ns", "ended_ns"})
        self.assertEqual(buffer.drain(), ())

    def test_denial_has_no_ticket_or_exception_content(self) -> None:
        buffer = Buffer()
        resolver = Resolver(telemetry=buffer)
        with self.assertRaises(Denied):
            resolver.resolve_and_inject("PRIVATE_CANARY")
        self.assertEqual(buffer.drain()[0].outcome, Outcome.ERROR)

    def test_capacity_and_contention_do_not_change_resolution(self) -> None:
        buffer = Buffer()
        for _ in range(CAPACITY + 4):
            buffer._record(Outcome.UNKNOWN, 0)
        self.assertEqual(len(buffer.drain()), CAPACITY)
        probe = Probe()
        probe.resolver._telemetry = buffer
        with buffer._lock:
            self.assertEqual(probe.run(), "injected")
        self.assertEqual(buffer.drain(), ())

    def test_observation_failure_isolated(self) -> None:
        probe = Probe()
        probe.resolver._telemetry = Buffer()
        with patch.object(
            Buffer, "_record", side_effect=RuntimeError("PRIVATE_CANARY")
        ):
            self.assertEqual(probe.run(), "injected")

    def test_subclass_callback_rejected(self) -> None:
        class Untrusted(Buffer):
            pass

        with self.assertRaises(TypeError):
            Resolver(telemetry=Untrusted())

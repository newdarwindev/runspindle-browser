"""Synthetic adapter conformance probes; no real authority/provider/browser."""

import contextlib
import dataclasses
import io
import traceback
import unittest
from unittest.mock import patch

from browser_runtime.credentials import (
    AdapterSet,
    Denied,
    Grant,
    Observation,
    Resolver,
    Target,
)
from browser_runtime.effects import Binding

PIN = "a" * 64
CANARY = "secret-canary-DO-NOT-EXPORT"


class Adapters:
    def __init__(self):
        self.target = Target(
            Binding(
                "principal",
                "account",
                "browser",
                "tab",
                "intent",
                1,
                "fill",
                1,
                "https://example.test",
            ),
            "native",
            "frame",
            "https://example.test",
        )
        self.grant = Grant(self.target, "credential:one", 12.0)
        self.ticket = object()
        self.now = 10.0
        self.calls = []
        self.observations = [Observation(self.target, 10.0)] * 3
        self.valid = True
        self.version = True
        self.fault = None
        self.active = False
        self.handle = object()
        self.spies = {"reads": 0, "injections": 0}
        self.guard_observations = []

    @contextlib.contextmanager
    def acquire(self):
        self.active = True
        try:
            yield self
        finally:
            self.active = False
            self.calls.append("fence_closed")

    def admit(self, ticket):
        self.calls.append("admit")
        return self.grant if ticket is self.ticket else None

    def observe(self):
        self.calls.append("observe")
        return self.observations.pop(0) if self.observations else None

    def current(self, *args):
        if len(args) == 1:
            return self.valid
        self.calls.append("version")
        if self.fault == "rotate":
            self.observations[-1] = None
        return self.version

    def read(self, grant):
        self.guard_observations.append(self.active)
        self.spies["reads"] += 1
        self.calls.append("read")
        if self.fault in ("timeout", "denial"):
            raise TimeoutError(CANARY)
        if self.fault == "expired":
            self.now = 12.0
        return self.handle

    def inject(self, handle, grant, fence):
        self.guard_observations.append(
            self.active and handle is self.handle and fence is self
        )
        if self.fault == "helper_denial":
            raise ValueError(CANARY)
        self.spies["injections"] += 1
        if self.fault == "uncertain":
            raise TimeoutError(CANARY)
        return True

    def release(self, handle):
        self.calls.append("release")
        if self.fault == "release":
            raise ValueError(CANARY)

    def resolver(self):
        return Resolver(
            AdapterSet(PIN, self, self, self),
            expected_digest=PIN,
            clock=lambda: self.now,
        )


class TrustedCredentialsTests(unittest.TestCase):
    def denied(self, adapter, resolver=None, ticket=None, reads=0, injections=0):
        resolver = resolver or adapter.resolver()
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            try:
                resolver.resolve_and_inject(
                    adapter.ticket if ticket is None else ticket
                )
            except Denied as error:
                envelope = (
                    repr(error)
                    + str(error)
                    + "".join(traceback.format_exception(error))
                )
                self.assertIsNone(error.__context__)
                self.assertIsNone(error.__cause__)
            else:
                self.fail("expected denial")
        self.assertNotIn(
            CANARY,
            envelope + output.getvalue() + repr(adapter.calls) + repr(adapter.spies),
        )
        self.assertEqual(adapter.spies, {"reads": reads, "injections": injections})
        self.assertFalse(adapter.active)
        self.assertTrue(all(adapter.guard_observations))

    def test_success_is_sanitized_and_once(self):
        adapter = Adapters()
        resolver = adapter.resolver()
        result = resolver.resolve_and_inject(adapter.ticket)
        self.assertEqual(result, "injected")
        self.assertEqual(adapter.guard_observations, [True, True])
        self.assertNotIn(
            CANARY, result + repr(adapter.grant) + repr(resolver._adapters)
        )
        self.assertEqual(
            adapter.calls,
            [
                "admit",
                "observe",
                "read",
                "observe",
                "version",
                "observe",
                "release",
                "fence_closed",
            ],
        )
        self.denied(adapter, resolver, reads=1, injections=1)

    def test_missing_and_wrong_pin_deny_before_authority(self):
        adapter = Adapters()
        self.denied(adapter, Resolver())
        self.denied(
            adapter,
            Resolver(
                AdapterSet(PIN, adapter, adapter, adapter), expected_digest="b" * 64
            ),
        )
        self.assertEqual(adapter.calls, [])

    def test_forged_ticket_cannot_supply_grant_or_observation(self):
        for ticket in (object(), {"authenticated": True}, Adapters().grant):
            adapter = Adapters()
            self.denied(adapter, ticket=ticket)

    def test_wrong_bindings_deny_before_read(self):
        for name, value in (
            ("account", "other"),
            ("principal", "other"),
            ("origin", "https://evil.test"),
            ("epoch", 2),
            ("browser", "other"),
            ("tab", "other"),
            ("operation", "other"),
            ("revision", 2),
        ):
            with self.subTest(name=name):
                adapter = Adapters()
                target = dataclasses.replace(
                    adapter.target,
                    binding=dataclasses.replace(
                        adapter.target.binding, **{name: value}
                    ),
                )
                adapter.observations[0] = Observation(target, 10.0)
                self.denied(adapter)
        for name, value in (
            ("native_session", "other"),
            ("frame", "other"),
            ("frame_origin", "https://evil.test"),
        ):
            adapter = Adapters()
            adapter.observations[0] = Observation(
                dataclasses.replace(adapter.target, **{name: value}), 10.0
            )
            self.denied(adapter)

    def test_unavailable_forged_stale_and_future_observations(self):
        for observation in (
            None,
            {"authenticated": True},
            Observation(Adapters().target, 8.0),
            Observation(Adapters().target, 11.0),
            Observation(Adapters().target, float("nan")),
        ):
            adapter = Adapters()
            adapter.observations[0] = observation
            self.denied(adapter)
        adapter = Adapters()
        adapter.valid = False
        self.denied(adapter)

    def test_redirect_after_read_and_during_version_check(self):
        for index in (1, 2):
            adapter = Adapters()
            adapter.observations[index] = Observation(
                dataclasses.replace(adapter.target, frame_origin="https://evil.test"),
                10.0,
            )
            self.denied(adapter, reads=1)
            self.assertIn("release", adapter.calls)
        adapter = Adapters()
        adapter.fault = "rotate"
        self.denied(adapter, reads=1)

    def test_suppressing_guard_cannot_forge_success(self):
        for fault in (
            "grant",
            "observation",
            "timeout",
            "helper_denial",
            "uncertain",
            "release",
        ):
            with self.subTest(fault=fault):
                adapter = Adapters()
                if fault == "grant":
                    adapter.grant = None
                elif fault == "observation":
                    adapter.observations[0] = None
                else:
                    adapter.fault = fault

                @contextlib.contextmanager
                def suppressing_guard():
                    adapter.active = True
                    try:
                        yield adapter
                    except Exception:
                        pass
                    finally:
                        adapter.active = False
                        adapter.calls.append("fence_closed")

                with patch.object(adapter, "acquire", suppressing_guard):
                    self.denied(
                        adapter,
                        reads=int(fault not in ("grant", "observation")),
                        injections=int(fault in ("uncertain", "release")),
                    )

    def test_invalid_grants_and_expired_identity_deny_before_read(self):
        for changes in (
            {"reference": "../escape"},
            {"reference": ""},
            {"deadline": 10.0},
            {"deadline": float("inf")},
        ):
            adapter = Adapters()
            adapter.grant = dataclasses.replace(adapter.grant, **changes)
            self.denied(adapter)

    def test_stale_epoch_after_read_blocks_injection(self):
        adapter = Adapters()
        stale = dataclasses.replace(
            adapter.target, binding=dataclasses.replace(adapter.target.binding, epoch=2)
        )
        adapter.observations[1] = Observation(stale, 10.0)
        self.denied(adapter, reads=1)
        self.assertIn("release", adapter.calls)

    def test_faults_cleanup_and_no_retry(self):
        for fault in (
            "timeout",
            "denial",
            "expired",
            "helper_denial",
            "uncertain",
            "release",
        ):
            with self.subTest(fault=fault):
                adapter = Adapters()
                adapter.fault = fault
                resolver = adapter.resolver()
                injections = int(fault in ("uncertain", "release"))
                self.denied(adapter, resolver, reads=1, injections=injections)
                calls = list(adapter.calls)
                self.denied(adapter, resolver, reads=1, injections=injections)
                self.assertEqual(adapter.calls, calls)
        adapter = Adapters()
        adapter.version = False
        self.denied(adapter, reads=1)

    def test_cancellation_releases_handle_and_fence(self):
        adapter = Adapters()
        resolver = adapter.resolver()
        with patch.object(adapter, "inject", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                resolver.resolve_and_inject(adapter.ticket)
        self.assertIn("release", adapter.calls)
        self.assertFalse(adapter.active)
        self.assertTrue(all(adapter.guard_observations))
        self.denied(adapter, resolver, reads=1)

    def test_deliberate_mutation_is_detected_by_forbidden_effect_spies(self):
        adapter = Adapters()
        adapter.observations[0] = None
        resolver = adapter.resolver()
        with patch.object(Resolver, "_check", return_value=None):
            resolver.resolve_and_inject(adapter.ticket)
        # This mutation removes the trusted observation guard. The ordinary
        # invariant assertion must fail, proving independent effects catch it.
        with self.assertRaises(AssertionError):
            self.assertEqual(adapter.spies, {"reads": 0, "injections": 0})
        self.assertEqual(adapter.spies, {"reads": 1, "injections": 1})


if __name__ == "__main__":
    unittest.main()

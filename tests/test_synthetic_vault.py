"""Synthetic, no-network observations; not production security acceptance."""

import importlib.util
import json
import socket
import sys
import tempfile
import traceback
import unittest
from dataclasses import replace
from pathlib import Path
from typing import Any
from unittest.mock import patch

from browser_testing.vault import (
    Denied,
    Entry,
    FakeVault,
    Observation,
    Scope,
    ScriptedObservations,
    Secret,
    resolve_and_inject,
)

ROOT = Path(__file__).resolve().parents[1]
SCOPE = Scope(
    "principal",
    "account",
    "https://top.example",
    "https://frame.example",
    "fill",
    "session",
    7,
)
CANARY = "SYNTHETIC-SECRET-CANARY-ONLY"
REFERENCE = "SYNTHETIC-HANDLE-ONLY"


class SyntheticVaultTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = 10
        self.vault = FakeVault(lambda: self.now)
        self.vault.put(REFERENCE, Entry(SCOPE, Secret(CANARY, 1), 20))
        self.injected: list[Secret] = []
        self.network = patch.object(
            socket.socket, "connect", side_effect=AssertionError("network forbidden")
        )
        self.network.start()
        self.addCleanup(self.network.stop)

    def run_case(self, values: list[Observation | None]) -> str:
        return resolve_and_inject(
            SCOPE,
            REFERENCE,
            ScriptedObservations(values),
            self.vault,
            self.injected.append,
            lambda: self.now,
        )

    def test_success_requires_two_fresh_observations(self) -> None:
        self.assertEqual(self.run_case([Observation(SCOPE, 10)] * 2), "injected")
        self.assertEqual(self.injected, [Secret(CANARY, 1)])
        self.assertEqual(self.vault.audit, ["read_attempt", "read_allowed"])
        self.assertNotIn(CANARY, repr(self.vault.entries))

    def test_every_wrong_binding_denied_before_vault_read(self) -> None:
        changes: list[dict[str, Any]] = [
            {"principal": "other"},
            {"account": "other"},
            {"top_origin": "https://other.example"},
            {"frame_origin": "https://other.example"},
            {"operation": "submit"},
            {"session": "other"},
            {"epoch": 6},
        ]
        for change in changes:
            with self.subTest(change=change), self.assertRaises(Denied):
                self.run_case([Observation(replace(SCOPE, **change), 10)])
        self.assertEqual(self.vault.audit, [])
        self.assertEqual(self.injected, [])

    def test_redirect_account_epoch_races_block_injection_after_read(self) -> None:
        for change in (
            {"frame_origin": "https://redirect.example"},
            {"account": "other"},
            {"epoch": 8},
        ):
            with self.subTest(change=change), self.assertRaises(Denied):
                self.run_case(
                    [Observation(SCOPE, 10), Observation(replace(SCOPE, **change), 10)]
                )
        self.assertEqual(self.vault.audit.count("read_allowed"), 3)
        self.assertEqual(self.injected, [])

    def test_vault_changes_during_second_observation_deny_injection(self) -> None:
        for change in (
            "forget",
            "rotate",
            "expiry",
            "replace_same",
            "forget_restore",
            "outage",
        ):
            with self.subTest(change=change):
                self.now = 10
                original = Entry(SCOPE, Secret(CANARY, 1), 20)
                self.vault.put(REFERENCE, original)
                self.vault.fault = "none"
                calls = 0

                def observe() -> Observation:
                    nonlocal calls
                    calls += 1
                    if calls == 2:
                        if change == "forget":
                            self.vault.forget(REFERENCE)
                        elif change == "rotate":
                            self.vault.put(
                                REFERENCE,
                                Entry(SCOPE, Secret("SYNTHETIC-ROTATED", 2), 30),
                            )
                        elif change == "expiry":
                            self.now = 20
                        elif change == "replace_same":
                            self.vault.put(REFERENCE, Entry(SCOPE, original.secret, 30))
                        elif change == "forget_restore":
                            self.vault.forget(REFERENCE)
                            self.vault.put(REFERENCE, original)
                        else:
                            self.vault.fault = "outage"
                    return Observation(SCOPE, self.now)

                try:
                    resolve_and_inject(
                        SCOPE,
                        REFERENCE,
                        observe,
                        self.vault,
                        self.injected.append,
                        lambda: self.now,
                    )
                    self.fail("changed vault must deny injection")
                except Denied as error:
                    envelope = json.dumps(
                        {
                            "error": str(error),
                            "audit": self.vault.audit,
                            "trace": "".join(traceback.format_exception(error)),
                        }
                    )
                    self.assertNotIn(CANARY, envelope)
                    self.assertNotIn(REFERENCE, envelope)
                self.assertEqual(calls, 2)
                self.assertEqual(self.injected, [])

    def test_missing_expired_future_or_stale_observations_deny(self) -> None:
        for value in (None, Observation(SCOPE, 8), Observation(SCOPE, 11)):
            with self.assertRaises(Denied):
                self.run_case([value])
        self.assertEqual(self.vault.audit, [])
        with self.assertRaises(Denied):
            self.run_case([Observation(SCOPE, 10)])
        self.assertEqual(self.injected, [])

    def test_outage_denial_timeout_malformed_are_sanitized(self) -> None:
        for fault in ("outage", "denied", "timeout", "malformed", "invalid"):
            self.vault.fault = fault
            try:
                self.run_case([Observation(SCOPE, 10)] * 2)
                self.fail("fault must deny")
            except Denied as error:
                envelope = json.dumps(
                    {
                        "status": str(error),
                        "audit": self.vault.audit,
                        "trace": "".join(traceback.format_exception(error)),
                    }
                )
                self.assertNotIn(CANARY, envelope)
                self.assertNotIn(REFERENCE, envelope)
        self.assertEqual(self.injected, [])

    def test_identity_expiry_rotation_forgetting_are_distinct(self) -> None:
        self.now = 20
        with self.assertRaises(Denied):
            self.run_case([Observation(SCOPE, 20)] * 2)
        self.assertEqual(self.injected, [])
        self.vault.put(REFERENCE, Entry(SCOPE, Secret("SYNTHETIC-ROTATED", 2), 30))
        self.assertEqual(self.run_case([Observation(SCOPE, 20)] * 2), "injected")
        self.assertEqual(self.injected[-1].version, 2)
        self.vault.forget(REFERENCE)
        with self.assertRaises(Denied):
            self.run_case([Observation(SCOPE, 20)] * 2)
        # Forgetting does not revoke a website session or erase earlier effects.
        self.assertEqual(len(self.injected), 1)

    def test_callback_secret_exception_is_not_serialized(self) -> None:
        def failed_observer() -> Observation:
            raise RuntimeError(CANARY + REFERENCE)

        with self.assertRaises(Denied) as caught:
            resolve_and_inject(
                SCOPE,
                REFERENCE,
                failed_observer,
                self.vault,
                self.injected.append,
                lambda: 10,
            )
        self.assertNotIn(CANARY, str(caught.exception))
        self.assertEqual(self.vault.audit, [])

    def test_deliberate_missing_second_scope_guard_has_forbidden_effect(self) -> None:
        source = (ROOT / "browser_testing/vault.py").read_text()
        anchor = "if second.scope != expected:"
        self.assertEqual(source.count(anchor), 1)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "mutated_vault.py"
            path.write_text(source.replace(anchor, "if False:"))
            spec = importlib.util.spec_from_file_location("mutated_vault", path)
            if spec is None or spec.loader is None:
                raise RuntimeError("mutation loader missing")
            module = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = module
            self.addCleanup(sys.modules.pop, spec.name)
            spec.loader.exec_module(module)
            expected = module.Scope(
                "principal",
                "account",
                "https://top.example",
                "https://frame.example",
                "fill",
                "session",
                7,
            )
            vault = module.FakeVault(lambda: 10)
            vault.put(REFERENCE, module.Entry(expected, module.Secret(CANARY, 1), 20))
            observed = module.ScriptedObservations(
                [
                    module.Observation(expected, 10),
                    module.Observation(
                        replace(expected, frame_origin="https://foreign.example"), 10
                    ),
                ]
            )
            effects: list[object] = []
            module.resolve_and_inject(
                expected, REFERENCE, observed, vault, effects.append, lambda: 10
            )
            self.assertEqual(
                len(effects), 1, "broken guard must cause observed forbidden injection"
            )

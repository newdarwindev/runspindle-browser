"""Specification-model checks only; no encryption or live deletion claims."""

import socket
import unittest
from dataclasses import replace
from unittest.mock import patch

from browser_testing.storage import StorageModel
from browser_testing.vault import Denied, Entry, FakeVault, Scope, Secret

SCOPE = Scope(
    "synthetic-owner",
    "account-a",
    "https://top.test",
    "https://frame.test",
    "inspect",
    "synthetic-session",
    7,
)


class StorageLifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.model = StorageModel(SCOPE)
        network = patch.object(
            socket.socket, "connect", side_effect=AssertionError("network forbidden")
        )
        network.start()
        self.addCleanup(network.stop)

    def act(self, action: str, *, result: str = "unknown") -> str:
        grant = replace(SCOPE, operation=action)
        return self.model.apply(action, grant, grant, site_result=result)

    def test_forgetting_operations_are_independent(self) -> None:
        for action in ("forget_credentials", "forget_profile", "revoke_site"):
            with self.subTest(action=action):
                self.model = StorageModel(SCOPE)
                self.act(action, result="revoked")
                state = self.model.state
                self.assertEqual(
                    state.credentials_present, action != "forget_credentials"
                )
                self.assertEqual(state.profile_present, action != "forget_profile")
                self.assertEqual(
                    state.site_status,
                    "revoked" if action == "revoke_site" else "active",
                )
                self.assertTrue(state.browser_running)

    def test_forgetting_requires_explicit_operation_and_current_scope(self) -> None:
        action = "forget_credentials"
        correct = replace(SCOPE, operation=action)
        changes = (
            replace(correct, principal="other"),
            replace(correct, account="other"),
            replace(correct, top_origin="https://other.test"),
            replace(correct, frame_origin="https://other.test"),
            replace(correct, operation="forget_profile"),
            replace(correct, session="other"),
            replace(correct, epoch=6),
        )
        initial = self.model.state
        for wrong in changes:
            for grant, observed in ((wrong, correct), (correct, wrong)):
                with self.subTest(wrong=wrong), self.assertRaises(Denied):
                    self.model.apply(action, grant, observed)
                self.assertEqual(self.model.state, initial)
        for missing_grant, missing_observation in ((None, correct), (correct, None)):
            with self.assertRaises(Denied):
                self.model.apply(action, missing_grant, missing_observation)
            self.assertEqual(self.model.state, initial)

    def test_other_accounts_are_unchanged(self) -> None:
        other = StorageModel(replace(SCOPE, account="account-b"))
        initial = other.state
        self.act("forget_credentials")
        self.act("forget_profile")
        self.assertEqual(other.state, initial)

    def test_rotation_does_not_delete_profile_or_revoke_site(self) -> None:
        before = self.model.state
        self.act("rotate")
        self.assertEqual(
            self.model.state,
            replace(before, credential_generation=before.credential_generation + 1),
        )

    def test_forgetting_invalidates_generation_and_cannot_be_rotated_back(self) -> None:
        before = self.model.state.credential_generation
        self.act("forget_credentials")
        self.assertGreater(self.model.state.credential_generation, before)
        forgotten = self.model.state
        with self.assertRaises(Denied):
            self.act("rotate")
        self.assertEqual(self.model.state, forgotten)

    def test_uncertain_site_result_is_not_revoked(self) -> None:
        self.assertEqual(self.act("revoke_site"), "unknown")
        self.assertEqual(self.model.state.site_status, "unknown")
        self.assertTrue(self.model.state.credentials_present)
        self.assertTrue(self.model.state.profile_present)
        self.assertEqual(self.act("revoke_site", result="revoked"), "revoked")
        self.assertEqual(self.model.state.site_status, "revoked")

    def test_failed_and_invalid_site_results_do_not_claim_revocation(self) -> None:
        before = self.model.state
        self.assertEqual(self.act("revoke_site", result="failed"), "failed")
        self.assertEqual(self.model.state, before)
        with self.assertRaises(Denied):
            self.act("revoke_site", result="SYNTHETIC-UNTRUSTED-RESULT")
        self.assertEqual(self.model.state, before)

    def test_cookie_expiry_retains_stored_material(self) -> None:
        self.act("expire_cookie")
        self.assertEqual(self.model.state.site_status, "expired")
        self.assertTrue(self.model.state.credentials_present)
        self.assertTrue(self.model.state.profile_present)

    def test_browser_termination_does_not_imply_remote_logout(self) -> None:
        self.act("terminate_browser")
        self.assertFalse(self.model.state.browser_running)
        self.assertEqual(self.model.state.site_status, "active")
        self.assertTrue(self.model.state.credentials_present)
        self.assertTrue(self.model.state.profile_present)

    def test_expired_identity_blocks_use_without_retention_ttl(self) -> None:
        now = 1
        vault = FakeVault(lambda: now)
        entry = Entry(SCOPE, Secret("SYNTHETIC-RETENTION-CANARY", 1), 2)
        vault.put("synthetic-reference", entry)
        now = 1000000
        with self.assertRaises(Denied):
            vault.read("synthetic-reference", SCOPE)
        self.assertIs(vault.entries["synthetic-reference"], entry)
        self.assertTrue(self.model.state.credentials_present)
        self.assertTrue(self.model.state.profile_present)
        vault.forget("synthetic-reference")
        self.assertNotIn("synthetic-reference", vault.entries)

    def test_invalid_operation_is_sanitized_and_has_no_effect(self) -> None:
        before = self.model.state
        with self.assertRaises(Denied) as caught:
            self.act("SYNTHETIC-CANARY")
        self.assertNotIn("SYNTHETIC-CANARY", str(caught.exception))
        self.assertEqual(self.model.state, before)


if __name__ == "__main__":
    unittest.main()

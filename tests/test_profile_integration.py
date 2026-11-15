"""Real composition of held components; synthetic authority and material only."""

import base64
import sqlite3
import subprocess
import sys
import tempfile
import traceback
import unittest
from pathlib import Path
from unittest.mock import patch

from browser_runtime.profile_store import Cancelled, Denied
from browser_testing.profile_integration_fixtures import OLD, Fixture, bundle
from browser_testing.profile_keys_fixtures import TOKEN, operation
from browser_testing.profile_store_fixtures import CANARY, KEY

ROOT = Path(__file__).resolve().parents[1]


class ProfileIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        for target in (
            "socket.socket.connect",
            "socket.socket.connect_ex",
            "socket.create_connection",
        ):
            network = patch(target, side_effect=AssertionError("network forbidden"))
            network.start()
            self.addCleanup(network.stop)

    def fixture(self, name: str = "run") -> Fixture:
        root = self.root / name
        root.mkdir(mode=0o700)
        f = Fixture(root, create=True)
        self.addCleanup(f.close)
        return f

    def scan(self, root: Path, value: bytes = CANARY) -> list[str]:
        variants = (
            value,
            base64.b64encode(value),
            KEY,
            base64.b64encode(KEY),
            TOKEN.encode(),
        )
        return [
            str(path.relative_to(root))
            for path in root.rglob("*")
            if path.is_file()
            and not path.is_symlink()
            and any(secret in path.read_bytes() for secret in variants)
        ]

    def states(self, f: Fixture) -> list[str]:
        with sqlite3.connect(f.custody / "custody.sqlite3") as db:
            return [
                row[0]
                for row in db.execute("SELECT state FROM attempts ORDER BY rowid")
            ]

    def crash(self, f: Fixture, action: str, fault: str) -> None:
        result = subprocess.run(
            [
                sys.executable,
                *(["-O"] if sys.flags.optimize else []),
                "-m",
                "browser_testing.profile_integration_fixtures",
                str(f.root),
                action,
                fault,
            ],
            cwd=ROOT,
            timeout=15,
            capture_output=True,
        )
        self.assertIn(result.returncode, range(71, 77), result.stderr)
        self.assertNotIn(CANARY, result.stdout + result.stderr)

    def test_scanner_detects_encoded_bundle_key_and_token(self) -> None:
        probe = self.root / "probe"
        for value in (
            CANARY,
            base64.b64encode(CANARY),
            bundle(operation().scope(), CANARY),
            KEY,
            base64.b64encode(KEY),
            TOKEN.encode(),
        ):
            probe.write_bytes(value)
            self.assertEqual(self.scan(self.root), ["probe"])
        probe.unlink()
        self.assertEqual(self.scan(self.root), [])

    def test_real_roundtrip_then_forget_without_keys(self) -> None:
        f = self.fixture()
        f.seed()
        self.assertEqual(f.run("save", "save"), "stored")
        self.assertEqual(self.scan(f.ciphertext), [])
        self.assertEqual(self.scan(f.custody), [])
        f.seed(OLD)
        self.assertEqual(f.run("restore", "restore"), "delivered")
        self.assertEqual(f.current(), CANARY)
        self.assertEqual(self.scan(f.profile, OLD), [])
        self.assertEqual(f.effects().count("fetch"), 2)
        self.assertEqual(self.states(f), ["released", "released"])
        f.keys.revoke(f.mapping.key_id())
        before = list(f.effects())
        self.assertEqual(f.run("forget", "forget"), "forgotten")
        self.assertEqual(f.effects(), before)
        self.assertEqual(f.state()["phase"], "forgotten")
        self.assertEqual(self.scan(f.root), [])
        for action in ("save", "restore"):
            with self.assertRaises(Denied):
                f.run(action, "late-" + action)
        self.assertEqual(f.effects(), before)

    def test_custody_denial_allows_only_existing_tree_preparation(self) -> None:
        f = self.fixture()
        f.seed()
        f.run("save", "save")
        f.seed(OLD)
        f.keys.revoke(f.mapping.key_id())
        before = f.effects()
        with self.assertRaises(Denied):
            f.run("restore", "restore")
        self.assertEqual(f.effects()[len(before) :], ["prepare"])
        self.assertEqual(f.current(), OLD)
        self.assertEqual(self.scan(f.profile), [])
        self.assertEqual(f.run("restore", "restore"), "unknown")
        self.assertEqual(f.effects()[len(before) :], ["prepare", "prepare"])
        with self.assertRaises(Denied):
            f.run("save", "second-save", reference="second")
        self.assertEqual(f.effects()[len(before) :], ["prepare", "prepare"])

    def test_disable_during_fetch_has_no_consume_then_issued_disable_can_finish(
        self,
    ) -> None:
        for stage in ("fetch", "issue"):
            f = self.fixture(stage)
            f.seed()
            f.run("save", "save")
            f.seed(OLD)
            original = f.peer.on_fetch if stage == "fetch" else f.keys.after_issue

            def disable() -> None:
                original()
                f.keys.revoke(f.mapping.key_id())

            if stage == "fetch":
                f.peer.on_fetch = disable
            else:
                f.keys.after_issue = disable
            before = f.effects()
            if stage == "fetch":
                with self.assertRaises(Denied):
                    f.run("restore", "restore")
                self.assertEqual(f.effects()[len(before) :], ["prepare", "fetch"])
                self.assertEqual(f.current(), OLD)
            else:
                self.assertEqual(f.run("restore", "restore"), "delivered")
                self.assertEqual(
                    f.effects()[len(before) :], ["prepare", "fetch", "issue", "consume"]
                )
                self.assertEqual(f.current(), CANARY)
            with self.assertRaises(Denied):
                f.run("restore", "fresh-restore")

    def test_browser_authority_loss_after_issue_prevents_materialization(self) -> None:
        f = self.fixture()
        f.seed()
        f.run("save", "save")
        f.seed(OLD)
        f.keys.after_issue = lambda: setattr(f.authority, "allowed", False)
        before = f.tree.consumes
        with self.assertRaises(Denied):
            f.run("restore", "restore")
        self.assertEqual(f.tree.consumes, before)
        self.assertEqual(f.current(), OLD)
        self.assertEqual(self.states(f), ["released", "released"])

    def test_pending_and_issued_process_death_burn_without_directory_replay(
        self,
    ) -> None:
        for fault in ("pending", "issued"):
            f = self.fixture(fault)
            f.seed()
            f.run("save", "save")
            f.seed(OLD)
            before = f.effects().count("consume")
            self.crash(f, "restore", fault)
            f.keys.revoke(f.mapping.key_id())
            effects = f.effects()
            self.assertEqual(f.run("restore", "child-restore"), "unknown")
            self.assertEqual(f.effects()[len(effects) :], ["prepare"])
            self.assertEqual(f.effects().count("consume"), before)
            self.assertEqual(f.current(), OLD)
            self.assertEqual(f.run("forget", "cleanup"), "forgotten")
            self.assertEqual(self.scan(f.root), [])

    def test_directory_crash_recovery_with_custody_disabled_does_not_decrypt_again(
        self,
    ) -> None:
        for fault, expected in (
            ("after-building", OLD),
            ("plaintext", OLD),
            ("after-cleanup", CANARY),
        ):
            f = self.fixture(fault)
            f.seed()
            f.run("save", "save")
            f.seed(OLD)
            self.crash(f, "restore", fault)
            remnants = self.scan(f.profile)
            if fault != "after-building":
                self.assertTrue(remnants)  # SIGKILL can leave private plaintext.
            f.keys.revoke(f.mapping.key_id())
            before = f.effects()
            self.assertEqual(f.run("restore", "child-restore"), "unknown")
            self.assertEqual(f.effects()[len(before) :], ["prepare"])
            self.assertEqual(f.current(), expected)
            self.assertEqual(f.state()["phase"], "ready")
            self.assertEqual(len(list(f.profile.glob("g-*"))), 1)
            self.assertFalse(list(f.profile.glob("stage-*")))
            self.assertEqual(f.run("forget", "cleanup"), "forgotten")
            self.assertEqual(self.scan(f.root), [])
            self.assertEqual(f.effects().count("fetch"), before.count("fetch"))

    def test_ciphertext_tombstone_crash_gate_precedes_all_recovery_and_keys(
        self,
    ) -> None:
        f = self.fixture()
        f.seed()
        f.run("save", "save")
        self.crash(f, "forget", "tombstone-gap")
        self.assertEqual(f.state()["phase"], "ready")
        self.assertTrue(self.scan(f.profile))
        f.keys.revoke(f.mapping.key_id())
        before = f.effects()
        with self.assertRaises(Denied):
            f.run("restore", "after-forget")
        self.assertEqual(f.effects(), before)
        self.assertEqual(f.run("forget", "finish-forget"), "forgotten")
        self.assertEqual(f.effects(), before)
        self.assertEqual(self.scan(f.root), [])

    def test_cancelled_directory_write_releases_custody_and_preserves_unknown(
        self,
    ) -> None:
        f = self.fixture()
        f.seed()
        f.run("save", "save")
        f.seed(OLD)
        write = f.tree._write
        for kind in (ValueError, KeyboardInterrupt):

            def fail(_fd: int, _data: bytes) -> None:
                if _data == CANARY:
                    raise kind(CANARY.decode())
                write(_fd, _data)

            name = "cancel-" + kind.__name__
            with patch.object(f.tree, "_write", side_effect=fail):
                with self.assertRaises(
                    Cancelled if kind is KeyboardInterrupt else Denied
                ) as caught:
                    f.run("restore", name)
            self.assertIsNone(caught.exception.__context__)
            self.assertNotIn(
                CANARY.decode(), "".join(traceback.format_exception(caught.exception))
            )
            self.assertEqual(self.states(f)[-1], "released")
            before = f.effects().count("fetch")
            self.assertEqual(f.run("restore", name), "unknown")
            self.assertEqual(f.effects().count("fetch"), before)
            self.assertEqual(f.current(), OLD)

    def test_mutation_exposes_forbidden_materialization_after_fetch_revocation(
        self,
    ) -> None:
        f = self.fixture()
        f.seed()
        f.run("save", "save")
        f.seed(OLD)
        original = f.peer.on_fetch

        def disable() -> None:
            original()
            f.keys.revoke(f.mapping.key_id())

        f.peer.on_fetch = disable
        before = f.tree.consumes
        with patch.object(f.keys, "_enabled", return_value=None):
            self.assertEqual(f.run("restore", "mutated"), "delivered")
        self.assertEqual(f.tree.consumes, before + 1)
        self.assertEqual(f.current(), CANARY)
        # The ordinary fetch-revocation case observes zero consume and OLD bytes.

    def test_forgetting_phase_process_death_recovers_without_provider(self) -> None:
        f = self.fixture()
        f.seed()
        f.run("save", "save")
        f.keys.revoke(f.mapping.key_id())
        before = f.effects()
        self.crash(f, "forget", "after-forgotten")
        self.assertEqual(f.state()["phase"], "forgotten")
        self.assertTrue(self.scan(f.profile))
        self.assertEqual(f.run("forget", "finish-forget"), "forgotten")
        self.assertEqual(f.effects(), before)
        self.assertEqual(self.scan(f.root), [])


if __name__ == "__main__":
    unittest.main()

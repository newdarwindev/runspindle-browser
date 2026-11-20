"""Real contained plaintext deletion with synthetic admissions, never a browser."""

import base64
import fcntl
import hashlib
import json
import os
import socket
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from typing import Any, Callable, cast
from unittest.mock import patch

from browser_runtime.profile_directory import DirectoryProfileIO, MaterializedStore
from browser_runtime.profile_store import Cancelled, Denied, Store, encoded
from browser_testing.profile_store_fixtures import BASE, CANARY, Fake, grant

ROOT = Path(__file__).resolve().parents[1]
OTHER = b"SYNTHETIC_UNRELATED_PROFILE_8e0c25"


def bundle(scope: str, content: bytes = CANARY) -> bytes:
    return encoded(
        {
            "version": 1,
            "scope": scope,
            "directories": [["empty"], ["nested"]],
            "files": [
                [["nested", "Cookies"], base64.b64encode(content).decode("ascii")],
                [["settings"], base64.b64encode(b"invented settings").decode("ascii")],
            ],
        }
    ).encode()


class DiscardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.cases = 0
        self.new_case()
        network = patch.object(
            socket.socket, "connect", side_effect=AssertionError("network forbidden")
        )
        network.start()
        self.addCleanup(network.stop)

    def new_case(self) -> None:
        self.cases += 1
        self.tree_path = self.root / f"tree-{self.cases}"
        self.store_path = self.root / f"store-{self.cases}"
        self.tree_path.mkdir(mode=0o700)
        self.store_path.mkdir(mode=0o700)
        self.fake = Fake()
        self.tree = DirectoryProfileIO(self.tree_path, self.fake.grant)
        self.store = MaterializedStore(
            self.store_path, self.fake, self.fake.adapters().keys, self.tree
        )
        self.addCleanup(self.tree.close)
        self.addCleanup(self.store.close)
        self.fake.grant = grant("restore")
        self.assertTrue(
            self.tree.consume(
                self.fake.grant, self.fake, bundle(self.fake.grant.scope())
            )
        )
        self.fake.grant = grant("save")
        self.assertEqual(self.store.run("trusted-ticket"), "stored")
        self.identifier = cast(str, self.state()["current"])
        self.before = self.rows()

    def state(self) -> dict[str, Any]:
        return cast(
            dict[str, Any], json.loads((self.tree_path / "state.json").read_text())
        )

    def rows(self) -> dict[str, list[tuple[Any, ...]]]:
        with sqlite3.connect(self.store_path / "profiles.sqlite3") as db:
            tables = [
                row[0]
                for row in db.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            ]
            return {
                table: db.execute(f'SELECT * FROM "{table}" ORDER BY 1').fetchall()
                for table in tables
            }

    def tree_bytes(self) -> dict[str, bytes]:
        return {
            str(path.relative_to(self.tree_path)): path.read_bytes()
            for path in self.tree_path.rglob("*")
            if path.is_file() and not path.is_symlink()
        }

    def discard(self, reference: str | None = None, **changes: Any) -> str:
        self.fake.grant = grant(
            "discard",
            reference=self.identifier if reference is None else reference,
            **changes,
        )
        return self.store.run("trusted-ticket")

    def restore(self, operation: str = "new-restore") -> str:
        self.fake.grant = grant(
            "restore",
            target=replace(BASE, binding=replace(BASE.binding, operation=operation)),
        )
        return self.store.run("trusted-ticket")

    def assert_empty(self) -> None:
        state = self.state()
        self.assertEqual(state["phase"], "ready")
        for field in ("current", "candidate", "retired", "digest", "candidate_digest"):
            self.assertIsNone(state[field])
        self.assertEqual(set(self.tree_bytes()), {"profile.lock", "state.json"})
        self.assertEqual(
            {p.name for p in self.tree_path.iterdir()}, {"profile.lock", "state.json"}
        )

    def pending(self) -> None:
        with patch.object(self.tree, "_remove", side_effect=OSError(CANARY.decode())):
            with self.assertRaises(Denied):
                self.discard()
        self.assertEqual(self.state()["phase"], "discarding")
        self.assertEqual(self.state()["current"], self.identifier)

    def test_discard_removes_plaintext_preserves_ciphertext_and_fresh_restore(
        self,
    ) -> None:
        reads = self.fake.reads
        self.assertEqual(self.discard(), "discarded")
        self.assert_empty()
        self.assertEqual(self.fake.reads, reads)
        self.assertEqual(self.rows(), self.before)
        for data in self.tree_bytes().values():
            self.assertNotIn(CANARY, data)
            self.assertNotIn(base64.b64encode(CANARY), data)
        self.assertEqual(self.restore(), "delivered")
        current = self.tree_path / ("g-" + self.state()["current"])
        self.assertEqual((current / "nested" / "Cookies").read_bytes(), CANARY)
        self.assertNotEqual(self.state()["current"], self.identifier)

    def test_old_discard_cannot_delete_fresh_generation_or_repeat_empty(self) -> None:
        self.assertEqual(self.discard(), "discarded")
        with self.assertRaises(Denied):
            self.discard()
        self.assert_empty()
        self.assertEqual(self.restore(), "delivered")
        before = self.tree_bytes()
        with self.assertRaises(Denied):
            self.discard()
        self.assertEqual(self.tree_bytes(), before)

    def test_completed_restore_status_never_replays_materialization(self) -> None:
        self.assertEqual(self.restore("first"), "delivered")
        self.identifier = self.state()["current"]
        self.assertEqual(self.discard(), "discarded")
        self.assertEqual(self.restore("first"), "delivered")
        self.assert_empty()  # Historical delivery is not current usable-profile proof.
        self.assertEqual(self.restore("second"), "delivered")
        self.assertIsNotNone(self.state()["current"])

    def test_base_store_rejects_new_action_without_io_or_ciphertext_mutation(
        self,
    ) -> None:
        self.fake.grant = grant("discard", reference=self.identifier)
        base = Store(self.store_path, self.fake.adapters())
        try:
            before = self.tree_bytes()
            reads = self.fake.reads
            with self.assertRaises(Denied):
                base.run("trusted-ticket")
            self.assertEqual(self.tree_bytes(), before)
            self.assertEqual(self.rows(), self.before)
            self.assertEqual(
                (self.fake.reads, self.fake.captures, self.fake.consumes), (reads, 0, 0)
            )
        finally:
            base.close()

    def test_checkpoint_reference_and_wrong_generation_have_zero_tree_effects(
        self,
    ) -> None:
        before = self.tree_bytes()
        for reference in ("checkpoint", "0" * 32, "../outside", "A" * 32):
            with self.subTest(reference=reference), self.assertRaises(Denied):
                self.discard(reference)
            self.assertEqual(self.tree_bytes(), before)
            self.assertEqual(self.rows(), self.before)

    def test_authority_scope_quiescence_and_stale_owner_deny_before_cleanup(
        self,
    ) -> None:
        before = self.tree_bytes()
        targets = (
            replace(BASE, binding=replace(BASE.binding, account="other")),
            replace(
                BASE, binding=replace(BASE.binding, origin="https://other.example")
            ),
            replace(BASE, frame_origin="https://other.example"),
            replace(BASE, native_session="other-owner"),
            replace(BASE, binding=replace(BASE.binding, epoch=6)),
        )
        for target in targets:
            with self.subTest(target=target), self.assertRaises(Denied):
                self.discard(target=target)
            self.assertEqual(self.tree_bytes(), before)
        for flag in ("allowed", "stopped"):
            setattr(self.fake, flag, False)
            with self.assertRaises(Denied):
                self.discard()
            setattr(self.fake, flag, True)
            self.assertEqual(self.tree_bytes(), before)
        with self.assertRaises(Denied):
            self.discard(deadline=0)
        with self.assertRaises(Denied):
            self.discard(profile="other-profile")
        self.assertEqual(self.rows(), self.before)

    def test_pending_discard_blocks_save_restore_and_wrong_generation(self) -> None:
        self.pending()
        before = self.tree_bytes()
        reads = self.fake.reads
        for action in ("save", "restore"):
            self.fake.grant = grant(
                action,
                reference="second-checkpoint" if action == "save" else "checkpoint",
            )
            with self.assertRaises(Denied):
                self.store.run("trusted-ticket")
            self.assertEqual(self.tree_bytes(), before)
        with self.assertRaises(Denied):
            self.discard("0" * 32)
        self.assertEqual(self.tree_bytes(), before)
        # Save may acquire its key before the directory rejects capture. No
        # plaintext consumption occurs; discard itself never requests a key.
        after_reads = self.fake.reads
        self.assertGreaterEqual(after_reads, reads)
        self.assertEqual(self.discard(), "discarded")
        self.assertEqual(self.fake.reads, after_reads)
        self.assert_empty()

    def test_pending_discard_allows_fresh_terminal_forget(self) -> None:
        self.pending()
        reads = self.fake.reads
        self.fake.grant = grant("forget")
        self.assertEqual(self.store.run("trusted-ticket"), "forgotten")
        self.assertEqual(self.fake.reads, reads)
        self.assertEqual(self.state()["phase"], "forgotten")
        self.assertEqual(self.rows()["checkpoints"], [])
        self.assertEqual(self.rows()["profiles"][0][-1], 1)
        self.assertFalse(list(self.tree_path.glob("g-*")))
        with self.assertRaises(Denied):
            self.restore()
        with self.assertRaises(Denied):
            self.discard()

    def test_ciphertext_tombstone_denies_before_any_directory_discard(self) -> None:
        original = self.tree.forget
        with patch.object(self.tree, "forget", side_effect=OSError("interrupted")):
            self.fake.grant = grant("forget")
            with self.assertRaises(Denied):
                self.store.run("trusted-ticket")
        before = self.tree_bytes()
        calls: list[object] = []
        with patch.object(
            self.tree, "discard", side_effect=lambda *args: calls.append(args)
        ):
            with self.assertRaises(Denied):
                self.discard()
        self.assertEqual(calls, [])
        self.assertEqual(self.tree_bytes(), before)
        self.fake.grant = grant("forget")
        self.assertEqual(self.store.run("trusted-ticket"), "forgotten")
        self.assertEqual(self.tree.forget, original)

    def test_pending_restore_phases_require_their_own_recovery(self) -> None:
        before = self.state()
        for phase in ("building", "cleanup"):
            state = dict(before, phase=phase)
            if phase == "building":
                state.update(candidate="a" * 32, candidate_digest="b" * 64)
            self.tree._write_state(state)
            files = self.tree_bytes()
            with self.assertRaises(Denied):
                self.discard()
            self.assertEqual(self.tree_bytes(), files)
            self.assertEqual(self.rows(), self.before)
        self.tree._write_state(before)

    def test_new_owner_epoch_is_fenced_after_successful_discard(self) -> None:
        target = replace(
            BASE, native_session="new-owner", binding=replace(BASE.binding, epoch=8)
        )
        self.assertEqual(self.discard(target=target), "discarded")
        self.assert_empty()
        with self.assertRaises(Denied):
            self.restore()
        self.fake.grant = grant(
            "restore",
            target=replace(target, binding=replace(target.binding, operation="new")),
        )
        self.assertEqual(self.store.run("trusted-ticket"), "delivered")
        self.assertIsNotNone(self.state()["current"])

    def test_actual_directory_lock_denies_discard_without_changes(self) -> None:
        before = self.tree_bytes()
        fd = os.open(self.tree_path / "profile.lock", os.O_RDWR)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises(Denied):
                self.discard()
            self.assertEqual(self.tree_bytes(), before)
            self.assertEqual(self.rows(), self.before)
        finally:
            os.close(fd)

    def test_close_does_not_discard_or_start_recovery(self) -> None:
        self.pending()
        before = self.tree_bytes()
        self.store.close()
        self.tree.close()
        self.assertEqual(self.tree_bytes(), before)
        tree = DirectoryProfileIO(self.tree_path, grant())
        tree.close()
        self.assertEqual(self.tree_bytes(), before)

    def test_unknown_files_and_links_are_not_deleted_or_followed(self) -> None:
        outside = self.root / "outside"
        outside.write_bytes(OTHER)
        unexpected = self.tree_path / "unrelated"
        unexpected.write_bytes(OTHER)
        unexpected.chmod(0o600)
        with self.assertRaises(Denied):
            self.discard()
        self.assertEqual(unexpected.read_bytes(), OTHER)
        unexpected.unlink()
        cookie = self.tree_path / ("g-" + self.identifier) / "nested" / "Cookies"
        cookie.unlink()
        cookie.symlink_to(outside)
        with self.assertRaises(Denied):
            self.discard()
        self.assertTrue(cookie.is_symlink())
        self.assertEqual(outside.read_bytes(), OTHER)
        self.assertEqual(self.rows(), self.before)

    def test_unrelated_profile_checkpoint_and_directory_survive(self) -> None:
        other_path = self.root / "other-tree"
        other_path.mkdir(mode=0o700)
        self.fake.grant = grant("restore", profile="other-profile")
        other = DirectoryProfileIO(other_path, self.fake.grant)
        self.addCleanup(other.close)
        other.consume(
            self.fake.grant, self.fake, bundle(self.fake.grant.scope(), OTHER)
        )
        other_store = MaterializedStore(
            self.store_path, self.fake, self.fake.adapters().keys, other
        )
        self.addCleanup(other_store.close)
        self.fake.grant = grant(
            "save", profile="other-profile", reference="other-checkpoint"
        )
        self.assertEqual(other_store.run("trusted-ticket"), "stored")
        rows = self.rows()
        files = {str(p): p.read_bytes() for p in other_path.rglob("*") if p.is_file()}
        self.assertEqual(self.discard(), "discarded")
        self.assertEqual(self.rows(), rows)
        self.assertEqual(
            {str(p): p.read_bytes() for p in other_path.rglob("*") if p.is_file()},
            files,
        )

    def test_cleanup_failure_cancellation_and_suppressing_guard_never_succeed(
        self,
    ) -> None:
        for error in (OSError(CANARY.decode()), KeyboardInterrupt(CANARY.decode())):
            with self.subTest(error=type(error).__name__):
                self.fake.suppress = True
                with patch.object(self.tree, "_remove", side_effect=error):
                    try:
                        self.discard()
                    except (Denied, Cancelled) as caught:
                        self.assertIsNone(caught.__cause__)
                        self.assertIsNone(caught.__context__)
                        self.assertNotIn(CANARY.decode(), str(caught))
                    else:
                        self.fail("cleanup failure was reported as success")
                self.fake.suppress = False
                self.assertEqual(self.state()["phase"], "discarding")
        self.assertEqual(self.discard(), "discarded")

    def test_authority_loss_after_discard_marker_leaves_explicit_pending_state(
        self,
    ) -> None:
        write = self.tree._write_state

        def lose(state: dict[str, object]) -> None:
            write(state)
            if state["phase"] == "discarding":
                self.fake.allowed = False

        with patch.object(self.tree, "_write_state", side_effect=lose):
            with self.assertRaises(Denied):
                self.discard()
        self.assertEqual(self.state()["phase"], "discarding")
        self.assertTrue(list(self.tree_path.glob("g-*")))
        self.assertEqual(self.rows(), self.before)
        self.fake.allowed = True
        self.assertEqual(self.discard(), "discarded")

    def revoke_after_first_plaintext_unlink(self, operation: Callable[[], str]) -> None:
        real_unlink = os.unlink
        names = self.tree._names
        tree = self.tree_path / ("g-" + self.identifier)
        contents = {p.name for p in tree.rglob("*") if p.is_file()}
        removed: list[str] = []

        def unlink(name: str, **kwargs: Any) -> None:
            real_unlink(name, **kwargs)
            if name in contents:
                removed.append(name)
                self.fake.allowed = False

        with (
            patch.object(
                self.tree, "_names", side_effect=lambda *args: sorted(names(*args))
            ),
            patch("os.unlink", side_effect=unlink),
            self.assertRaises(Denied),
        ):
            operation()
        self.assertEqual(removed, ["Cookies"], "revoked cleanup removed another file")
        self.assertTrue(
            (tree / "nested").is_dir(), "revoked cleanup removed a directory"
        )
        remaining = {p.name for p in tree.rglob("*") if p.is_file()}
        self.assertEqual(remaining, contents - set(removed))

    def test_discard_rechecks_authority_between_plaintext_removals(self) -> None:
        sibling = self.tree_path / ("g-" + self.identifier) / "nested" / "Session"
        sibling.write_bytes(b"synthetic session")
        sibling.chmod(0o600)
        self.revoke_after_first_plaintext_unlink(self.discard)
        self.assertEqual(self.state()["phase"], "discarding")
        self.assertEqual(self.rows(), self.before)
        recovered = self.child("recover")
        self.assertEqual(recovered.returncode, 0, recovered.stderr)
        self.assertIn("discarded", recovered.stdout)
        self.assert_empty()

    def test_forget_stops_plaintext_cleanup_after_authority_loss(self) -> None:
        self.fake.grant = grant("forget")
        self.revoke_after_first_plaintext_unlink(
            lambda: self.store.run("trusted-ticket")
        )
        self.assertEqual(self.state()["phase"], "forgotten")
        self.assertEqual(self.rows()["checkpoints"], [])
        self.fake.allowed = True
        self.fake.grant = grant("forget")
        self.assertEqual(self.store.run("trusted-ticket"), "forgotten")
        self.assertIsNone(self.state()["current"])
        self.assertEqual(set(self.tree_bytes()), {"profile.lock", "state.json"})

    def child(self, fault: str) -> subprocess.CompletedProcess[str]:
        script = r"""
import hashlib, json, os, socket, sys
from unittest.mock import patch
from browser_runtime.profile_directory import DirectoryProfileIO, MaterializedStore
from browser_runtime.profile_store import Denied
from browser_testing.profile_store_fixtures import Fake, grant
fake = Fake()
fake.grant = grant("discard", reference=sys.argv[3])
tree = DirectoryProfileIO(sys.argv[1], fake.grant)
store = MaterializedStore(sys.argv[2], fake, fake.adapters().keys, tree)
count = 0
real_sync = os.fsync
fault = sys.argv[4]
def sync(fd):
    global count
    count += 1
    if fault == "before-" + str(count): os._exit(81)
    real_sync(fd)
    if fault == "after-" + str(count): os._exit(82)
os.fsync = sync
with patch.object(socket.socket, "connect", side_effect=AssertionError("network forbidden")):
    try:
        print(store.run("trusted-ticket"))
    except Denied:
        print("denied")
    finally:
        store.close()
        tree.close()
    print("sync-count", count)
    print("key-reads", fake.reads)
"""
        return subprocess.run(
            [
                sys.executable,
                *(["-O"] if sys.flags.optimize else []),
                "-c",
                script,
                str(self.tree_path),
                str(self.store_path),
                self.identifier,
                fault,
            ],
            cwd=ROOT,
            env=dict(os.environ, PYTHONPATH=str(ROOT)),
            capture_output=True,
            text=True,
            timeout=15,
        )

    def test_fresh_process_crashes_before_after_every_discard_fsync(self) -> None:
        counted = self.child("count")
        self.assertEqual(counted.returncode, 0, counted.stderr)
        count = int(counted.stdout.split("sync-count ")[1].splitlines()[0])
        self.assertGreaterEqual(count, 10)
        self.assertIn("key-reads 0", counted.stdout)
        for boundary in range(1, count + 1):
            for when in ("before", "after"):
                with self.subTest(boundary=boundary, when=when):
                    self.new_case()
                    died = self.child(f"{when}-{boundary}")
                    self.assertIn(died.returncode, (81, 82), died.stderr)
                    self.assertEqual(self.rows(), self.before)
                    state = self.state()
                    self.assertIn(state["phase"], ("ready", "discarding"))
                    if state["phase"] == "ready" and state["current"] is not None:
                        # Without durable DISCARDING, partial deletion must never
                        # leave the generation represented as READY.
                        current = self.tree_path / ("g-" + self.identifier)
                        self.assertEqual(
                            (current / "nested" / "Cookies").read_bytes(), CANARY
                        )
                        self.assertEqual(
                            (current / "settings").read_bytes(), b"invented settings"
                        )
                        self.assertTrue((current / "empty").is_dir())
                    recovered = self.child("recover")
                    self.assertEqual(recovered.returncode, 0, recovered.stderr)
                    self.assertIn("key-reads 0", recovered.stdout)
                    self.assert_empty()
                    self.assertEqual(self.rows(), self.before)
                    self.assertEqual(self.restore(), "delivered")
                    current = self.tree_path / ("g-" + self.state()["current"])
                    self.assertEqual(
                        (current / "nested" / "Cookies").read_bytes(), CANARY
                    )

    def test_cancellation_after_plaintext_unlink_is_pending_and_freshly_recoverable(
        self,
    ) -> None:
        before_ciphertext = hashlib.sha256(
            (self.store_path / "profiles.sqlite3").read_bytes()
        ).hexdigest()
        real_unlink = os.unlink

        def unlink(name: str, **kwargs: Any) -> None:
            real_unlink(name, **kwargs)
            if name == "Cookies":
                self.fake.allowed = False
                raise KeyboardInterrupt(CANARY.decode())

        with patch("os.unlink", side_effect=unlink):
            with self.assertRaises(Cancelled):
                self.discard()
        self.assertEqual(self.state()["phase"], "discarding")
        self.assertEqual(self.rows(), self.before)
        self.assertEqual(
            hashlib.sha256(
                (self.store_path / "profiles.sqlite3").read_bytes()
            ).hexdigest(),
            before_ciphertext,
        )
        recovered = self.child("recover")
        self.assertEqual(recovered.returncode, 0, recovered.stderr)
        self.assertIn("discarded", recovered.stdout)
        self.assert_empty()


if __name__ == "__main__":
    unittest.main()

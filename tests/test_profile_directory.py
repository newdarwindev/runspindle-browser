"""Synthetic directories and real filesystem/crash evidence; no browser launch."""

import base64
import json
import os
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import closing
from dataclasses import replace
from pathlib import Path
from typing import Any, cast
from unittest.mock import patch

from browser_runtime.profile_directory import DirectoryProfileIO, MaterializedStore
from browser_runtime.profile_store import Cancelled, Denied, encoded
from browser_testing.profile_store_fixtures import BASE, CANARY, Fake, grant

ROOT = Path(__file__).resolve().parents[1]
OLD = b"SYNTHETIC_OLD_COOKIE_12923"


def bundle(scope: str, value: bytes = CANARY) -> bytes:
    return encoded(
        {
            "version": 1,
            "scope": scope,
            "directories": [["empty"], ["nested"]],
            "files": [
                [["nested", "Cookies"], base64.b64encode(value).decode("ascii")],
                [
                    ["preferences"],
                    base64.b64encode(b"synthetic preferences").decode("ascii"),
                ],
            ],
        }
    ).encode()


class DirectoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.tree_path, self.store_path = self.root / "tree", self.root / "ciphertext"
        self.tree_path.mkdir(mode=0o700)
        self.store_path.mkdir(mode=0o700)
        self.fake = Fake()
        self.tree = DirectoryProfileIO(self.tree_path, self.fake.grant)
        self.addCleanup(self.tree.close)
        self.store = MaterializedStore(
            self.store_path, self.fake, self.fake.adapters().keys, self.tree
        )
        self.addCleanup(self.store.close)
        self.network = patch.object(
            socket.socket, "connect", side_effect=AssertionError("network forbidden")
        )
        self.network.start()
        self.addCleanup(self.network.stop)

    def state(self) -> dict[str, Any]:
        return cast(
            dict[str, Any], json.loads((self.tree_path / "state.json").read_text())
        )

    def active(self) -> Path:
        # Independent test observation only. Runtime exposes no active path.
        return self.tree_path / ("g-" + cast(str, self.state()["current"]))

    def seed(self, data: bytes = CANARY) -> None:
        self.fake.grant = grant("restore")
        self.assertTrue(
            self.tree.consume(
                self.fake.grant, self.fake, bundle(self.fake.grant.scope(), data)
            )
        )

    def run_action(self, action: str, **changes: Any) -> str:
        self.fake.grant = grant(action, **changes)
        return self.store.run("trusted-ticket")

    def all_files(self, base: Path) -> list[bytes]:
        return [
            p.read_bytes()
            for p in base.rglob("*")
            if p.is_file() and not p.is_symlink()
        ]

    def test_real_nested_capture_encryption_materialization_and_forget(self) -> None:
        self.seed()
        self.assertEqual(self.run_action("save"), "stored")
        self.assertFalse(
            any(CANARY in value for value in self.all_files(self.store_path))
        )
        self.seed(OLD)
        self.assertEqual(self.run_action("restore"), "delivered")
        self.assertEqual((self.active() / "nested" / "Cookies").read_bytes(), CANARY)
        self.assertTrue((self.active() / "empty").is_dir())
        self.assertFalse(any(OLD in value for value in self.all_files(self.tree_path)))
        self.assertEqual(len(list(self.tree_path.glob("g-*"))), 1)
        self.assertEqual(self.run_action("forget"), "forgotten")
        self.assertEqual(self.state()["phase"], "forgotten")
        self.assertFalse(any(CANARY in value for value in self.all_files(self.root)))
        self.assertFalse(list(self.tree_path.glob("g-*")))
        with self.assertRaises(Denied):
            self.run_action("restore")
        with self.assertRaises(Denied):
            self.run_action("save", reference="new")

    def test_wrong_scope_origin_and_stale_owner_have_zero_tree_changes(self) -> None:
        self.seed()
        before = self.all_files(self.tree_path)
        other = replace(BASE, binding=replace(BASE.binding, account="other"))
        self.fake.grant = grant("restore", target=other)
        with self.assertRaises(Denied):
            self.tree.consume(
                self.fake.grant, self.fake, bundle(self.fake.grant.scope())
            )
        self.assertEqual(self.all_files(self.tree_path), before)
        other = replace(BASE, native_session="other-owner")
        self.fake.grant = grant("restore", target=other)
        with self.assertRaises(Denied):
            self.tree.consume(
                self.fake.grant, self.fake, bundle(self.fake.grant.scope())
            )
        self.assertEqual(self.all_files(self.tree_path), before)

    def test_forget_rejects_mismatched_tree_before_ciphertext_deletion(self) -> None:
        self.seed()
        self.assertEqual(self.run_action("save"), "stored")

        def persisted() -> tuple[list[tuple[Any, ...]], list[tuple[Any, ...]]]:
            with closing(sqlite3.connect(self.store_path / "profiles.sqlite3")) as db:
                return (
                    db.execute("SELECT * FROM profiles").fetchall(),
                    db.execute("SELECT * FROM checkpoints").fetchall(),
                )

        before = persisted()
        scopes = {
            "principal": grant(
                target=replace(BASE, binding=replace(BASE.binding, principal="other"))
            ),
            "account": grant(
                target=replace(BASE, binding=replace(BASE.binding, account="other"))
            ),
            "profile": grant(profile="other"),
            "top-origin": grant(
                target=replace(
                    BASE, binding=replace(BASE.binding, origin="https://other.example")
                )
            ),
            "frame-origin": grant(
                target=replace(BASE, frame_origin="https://other.example")
            ),
        }
        for name, selection in scopes.items():
            with self.subTest(scope=name):
                path = self.root / name
                path.mkdir(mode=0o700)
                wrong_tree = DirectoryProfileIO(path, selection)
                self.addCleanup(wrong_tree.close)
                wrong_store = MaterializedStore(
                    self.store_path, self.fake, self.fake.adapters().keys, wrong_tree
                )
                self.addCleanup(wrong_store.close)
                self.fake.grant = grant("forget")
                tree_before = self.all_files(path)
                with patch.object(
                    wrong_tree, "forget", wraps=wrong_tree.forget
                ) as cleanup:
                    with self.assertRaises(Denied):
                        wrong_store.run("trusted-ticket")
                    self.assertEqual(persisted(), before)
                    cleanup.assert_not_called()
                self.assertEqual(self.all_files(path), tree_before)

        self.assertEqual(self.run_action("restore"), "delivered")
        self.assertEqual(self.run_action("forget"), "forgotten")

    def test_malformed_bundles_never_write_plaintext_or_outside_root(self) -> None:
        good = json.loads(bundle(self.fake.grant.scope()))
        values: list[bytes] = []
        for path in (
            ["..", "outside"],
            ["/outside"],
            ["x/y"],
            ["x\\y"],
            ["a"] * 9,
            ["a\n"],
        ):
            bad = dict(
                good, directories=[], files=[[path, base64.b64encode(CANARY).decode()]]
            )
            values.append(encoded(bad).encode())
        values.extend(
            [
                encoded(dict(good, scope="wrong")).encode(),
                encoded(dict(good, files=good["files"] + good["files"])).encode(),
                b'{"version":1,"version":1}',
                encoded(dict(good, files=[[None]])).encode(),
                encoded(dict(good, files=[[["file"], None]])).encode(),
            ]
        )
        for data in values:
            self.fake.grant = grant("restore")
            with self.assertRaises(Denied):
                self.tree.consume(self.fake.grant, self.fake, data)
            self.assertEqual(self.state()["phase"], "ready")
            self.assertEqual(list(self.tree_path.glob("stage-*")), [])
            self.assertEqual(list(self.tree_path.glob("g-*")), [])
        self.assertFalse(any(CANARY in value for value in self.all_files(self.root)))

    def test_file_link_device_and_permissions_capture_rejection(self) -> None:
        self.seed()
        cookie = self.active() / "nested" / "Cookies"
        outside = self.root / "outside"
        outside.write_bytes(b"outside must survive")
        for kind in ("symlink", "hardlink", "fifo", "permissions"):
            original = cookie.read_bytes()
            cookie.unlink()
            if kind == "symlink":
                cookie.symlink_to(outside)
            elif kind == "hardlink":
                os.link(outside, cookie)
            elif kind == "fifo":
                os.mkfifo(cookie, 0o600)
            else:
                cookie.write_bytes(original)
                cookie.chmod(0o644)
            started = time.monotonic()
            with self.assertRaises(Denied):
                self.run_action("save", reference=kind)
            self.assertLess(time.monotonic() - started, 2)
            self.assertEqual(outside.read_bytes(), b"outside must survive")
            cookie.unlink()
            fd = os.open(cookie, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.write(fd, original)
            os.close(fd)

    def test_nested_symlink_and_root_alias_rejected_without_following(self) -> None:
        self.seed()
        outside = self.root / "outside-dir"
        outside.mkdir(mode=0o700)
        (outside / "sentinel").write_bytes(b"untouched")
        (self.active() / "link").symlink_to(outside, target_is_directory=True)
        with self.assertRaises(Denied):
            self.run_action("save")
        with self.assertRaises(Denied):
            self.run_action("forget")
        self.assertEqual((outside / "sentinel").read_bytes(), b"untouched")
        alias = self.root / "alias"
        alias.symlink_to(self.tree_path, target_is_directory=True)
        with self.assertRaises(Denied):
            DirectoryProfileIO(alias, grant())

    def test_payload_limits_and_unsupported_names_deny(self) -> None:
        with patch("browser_runtime.profile_directory.MAX_DATA", 8):
            self.fake.grant = grant("restore")
            with self.assertRaises(Denied):
                self.tree.consume(
                    self.fake.grant, self.fake, bundle(self.fake.grant.scope())
                )
        self.assertFalse(list(self.tree_path.glob("g-*")))
        self.seed()
        with (
            patch("browser_runtime.profile_directory.MAX_NODES", 1),
            self.assertRaises(Denied),
        ):
            self.run_action("save")
        self.assertFalse(list(self.tree_path.glob("stage-*")))

    def test_capture_detects_mutation_after_earlier_file_read(self) -> None:
        self.seed()
        original = self.tree._walk
        calls = 0

        def changed(*args: Any, **kwargs: Any) -> None:
            nonlocal calls
            original(*args, **kwargs)
            if args[1] == () and kwargs["contents"]:
                calls += 1
                (self.active() / "nested" / "Cookies").write_bytes(b"different")

        with (
            patch.object(self.tree, "_walk", side_effect=changed),
            self.assertRaises(Denied),
        ):
            self.run_action("save")
        self.assertEqual(calls, 1)
        with sqlite3.connect(self.store_path / "profiles.sqlite3") as db:
            self.assertEqual(
                db.execute("SELECT count(*) FROM checkpoints").fetchone()[0], 0
            )

    def test_same_and_cross_instance_reentrancy_are_bounded(self) -> None:
        self.seed()
        other = DirectoryProfileIO(self.tree_path, grant())
        self.addCleanup(other.close)
        original = self.tree._bundle
        calls = 0

        def nested(identifier: object, scoped: Any, guard: Any) -> bytes:
            nonlocal calls
            calls += 1
            with self.assertRaises(Denied):
                self.tree.capture(scoped, guard)
            with self.assertRaises(Denied):
                other.capture(scoped, guard)
            return original(identifier, scoped, guard)

        with patch.object(self.tree, "_bundle", side_effect=nested):
            self.assertEqual(self.run_action("save"), "stored")
        self.assertEqual(calls, 1)

    def test_revocation_before_publication_retains_no_success(self) -> None:
        self.seed()
        self.run_action("save")
        self.seed(OLD)
        original = self.tree._write

        def revoke(fd: int, data: bytes) -> None:
            original(fd, data)
            if data == CANARY:
                self.fake.allowed = False

        with (
            patch.object(self.tree, "_write", side_effect=revoke),
            self.assertRaises(Denied),
        ):
            self.run_action("restore")
        self.assertEqual(self.state()["phase"], "building")
        self.assertEqual((self.active() / "nested" / "Cookies").read_bytes(), OLD)
        # Expiry/revocation can leave private staging until new admitted recovery.
        self.assertTrue(
            any(CANARY in value for value in self.all_files(self.tree_path))
        )
        self.fake.allowed = True
        self.assertEqual(self.run_action("restore"), "unknown")
        self.assertEqual(self.state()["phase"], "ready")
        self.assertFalse(
            any(CANARY in value for value in self.all_files(self.tree_path))
        )

    def test_exception_cancellation_cleanup_and_failure_are_explicit(self) -> None:
        self.seed()
        self.run_action("save")
        self.seed(OLD)
        for cancellation in (False, True):
            original = self.tree._write

            def fail(fd: int, data: bytes) -> None:
                if data == CANARY:
                    if cancellation:
                        raise KeyboardInterrupt(CANARY.decode())
                    raise OSError(CANARY.decode())
                original(fd, data)

            target = replace(
                BASE,
                binding=replace(BASE.binding, operation="cancel-" + str(cancellation)),
            )
            with (
                patch.object(self.tree, "_write", side_effect=fail),
                self.assertRaises(Cancelled if cancellation else Denied) as caught,
            ):
                self.run_action("restore", target=target)
            self.assertIsNone(caught.exception.__context__)
            self.assertIsNone(caught.exception.__cause__)
            self.assertFalse(
                any(CANARY in value for value in self.all_files(self.tree_path))
            )
            self.assertEqual(self.state()["phase"], "ready")

    def test_unknown_objects_and_corrupt_state_deny_without_deletion(self) -> None:
        self.seed()
        sentinel = self.tree_path / "unowned"
        sentinel.write_bytes(b"do not delete")
        with self.assertRaises(Denied):
            self.run_action("save")
        self.assertEqual(sentinel.read_bytes(), b"do not delete")
        sentinel.unlink()
        before = (self.tree_path / "state.json").read_bytes()
        (self.tree_path / "state.json").write_text('{"version":999}')
        with self.assertRaises(Denied):
            self.run_action("save")
        self.assertTrue(
            any(CANARY in value for value in self.all_files(self.tree_path))
        )
        (self.tree_path / "state.json").write_bytes(before)

    def child(self, action: str, fault: str) -> subprocess.CompletedProcess[str]:
        script = r"""
import os,sys,socket
from pathlib import Path
from unittest.mock import patch
from browser_runtime.profile_directory import DirectoryProfileIO,MaterializedStore
from browser_testing.profile_store_fixtures import Fake,grant,CANARY
fake=Fake();fake.grant=grant(sys.argv[3])
tree=DirectoryProfileIO(sys.argv[1],fake.grant)
store=MaterializedStore(sys.argv[2],fake,fake.adapters().keys,tree)
fault=sys.argv[4]
write=tree._write_state

def state(value):
 if fault=='before-'+value['phase']: os._exit(81)
 write(value)
 if fault=='after-'+value['phase']: os._exit(82)
tree._write_state=state
original=tree._write

def file(fd,data):
 original(fd,data)
 if fault=='plaintext' and data==CANARY: os._exit(83)
tree._write=file
real_sync=os.fsync
sync_count=0
def sync(fd):
 global sync_count
 sync_count+=1
 if fault=='sync-before-'+str(sync_count): os._exit(85)
 real_sync(fd)
 if fault=='sync-after-'+str(sync_count): os._exit(86)
os.fsync=sync
real_rename=os.rename
def rename(*args,**kwargs):
 if fault=='before-rename': os._exit(87)
 result=real_rename(*args,**kwargs)
 if fault=='after-rename': os._exit(88)
 return result
os.rename=rename
oldforget=tree.forget

def forget(g,guard):
 if fault=='forget-gap': os._exit(84)
 return oldforget(g,guard)
tree.forget=forget
with patch.object(socket.socket,'connect',side_effect=AssertionError('network forbidden')):
 try:
  print(store.run('trusted-ticket'))
  if fault=='count-sync': print('sync-count',sync_count)
 finally: store.close();tree.close()
"""
        return subprocess.run(
            [
                sys.executable,
                *(["-O"] if sys.flags.optimize else []),
                "-c",
                script,
                str(self.tree_path),
                str(self.store_path),
                action,
                fault,
            ],
            env=dict(
                os.environ,
                PYTHONPATH=os.pathsep.join(
                    [str(ROOT), os.environ.get("PYTHONPATH", "")]
                ),
            ),
            capture_output=True,
            text=True,
            timeout=15,
        )

    def reset(self) -> None:
        self.store.close()
        self.tree.close()
        import shutil

        shutil.rmtree(self.tree_path)
        shutil.rmtree(self.store_path)
        self.tree_path.mkdir(mode=0o700)
        self.store_path.mkdir(mode=0o700)
        self.fake = Fake()
        self.tree = DirectoryProfileIO(self.tree_path, grant())
        self.store = MaterializedStore(
            self.store_path, self.fake, self.fake.adapters().keys, self.tree
        )
        self.addCleanup(self.store.close)
        self.addCleanup(self.tree.close)

    def test_process_crashes_recover_without_publishing_incomplete_tree(self) -> None:
        for fault, expected in (
            ("before-building", OLD),
            ("after-building", OLD),
            ("plaintext", OLD),
            ("before-cleanup", OLD),
            ("after-cleanup", CANARY),
        ):
            with self.subTest(fault=fault):
                self.reset()
                self.seed()
                self.run_action("save")
                self.seed(OLD)
                result = self.child("restore", fault)
                self.assertIn(result.returncode, (81, 82, 83), result.stderr)
                self.assertNotIn(CANARY.decode(), result.stdout + result.stderr)
                # A fresh wrapper checks the encrypted tombstone before recovery.
                fresh_tree = DirectoryProfileIO(self.tree_path, grant())
                fresh_store = MaterializedStore(
                    self.store_path, self.fake, self.fake.adapters().keys, fresh_tree
                )
                self.fake.grant = grant("restore")
                try:
                    self.assertEqual(fresh_store.run("trusted-ticket"), "unknown")
                finally:
                    fresh_store.close()
                    fresh_tree.close()
                self.assertEqual(self.state()["phase"], "ready")
                self.assertEqual(
                    (self.active() / "nested" / "Cookies").read_bytes(), expected
                )
                self.assertEqual(len(list(self.tree_path.glob("g-*"))), 1)
                self.assertFalse(list(self.tree_path.glob("stage-*")))

    def test_every_directory_fsync_and_generation_rename_crash_boundary(self) -> None:
        self.seed()
        self.run_action("save")
        self.seed(OLD)
        count_run = self.child("restore", "count-sync")
        self.assertEqual(count_run.returncode, 0, count_run.stderr)
        count = int(count_run.stdout.split("sync-count ")[1].strip())
        self.assertGreater(count, 10)
        faults = [
            f"sync-{side}-{number}"
            for number in range(1, count + 1)
            for side in ("before", "after")
        ]
        faults += ["before-rename", "after-rename"]
        for fault in faults:
            with self.subTest(fault=fault):
                self.reset()
                self.seed()
                self.run_action("save")
                self.seed(OLD)
                result = self.child("restore", fault)
                self.assertIn(
                    result.returncode, (85, 86, 87, 88), result.stdout + result.stderr
                )
                fresh_tree = DirectoryProfileIO(self.tree_path, grant())
                fresh_store = MaterializedStore(
                    self.store_path, self.fake, self.fake.adapters().keys, fresh_tree
                )
                self.fake.grant = grant("restore")
                try:
                    self.assertIn(
                        fresh_store.run("trusted-ticket"), ("unknown", "delivered")
                    )
                finally:
                    fresh_store.close()
                    fresh_tree.close()
                self.assertEqual(self.state()["phase"], "ready")
                self.assertIn(
                    (self.active() / "nested" / "Cookies").read_bytes(), (OLD, CANARY)
                )
                self.assertEqual(
                    (self.active() / "preferences").read_bytes(),
                    b"synthetic preferences",
                )
                self.assertEqual(len(list(self.tree_path.glob("g-*"))), 1)
                self.assertFalse(list(self.tree_path.glob("stage-*")))
                self.assertNotIn(CANARY.decode(), result.stdout + result.stderr)

    def test_forget_crash_at_every_directory_sync_retains_terminal_fence(self) -> None:
        self.seed()
        self.run_action("save")
        count_run = self.child("forget", "count-sync")
        self.assertEqual(count_run.returncode, 0, count_run.stderr)
        count = int(count_run.stdout.split("sync-count ")[1].strip())
        self.assertGreater(count, 4)
        for number in range(1, count + 1):
            for side in ("before", "after"):
                fault = f"sync-{side}-{number}"
                with self.subTest(fault=fault):
                    self.reset()
                    self.seed()
                    self.run_action("save")
                    result = self.child("forget", fault)
                    self.assertIn(
                        result.returncode, (85, 86), result.stdout + result.stderr
                    )
                    fresh_tree = DirectoryProfileIO(self.tree_path, grant())
                    fresh_store = MaterializedStore(
                        self.store_path,
                        self.fake,
                        self.fake.adapters().keys,
                        fresh_tree,
                    )
                    try:
                        self.fake.grant = grant("restore")
                        with patch.object(
                            fresh_tree,
                            "_prepare",
                            side_effect=AssertionError("forbidden preparation"),
                        ) as spy:
                            with self.assertRaises(Denied):
                                fresh_store.run("trusted-ticket")
                            self.assertEqual(spy.call_count, 0)
                        self.fake.grant = grant("forget")
                        self.assertEqual(fresh_store.run("trusted-ticket"), "forgotten")
                    finally:
                        fresh_store.close()
                        fresh_tree.close()
                    self.assertEqual(self.state()["phase"], "forgotten")
                    self.assertFalse(
                        any(CANARY in value for value in self.all_files(self.root))
                    )

    def test_write_cleanup_and_unlock_errors_are_sanitized(self) -> None:
        self.seed()
        self.run_action("save")
        self.seed(OLD)
        original = self.tree._write

        def broken(fd: int, data: bytes) -> None:
            original(fd, data)
            if data == CANARY:
                raise OSError(CANARY.decode())

        with (
            patch.object(self.tree, "_write", side_effect=broken),
            self.assertRaises(Denied) as failure,
        ):
            self.run_action("restore")
        self.assertIsNone(failure.exception.__context__)
        self.assertEqual(self.state()["phase"], "ready")
        self.assertFalse(
            any(CANARY in value for value in self.all_files(self.tree_path))
        )
        import fcntl

        real_flock = fcntl.flock

        def unlock(fd: int, operation: int) -> None:
            real_flock(fd, operation)
            if operation == fcntl.LOCK_UN:
                raise OSError(CANARY.decode())

        self.fake.grant = grant("save", reference="another")
        with (
            patch("browser_runtime.profile_directory.fcntl.flock", side_effect=unlock),
            self.assertRaises(Denied) as failure2,
        ):
            self.tree.capture(self.fake.grant, self.fake)
        self.assertIsNone(failure2.exception.__context__)

    def test_initialization_cancellation_closes_descriptors_and_sanitizes(self) -> None:
        for cancellation in (False, True):
            path = self.root / ("new-" + str(cancellation))
            path.mkdir(mode=0o700)
            descriptors: list[int] = []
            real_close = os.close

            def interrupted(tree: DirectoryProfileIO, state: object) -> None:
                descriptors.extend((tree._lock_fd, tree._fd))
                if cancellation:
                    raise KeyboardInterrupt(CANARY.decode())
                raise OSError(CANARY.decode())

            def close_with_error(fd: int) -> None:
                real_close(fd)
                if fd in descriptors:
                    raise OSError(CANARY.decode())

            with (
                patch.object(DirectoryProfileIO, "_write_state", interrupted),
                patch("browser_runtime.profile_directory.os.close", close_with_error),
                self.assertRaises(Cancelled if cancellation else Denied) as caught,
            ):
                DirectoryProfileIO(path, grant())
            self.assertEqual(len(descriptors), 2)
            self.assertIsNone(caught.exception.__context__)
            self.assertIsNone(caught.exception.__cause__)
            self.assertNotIn(CANARY.decode(), str(caught.exception))
            for fd in descriptors:
                with self.assertRaises(OSError):
                    os.fstat(fd)

    def test_missing_and_replaced_lock_are_not_silently_accepted(self) -> None:
        self.seed()
        lock = self.tree_path / "profile.lock"
        lock.unlink()
        with self.assertRaises(Denied):
            DirectoryProfileIO(self.tree_path, grant())
        self.assertFalse(lock.exists())
        lock.touch(mode=0o600)
        before = (self.tree_path / "state.json").read_bytes()
        with self.assertRaises(Denied):
            self.run_action("save")
        self.assertEqual((self.tree_path / "state.json").read_bytes(), before)
        self.assertTrue(any(CANARY in data for data in self.all_files(self.tree_path)))

    def test_close_failure_sanitizes_and_does_not_retry_uncertain_descriptors(
        self,
    ) -> None:
        descriptors = (self.tree._lock_fd, self.tree._fd)
        real_close = os.close
        calls: list[int] = []

        def interrupted(fd: int) -> None:
            real_close(fd)
            calls.append(fd)
            raise KeyboardInterrupt(CANARY.decode())

        with (
            patch("browser_runtime.profile_directory.os.close", interrupted),
            self.assertRaises(Cancelled) as caught,
        ):
            self.tree.close()
        self.assertEqual(calls, list(descriptors))
        self.assertIsNone(caught.exception.__context__)
        self.tree.close()
        for fd in descriptors:
            with self.assertRaises(OSError):
                os.fstat(fd)

    def test_file_and_publication_fsync_errors_never_claim_delivery(self) -> None:
        import stat

        for boundary in ("file", "publication"):
            with self.subTest(boundary=boundary):
                self.reset()
                self.seed()
                self.run_action("save")
                self.seed(OLD)
                real = os.fsync
                failed = False

                def sync(fd: int) -> None:
                    nonlocal failed
                    info = os.fstat(fd)
                    selected = (
                        stat.S_ISREG(info.st_mode) and info.st_size == len(CANARY)
                        if boundary == "file"
                        else fd == self.tree._fd and self.state()["phase"] == "cleanup"
                    )
                    if selected and not failed:
                        failed = True
                        raise OSError(CANARY.decode())
                    real(fd)

                with (
                    patch(
                        "browser_runtime.profile_directory.os.fsync", side_effect=sync
                    ),
                    self.assertRaises(Denied) as failure,
                ):
                    self.run_action("restore")
                self.assertTrue(failed)
                self.assertIsNone(failure.exception.__context__)
                with sqlite3.connect(self.store_path / "profiles.sqlite3") as db:
                    self.assertEqual(
                        db.execute("SELECT result FROM restores").fetchone()[0],
                        "unknown",
                    )
                self.assertEqual(self.state()["phase"], "ready")
                expected = OLD if boundary == "file" else CANARY
                self.assertEqual(
                    (self.active() / "nested" / "Cookies").read_bytes(), expected
                )
                self.assertEqual(len(list(self.tree_path.glob("g-*"))), 1)
                self.assertFalse(list(self.tree_path.glob("stage-*")))

    def test_root_replacement_and_metadata_traversal_deny(self) -> None:
        self.seed()
        original = (self.tree_path / "state.json").read_bytes()
        malicious = self.state()
        malicious.update(current="../../outside")
        (self.tree_path / "state.json").write_text(encoded(malicious))
        with self.assertRaises(Denied):
            self.run_action("save")
        (self.tree_path / "state.json").write_bytes(original)
        moved = self.root / "moved-tree"
        self.tree_path.rename(moved)
        self.tree_path.mkdir(mode=0o700)
        with self.assertRaises(Denied):
            self.run_action("save")
        self.assertEqual(list(self.tree_path.iterdir()), [])
        self.assertTrue(any(CANARY in value for value in self.all_files(moved)))

    def test_separate_process_tree_lock_denies_without_hanging(self) -> None:
        self.seed()
        script = """
import fcntl,sys,time
from pathlib import Path
from browser_runtime.profile_directory import DirectoryProfileIO
from browser_testing.profile_store_fixtures import grant
tree=DirectoryProfileIO(sys.argv[1],grant())
fcntl.flock(tree._lock_fd,fcntl.LOCK_EX)
Path(sys.argv[2]).write_text('ready')
end=time.monotonic()+5
while not Path(sys.argv[3]).exists() and time.monotonic()<end: time.sleep(.01)
tree.close()
"""
        ready, release = self.root / "ready", self.root / "release"
        process = subprocess.Popen(
            [
                sys.executable,
                "-c",
                script,
                str(self.tree_path),
                str(ready),
                str(release),
            ],
            env=dict(
                os.environ,
                PYTHONPATH=os.pathsep.join(
                    [str(ROOT), os.environ.get("PYTHONPATH", "")]
                ),
            ),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            deadline = time.monotonic() + 5
            while not ready.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(ready.exists())
            started = time.monotonic()
            with self.assertRaises(Denied):
                self.run_action("save")
            self.assertLess(time.monotonic() - started, 2)
            release.touch()
            _, error = process.communicate(timeout=5)
            self.assertEqual(process.returncode, 0, error)
        finally:
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=5)

    def test_exact_forget_gap_blocks_recovery_then_fresh_forget_cleans(self) -> None:
        for fault in ("forget-gap", "after-forgotten"):
            with self.subTest(fault=fault):
                self.reset()
                self.seed()
                self.run_action("save")
                result = self.child("forget", fault)
                self.assertIn(result.returncode, (82, 84), result.stderr)
                with sqlite3.connect(self.store_path / "profiles.sqlite3") as db:
                    self.assertEqual(
                        db.execute("SELECT forgotten FROM profiles").fetchone()[0], 1
                    )
                    self.assertEqual(
                        db.execute("SELECT count(*) FROM checkpoints").fetchone()[0], 0
                    )
                self.assertTrue(
                    any(CANARY in value for value in self.all_files(self.tree_path))
                )
                fresh_tree = DirectoryProfileIO(self.tree_path, grant())
                fresh_store = MaterializedStore(
                    self.store_path, self.fake, self.fake.adapters().keys, fresh_tree
                )
                try:
                    self.fake.grant = grant("restore")
                    with patch.object(
                        fresh_tree,
                        "_prepare",
                        side_effect=AssertionError("forbidden recovery"),
                    ) as forbidden:
                        with self.assertRaises(Denied):
                            fresh_store.run("trusted-ticket")
                        self.assertEqual(forbidden.call_count, 0)
                    self.fake.grant = grant("forget")
                    self.assertEqual(fresh_store.run("trusted-ticket"), "forgotten")
                finally:
                    fresh_store.close()
                    fresh_tree.close()
                self.assertFalse(
                    any(CANARY in value for value in self.all_files(self.root))
                )
                self.assertEqual(self.state()["phase"], "forgotten")

    def test_deliberate_tombstone_bypass_mutation_observes_forbidden_prepare(
        self,
    ) -> None:
        self.seed()
        self.run_action("save")
        result = self.child("forget", "forget-gap")
        self.assertEqual(result.returncode, 84)
        with patch.object(
            self.tree, "_prepare", side_effect=RuntimeError("observed")
        ) as spy:
            with self.assertRaises(Denied):
                self.run_action("restore")
            self.assertEqual(spy.call_count, 0)
            # Remove both database gates solely in this deliberate negative mutant.
            with (
                patch.object(self.store, "_claim"),
                patch.object(self.store, "_checkpoint"),
            ):
                with self.assertRaises(Denied):
                    self.run_action("restore")
            self.assertEqual(spy.call_count, 1)


if __name__ == "__main__":
    unittest.main()

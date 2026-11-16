"""Real AEAD, private temp SQLite files, process death and independent effect spies."""

import builtins
import os
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import traceback
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from browser_runtime.credentials import Observation
from browser_runtime.profile_schema import FILENAME
from browser_runtime.profile_store import (
    Cancelled,
    Denied,
    DependencyUnavailable,
    Store,
)
from browser_testing.profile_store_fixtures import BASE, CANARY, Fake, grant

ROOT = Path(__file__).resolve().parents[1]


class ProfileStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.directory = self.root / "store"
        self.directory.mkdir(mode=0o700)
        self.fake = Fake()
        self.store = Store(self.directory, self.fake.adapters())
        self.addCleanup(self.store.close)
        self.network = patch.object(
            socket.socket, "connect", side_effect=AssertionError("network forbidden")
        )
        self.network.start()
        self.addCleanup(self.network.stop)

    def rows(self, table: str) -> list[tuple[object, ...]]:
        with sqlite3.connect(self.directory / FILENAME) as db:
            return db.execute("SELECT * FROM " + table).fetchall()

    def run_action(
        self, action: str, reference: str = "checkpoint", **changes: object
    ) -> str:
        self.fake.grant = grant(action, reference, **changes)
        return self.store.run("trusted-ticket")

    def scan(self) -> None:
        for path in self.root.rglob("*"):
            if path.is_file() and not path.is_symlink():
                self.assertNotIn(CANARY, path.read_bytes(), str(path))

    def test_real_crypto_roundtrip_immutable_retention_and_plaintext_absence(
        self,
    ) -> None:
        self.assertEqual(self.run_action("save"), "stored")
        self.assertEqual(self.run_action("save", "checkpoint-two"), "stored")
        self.assertEqual(len(self.rows("checkpoints")), 2)
        self.assertEqual(self.run_action("restore"), "delivered")
        self.assertEqual(self.fake.received, [CANARY])
        self.assertEqual(self.run_action("restore"), "delivered")
        self.assertEqual(self.fake.consumes, 1)
        with self.assertRaises(Denied):
            self.run_action("save")
        self.assertEqual(len(self.rows("checkpoints")), 2)
        self.scan()

    def test_missing_adapters_dependency_and_invalid_ticket_are_explicit(self) -> None:
        with patch.object(self.store, "_adapters", None), self.assertRaises(Denied):
            self.store.run("trusted-ticket")
        with self.assertRaises(Denied):
            self.store.run("forged-ticket")
        original = builtins.__import__

        def unavailable(name: str, *args: object, **kwargs: object) -> object:
            if name.startswith("cryptography"):
                raise ModuleNotFoundError("synthetic unavailable")
            return original(name, *args, **kwargs)  # type: ignore[arg-type]

        with (
            patch("builtins.__import__", side_effect=unavailable),
            self.assertRaises(DependencyUnavailable),
        ):
            Store(self.directory, self.fake.adapters())
        self.assertEqual(
            (self.fake.reads, self.fake.captures, self.fake.consumes), (0, 0, 0)
        )

    def test_wrong_account_origin_observation_and_expired_admission_deny_before_keys(
        self,
    ) -> None:
        self.run_action("save")
        initial = self.fake.reads
        for target in (
            replace(BASE, binding=replace(BASE.binding, account="other")),
            replace(
                BASE, binding=replace(BASE.binding, origin="https://other.example")
            ),
            replace(BASE, frame_origin="https://frame.example"),
        ):
            with self.assertRaises(Denied):
                self.run_action("restore", target=target)
        self.fake.observation = Observation(
            replace(BASE, native_session="forged"), time.monotonic()
        )
        with self.assertRaises(Denied):
            self.run_action("restore")
        self.fake.observation = None
        with self.assertRaises(Denied):
            self.run_action("restore", deadline=0)
        self.assertEqual(self.fake.reads, initial)
        self.assertEqual(self.fake.consumes, 0)

    def test_quiescence_revocation_after_key_capture_and_consume(self) -> None:
        self.fake.stopped = False
        with self.assertRaises(Denied):
            self.run_action("save")
        self.assertEqual(self.fake.reads, 0)
        self.fake.stopped = True
        self.fake.after_key = lambda: setattr(self.fake, "allowed", False)
        with self.assertRaises(Denied):
            self.run_action("save")
        self.assertEqual(self.fake.captures, 0)
        self.fake.after_key = lambda: None
        self.fake.allowed = True
        self.fake.after_capture = lambda: setattr(self.fake, "allowed", False)
        with self.assertRaises(Denied):
            self.run_action("save")
        self.assertEqual(self.rows("checkpoints"), [])
        self.assertEqual(len(self.rows("nonces")), 1)
        self.fake.allowed = True
        self.fake.after_capture = lambda: None
        self.run_action("save")
        self.fake.after_consume = lambda: setattr(self.fake, "allowed", False)
        with self.assertRaises(Denied):
            self.run_action("restore")
        self.assertEqual(self.rows("restores")[0][2], "unknown")
        self.fake.allowed = True
        self.assertEqual(self.run_action("restore"), "unknown")
        self.assertEqual(self.fake.consumes, 1)
        self.scan()

    def test_corrupt_ciphertext_nonce_aad_and_key_never_reach_consumer(self) -> None:
        for mutation in ("ciphertext", "nonce", "reference", "origin", "key"):
            with self.subTest(mutation=mutation):
                reference = "checkpoint-" + mutation
                self.run_action("save", reference)
                with sqlite3.connect(self.directory / FILENAME) as db:
                    if mutation == "ciphertext":
                        db.execute(
                            "UPDATE checkpoints SET ciphertext=? WHERE reference=?",
                            (b"x" * 40, reference),
                        )
                    elif mutation == "nonce":
                        db.execute(
                            "UPDATE checkpoints SET nonce=? WHERE reference=?",
                            (b"x" * 12, reference),
                        )
                    elif mutation == "reference":
                        db.execute(
                            "UPDATE checkpoints SET reference=? WHERE reference=?",
                            (reference + "-changed", reference),
                        )
                        reference += "-changed"
                    elif mutation == "origin":
                        # Bypass only row scope checks to isolate AEAD's origin binding.
                        pass
                target = replace(
                    BASE, binding=replace(BASE.binding, operation="restore-" + mutation)
                )
                if mutation == "key":
                    self.fake.material = b"K" * 32
                if mutation == "origin":
                    original = self.store._aad
                    with patch.object(
                        self.store,
                        "_aad",
                        side_effect=lambda g, v: original(
                            replace(
                                g,
                                target=replace(
                                    g.target, frame_origin="https://wrong.example"
                                ),
                            ),
                            v,
                        ),
                    ):
                        with self.assertRaises(Denied):
                            self.run_action("restore", reference, target=target)
                else:
                    with self.assertRaises(Denied):
                        self.run_action("restore", reference, target=target)
                from browser_testing.profile_store_fixtures import KEY

                self.fake.material = KEY
        self.assertEqual(self.fake.consumes, 0)
        self.scan()

    def test_nonce_burns_survive_failures_aliases_and_forget(self) -> None:
        nonce = b"n" * 12
        with patch("browser_runtime.profile_store.os.urandom", return_value=nonce):
            self.run_action("save")
            self.fake.version = "alias-same-key"
            with self.assertRaises(Denied):
                self.run_action("save", "another")
            self.assertEqual(self.fake.captures, 1)
            self.run_action("forget")
            with self.assertRaises(Denied):
                self.run_action("save", "new-profile-checkpoint", profile="new-profile")
        self.assertEqual(len(self.rows("nonces")), 1)
        self.assertEqual(self.rows("checkpoints"), [])

    def test_immutable_key_version_and_rotation_retains_old_ciphertext(self) -> None:
        self.run_action("save")
        self.fake.material = b"K" * 32
        with self.assertRaises(Denied):
            self.run_action("save", "other")
        self.fake.version = "test-key-v2"
        self.assertEqual(self.run_action("save", "other"), "stored")
        self.assertEqual(self.run_action("restore", "other"), "delivered")
        self.assertEqual(len(self.rows("checkpoints")), 2)
        self.assertEqual(len(self.rows("key_versions")), 2)

    def test_forget_is_terminal_account_scoped_and_independent(self) -> None:
        self.run_action("save")
        other = replace(BASE, binding=replace(BASE.binding, account="other-account"))
        self.run_action("save", "other-checkpoint", target=other)
        before = (self.fake.reads, self.fake.captures, self.fake.consumes)
        self.assertEqual(self.run_action("forget"), "forgotten")
        self.assertEqual(self.run_action("forget"), "forgotten")
        self.assertEqual(
            (self.fake.reads, self.fake.captures, self.fake.consumes), before
        )
        with self.assertRaises(Denied):
            self.run_action("restore")
        with self.assertRaises(Denied):
            self.run_action("save", "replacement")
        with self.assertRaises(Denied):
            self.run_action("save", "checkpoint", profile="new-profile")
        self.assertEqual(
            self.run_action("restore", "other-checkpoint", target=other), "delivered"
        )
        self.scan()

    def test_owner_epoch_fences_and_never_resumes_authority(self) -> None:
        self.run_action("save")
        owner = replace(BASE, native_session="new-native")
        with self.assertRaises(Denied):
            self.run_action("save", "competing", target=owner)
        self.run_action(
            "save",
            "new-epoch",
            target=replace(owner, binding=replace(owner.binding, epoch=8)),
        )
        with self.assertRaises(Denied):
            self.run_action("save", "stale")
        reopened = Store(self.directory)
        self.addCleanup(reopened.close)
        with self.assertRaises(Denied):
            reopened.run("trusted-ticket")

    def test_reentrant_same_instance_and_other_connection_are_bounded(self) -> None:
        def recurse() -> None:
            with self.assertRaises(Denied):
                self.store.run("trusted-ticket")
            with self.assertRaises(Denied):
                self.store.close()

        self.fake.after_key = recurse
        self.assertEqual(self.run_action("save"), "stored")
        other_fake = Fake()
        other_store = Store(self.directory, other_fake.adapters())
        self.addCleanup(other_store.close)

        def cross_connection() -> None:
            started = time.monotonic()
            with self.assertRaises(Denied):
                other_store.run("trusted-ticket")
            self.assertLess(time.monotonic() - started, 2)

        self.fake.after_consume = cross_connection
        self.assertEqual(self.run_action("restore"), "delivered")
        self.assertEqual(other_fake.captures, 0)

    def test_exception_cancellation_and_suppressing_guards_do_not_leak(self) -> None:
        class Stop(BaseException):
            pass

        for cancellation in (False, True):

            def fail() -> None:
                raise (
                    Stop(CANARY.decode())
                    if cancellation
                    else RuntimeError(CANARY.decode())
                )

            self.fake.after_capture = fail
            with self.assertRaises(Cancelled if cancellation else Denied) as caught:
                self.run_action("save")
            self.assertIsNone(caught.exception.__context__)
            self.assertIsNone(caught.exception.__cause__)
            self.assertNotIn(
                CANARY.decode(), "".join(traceback.format_exception(caught.exception))
            )
        self.fake.suppress = True
        # The still-installed Stop cancellation must survive guard suppression.
        with self.assertRaises(Cancelled):
            self.run_action("save")
        self.fake.suppress = False
        self.fake.after_capture = lambda: None
        self.fake.raise_on_release = True
        with self.assertRaises(Denied) as release_error:
            self.run_action("save")
        self.assertIsNone(release_error.exception.__context__)
        self.assertEqual(len(self.rows("checkpoints")), 1)
        self.scan()

    def test_schema_path_and_permissions_reject_without_callbacks(self) -> None:
        self.store.close()
        with sqlite3.connect(self.directory / FILENAME) as db:
            db.execute("CREATE TABLE foreign_table (value TEXT)")
        original = (self.directory / FILENAME).read_bytes()
        with self.assertRaises(Denied):
            Store(self.directory, self.fake.adapters())
        self.assertEqual((self.directory / FILENAME).read_bytes(), original)
        alias = self.root / "alias"
        alias.symlink_to(self.directory, target_is_directory=True)
        with self.assertRaises(Denied):
            Store(alias, self.fake.adapters())
        for name in ("hard", "link", "sidecar"):
            place = self.root / name
            place.mkdir(mode=0o700)
            if name == "hard":
                os.link(self.directory / FILENAME, place / FILENAME)
            elif name == "link":
                (place / FILENAME).symlink_to(self.directory / FILENAME)
            else:
                (place / (FILENAME + "-journal")).symlink_to(self.directory / FILENAME)
            with self.assertRaises(Denied):
                Store(place, self.fake.adapters())
        public = self.root / "public"
        public.mkdir(mode=0o755)
        with self.assertRaises(Denied):
            Store(public, self.fake.adapters())
        self.assertEqual(self.fake.reads, 0)

    def child(self, action: str, fault: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                *(["-O"] if sys.flags.optimize else []),
                "-c",
                "from browser_testing.profile_store_fixtures import child; import sys; child(*sys.argv[1:])",
                str(self.directory),
                action,
                fault,
                str(self.root / "consumer-marker"),
            ],
            env=dict(
                os.environ,
                PYTHONPATH=os.pathsep.join(
                    [str(ROOT), str(ROOT / "tests"), os.environ.get("PYTHONPATH", "")]
                ),
            ),
            capture_output=True,
            text=True,
            timeout=10,
        )

    def reset_store(self) -> None:
        self.store.close()
        for child in self.directory.iterdir():
            child.unlink()
        self.store = Store(self.directory, self.fake.adapters())
        self.addCleanup(self.store.close)
        self.fake = Fake()
        self.store._adapters = self.fake.adapters()
        (self.root / "consumer-marker").unlink(missing_ok=True)

    def test_fresh_process_save_crashes_burn_nonce_and_never_leave_plaintext(
        self,
    ) -> None:
        for fault, burned, saved in (
            ("key", 0, 0),
            ("before-1", 0, 0),
            ("after-1", 1, 0),
            ("capture", 1, 0),
            ("before-2", 1, 0),
            ("after-2", 1, 1),
        ):
            with self.subTest(fault=fault):
                self.reset_store()
                result = self.child("save", fault)
                self.assertIn(result.returncode, (71, 72, 74, 75), result.stderr)
                reopened = Store(self.directory, self.fake.adapters())
                reopened.close()
                self.assertEqual(len(self.rows("nonces")), burned)
                self.assertEqual(len(self.rows("checkpoints")), saved)
                self.assertNotIn(CANARY.decode(), result.stdout + result.stderr)
                self.scan()

    def test_fresh_process_restore_crashes_never_repeat_uncertain_consumption(
        self,
    ) -> None:
        for fault, consumed, status in (
            ("before-1", 0, None),
            ("after-1", 0, "unknown"),
            ("key", 0, "unknown"),
            ("consume", 1, "unknown"),
            ("before-2", 1, "unknown"),
            ("after-2", 1, "delivered"),
        ):
            with self.subTest(fault=fault):
                self.reset_store()
                self.run_action("save")
                result = self.child("restore", fault)
                self.assertIn(result.returncode, (71, 72, 73, 75), result.stderr)
                marker = self.root / "consumer-marker"
                self.assertEqual(
                    len(marker.read_text().splitlines()) if marker.exists() else 0,
                    consumed,
                )
                reopened = Store(self.directory, self.fake.adapters())
                reopened.close()
                attempts = self.rows("restores")
                self.assertEqual(attempts[0][2] if attempts else None, status)
                self.fake.grant = grant("restore")
                value = self.store.run("trusted-ticket")
                self.assertEqual(value, status or "delivered")
                self.assertEqual(self.fake.consumes, 0 if status else 1)
                self.scan()

    def test_fresh_process_forget_crashes_atomic_tombstone_and_deletion(self) -> None:
        for fault, forgotten in (("before-1", 0), ("after-1", 1)):
            with self.subTest(fault=fault):
                self.reset_store()
                self.run_action("save")
                result = self.child("forget", fault)
                self.assertIn(result.returncode, (71, 72), result.stderr)
                reopened = Store(self.directory, self.fake.adapters())
                reopened.close()
                self.assertEqual(self.rows("profiles")[0][4], forgotten)
                self.assertEqual(len(self.rows("checkpoints")), 1 - forgotten)
                self.assertEqual(len(self.rows("nonces")), 1)
                self.scan()

    def test_forced_hot_journal_recovery_after_spilled_transaction(self) -> None:
        self.run_action("save")
        script = """
import sqlite3,sys,os
con=sqlite3.connect(sys.argv[1], isolation_level=None)
con.execute('PRAGMA cache_size=5')
con.execute('PRAGMA synchronous=EXTRA')
con.execute('BEGIN IMMEDIATE')
for i in range(200):
 con.execute('INSERT INTO checkpoints VALUES (?,?,?,?,?)',(str(i),'synthetic','synthetic',bytes(12),bytes(16000)))
os._exit(76)
"""
        result = subprocess.run(
            [sys.executable, "-c", script, str(self.directory / FILENAME)], timeout=10
        )
        self.assertEqual(result.returncode, 76)
        self.assertGreater(
            (self.directory / (FILENAME + "-journal")).stat().st_size, 512
        )
        reopened = Store(self.directory, self.fake.adapters())
        reopened.close()
        self.assertEqual(len(self.rows("checkpoints")), 1)
        self.assertEqual(self.run_action("restore"), "delivered")
        self.scan()

    def test_process_competition_holds_one_writer_and_rechecks_freshness(self) -> None:
        script = """
from browser_testing.profile_store_fixtures import Fake
from browser_runtime.profile_store import Store
from pathlib import Path
import sys,time,socket
from unittest.mock import patch
fake=Fake()
def hold():
 Path(sys.argv[2]).write_text('ready')
 deadline=time.monotonic()+5
 while not Path(sys.argv[3]).exists() and time.monotonic()<deadline: time.sleep(.01)
fake.after_key=hold
with patch.object(socket.socket,'connect',side_effect=AssertionError('network forbidden')):
 store=Store(sys.argv[1],fake.adapters())
 try: print(store.run('trusted-ticket'))
 finally: store.close()
"""
        ready, release = self.root / "ready", self.root / "release"
        process = subprocess.Popen(
            [
                sys.executable,
                "-c",
                script,
                str(self.directory),
                str(ready),
                str(release),
            ],
            env=dict(
                os.environ,
                PYTHONPATH=os.pathsep.join(
                    [str(ROOT), str(ROOT / "tests"), os.environ.get("PYTHONPATH", "")]
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
            target = replace(BASE, native_session="competing-owner")
            with self.assertRaises(Denied):
                self.run_action("save", "competing-checkpoint", target=target)
            self.assertEqual(self.fake.reads, 0)
            release.touch()
            stdout, stderr = process.communicate(timeout=5)
            self.assertEqual(process.returncode, 0, stderr)
            self.assertIn("stored", stdout)
            with self.assertRaises(Denied):
                self.run_action("save", "competing-checkpoint", target=target)
            self.assertEqual(self.fake.reads, 0)
            newer = replace(target, binding=replace(target.binding, epoch=8))
            self.assertEqual(
                self.run_action("save", "competing-checkpoint", target=newer), "stored"
            )
            with self.assertRaises(Denied):
                self.run_action("restore")
        finally:
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=5)

    def test_forget_between_reservation_transactions_fences_stale_capture(self) -> None:
        other = Fake()
        owner = replace(
            BASE, native_session="new-owner", binding=replace(BASE.binding, epoch=8)
        )
        other.grant = grant("forget", target=owner)
        other_store = Store(self.directory, other.adapters())
        self.addCleanup(other_store.close)
        db = self.store._db
        commits = 0

        class Interleave:
            def __getattr__(self, name: str) -> object:
                return getattr(db, name)

            def execute(
                self, sql: str, parameters: tuple[object, ...] = ()
            ) -> sqlite3.Cursor:
                nonlocal commits
                result = db.execute(sql, parameters)
                if sql == "COMMIT":
                    commits += 1
                    if commits == 1:
                        other_store.run("trusted-ticket")
                return result

        with patch.object(self.store, "_db", Interleave()), self.assertRaises(Denied):
            self.run_action("save")
        self.assertEqual(self.fake.captures, 0)
        self.assertEqual(self.rows("checkpoints"), [])
        self.assertEqual(len(self.rows("nonces")), 1)
        self.assertEqual(self.rows("profiles")[0][4], 1)

    def test_clock_sample_is_after_guard_callbacks_and_lock_wait(self) -> None:
        clock = [time.monotonic()]
        self.store._clock = lambda: clock[0]
        self.fake.grant = replace(grant(), deadline=clock[0] + 1)

        def current(_grant: object) -> bool:
            clock[0] += 10
            return True

        with (
            patch.object(self.fake, "current", side_effect=current),
            self.assertRaises(Denied),
        ):
            self.store.run("trusted-ticket")
        self.assertEqual(self.fake.reads, 0)

    def test_cross_account_ciphertext_substitution_fails_aead(self) -> None:
        self.run_action("save")
        account = replace(BASE, binding=replace(BASE.binding, account="other-account"))
        self.run_action("save", "other-checkpoint", target=account)
        with sqlite3.connect(self.directory / FILENAME) as db:
            profile = db.execute(
                "SELECT profile FROM checkpoints WHERE reference='other-checkpoint'"
            ).fetchone()[0]
            db.execute(
                "UPDATE checkpoints SET profile=? WHERE reference='checkpoint'",
                (profile,),
            )
        with self.assertRaises(Denied):
            self.run_action("restore", target=account)
        self.assertEqual(self.fake.consumes, 0)

    def test_key_cancellation_after_commit_remains_committed_but_no_success(
        self,
    ) -> None:
        from contextlib import contextmanager
        from typing import Iterator

        from browser_runtime.profile_store import Adapters, Key
        from browser_testing.profile_store_fixtures import KEY

        class FailingExit:
            @contextmanager
            def acquire(
                self, store_id: str, scoped: object, version: str | None
            ) -> Iterator[Key]:
                yield Key("test-key-v1", KEY)
                raise KeyboardInterrupt(CANARY.decode())

        self.store._adapters = Adapters(self.fake, FailingExit(), self.fake)
        with self.assertRaises(Cancelled) as cancelled:
            self.run_action("save")
        self.assertIsNone(cancelled.exception.__context__)
        self.assertEqual(len(self.rows("checkpoints")), 1)
        self.scan()

    def test_deliberate_authentication_mutation_is_observed_by_consumer_spy(
        self,
    ) -> None:
        self.run_action("save")
        with sqlite3.connect(self.directory / FILENAME) as db:
            db.execute(
                "UPDATE checkpoints SET ciphertext=?", (b"corrupted-ciphertext",)
            )
        with self.assertRaises(Denied):
            self.run_action("restore")
        self.assertEqual(self.fake.consumes, 0)

        class BrokenCipher:
            def __init__(self, _key: bytes) -> None:
                pass

            def decrypt(self, _nonce: bytes, _ciphertext: bytes, _aad: bytes) -> bytes:
                return CANARY

        with patch.object(self.store, "_cipher", BrokenCipher):
            target = replace(
                BASE, binding=replace(BASE.binding, operation="mutation-operation")
            )
            self.assertEqual(self.run_action("restore", target=target), "delivered")
        # Independent helper observes the forbidden effect when authentication breaks.
        self.assertEqual(self.fake.consumes, 1)
        self.assertEqual(self.fake.received, [CANARY])


if __name__ == "__main__":
    unittest.main()

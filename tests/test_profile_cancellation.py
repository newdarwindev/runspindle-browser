"""Synthetic cancellation boundaries; real local durable outcomes, no providers."""

import socket
import subprocess
import sys
import tempfile
import traceback
import unittest
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from browser_runtime.profile_directory import DirectoryProfileIO
from browser_runtime.profile_store import (
    Adapters,
    Cancelled,
    Denied,
    Grant,
    Guard,
    Key,
    Store,
)
from browser_testing.profile_store_fixtures import CANARY, Fake, grant
from tests.test_profile_directory import bundle


def cancel() -> None:
    raise KeyboardInterrupt(CANARY.decode())


class CancellationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        network = patch.object(
            socket.socket, "connect", side_effect=AssertionError("network forbidden")
        )
        network.start()
        self.addCleanup(network.stop)

    def store(self) -> tuple[Store, Fake]:
        path = self.root / str(len(list(self.root.iterdir())))
        path.mkdir(mode=0o700)
        fake = Fake()
        store = Store(path, fake.adapters())
        self.addCleanup(store.close)
        return store, fake

    def safe(self, error: BaseException) -> None:
        self.assertIsNone(error.__context__)
        self.assertIsNone(error.__cause__)
        self.assertNotIn(CANARY.decode(), str(error))
        self.assertNotIn(CANARY.decode(), "".join(traceback.format_exception(error)))

    def test_capture_and_consume_cancellation_survive_both_contexts(self) -> None:
        for action in ("save", "restore"):
            for mode in ("suppress", "replace"):
                with self.subTest(action=action, mode=mode):
                    store, fake = self.store()
                    if action == "restore":
                        self.assertEqual(store.run("trusted-ticket"), "stored")
                    fake.reads = fake.captures = fake.consumes = fake.releases = 0
                    fake.grant = grant(action)
                    setattr(
                        fake,
                        "after_capture" if action == "save" else "after_consume",
                        cancel,
                    )
                    original = fake.adapters().keys

                    class Keys:
                        @contextmanager
                        def acquire(
                            self, store_id: str, grant: Grant, version: str | None
                        ) -> Iterator[Key]:
                            try:
                                with original.acquire(store_id, grant, version) as key:
                                    yield key
                            except BaseException:
                                if mode == "replace":
                                    raise RuntimeError(CANARY.decode())

                    @contextmanager
                    def authority() -> Iterator[Fake]:
                        try:
                            yield fake
                        except BaseException:
                            if mode == "replace":
                                raise RuntimeError(CANARY.decode())

                    with patch.object(fake, "acquire", side_effect=authority):
                        store._adapters = Adapters(fake, Keys(), fake)
                        with self.assertRaises(Cancelled) as caught:
                            store.run("trusted-ticket")
                    self.safe(caught.exception)
                    self.assertEqual((fake.reads, fake.releases), (1, 1))
                    self.assertEqual(
                        (fake.captures, fake.consumes),
                        (1, 0) if action == "save" else (0, 1),
                    )
                    store._adapters = fake.adapters()
                    fake.after_capture = fake.after_consume = lambda: None
                    if action == "restore":
                        self.assertEqual(
                            store._db.execute("SELECT result FROM restores").fetchall(),
                            [("unknown",)],
                        )
                        self.assertEqual(store.run("trusted-ticket"), "unknown")
                        self.assertEqual(fake.consumes, 1)
                    else:
                        self.assertEqual(
                            store._db.execute(
                                "SELECT count(*) FROM checkpoints"
                            ).fetchone()[0],
                            0,
                        )
                        self.assertEqual(
                            store._db.execute("SELECT count(*) FROM nonces").fetchone()[
                                0
                            ],
                            1,
                        )

    def test_key_entry_cancellation_survives_authority_suppression(self) -> None:
        store, fake = self.store()
        fake.after_key = cancel
        fake.suppress = True
        with self.assertRaises(Cancelled) as caught:
            store.run("trusted-ticket")
        self.safe(caught.exception)
        self.assertEqual((fake.reads, fake.captures, fake.consumes), (1, 0, 0))

    def test_release_cancellation_preserves_committed_restore_without_replay(
        self,
    ) -> None:
        store, fake = self.store()
        store.run("trusted-ticket")
        fake.grant = grant("restore")
        original = fake.adapters().keys

        class Keys:
            @contextmanager
            def acquire(
                self, store_id: str, grant: Grant, version: str | None
            ) -> Iterator[Key]:
                with original.acquire(store_id, grant, version) as key:
                    yield key
                cancel()

        store._adapters = Adapters(fake, Keys(), fake)
        fake.suppress = True
        with self.assertRaises(Cancelled) as caught:
            store.run("trusted-ticket")
        self.safe(caught.exception)
        self.assertEqual(
            store._db.execute("SELECT result FROM restores").fetchall(),
            [("delivered",)],
        )
        self.assertEqual(fake.consumes, 1)
        store._adapters = fake.adapters()
        self.assertEqual(store.run("trusted-ticket"), "delivered")
        self.assertEqual(fake.consumes, 1)

    def test_authority_exit_cancellation_preserves_saved_checkpoint(self) -> None:
        store, fake = self.store()

        @contextmanager
        def authority() -> Iterator[Fake]:
            yield fake
            cancel()

        with patch.object(fake, "acquire", side_effect=authority):
            with self.assertRaises(Cancelled) as caught:
                store.run("trusted-ticket")
        self.safe(caught.exception)
        self.assertEqual((fake.reads, fake.captures, fake.releases), (1, 1, 1))
        self.assertEqual(
            store._db.execute("SELECT count(*) FROM checkpoints").fetchone()[0], 1
        )
        with self.assertRaises(Denied):
            store.run("trusted-ticket")
        self.assertEqual(fake.captures, 1)

    def test_swallowed_ordinary_errors_are_not_success(self) -> None:
        store, fake = self.store()
        fake.suppress = True
        fake.after_capture = lambda: (_ for _ in ()).throw(ValueError(CANARY.decode()))
        with self.assertRaises(Denied):
            store.run("trusted-ticket")
        self.assertEqual(
            store._db.execute("SELECT count(*) FROM checkpoints").fetchone()[0], 0
        )

    def test_directory_recovery_cancellation_overrides_ordinary_failure(self) -> None:
        path = self.root / "tree"
        path.mkdir(mode=0o700)
        fake = Fake()
        fake.grant = grant("restore")
        tree = DirectoryProfileIO(path, fake.grant)
        self.addCleanup(tree.close)
        original = tree._recover
        calls = [0]

        def recovery(grant: Grant, guard: Guard) -> None:
            calls[0] += 1
            if calls[0] == 2:
                cancel()
            original(grant, guard)

        with patch.object(tree, "_recover", side_effect=recovery):
            with self.assertRaises(Cancelled) as caught:
                tree.consume(fake.grant, fake, b"invalid bundle")
        self.safe(caught.exception)
        self.assertEqual(calls[0], 2)
        # Locks released; a fresh explicit operation still works.
        self.assertTrue(tree.consume(fake.grant, fake, bundle(fake.grant.scope())))

    def test_wrapper_bypass_mutation_is_detected(self) -> None:
        script = r"""
import pathlib, sys, unittest
import browser_runtime.profile_store as module
source = pathlib.Path(module.__file__).read_text()
start = source.index("@contextmanager\ndef _cancellation_guard")
end = source.index("\n\nclass DependencyUnavailable", start)
source = (source[:start] + "def _cancellation_guard(context):\n    return context\n"
          + source[end:])
exec(compile(source, module.__file__, "exec"), module.__dict__)
sys.path.insert(0, "tests")
from test_profile_cancellation import CancellationTests
result = unittest.TextTestRunner().run(unittest.TestSuite([
    CancellationTests("test_capture_and_consume_cancellation_survive_both_contexts")
]))
sys.exit(0 if result.wasSuccessful() else 1)
"""
        result = subprocess.run(
            [sys.executable, *(["-O"] if sys.flags.optimize else []), "-c", script],
            cwd=Path(__file__).resolve().parents[1],
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("profile operation denied", result.stderr)
        self.assertIn("ERROR:", result.stderr)
        self.assertNotIn("ImportError", result.stderr)

    def test_public_failures_clear_active_caller_context(self) -> None:
        store, fake = self.store()
        path = self.root / "tree"
        path.mkdir(mode=0o700)
        tree = DirectoryProfileIO(path, fake.grant)
        self.addCleanup(tree.close)
        operations: list[Callable[[], object]] = [
            lambda: store.run("invalid"),
            lambda: tree.capture(fake.grant, fake),
            lambda: Store(self.root / "missing", fake.adapters()),
            lambda: DirectoryProfileIO(self.root / "missing", fake.grant),
        ]
        fake.after_capture = cancel
        operations.append(lambda: store.run("trusted-ticket"))
        for operation in operations:
            try:
                raise ValueError(CANARY.decode())
            except ValueError:
                with self.assertRaises((Denied, Cancelled)) as caught:
                    operation()
                self.safe(caught.exception)
        for owner, lock in ((store, store._lock), (tree, tree._mutex)):
            lock.acquire()
            try:
                try:
                    raise ValueError(CANARY.decode())
                except ValueError:
                    with self.assertRaises(Denied) as denied:
                        owner.close()
                    self.safe(denied.exception)
            finally:
                lock.release()


if __name__ == "__main__":
    unittest.main()

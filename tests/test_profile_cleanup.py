"""Fault-injected cleanup around real temporary synthetic SQLite checkpoints."""

import inspect
import io
import socket
import sqlite3
import tempfile
import textwrap
import traceback
import unittest
from contextlib import closing
from pathlib import Path
from typing import Callable, cast
from unittest.mock import patch

from browser_runtime.profile_schema import FILENAME
from browser_runtime.profile_store import Cancelled, Denied, Store
from browser_testing.profile_store_fixtures import CANARY, Fake, grant


def fail(kind: type[BaseException]) -> None:
    error = kind(CANARY.decode())
    error.add_note(CANARY.decode())
    raise error


class FaultDB:
    def __init__(self, db: sqlite3.Connection) -> None:
        self.db = db
        self.rollback_calls = 0
        self.close_calls = 0
        self.state_reads = 0
        self.rollback_before: Callable[[], None] = lambda: None
        self.rollback_after: Callable[[], None] = lambda: None
        self.close_before: Callable[[], None] = lambda: None
        self.close_after: Callable[[], None] = lambda: None
        self.state_fault: Callable[[], None] = lambda: None

    @property
    def in_transaction(self) -> bool:
        self.state_reads += 1
        self.state_fault()
        return self.db.in_transaction

    def execute(self, sql: str, parameters: tuple[object, ...] = ()) -> sqlite3.Cursor:
        if sql == "ROLLBACK":
            self.rollback_calls += 1
            self.rollback_before()
        result = self.db.execute(sql, parameters)
        if sql == "ROLLBACK":
            self.rollback_after()
        return result

    def close(self) -> None:
        self.close_calls += 1
        self.close_before()
        self.db.close()
        self.close_after()


class ProfileCleanupTests(unittest.TestCase):
    def setUp(self) -> None:
        network = patch.object(
            socket.socket, "connect", side_effect=AssertionError("network forbidden")
        )
        network.start()
        self.addCleanup(network.stop)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name).resolve() / "store"
        self.directory.mkdir(mode=0o700)
        self.fake = Fake()
        self.store = Store(self.directory, self.fake.adapters())
        self.db = FaultDB(self.store._db)
        # Test harness owns the underlying handle even if a simulated close fails.
        self.addCleanup(self.db.db.close)
        self.store._db = cast(sqlite3.Connection, self.db)
        self.addCleanup(self.store.close)

    def run_action(self, action: str = "save") -> str:
        self.fake.grant = grant(action)
        return self.store.run("trusted-ticket")

    def safe_failure(
        self, call: Callable[[], object], kind: type[BaseException]
    ) -> None:
        try:
            call()
        except BaseException as error:
            self.assertIs(type(error), kind)
            self.assertIsNone(error.__cause__)
            self.assertIsNone(error.__context__)
            self.assertEqual(getattr(error, "__notes__", []), [])
            self.assertNotIn(CANARY.decode(), repr(error.args))
            self.assertNotIn(
                CANARY.decode(), "".join(traceback.format_exception(error))
            )
        else:
            self.fail("cleanup failure reported success")

    def poisoned(self) -> None:
        before = (self.fake.reads, self.fake.captures, self.fake.consumes)
        cleanup = (self.db.rollback_calls, self.db.close_calls, self.db.state_reads)
        self.assertTrue(self.store._closed)
        with patch.object(self.fake, "acquire", wraps=self.fake.acquire) as acquire:
            for action in ("save", "restore", "forget"):
                self.safe_failure(lambda: self.run_action(action), Denied)
            self.store.close()
            self.store.close()
            acquire.assert_not_called()
        self.assertEqual(
            before, (self.fake.reads, self.fake.captures, self.fake.consumes)
        )
        self.assertEqual(
            cleanup,
            (self.db.rollback_calls, self.db.close_calls, self.db.state_reads),
        )

    def rows(self, table: str) -> list[tuple[object, ...]]:
        with closing(sqlite3.connect(self.directory / FILENAME)) as db:
            return db.execute("SELECT * FROM " + table).fetchall()

    def test_operation_denial_then_rollback_cancellation_is_cancelled(self) -> None:
        self.fake.after_capture = lambda: fail(ValueError)
        self.db.rollback_before = lambda: fail(KeyboardInterrupt)
        self.safe_failure(self.run_action, Cancelled)
        self.assertEqual((self.db.rollback_calls, self.db.close_calls), (1, 1))
        self.poisoned()
        self.assertEqual(len(self.rows("nonces")), 1)
        self.assertEqual(self.rows("checkpoints"), [])

    def test_original_cancellation_survives_ordinary_cleanup_errors(self) -> None:
        self.fake.after_capture = lambda: fail(SystemExit)
        self.db.rollback_before = lambda: fail(OSError)
        self.db.close_after = lambda: fail(OSError)
        self.safe_failure(self.run_action, Cancelled)
        self.poisoned()
        self.assertEqual((self.db.rollback_calls, self.db.close_calls), (1, 1))

    def test_close_cancellation_after_rollback_error_is_cancelled(self) -> None:
        self.fake.after_capture = lambda: fail(ValueError)
        self.db.rollback_before = lambda: fail(OSError)
        self.db.close_after = lambda: fail(GeneratorExit)
        self.safe_failure(self.run_action, Cancelled)
        self.poisoned()

    def test_failed_close_is_not_retried_or_used_for_new_callbacks(self) -> None:
        self.fake.after_capture = lambda: fail(ValueError)
        self.db.rollback_before = lambda: fail(OSError)
        self.db.close_before = lambda: fail(OSError)
        self.safe_failure(self.run_action, Denied)
        self.assertTrue(self.db.db.in_transaction)
        self.poisoned()
        self.assertEqual((self.db.rollback_calls, self.db.close_calls), (1, 1))
        # No assertion that the runtime released this failed handle or its lock.

    def test_after_rollback_fault_still_poisoned_without_retry(self) -> None:
        self.fake.after_capture = lambda: fail(ValueError)
        self.db.rollback_after = lambda: fail(OSError)
        self.safe_failure(self.run_action, Denied)
        self.poisoned()
        self.assertEqual(self.rows("checkpoints"), [])
        self.assertEqual((self.db.rollback_calls, self.db.close_calls), (1, 1))

    def test_transaction_state_failure_also_fences_instance(self) -> None:
        self.fake.after_capture = lambda: fail(ValueError)
        self.db.state_fault = lambda: fail(KeyboardInterrupt)
        self.safe_failure(self.run_action, Cancelled)
        self.poisoned()
        self.assertEqual((self.db.rollback_calls, self.db.close_calls), (0, 1))

    def test_successful_rollback_leaves_instance_reusable(self) -> None:
        for kind, expected in ((ValueError, Denied), (KeyboardInterrupt, Cancelled)):
            self.fake.after_capture = lambda: fail(kind)
            self.safe_failure(self.run_action, expected)
            self.assertFalse(self.store._closed)
            self.assertFalse(self.db.db.in_transaction)
        self.fake.after_capture = lambda: None
        self.assertEqual(self.run_action(), "stored")
        self.assertEqual(self.run_action("restore"), "delivered")
        self.assertEqual((self.db.rollback_calls, self.db.close_calls), (2, 0))

    def test_restore_uncertainty_survives_cleanup_cancellation_and_reopen(self) -> None:
        self.assertEqual(self.run_action(), "stored")
        self.fake.after_consume = lambda: fail(ValueError)
        self.db.rollback_before = lambda: fail(KeyboardInterrupt)
        self.safe_failure(lambda: self.run_action("restore"), Cancelled)
        self.assertEqual(self.fake.consumes, 1)
        self.poisoned()
        self.assertEqual(self.rows("restores")[0][2], "unknown")
        fresh = Fake()
        fresh.grant = grant("restore")
        reopened = Store(self.directory, fresh.adapters())
        try:
            self.assertEqual(reopened.run("trusted-ticket"), "unknown")
            self.assertEqual((fresh.reads, fresh.captures, fresh.consumes), (0, 0, 0))
        finally:
            reopened.close()

    def test_post_commit_state_failure_preserves_saved_checkpoint(self) -> None:
        self.db.state_fault = lambda: fail(KeyboardInterrupt)
        self.safe_failure(self.run_action, Cancelled)
        self.poisoned()
        self.assertEqual(len(self.rows("checkpoints")), 1)
        self.assertEqual(len(self.rows("nonces")), 1)

    def test_post_commit_state_failure_preserves_delivered_restore(self) -> None:
        self.assertEqual(self.run_action(), "stored")
        self.db.state_fault = lambda: fail(OSError)
        self.safe_failure(lambda: self.run_action("restore"), Denied)
        self.poisoned()
        self.assertEqual(self.rows("restores")[0][2], "delivered")
        self.assertEqual(self.fake.consumes, 1)

    def test_explicit_close_failure_is_sanitized_and_not_retried(self) -> None:
        self.assertEqual(self.run_action(), "stored")
        self.db.close_after = lambda: fail(OSError)
        self.safe_failure(self.store.close, Denied)
        self.poisoned()
        self.assertEqual(self.db.close_calls, 1)
        self.assertEqual(len(self.rows("checkpoints")), 1)

    def test_explicit_close_cancellation_is_sanitized_and_not_retried(self) -> None:
        self.db.close_after = lambda: fail(KeyboardInterrupt)
        self.safe_failure(self.store.close, Cancelled)
        self.poisoned()
        self.assertEqual(self.db.close_calls, 1)

    def test_deliberate_cleanup_mutations_fail_independent_assertions(self) -> None:
        source = textwrap.dedent(inspect.getsource(Store.run))
        mutations = (
            (
                "cancelled = cancelled or not isinstance(error, Exception)",
                "cancelled = cancelled",
                "test_operation_denial_then_rollback_cancellation_is_cancelled",
            ),
            (
                "require(not self._closed and type(self._adapters) is Adapters)",
                "require(type(self._adapters) is Adapters)",
                "test_failed_close_is_not_retried_or_used_for_new_callbacks",
            ),
        )
        for old, new, scenario in mutations:
            with self.subTest(mutation=old):
                self.assertIn(old, source)
                namespace = dict(Store.run.__globals__)
                exec(
                    compile(
                        "from __future__ import annotations\n"
                        + source.replace(old, new),
                        "synthetic-cleanup-mutation",
                        "exec",
                    ),
                    namespace,
                )
                with patch.object(Store, "run", namespace["run"]):
                    suite = unittest.TestSuite([ProfileCleanupTests(scenario)])
                    result = unittest.TextTestRunner(stream=io.StringIO()).run(suite)
                self.assertEqual(result.testsRun, 1)
                self.assertTrue(result.failures, "broken cleanup invariant escaped")

    def test_close_marks_unusable_before_underlying_close_callback(self) -> None:
        observed: list[bool] = []
        self.db.close_before = lambda: observed.append(self.store._closed)
        self.store.close()
        self.assertEqual(observed, [True])
        self.poisoned()

    def test_failed_rollback_marks_unusable_before_close_callback(self) -> None:
        observed: list[bool] = []
        self.fake.after_capture = lambda: fail(ValueError)
        self.db.rollback_before = lambda: fail(OSError)
        self.db.close_before = lambda: observed.append(self.store._closed)
        self.safe_failure(self.run_action, Denied)
        self.assertEqual(observed, [True])
        self.poisoned()


if __name__ == "__main__":
    unittest.main()

"""Real journal/site stores with invented exception canaries and fault boundaries."""

import hashlib
import os
import socket
import sqlite3
import subprocess
import sys
import tempfile
import traceback
import unittest
from dataclasses import replace
from pathlib import Path
from typing import Any, Callable, NoReturn, cast
from unittest.mock import patch

from browser_runtime.effects import Binding, Cancelled, Denied, Journal
from browser_testing.effect_site import Site

ROOT = Path(__file__).resolve().parents[1]
CANARY = "SYNTHETIC_JOURNAL_EXCEPTION_SECRET_7b3f19"
BINDING = Binding(
    "principal",
    "account",
    "browser",
    "tab",
    "intent",
    1,
    "operation",
    7,
    "https://site.example",
)
PAYLOAD = b"invented submission"
DIGEST = hashlib.sha256(PAYLOAD).hexdigest()


class FaultDB:
    """Faults surround actual SQLite operations; never fake stored outcomes."""

    def __init__(self, db: sqlite3.Connection) -> None:
        self.db = db
        self.before: Callable[[str], None] = lambda _sql: None
        self.after: Callable[[str], None] = lambda _sql: None
        self.on_close: Callable[[], None] = lambda: None
        self.close_calls = 0

    @property
    def in_transaction(self) -> bool:
        return self.db.in_transaction

    def execute(self, sql: str, *args: Any) -> sqlite3.Cursor:
        self.before(sql)
        result = self.db.execute(sql, *args)
        self.after(sql)
        return result

    def close(self) -> None:
        self.close_calls += 1
        self.db.close()
        self.on_close()


class EffectExceptionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.path = self.root / "journal.sqlite"
        self.site = Site(self.root / "site.sqlite")
        self.journal = Journal(
            self.path, lambda *_: True, self.site.submit, self.site.observe
        )
        self.addCleanup(self.journal.close)
        self.db = FaultDB(self.journal.db)
        self.journal.db = cast(sqlite3.Connection, self.db)
        network = patch.object(
            socket.socket, "connect", side_effect=AssertionError("network forbidden")
        )
        network.start()
        self.addCleanup(network.stop)

    @staticmethod
    def raise_secret(error: BaseException) -> NoReturn:
        error.add_note(CANARY)
        raise error

    def safe_failure(
        self, call: Callable[[], object], category: type[BaseException]
    ) -> BaseException:
        # Inspect while the traceback is still retained, unlike assertRaises.
        try:
            call()
        except BaseException as error:
            self.assertIs(type(error), category)
            self.assertIsNone(error.__cause__)
            self.assertIsNone(error.__context__)
            self.assertEqual(getattr(error, "__notes__", []), [])
            self.assertEqual(len(error.args), 1)
            self.assertIs(type(error.args[0]), str)
            self.assertNotIn(CANARY, str(error.args))
            self.assertNotIn(CANARY, repr(error))
            self.assertNotIn(CANARY, "".join(traceback.format_exception(error)))
            self.assertNotIn(
                "fail",
                [frame.name for frame in traceback.extract_tb(error.__traceback__)],
            )
            return error
        self.fail("failure was represented as success")

    def state(self) -> list[tuple[Any, ...]]:
        with sqlite3.connect(self.path) as db:
            return db.execute(
                "SELECT operation,binding,digest,outcome,evidence FROM operations"
            ).fetchall()

    def dispatch(self) -> str:
        return self.journal.dispatch(BINDING, PAYLOAD)

    def reconcile(self) -> str:
        return self.journal.reconcile(BINDING, DIGEST)

    def reopen(self) -> Journal:
        journal = Journal(
            self.path, lambda *_: True, self.site.submit, self.site.observe
        )
        self.addCleanup(journal.close)
        return journal

    def test_approval_exception_and_cancellation_have_empty_chains(self) -> None:
        for kind in (
            ValueError,
            KeyboardInterrupt,
            SystemExit,
            GeneratorExit,
            Cancelled,
        ):
            for stage in (1, 2):
                with self.subTest(kind=kind.__name__, stage=stage):
                    calls = 0

                    def approve(*_args: object) -> bool:
                        nonlocal calls
                        calls += 1
                        if calls == stage:
                            self.raise_secret(kind(CANARY))
                        return True

                    self.journal.approve = approve
                    self.safe_failure(
                        self.dispatch, Denied if kind is ValueError else Cancelled
                    )
                    self.assertEqual(self.site.effects(), 0)
                    if stage == 2:
                        self.assertEqual(self.state()[0][3], "unknown")
                    # Reset only this synthetic case's durable reservation.
                    self.db.db.execute("DELETE FROM operations")

    def test_cancellation_after_effect_stays_unknown_without_resubmit(self) -> None:
        def submit(binding: Binding, payload: bytes) -> None:
            self.site.submit(binding, payload)
            self.raise_secret(KeyboardInterrupt(CANARY))

        self.journal.submit = submit
        self.safe_failure(self.dispatch, Cancelled)
        self.assertEqual(self.site.effects(), 1)
        self.assertEqual(self.state()[0][3], "unknown")
        self.assertEqual(self.dispatch(), "unknown")
        self.assertEqual(self.reopen().dispatch(BINDING, PAYLOAD), "unknown")
        self.assertEqual(self.site.effects(), 1)

    def test_validation_failure_drops_parser_context_before_any_effect(self) -> None:
        invalid = replace(BINDING, origin="https://site.example:" + CANARY)
        self.safe_failure(lambda: self.journal.dispatch(invalid, PAYLOAD), Denied)
        self.assertEqual(self.site.effects(), 0)
        self.assertEqual(self.state(), [])

    def test_readback_cancellation_never_confirms_or_releases_retry(self) -> None:
        self.dispatch()
        self.journal.observe = lambda *_: self.raise_secret(SystemExit(CANARY))
        self.safe_failure(self.reconcile, Cancelled)
        self.assertEqual(self.state()[0][3:], ("unknown", None))
        self.assertEqual(self.reopen().dispatch(BINDING, PAYLOAD), "unknown")
        self.assertEqual(self.site.effects(), 1)

    def test_post_readback_authority_failure_sanitizes_the_entire_envelope(
        self,
    ) -> None:
        self.dispatch()
        observed = False

        def observe(binding: Binding, digest: str) -> object:
            nonlocal observed
            observed = True
            return self.site.observe(binding, digest)

        self.journal.observe = cast(Any, observe)
        self.journal.approve = (
            lambda *_: self.raise_secret(ValueError(CANARY)) if observed else True
        )
        self.safe_failure(self.reconcile, Denied)
        self.assertEqual(self.state()[0][3:], ("unknown", None))
        self.assertEqual(self.site.effects(), 1)

    def test_ordinary_submit_and_observe_failures_keep_existing_unknown_semantics(
        self,
    ) -> None:
        def submit(binding: Binding, payload: bytes) -> None:
            self.site.submit(binding, payload)
            self.raise_secret(ValueError(CANARY))

        self.journal.submit = submit
        self.assertEqual(self.dispatch(), "unknown")
        self.journal.observe = lambda *_: self.raise_secret(ValueError(CANARY))
        self.assertEqual(self.reconcile(), "unknown")
        self.assertEqual(self.dispatch(), "unknown")
        self.assertEqual(self.site.effects(), 1)
        self.assertNotIn(CANARY, repr(self.state()))

    def test_active_caller_exception_is_not_inherited_by_public_failures(self) -> None:
        # Exercise the otherwise easy-to-miss implicit exception context.
        try:
            self.raise_secret(ValueError(CANARY))
        except ValueError:
            self.journal.approve = lambda *_: False
            self.safe_failure(self.dispatch, Denied)
            self.safe_failure(lambda: Journal(":memory:"), Denied)
            self.journal._lock.acquire()
            try:
                self.safe_failure(self.journal.close, Denied)
            finally:
                self.journal._lock.release()
        self.assertEqual(self.site.effects(), 0)

    def test_reservation_commit_uncertainty_stops_before_submit(self) -> None:
        for when in ("before", "after"):
            for kind in (sqlite3.OperationalError, KeyboardInterrupt):
                with self.subTest(when=when, kind=kind.__name__):

                    def fault(sql: str) -> None:
                        if sql == "COMMIT":
                            self.raise_secret(kind(CANARY))

                    setattr(self.db, when, fault)
                    self.safe_failure(
                        self.dispatch,
                        Denied if kind is sqlite3.OperationalError else Cancelled,
                    )
                    setattr(self.db, when, lambda _sql: None)
                    self.assertEqual(self.site.effects(), 0)
                    if when == "before":
                        self.assertEqual(self.state(), [])
                    else:
                        self.assertEqual(self.state()[0][3], "unknown")
                        self.assertEqual(
                            self.reopen().dispatch(BINDING, PAYLOAD), "unknown"
                        )
                        self.assertEqual(self.site.effects(), 0)
                    self.db.db.execute("DELETE FROM operations")

    def test_readback_commit_failure_preserves_actual_durable_state(self) -> None:
        self.dispatch()
        for when, expected in (("before", "unknown"), ("after", "confirmed")):

            def fault(sql: str) -> None:
                if sql == "COMMIT":
                    self.raise_secret(KeyboardInterrupt(CANARY))

            setattr(self.db, when, fault)
            self.safe_failure(self.reconcile, Cancelled)
            setattr(self.db, when, lambda _sql: None)
            self.assertEqual(self.state()[0][3], expected)
            self.assertEqual(self.reopen().dispatch(BINDING, PAYLOAD), expected)
            self.assertEqual(self.site.effects(), 1)

    def test_rollback_failure_poisoning_closes_once_and_never_claims_success(
        self,
    ) -> None:
        self.db.before = (
            lambda sql: self.raise_secret(OSError(CANARY))
            if sql == "ROLLBACK"
            else None
        )
        self.safe_failure(self.dispatch, Denied)
        self.assertEqual(self.db.close_calls, 1)
        self.assertEqual(self.site.effects(), 1)
        self.assertEqual(self.state()[0][3], "unknown")
        callbacks: list[str] = []

        def approve(*_args: object) -> bool:
            callbacks.append("approve")
            return True

        self.journal.approve = approve
        self.safe_failure(self.dispatch, Denied)
        self.assertEqual(callbacks, [])
        self.journal.close()
        self.assertEqual(self.db.close_calls, 1)
        self.assertEqual(self.reopen().dispatch(BINDING, PAYLOAD), "unknown")
        self.assertEqual(self.site.effects(), 1)

    def test_cancellation_survives_ordinary_rollback_and_close_failures(self) -> None:
        def submit(binding: Binding, payload: bytes) -> None:
            self.site.submit(binding, payload)
            self.raise_secret(KeyboardInterrupt(CANARY))

        self.journal.submit = submit
        self.db.before = (
            lambda sql: self.raise_secret(OSError(CANARY))
            if sql == "ROLLBACK"
            else None
        )
        self.db.on_close = lambda: self.raise_secret(OSError(CANARY))
        self.safe_failure(self.dispatch, Cancelled)
        self.assertEqual(self.db.close_calls, 1)
        self.journal.close()
        self.assertEqual(self.db.close_calls, 1)
        self.assertEqual(self.reopen().dispatch(BINDING, PAYLOAD), "unknown")
        self.assertEqual(self.site.effects(), 1)

    def test_cleanup_cancellation_is_not_swallowed_as_normal_unknown(self) -> None:
        self.db.before = (
            lambda sql: self.raise_secret(SystemExit(CANARY))
            if sql == "ROLLBACK"
            else None
        )
        self.safe_failure(self.dispatch, Cancelled)
        self.assertEqual(self.db.close_calls, 1)
        self.assertEqual(self.reopen().dispatch(BINDING, PAYLOAD), "unknown")
        self.assertEqual(self.site.effects(), 1)

    def test_close_errors_and_cancellations_are_sanitized_and_not_retried(self) -> None:
        for kind in (OSError, KeyboardInterrupt):
            journal = self.reopen()
            fault = FaultDB(journal.db)
            journal.db = cast(sqlite3.Connection, fault)
            fault.on_close = lambda: self.raise_secret(kind(CANARY))
            self.safe_failure(journal.close, Denied if kind is OSError else Cancelled)
            journal.close()
            self.assertEqual(fault.close_calls, 1)
            self.safe_failure(lambda: journal.dispatch(BINDING, PAYLOAD), Denied)
        self.assertEqual(self.site.effects(), 0)

    def test_reentrant_calls_do_not_rollback_the_outer_transaction(self) -> None:
        states: list[bool] = []

        def submit(binding: Binding, payload: bytes) -> None:
            states.append(self.db.in_transaction)
            self.safe_failure(self.journal.close, Denied)
            self.safe_failure(self.dispatch, Denied)
            self.safe_failure(self.reconcile, Denied)
            states.append(self.db.in_transaction)
            self.site.submit(binding, payload)

        self.journal.submit = submit
        self.assertEqual(self.dispatch(), "unknown")
        self.assertEqual(states, [True, True])
        self.assertEqual(self.site.effects(), 1)
        self.assertEqual(self.dispatch(), "unknown")

    def test_constructor_cancellation_survives_close_errors_at_each_connection(
        self,
    ) -> None:
        real_connect = sqlite3.connect
        for phase in ("model", "probe", "writer"):
            closes: list[str] = []

            class Fault(sqlite3.Connection):
                def execute(
                    self, sql: str, *args: Any, **kwargs: Any
                ) -> sqlite3.Cursor:
                    selected = (
                        sql.startswith("CREATE")
                        if phase == "model"
                        else sql == ("BEGIN" if phase == "probe" else "BEGIN IMMEDIATE")
                    )
                    if selected:
                        raise KeyboardInterrupt(CANARY)
                    return super().execute(sql, *args, **kwargs)

                def close(self) -> None:
                    closes.append(phase)
                    super().close()
                    raise OSError(CANARY)

            def connect(path: Any, *args: Any, **kwargs: Any) -> sqlite3.Connection:
                selected = (
                    (phase == "model" and str(path) == ":memory:")
                    or (phase == "probe" and kwargs.get("uri"))
                    or (
                        phase == "writer"
                        and str(path) == str(self.path)
                        and not kwargs.get("uri")
                    )
                )
                if selected:
                    kwargs["factory"] = Fault
                connection: sqlite3.Connection = real_connect(path, *args, **kwargs)
                return connection

            with patch.object(sqlite3, "connect", side_effect=connect):
                self.safe_failure(lambda: Journal(self.path), Cancelled)
            self.assertEqual(closes, [phase])
            self.reopen().close()

    def test_constructor_storage_and_schema_errors_drop_hidden_context(self) -> None:
        from browser_runtime.effect_schema import SchemaRejected

        for error in (
            SchemaRejected(CANARY),
            sqlite3.OperationalError(CANARY),
            KeyboardInterrupt(CANARY),
        ):
            with patch("browser_runtime.effects.open_journal", side_effect=error):
                self.safe_failure(
                    lambda: Journal(self.path),
                    Cancelled if isinstance(error, KeyboardInterrupt) else Denied,
                )

    def test_fresh_process_after_uncertain_commit_does_not_submit(self) -> None:
        self.db.after = (
            lambda sql: self.raise_secret(KeyboardInterrupt(CANARY))
            if sql == "COMMIT"
            else None
        )
        self.safe_failure(self.dispatch, Cancelled)
        self.db.after = lambda _sql: None
        script = """
import socket, sys
from unittest.mock import patch
from browser_runtime.effects import Binding, Journal
from browser_testing.effect_site import Site
binding=Binding("principal","account","browser","tab","intent",1,"operation",7,"https://site.example")
site=Site(sys.argv[2])
with patch.object(socket.socket,"connect",side_effect=AssertionError("network forbidden")):
    journal=Journal(sys.argv[1],lambda *_:True,site.submit,site.observe)
    try: print(journal.dispatch(binding,b"invented submission"),site.effects())
    finally: journal.close()
"""
        result = subprocess.run(
            [
                sys.executable,
                *(["-O"] if sys.flags.optimize else []),
                "-c",
                script,
                str(self.path),
                str(self.site.path),
            ],
            cwd=ROOT,
            env=dict(os.environ, PYTHONPATH=str(ROOT)),
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "unknown 0")
        self.assertEqual(self.site.effects(), 0)


if __name__ == "__main__":
    unittest.main()

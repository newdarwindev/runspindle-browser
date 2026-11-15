"""Failed consumption is fenced before unlock, with no real provider or socket."""

from __future__ import annotations

import asyncio
import contextlib
import io
import threading
import unittest
from _thread import LockType
from collections.abc import Callable, Iterator
from types import TracebackType
from typing import cast
from unittest.mock import patch

from browser_runtime.credentials import Grant
from browser_runtime.openbao import Denied as VaultDenied
from browser_runtime.openbao import Handle, Mapping, Response, Vault, check
from tests.test_openbao_cancellation import CANCELLATIONS, STAGES, Fixture
from tests.test_openbao_http import CANARY, TOKEN


class InterruptedLock:
    def __init__(self, original: LockType, error: BaseException) -> None:
        self.original = original
        self.error = error
        self.acquisitions = 0

    def __enter__(self) -> None:
        self.acquisitions += 1
        if self.acquisitions == 1:
            raise self.error
        self.original.acquire()

    def __exit__(
        self,
        kind: type[BaseException] | None,
        value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.original.release()


class ConsumeTests(unittest.TestCase):
    def setUp(self) -> None:
        for name in (
            "socket.create_connection",
            "socket.socket.connect",
            "socket.socket.connect_ex",
        ):
            guard = patch(name, side_effect=AssertionError("network forbidden"))
            guard.start()
            self.addCleanup(guard.stop)

    def assert_revoked(self, f: Fixture, handle: object) -> None:
        before = f.effects()
        self.assertFalse(f.vault.current(handle, f.grant))
        self.assertFalse(f.vault.consume(handle, f.grant, f.sink))
        self.assertEqual(f.effects(), before)

    def assert_failure(self, f: Fixture, handle: object, error: BaseException) -> None:
        if isinstance(error, Exception):
            self.assertIs(f.vault.consume(handle, f.grant, f.sink), False)
        else:
            with self.assertRaises(type(error)) as caught:
                f.vault.consume(handle, f.grant, f.sink)
            self.assertIs(caught.exception, error)
            self.assertIsNone(caught.exception.__context__)

    def unlock_probe(
        self, f: Fixture, handle: object, stage: str, error: BaseException
    ) -> tuple[list[bool], list[bool]]:
        original = f.vault._lock
        retained: list[bool] = []
        consumed: list[bool] = []

        @contextlib.contextmanager
        def observed_lock() -> Iterator[None]:
            try:
                with original:
                    try:
                        yield
                    finally:
                        retained.append(handle in f.vault._entries)
            finally:
                f.vault._lock = original
                consumed.append(f.vault.consume(handle, f.grant, f.sink))

        f.arm(stage, error)
        with patch.object(f.vault, "_lock", observed_lock()):
            self.assert_failure(f, handle, error)
        return retained, consumed

    def test_failures_invalidate_before_unlock_and_reuse_has_zero_effects(self) -> None:
        for stage in STAGES:
            for error_type in (RuntimeError, *CANCELLATIONS):
                with self.subTest(stage=stage, error=error_type.__name__):
                    f = Fixture()
                    with f.peer.installed():
                        handle, other = f.handles()
                        observed = self.unlock_probe(f, handle, stage, error_type())
                        self.assertEqual(observed, ([False], [False]))
                        self.assertEqual(f.injections, [])
                        self.assert_revoked(f, handle)
                        self.assertEqual(len(f.vault._entries), 1)
                        self.assertTrue(f.vault.consume(other, f.grant, f.sink))
                        self.assertEqual(f.injections, ["injection"])
                        self.assertEqual(len(f.vault._entries), 0)
                    self.assertEqual(f.peer.closed, len(f.peer.requests))
                    self.assertTrue(all(r.closed for r in f.peer.responses))

    def thread_probe(
        self, f: Fixture, handle: object, error: BaseException
    ) -> tuple[list[bool], list[bool]]:
        original = f.vault._lock
        owner = threading.get_ident()
        released, completed = threading.Event(), threading.Event()
        retained: list[bool] = []
        consumed: list[bool] = []
        failures: list[BaseException] = []

        class ObservedLock:
            armed = True

            def __enter__(self) -> None:
                original.acquire()

            def __exit__(
                self,
                kind: type[BaseException] | None,
                value: BaseException | None,
                traceback: TracebackType | None,
            ) -> None:
                pause = threading.get_ident() == owner and self.armed
                if pause:
                    self.armed = False
                    retained.append(handle in f.vault._entries)
                original.release()
                if pause:
                    # A real second thread wins the just-released lock before
                    # the first caller can execute its outside-lock cleanup.
                    released.set()
                    if not completed.wait(3):
                        raise AssertionError("consumer did not finish")

        def waiter() -> None:
            try:
                if not released.wait(3):
                    raise AssertionError("owner did not unlock")
                consumed.append(f.vault.consume(handle, f.grant, f.sink))
            except BaseException as failure:
                failures.append(failure)
            finally:
                completed.set()

        f.arm("metadata", error)
        with patch.object(f.vault, "_lock", ObservedLock()):
            worker = threading.Thread(target=waiter)
            worker.start()
            try:
                self.assert_failure(f, handle, error)
            finally:
                released.set()
                worker.join(5)
            self.assertFalse(worker.is_alive(), "consumer thread retained")
        self.assertEqual(failures, [])
        return retained, consumed

    def test_real_contender_cannot_reuse_failed_or_cancelled_consume(self) -> None:
        for error_type in (RuntimeError, *CANCELLATIONS):
            with self.subTest(error=error_type.__name__):
                f = Fixture()
                with f.peer.installed():
                    handle, other = f.handles()
                    observed = self.thread_probe(f, handle, error_type())
                    self.assertEqual(observed, ([False], [False]))
                    self.assertEqual(f.injections, [])
                    self.assert_revoked(f, handle)
                    self.assertTrue(f.vault.consume(other, f.grant, f.sink))

    def test_delayed_cleanup_mutation_permits_real_contender_injection(self) -> None:
        def delayed(
            vault: Vault, handle: object, grant: Grant, sink: Callable[[str], bool]
        ) -> bool:
            success = False
            try:
                with vault._lock:
                    entry = vault._current(handle, grant)
                    del vault._entries[cast(Handle, handle)]
                    check(vault._scope(grant) == entry.mapping)
                    success = sink(entry.secret) is True
            except Exception:
                pass
            finally:
                vault.release(handle)  # Deliberately restores pre-fix ordering.
            return success

        for error_type in (RuntimeError, asyncio.CancelledError):
            with self.subTest(error=error_type.__name__):
                f = Fixture()
                with f.peer.installed():
                    handle, other = f.handles()
                    with patch.object(Vault, "consume", delayed):
                        observed = self.thread_probe(f, handle, error_type())
                    with self.assertRaises(AssertionError):
                        self.assertEqual(f.injections, [])
                    self.assertEqual(observed, ([True], [True]))
                    self.assertEqual(f.injections, ["injection"])
                    f.vault.release(other)

    def test_handle_is_removed_before_sink_even_when_sink_fails_or_cancels(
        self,
    ) -> None:
        for error_type in (RuntimeError, *CANCELLATIONS):
            with self.subTest(error=error_type.__name__):
                f = Fixture()
                with f.peer.installed():
                    handle, other = f.handles()
                    error = error_type()
                    retained: list[bool] = []
                    independent_sink = f.sink

                    def uncertain(
                        secret: str,
                        retained: list[bool] = retained,
                        handle: object = handle,
                        f: Fixture = f,
                        independent_sink: Callable[[str], bool] = independent_sink,
                        error: BaseException = error,
                    ) -> bool:
                        retained.append(handle in f.vault._entries)
                        independent_sink(secret)
                        raise error

                    with patch.object(f, "sink", uncertain):
                        self.assert_failure(f, handle, error)
                    self.assertEqual(retained, [False])
                    self.assertEqual(f.injections, ["injection"])
                    self.assert_revoked(f, handle)
                    self.assertTrue(f.vault.consume(other, f.grant, f.sink))
                    self.assertEqual(f.injections, ["injection", "injection"])

    def test_final_scope_failure_has_no_sink_effect_or_reusable_handle(self) -> None:
        for error_type in (RuntimeError, *CANCELLATIONS):
            with self.subTest(error=error_type.__name__):
                f = Fixture()
                with f.peer.installed():
                    handle, other = f.handles()
                    error = error_type()
                    original = f.vault._scope

                    def final_scope(
                        grant: Grant,
                        handle: object = handle,
                        f: Fixture = f,
                        error: BaseException = error,
                        original: Callable[[Grant], Mapping] = original,
                    ) -> Mapping:
                        if handle not in f.vault._entries:
                            raise error
                        return original(grant)

                    with patch.object(f.vault, "_scope", final_scope):
                        self.assert_failure(f, handle, error)
                    self.assertEqual(f.injections, [])
                    self.assert_revoked(f, handle)
                    self.assertTrue(f.vault.consume(other, f.grant, f.sink))

    def test_missing_cleanup_mutation_leaves_handle_reusable_after_failure(
        self,
    ) -> None:
        def missing(
            vault: Vault, handle: object, grant: Grant, sink: Callable[[str], bool]
        ) -> bool:
            try:
                with vault._lock:
                    entry = vault._current(handle, grant)
                    del vault._entries[cast(Handle, handle)]
                    check(vault._scope(grant) == entry.mapping)
                    return sink(entry.secret) is True
            except Exception:
                pass
            return False

        f = Fixture()
        with f.peer.installed():
            handle, other = f.handles()
            error = asyncio.CancelledError()
            f.arm("metadata", error)
            with patch.object(Vault, "consume", missing):
                self.assert_failure(f, handle, error)
            self.assertTrue(f.vault.consume(handle, f.grant, f.sink))
            with self.assertRaises(AssertionError):
                self.assertEqual(f.injections, [])
            self.assertEqual(f.injections, ["injection"])
            f.vault.release(other)

    def test_interrupted_acquisition_preserves_existing_outer_cleanup(self) -> None:
        for error_type in (RuntimeError, *CANCELLATIONS):
            with self.subTest(error=error_type.__name__):
                f = Fixture()
                with f.peer.installed():
                    handle, other = f.handles()
                    error = error_type()
                    lock = InterruptedLock(f.vault._lock, error)
                    before = f.effects()
                    with patch.object(f.vault, "_lock", lock):
                        self.assert_failure(f, handle, error)
                    self.assertEqual(lock.acquisitions, 2)
                    self.assertEqual(f.effects(), before)
                    self.assert_revoked(f, handle)
                    self.assertTrue(f.vault.consume(other, f.grant, f.sink))

    def test_read_callback_failure_never_installs_an_unreturned_handle(self) -> None:
        for stage in ("authority", "token", "data_return"):
            for error_type in (RuntimeError, *CANCELLATIONS):
                with self.subTest(stage=stage, error=error_type.__name__):
                    f = Fixture()
                    with f.peer.installed():
                        other = f.vault.read(f.grant)
                        error = error_type()
                        transport = f.vault._transport

                        def interrupted(
                            path: str,
                            token: str,
                            timeout: float,
                            transport: Callable[
                                [str, str, float], Response
                            ] = transport,
                            error: BaseException = error,
                        ) -> Response:
                            transport(path, token, timeout)
                            raise error

                        if stage == "data_return":
                            f.vault._transport = interrupted
                        else:
                            f.arm(stage, error)
                        if isinstance(error, Exception):
                            with self.assertRaises(VaultDenied) as caught:
                                f.vault.read(f.grant)
                            self.assertIsNone(caught.exception.__context__)
                        else:
                            with self.assertRaises(type(error)) as cancelled:
                                f.vault.read(f.grant)
                            self.assertIs(cancelled.exception, error)
                        self.assertEqual(list(f.vault._entries), [other])
                        self.assertEqual(f.injections, [])
                        f.vault.release(other)
                    self.assertEqual(f.peer.closed, len(f.peer.requests))

    def test_ordinary_failure_does_not_export_canaries(self) -> None:
        for stage in STAGES:
            with self.subTest(stage=stage):
                f = Fixture()
                output = io.StringIO()
                with (
                    f.peer.installed(),
                    contextlib.redirect_stdout(output),
                    contextlib.redirect_stderr(output),
                ):
                    handle, other = f.handles()
                    f.arm(stage, RuntimeError(CANARY + TOKEN))
                    result = f.vault.consume(handle, f.grant, f.sink)
                    self.assertIs(result, False)
                    self.assert_revoked(f, handle)
                    self.assertEqual(f.injections, [])
                    self.assertTrue(f.vault.consume(other, f.grant, f.sink))
                envelope = repr(result) + output.getvalue() + repr(f.effects())
                self.assertNotIn(CANARY, envelope)
                self.assertNotIn(TOKEN, envelope)

    def test_success_foreign_handles_release_and_forget_remain_scoped(self) -> None:
        f = Fixture()
        with f.peer.installed():
            handle, other = f.handles()
            for foreign in (Handle(), object(), [], None):
                before = f.effects()
                self.assertFalse(f.vault.consume(foreign, f.grant, f.sink))
                self.assertEqual(f.effects(), before)
                self.assertEqual(len(f.vault._entries), 2)
            self.assertTrue(f.vault.current(handle, f.grant))
            self.assertTrue(f.vault.consume(handle, f.grant, f.sink))
            self.assert_revoked(f, handle)
            self.assertTrue(f.vault.current(other, f.grant))
            f.vault.release(handle)
            self.assertEqual(len(f.vault._entries), 1)
            f.vault.forget()
            self.assert_revoked(f, other)
            self.assertEqual(f.injections, ["injection"])


if __name__ == "__main__":
    unittest.main()

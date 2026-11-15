"""Cancellation lifecycle probes with real helpers and in-memory HTTP peers."""

from __future__ import annotations

import asyncio
import contextlib
import io
import unittest
from collections.abc import Iterator
from unittest.mock import patch

from browser_runtime.credentials import Denied as ResolverDenied
from browser_runtime.credentials import Grant
from browser_runtime.openbao import Handle, Response, Vault
from tests.test_openbao_http import (
    CANARY,
    DATA,
    METADATA,
    TOKEN,
    Peer,
    resolver,
    scoped_vault,
    sized,
)

STAGES = ("authority", "token", "metadata", "post_metadata_authority")
CANCELLATIONS = (asyncio.CancelledError, KeyboardInterrupt, SystemExit)


class Fixture:
    def __init__(self) -> None:
        self.vault, self.grant = scoped_vault()
        self.peer = Peer(sized(DATA), sized(DATA), *([sized(METADATA)] * 8))
        self.tokens = 0
        self.transports: list[str] = []
        self.injections: list[str] = []
        self.stage: str | None = None
        self.error: BaseException = asyncio.CancelledError()
        self.metadata_returned = False
        transport = self.vault._transport

        def authorize(candidate: Grant) -> bool:
            self.fail("authority")
            if self.metadata_returned:
                self.fail("post_metadata_authority")
            return candidate == self.grant

        def token() -> str:
            self.tokens += 1
            self.fail("token")
            return TOKEN

        def request(path: str, token: str, timeout: float) -> Response:
            self.transports.append(path)
            response = transport(path, token, timeout)
            if "/metadata/" in path:
                self.metadata_returned = True
                self.fail("metadata")
            return response

        self.vault._authorize = authorize
        self.vault._token = token
        self.vault._transport = request

    def fail(self, stage: str) -> None:
        if self.stage == stage:
            self.stage = None  # One interruption; later reads would succeed.
            raise self.error

    def arm(self, stage: str, error: BaseException) -> None:
        self.stage, self.error = stage, error
        self.metadata_returned = False

    def sink(self, _secret: str) -> bool:
        self.injections.append("injection")
        return True

    def effects(self) -> tuple[int, int, int, int]:
        return (
            self.tokens,
            len(self.transports),
            len(self.peer.requests),
            len(self.injections),
        )

    def handles(self) -> tuple[object, object]:
        return self.vault.read(self.grant), self.vault.read(self.grant)


class CancellationTests(unittest.TestCase):
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
        self.assertEqual(f.injections, [])

    def test_cancellation_revokes_only_affected_handle_and_propagates(self) -> None:
        for stage in STAGES:
            for error_type in CANCELLATIONS:
                with self.subTest(stage=stage, cancellation=error_type.__name__):
                    f = Fixture()
                    with f.peer.installed():
                        handle, other = f.handles()
                        error = error_type()
                        f.arm(stage, error)
                        with self.assertRaises(error_type) as caught:
                            f.vault.current(handle, f.grant)
                        self.assertIs(caught.exception, error)
                        self.assertIsNone(caught.exception.__context__)
                        self.assert_revoked(f, handle)
                        self.assertEqual(len(f.vault._entries), 1)
                        self.assertTrue(f.vault.current(other, f.grant))
                        self.assertTrue(f.vault.consume(other, f.grant, f.sink))
                        self.assertEqual(f.injections, ["injection"])
                        self.assertEqual(len(f.vault._entries), 0)
                    self.assertEqual(f.peer.closed, len(f.peer.requests))
                    self.assertTrue(all(r.closed for r in f.peer.responses))

    def test_ordinary_failures_stay_false_and_do_not_export_canaries(self) -> None:
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
                    result = f.vault.current(handle, f.grant)
                    self.assertIs(result, False)
                    self.assert_revoked(f, handle)
                    self.assertTrue(f.vault.consume(other, f.grant, f.sink))
                envelope = repr(result) + output.getvalue() + repr(f.effects())
                self.assertNotIn(CANARY, envelope)
                self.assertNotIn(TOKEN, envelope)

    def unlock_probe(
        self, f: Fixture, handle: object, stage: str, error: BaseException
    ) -> tuple[list[bool], list[bool]]:
        original_lock = f.vault._lock
        retained_at_unlock: list[bool] = []
        consumed_at_unlock: list[bool] = []

        @contextlib.contextmanager
        def observed_lock() -> Iterator[None]:
            try:
                with original_lock:
                    try:
                        yield
                    finally:
                        retained_at_unlock.append(handle in f.vault._entries)
            finally:
                # Model a waiting consumer immediately after the lock exits,
                # before current() can run any outside-the-lock cleanup.
                f.vault._lock = original_lock
                consumed_at_unlock.append(f.vault.consume(handle, f.grant, f.sink))

        f.arm(stage, error)
        with patch.object(f.vault, "_lock", observed_lock()):
            with self.assertRaises(type(error)) as caught:
                f.vault.current(handle, f.grant)
        self.assertIs(caught.exception, error)
        return retained_at_unlock, consumed_at_unlock

    def test_cancellation_invalidates_before_unlock_and_waiting_reentry(self) -> None:
        for stage in STAGES:
            for error_type in CANCELLATIONS:
                with self.subTest(stage=stage, cancellation=error_type.__name__):
                    f = Fixture()
                    with f.peer.installed():
                        handle, other = f.handles()
                        observed = self.unlock_probe(f, handle, stage, error_type())
                        self.assertEqual(observed, ([False], [False]))
                        self.assert_revoked(f, handle)
                        self.assertTrue(f.vault.consume(other, f.grant, f.sink))

    def test_deliberate_delayed_cleanup_mutation_breaks_zero_injection(self) -> None:
        def delayed_cleanup(vault: Vault, handle: object, grant: Grant) -> bool:
            valid = False
            try:
                with vault._lock:
                    vault._current(handle, grant)
                    valid = True
            finally:
                if not valid:
                    vault.release(handle)  # Deliberately too late: already unlocked.
            return valid

        f = Fixture()
        with f.peer.installed():
            handle, other = f.handles()
            with patch.object(Vault, "current", delayed_cleanup):
                observed = self.unlock_probe(
                    f, handle, "metadata", asyncio.CancelledError()
                )
            with self.assertRaises(AssertionError):
                self.assertEqual(f.injections, [])
            self.assertEqual(observed, ([True], [True]))
            self.assertEqual(f.injections, ["injection"])
            f.vault.release(other)

    def test_deliberate_missing_cleanup_mutation_permits_cancelled_handle(self) -> None:
        def missing_cleanup(vault: Vault, handle: object, grant: Grant) -> bool:
            try:
                with vault._lock:
                    vault._current(handle, grant)
                    return True
            except Exception:
                vault.release(handle)
            return False

        f = Fixture()
        with f.peer.installed():
            handle, other = f.handles()
            f.arm("metadata", asyncio.CancelledError())
            with patch.object(Vault, "current", missing_cleanup):
                with self.assertRaises(asyncio.CancelledError):
                    f.vault.current(handle, f.grant)
            self.assertTrue(f.vault.consume(handle, f.grant, f.sink))
            with self.assertRaises(AssertionError):
                self.assertEqual(f.injections, [])
            self.assertEqual(f.injections, ["injection"])
            f.vault.release(other)

    def test_success_and_foreign_handles_preserve_existing_lifecycle(self) -> None:
        f = Fixture()
        with f.peer.installed():
            handle, other = f.handles()
            for foreign in (Handle(), object(), [], None):
                before = f.effects()
                self.assertFalse(f.vault.current(foreign, f.grant))
                self.assertEqual(f.effects(), before)
                self.assertEqual(len(f.vault._entries), 2)
            self.assertTrue(f.vault.current(handle, f.grant))
            self.assertTrue(f.vault.current(handle, f.grant))
            self.assertTrue(f.vault.consume(handle, f.grant, f.sink))
            self.assertFalse(f.vault.consume(handle, f.grant, f.sink))
            self.assertTrue(f.vault.consume(other, f.grant, f.sink))
            self.assertEqual(f.injections, ["injection", "injection"])

    def test_resolver_cancellation_releases_handle_and_remains_one_shot(self) -> None:
        f = Fixture()
        # The resolver reads one data response, then validates metadata.
        f.peer.pending.pop(0)
        releases: list[object] = []
        release = f.vault.release

        def recorded_release(handle: object) -> None:
            releases.append(handle)
            release(handle)

        current = resolver(f.vault, f.grant, f.injections)
        error = asyncio.CancelledError()
        f.arm("metadata", error)
        with f.peer.installed(), patch.object(f.vault, "release", recorded_release):
            with self.assertRaises(asyncio.CancelledError) as caught:
                current.resolve_and_inject(object())
            self.assertIs(caught.exception, error)
            self.assertEqual(len(releases), 1)
            self.assertEqual(len(f.vault._entries), 0)
            self.assert_revoked(f, releases[0])
            before = f.effects()
            with self.assertRaises(ResolverDenied):
                current.resolve_and_inject(object())
            self.assertEqual(f.effects(), before)
            self.assertEqual(f.injections, [])


if __name__ == "__main__":
    unittest.main()

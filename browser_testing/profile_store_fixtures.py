"""Invented adapters for actual encrypted-store tests; never production authority."""

import hashlib
import os
import socket
import time
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from typing import Any, Callable, Iterator
from unittest.mock import patch

from browser_runtime.credentials import Observation, Target
from browser_runtime.effects import Binding
from browser_runtime.profile_store import Adapters, Grant, Guard, Key, Store

CANARY = b"SYNTHETIC_PROFILE_COOKIE_NEVER_LOG_7e574319"
KEY = bytes(
    range(32)
)  # Public deterministic TEST key only; never runtime provisioning.
BASE = Target(
    Binding(
        "principal",
        "account",
        "browser",
        "tab",
        "intent",
        1,
        "operation",
        7,
        "https://site.example",
    ),
    "native",
    "frame",
    "https://site.example",
)


def grant(action: str = "save", reference: str = "checkpoint", **changes: Any) -> Grant:
    from typing import cast

    from browser_runtime.profile_store import Action

    return replace(
        Grant(BASE, "profile", cast(Action, action), reference, time.monotonic() + 100),
        **changes,
    )


class Fake:
    def __init__(self) -> None:
        self.grant = grant()
        self.observation: Observation | None = None
        self.allowed = True
        self.stopped = True
        self.reads = 0
        self.captures = 0
        self.consumes = 0
        self.releases = 0
        self.material = KEY
        self.version = "test-key-v1"
        self.captured = CANARY
        self.after_key: Callable[[], None] = lambda: None
        self.after_capture: Callable[[], None] = lambda: None
        self.after_consume: Callable[[], None] = lambda: None
        self.consume_marker: Path | None = None
        self.received: list[bytes] = []
        self.raise_on_release = False
        self.suppress = False

    @contextmanager
    def acquire(self) -> Iterator[Guard]:
        try:
            yield self
        except BaseException:
            if not self.suppress:
                raise

    def admit(self, ticket: object) -> Grant | None:
        return self.grant if ticket == "trusted-ticket" else None

    def observe(self) -> Observation | None:
        return (
            self.observation
            if self.observation is not None
            else Observation(self.grant.target, time.monotonic())
        )

    def current(self, _grant: Grant) -> bool:
        return self.allowed

    def quiescent(self, _grant: Grant) -> bool:
        return self.stopped

    @contextmanager
    def key(self, _grant: Grant, version: str | None) -> Iterator[Key]:
        self.reads += 1
        self.after_key()
        try:
            yield Key(self.version if version is None else version, self.material)
        finally:
            self.releases += 1
            if self.raise_on_release:
                raise RuntimeError(CANARY.decode())

    def capture(self, _grant: Grant, _guard: Guard) -> bytes:
        self.captures += 1
        self.after_capture()
        return self.captured

    def consume(self, _grant: Grant, _guard: Guard, plaintext: bytes) -> bool:
        self.consumes += 1
        self.received.append(plaintext)
        if self.consume_marker is not None:
            with self.consume_marker.open("ab") as stream:
                stream.write(hashlib.sha256(plaintext).hexdigest().encode() + b"\n")
                stream.flush()
                os.fsync(stream.fileno())
        self.after_consume()
        return True

    def adapters(self) -> Adapters:
        outer = self

        class KeyAdapter:
            def acquire(
                self, store_id: str, grant: Grant, version: str | None
            ) -> object:
                return outer.key(grant, version)

        from typing import cast

        from browser_runtime.profile_store import Keys

        return Adapters(self, cast(Keys, KeyAdapter()), self)


def child(directory: str, action: str, fault: str, marker: str) -> None:
    fake = Fake()
    fake.grant = grant(action)
    fake.consume_marker = Path(marker)
    with patch.object(
        socket.socket, "connect", side_effect=AssertionError("network forbidden")
    ):
        store = Store(directory, fake.adapters())
        db = store._db
        commits = 0

        class CrashConnection:
            def __getattr__(self, name: str) -> object:
                return getattr(db, name)

            def execute(self, sql: str, parameters: object = ()) -> object:
                nonlocal commits
                if sql == "COMMIT":
                    commits += 1
                    if fault == f"before-{commits}":
                        os._exit(71)
                result = db.execute(sql, parameters)  # type: ignore[arg-type]
                if sql == "COMMIT" and fault == f"after-{commits}":
                    os._exit(72)
                return result

        with patch.object(store, "_db", CrashConnection()):
            if fault == "consume":
                fake.after_consume = lambda: os._exit(73)
            if fault == "capture":
                fake.after_capture = lambda: os._exit(74)
            if fault == "key":
                fake.after_key = lambda: os._exit(75)
            print(store.run("trusted-ticket"))
        store.close()

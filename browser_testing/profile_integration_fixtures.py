"""Local synthetic composition; real custody, encryption and directory IO."""

from __future__ import annotations

import base64
import json
import os
import socket
import sqlite3
import sys
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from typing import Callable, Iterator, cast
from unittest.mock import patch

from browser_runtime.profile_directory import DirectoryProfileIO, MaterializedStore
from browser_runtime.profile_keys import Keys, manifest_digest
from browser_runtime.profile_store import Grant, Guard, Key, Store, encoded
from browser_testing.profile_keys_fixtures import Peer, mapping, operation, provision
from browser_testing.profile_store_fixtures import CANARY, Fake

OLD = b"SYNTHETIC_PREVIOUS_PROFILE_293"


def bundle(scope: str, data: bytes) -> bytes:
    return encoded(
        {
            "version": 1,
            "scope": scope,
            "directories": [["nested"], ["zero"]],
            "files": [
                [["empty-file"], ""],
                [["nested", "Cookies"], base64.b64encode(data).decode("ascii")],
            ],
        }
    ).encode("ascii")


def marker(root: Path, event: str) -> None:
    # Independent, non-secret effect receipt. Never a runtime admission input.
    with (root / "effects").open("ab") as stream:
        stream.write(event.encode("ascii") + b"\n")
        stream.flush()
        os.fsync(stream.fileno())


class ObservedKeys(Keys):
    after_issue: Callable[[], object] = staticmethod(lambda: None)

    @contextmanager
    def acquire(
        self, store_id: str, grant: Grant, version: str | None
    ) -> Iterator[Key]:
        with super().acquire(store_id, grant, version) as key:
            self.after_issue()
            yield key


class ObservedDirectory(DirectoryProfileIO):
    def __init__(self, directory: Path, grant: Grant, effects_root: Path) -> None:
        self.effects_root = effects_root
        self.prepares = self.captures = self.consumes = 0
        super().__init__(directory, grant)

    def _prepare(self, grant: Grant, guard: Guard) -> None:
        self.prepares += 1
        marker(self.effects_root, "prepare")
        super()._prepare(grant, guard)

    def capture(self, grant: Grant, guard: Guard) -> bytes:
        self.captures += 1
        marker(self.effects_root, "capture")
        return super().capture(grant, guard)

    def consume(self, grant: Grant, guard: Guard, plaintext: bytes) -> bool:
        self.consumes += 1
        marker(self.effects_root, "consume")
        return super().consume(grant, guard, plaintext)


class Fixture:
    def __init__(self, root: Path, *, create: bool = False) -> None:
        self.root = root
        self.profile = root / "profile"
        self.ciphertext = root / "ciphertext"
        self.custody = root / "custody"
        if create:
            self.profile.mkdir(mode=0o700)
            self.ciphertext.mkdir(mode=0o700)
            bootstrap = Store(self.ciphertext)
            bootstrap.close()
        with sqlite3.connect(
            (self.ciphertext / "profiles.sqlite3").as_uri() + "?mode=ro", uri=True
        ) as db:
            self.store_id = db.execute("SELECT store_id FROM metadata").fetchone()[0]
        self.mapping = mapping(self.store_id)
        if create:
            provision(self.custody, (self.mapping,))
        self.peer = Peer()
        self.peer.on_fetch = lambda: marker(root, "fetch")
        self.authority = Fake()
        self.tree = ObservedDirectory(self.profile, self.authority.grant, root)
        self.keys = ObservedKeys(
            self.custody,
            expected_manifest=manifest_digest((self.mapping,)),
            transport=self.peer.transport,
            token_source=self.peer.token,
        )
        self.keys.after_issue = lambda: marker(root, "issue")
        self.store = MaterializedStore(
            self.ciphertext, self.authority, self.keys, self.tree
        )

    def close(self) -> None:
        self.store.close()
        self.tree.close()

    def seed(self, data: bytes = CANARY) -> None:
        # Explicit synthetic fixture preparation, never a claimed production route.
        self.authority.grant = operation("seed", "restore")
        self.tree.consume(
            self.authority.grant,
            self.authority,
            bundle(self.authority.grant.scope(), data),
        )

    def run(self, action: str, name: str, *, reference: str = "checkpoint") -> str:
        self.authority.grant = replace(operation(name, action), reference=reference)
        return self.store.run("trusted-ticket")

    def state(self) -> dict[str, object]:
        return cast(
            dict[str, object], json.loads((self.profile / "state.json").read_text())
        )

    def current(self) -> bytes:
        return (
            self.profile
            / ("g-" + cast(str, self.state()["current"]))
            / "nested"
            / "Cookies"
        ).read_bytes()

    def effects(self) -> list[str]:
        path = self.root / "effects"
        return path.read_text().splitlines() if path.exists() else []


def child(root: Path, action: str, fault: str) -> None:
    with patch.object(
        socket.socket, "connect", side_effect=AssertionError("network forbidden")
    ):
        f = Fixture(root)
        write_state = f.tree._write_state

        def state(state: dict[str, object]) -> None:
            if fault == "before-" + str(state["phase"]):
                os._exit(71)
            write_state(state)
            if fault == "after-" + str(state["phase"]):
                os._exit(72)

        f.tree._write_state = state  # type: ignore[method-assign]
        write = f.tree._write

        def file(fd: int, data: bytes) -> None:
            write(fd, data)
            if data == CANARY:
                marker(root, "plaintext-write")
                if fault == "plaintext":
                    os._exit(73)

        f.tree._write = file  # type: ignore[method-assign]

        def issued() -> None:
            marker(root, "issue")
            if fault == "issued":
                os._exit(74)

        f.keys.after_issue = issued
        fetch = f.peer.on_fetch

        def fetched() -> None:
            fetch()
            if fault == "pending":
                os._exit(75)

        f.peer.on_fetch = fetched
        forget = f.tree.forget

        def forgotten(grant: Grant, guard: Guard) -> None:
            if fault == "tombstone-gap":
                os._exit(76)
            forget(grant, guard)

        f.tree.forget = forgotten  # type: ignore[method-assign]
        try:
            f.run(action, "child-" + action)
        finally:
            f.close()


if __name__ == "__main__":
    child(Path(sys.argv[1]), sys.argv[2], sys.argv[3])

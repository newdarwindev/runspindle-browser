"""Synthetic custody registry provisioning ONLY for tests; no production enrollment."""

import base64
import hashlib
import json
import os
import sqlite3
import sys
import time
from dataclasses import replace
from pathlib import Path
from typing import Callable

from browser_runtime.openbao import Response
from browser_runtime.profile_custody_schema import (
    GATE,
    GATE_DDL,
    GATE_ID,
    LEASE,
    LEASE_DDL,
    LEASE_ID,
)
from browser_runtime.profile_keys import Keys, Mapping, manifest_digest
from browser_runtime.profile_store import Grant
from browser_testing.profile_store_fixtures import KEY, grant

STORE_ID = "a" * 64
TOKEN = "SYNTHETIC_CUSTODY_TOKEN_98"


def mapping(store_id: str = STORE_ID) -> Mapping:
    g = grant()
    b = g.target.binding
    return Mapping(
        store_id,
        b.principal,
        b.account,
        g.profile,
        b.origin,
        g.target.frame_origin,
        "profiles",
        ("synthetic", "key"),
        "key",
        3,
        hashlib.sha256(KEY).hexdigest(),
        True,
    )


def operation(name: str = "first", action: str = "save") -> Grant:
    g = grant(action)
    return replace(
        g, target=replace(g.target, binding=replace(g.target.binding, operation=name))
    )


def provision(root: Path, mappings: tuple[Mapping, ...]) -> str:
    root.mkdir(mode=0o700)
    for name, ddl, app_id in ((GATE, GATE_DDL, GATE_ID), (LEASE, LEASE_DDL, LEASE_ID)):
        path = root / name
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
        with sqlite3.connect(path) as db:
            for statement in ddl:
                db.execute(statement)
            db.execute(f"PRAGMA application_id={app_id}")
            db.execute("PRAGMA user_version=1")
            if name == GATE:
                for m in mappings:
                    db.execute(
                        "INSERT INTO registry VALUES (?,?,0)", (m.key_id(), m.config())
                    )
            else:
                db.execute("INSERT INTO fence VALUES (1)")
    return manifest_digest(mappings)


class Peer:
    def __init__(self) -> None:
        self.calls: list[str] = []
        self.tokens = 0
        self.on_token: Callable[[], object] = lambda: None
        self.on_fetch: Callable[[], object] = lambda: None
        self.reply: Response | None = None

    def token(self) -> str:
        self.tokens += 1
        self.on_token()
        return TOKEN

    def transport(self, path: str, token: str, timeout: float) -> Response:
        if token != TOKEN or not 0 < timeout <= 2:
            raise ValueError("synthetic transport binding failed")
        self.calls.append(path)
        self.on_fetch()
        return self.reply if self.reply is not None else self.response()

    @staticmethod
    def response(**metadata: object) -> Response:
        meta: dict[str, object] = {
            "version": 3,
            "deletion_time": "",
            "destroyed": False,
        }
        meta.update(metadata)
        return Response(
            200,
            json.dumps(
                {
                    "data": {
                        "metadata": meta,
                        "data": {"key": base64.b64encode(KEY).decode("ascii")},
                    }
                }
            ).encode(),
        )

    def keys(self, root: Path, digest: str) -> Keys:
        return Keys(
            root,
            expected_manifest=digest,
            transport=self.transport,
            token_source=self.token,
        )


def main() -> None:
    import socket
    from unittest.mock import patch

    root, stage = Path(sys.argv[1]), sys.argv[2]
    peer = Peer()
    keys = peer.keys(root, manifest_digest((mapping(),)))
    with patch.object(
        socket.socket, "connect", side_effect=AssertionError("network forbidden")
    ):
        if stage == "pending":
            peer.on_fetch = lambda: os._exit(41)
        with keys.acquire(STORE_ID, operation(), None):
            if stage == "issued":
                os._exit(42)
            (root.parent / "ready").touch()
            deadline = time.monotonic() + 10
            while not (root.parent / "release").exists():
                if time.monotonic() > deadline:
                    raise RuntimeError("synthetic test wait expired")
                time.sleep(0.01)


if __name__ == "__main__":
    main()

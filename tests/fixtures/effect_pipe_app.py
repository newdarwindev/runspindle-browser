"""Explicit synthetic application composition for cross-language pipe tests only.

No real browser, credential, Core issuer or operation repository is implemented.
The target fixture owns its ephemeral action ledger, not Browser persistence.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from browser_runtime.credentials import Observation, Target  # noqa: E402
from browser_runtime.effect_pipe import serve_once  # noqa: E402
from browser_runtime.effect_wire import Receiver  # noqa: E402
from browser_runtime.effects import Binding, Readback  # noqa: E402
from browser_runtime.guarded_peer import Grant, Guard, GuardedPeer  # noqa: E402

PAYLOAD = b"synthetic-pipe-action"
DIGEST = hashlib.sha256(PAYLOAD).hexdigest()
TARGET = Target(
    Binding(
        "fixture",
        "fixture-account",
        "fixture-browser",
        "fixture-tab",
        "fixture-intent",
        1,
        "fixture-operation",
        1,
        "https://fixture.invalid",
    ),
    "fixture-session",
    "fixture-frame",
    "https://fixture.invalid",
)


class Application:
    def __init__(self, site_state: Path, action: str, lose_response: bool) -> None:
        self.site_state = site_state
        self.grant = Grant(TARGET, DIGEST, action, time.monotonic() + 30)
        self.ticket = object()  # Never constructed from transport bytes.
        self.active = False
        self.lose_response = lose_response

    @contextmanager
    def acquire(self) -> Iterator[Application]:
        self.active = True
        try:
            yield self
        finally:
            self.active = False

    def admit(self, ticket: object) -> Grant | None:
        return self.grant if self.active and ticket is self.ticket else None

    def current(self, grant: Grant) -> bool:
        return self.active and grant == self.grant

    def observe(self) -> Observation:
        return Observation(TARGET, time.monotonic())

    def submit(self, grant: Grant, payload: bytes, guard: Guard) -> None:
        if guard is not self or not self.current(grant) or payload != PAYLOAD:
            raise ValueError
        with self.site_state.open("ab") as stream:
            stream.write(b"accepted\n")
            stream.flush()
            os.fsync(stream.fileno())
        if self.lose_response:
            raise SystemExit(2)

    def readback(self, grant: Grant, guard: Guard) -> Readback:
        if guard is not self or not self.current(grant):
            raise ValueError
        data = self.site_state.read_bytes() if self.site_state.exists() else b""
        return Readback(
            TARGET.binding,
            DIGEST,
            "confirmed" if data == b"accepted\n" else "unknown",
            hashlib.sha256(data).hexdigest(),
        )


def main() -> int:
    if os.environ.get("RUNSPINDLE_SYNTHETIC_PIPE_APP") != "1":
        return 2
    parser = argparse.ArgumentParser()
    parser.add_argument("--site-state", type=Path, required=True)
    parser.add_argument("--action", choices=("dispatch", "reconcile"), required=True)
    parser.add_argument("--lose-response", action="store_true")
    args = parser.parse_args()
    app = Application(args.site_state, args.action, args.lose_response)
    receiver = Receiver(GuardedPeer(authority=app, site=app))
    return (
        0
        if serve_once(sys.stdin.buffer, sys.stdout.buffer, receiver, app.ticket)
        else 2
    )


if __name__ == "__main__":
    raise SystemExit(main())

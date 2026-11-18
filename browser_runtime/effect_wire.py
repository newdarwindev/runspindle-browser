"""Closed bounded local wire receiver; no launcher, network or issuer.

A trusted composition root supplies a GuardedPeer and out-of-band admission
ticket. Wire values constrain that authenticated grant, never create one.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, NoReturn

from browser_runtime.credentials import Target
from browser_runtime.effects import Binding, Cancelled, Denied
from browser_runtime.guarded_peer import GuardedPeer

VERSION = "runspindle.browser-effect.v1"
MAX_PAYLOAD = 1048576
MAX_REQUEST = 2 * MAX_PAYLOAD + 8192
EVIDENCE_CLASS = "browser_guarded_effect_observation"


def _fail(cancelled: bool = False) -> NoReturn:
    try:
        if cancelled:
            raise Cancelled("effect wire cancelled")
        raise Denied("effect wire denied")
    except (Denied, Cancelled) as error:
        error.__cause__ = error.__context__ = None
        raise


def _pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _constant(_: str) -> NoReturn:
    raise ValueError


def _closed(value: Any, keys: set[str]) -> dict[str, Any]:
    if type(value) is not dict or set(value) != keys:
        raise ValueError
    return value


@dataclass(frozen=True)
class Request:
    action: str
    target: Target
    payload_digest: str
    payload: bytes | None


def decode(raw: bytes) -> Request:
    result: Request | None = None
    cancelled = False
    try:
        if type(raw) is not bytes or not 0 < len(raw) <= MAX_REQUEST:
            raise ValueError
        value = _closed(
            json.loads(
                raw.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_constant
            ),
            {"version", "action", "target", "payload_digest", "payload_hex"},
        )
        if value["version"] != VERSION or value["action"] not in (
            "dispatch",
            "reconcile",
        ):
            raise ValueError
        target = _closed(
            value["target"], {"binding", "native_session", "frame", "frame_origin"}
        )
        binding = _closed(
            target["binding"],
            {
                "principal",
                "account",
                "browser",
                "tab",
                "intent",
                "revision",
                "operation",
                "epoch",
                "origin",
            },
        )
        expected = Target(
            Binding(**binding),
            target["native_session"],
            target["frame"],
            target["frame_origin"],
        )
        expected.validate()
        digest = value["payload_digest"]
        if type(digest) is not str or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise ValueError
        payload = None
        encoded = value["payload_hex"]
        if value["action"] == "dispatch":
            if (
                type(encoded) is not str
                or not 0 < len(encoded) <= MAX_PAYLOAD * 2
                or len(encoded) % 2
                or re.fullmatch(r"[0-9a-f]+", encoded) is None
            ):
                raise ValueError
            payload = bytes.fromhex(encoded)
            if hashlib.sha256(payload).hexdigest() != digest:
                raise ValueError
        elif encoded is not None:
            raise ValueError
        result = Request(value["action"], expected, digest, payload)
    except BaseException as error:
        cancelled = not isinstance(error, Exception)
    if result is None:
        _fail(cancelled)
    return result


class Receiver:
    """Caller supplies trusted peer/ticket; bytes contain neither adapters nor credentials."""

    def __init__(self, journal: GuardedPeer) -> None:
        self._journal = journal

    def exchange(self, raw: bytes, ticket: object) -> bytes:
        request = decode(raw)
        response: bytes | None = None
        cancelled = False
        try:
            if request.action == "dispatch":
                if request.payload is None:
                    raise ValueError
                outcome = self._journal.dispatch(
                    ticket,
                    request.payload,
                    expected_target=request.target,
                    expected_digest=request.payload_digest,
                )
            else:
                outcome = self._journal.reconcile(
                    ticket,
                    expected_target=request.target,
                    expected_digest=request.payload_digest,
                )
            if outcome not in ("unknown", "confirmed", "rejected"):
                raise ValueError
            response = json.dumps(
                {
                    "version": VERSION,
                    "request_sha256": hashlib.sha256(raw).hexdigest(),
                    "evidence_class": EVIDENCE_CLASS,
                    "outcome": outcome,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        except BaseException as error:
            cancelled = not isinstance(error, Exception)
        if response is None:
            _fail(cancelled)
        return response

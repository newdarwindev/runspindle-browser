"""Narrow KV-v2 protocol adapter. Trusted construction only; no default authority."""

from __future__ import annotations

import http.client
import json
import math
import re
import ssl
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, cast
from urllib.parse import urlsplit

from browser_runtime.credentials import Grant, Target

MAX_BODY = 65536


class Denied(ValueError):
    pass


def check(ok: bool) -> None:
    if not ok:
        raise ValueError


def number(value: object) -> float:
    check(type(value) in (int, float))
    result = float(cast(float, value))
    check(math.isfinite(result))
    return result


def segment(value: str) -> None:
    check(
        type(value) is str and re.fullmatch(r"[A-Za-z0-9_-]{1,128}", value) is not None
    )


@dataclass(frozen=True, repr=False)
class Response:
    status: int
    body: bytes = field(repr=False)


class HTTPS:
    """Fixed HTTPS origin; no proxy discovery, redirects, retries or logging.

    Socket timeout bounds inactivity, not DNS or total execution time. Callers
    still check grant deadline after return; trusted composition must bound DNS.
    """

    def __init__(self, origin: str) -> None:
        parsed = urlsplit(origin)
        check(parsed.scheme == "https" and bool(parsed.hostname))
        check(
            not any(
                (
                    parsed.username,
                    parsed.password,
                    parsed.path,
                    parsed.query,
                    parsed.fragment,
                )
            )
        )
        self._host = cast(str, parsed.hostname)
        port = parsed.port
        check(port is None or 1 <= port <= 65535)
        self._port = 443 if port is None else port

    def __call__(self, path: str, token: str, timeout: float) -> Response:
        conn = http.client.HTTPSConnection(
            self._host,
            self._port,
            timeout=timeout,
            context=ssl.create_default_context(),
        )
        try:
            conn.request(
                "GET",
                path,
                headers={"X-Vault-Token": token, "Accept": "application/json"},
            )
            reply = conn.getresponse()
            check(reply.status == 200)
            check(reply.getheader("Content-Encoding", "identity") == "identity")
            length = reply.getheader("Content-Length")
            if length is not None:
                check(
                    length.isascii() and length.isdecimal() and int(length) <= MAX_BODY
                )
            body = reply.read(MAX_BODY + 1)
            check(len(body) <= MAX_BODY)
            return Response(reply.status, body)
        finally:
            conn.close()


@dataclass(frozen=True)
class Mapping:
    principal: str
    account: str
    origin: str
    frame_origin: str
    reference: str = field(repr=False)
    mount: str = field(repr=False)
    path: tuple[str, ...] = field(repr=False)
    field_name: str = field(repr=False)


class Handle:
    __slots__ = ()

    def __repr__(self) -> str:
        return "<credential handle>"


@dataclass(repr=False)
class _Entry:
    grant: Grant
    mapping: Mapping
    version: int
    secret: str


def reject_constant(_: str) -> object:
    raise ValueError


def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in items:
        check(key not in result)
        result[key] = value
    return result


def object_value(value: object) -> dict[str, object]:
    check(type(value) is dict)
    return cast(dict[str, object], value)


def version(value: object) -> int:
    check(type(value) is int and 1 <= value <= 2**63 - 1)
    return cast(int, value)


def alive(data: dict[str, object]) -> None:
    check(data.get("destroyed") is False and data.get("deletion_time") == "")


class Vault:
    """Process-local handles, not durable credentials or atomic remote fencing.

    authorize is the trusted grant verifier. It must authenticate current authority;
    a caller's equality comparison is not authentication. consume's sink is a
    trusted helper within the already held browser fence, never orchestrator code.
    """

    def __init__(
        self,
        mappings: tuple[Mapping, ...],
        *,
        transport: Callable[[str, str, float], Response],
        token: Callable[[], str],
        authorize: Callable[[Grant], bool] | None = None,
        clock: Callable[[], float] = time.monotonic,
        timeout: float = 2.0,
    ) -> None:
        check(type(mappings) is tuple and 0 < len(mappings) <= 128)
        check(0 < number(timeout) <= 10)
        keys = set()
        for m in mappings:
            check(type(m) is Mapping and type(m.path) is tuple and 0 < len(m.path) <= 8)
            for v in (m.mount, m.field_name, *m.path):
                segment(v)
            key = (m.principal, m.account, m.origin, m.frame_origin, m.reference)
            check(all(type(v) is str for v in key) and key not in keys)
            keys.add(key)
        self._mappings = mappings
        self._transport, self._token = transport, token
        self._authorize, self._clock, self._timeout = authorize, clock, timeout
        self._entries: dict[Handle, _Entry] = {}
        self._lock = threading.Lock()

    def _scope(self, grant: Grant) -> Mapping:
        check(type(grant) is Grant and type(grant.target) is Target)
        grant.target.validate()
        check(type(grant.reference) is str)
        check(number(self._clock()) < number(grant.deadline))
        b = grant.target.binding
        key = (
            b.principal,
            b.account,
            b.origin,
            grant.target.frame_origin,
            grant.reference,
        )
        selected = [
            m
            for m in self._mappings
            if (m.principal, m.account, m.origin, m.frame_origin, m.reference) == key
        ]
        check(len(selected) == 1)
        check(self._authorize is not None and self._authorize(grant) is True)
        check(number(self._clock()) < number(grant.deadline))
        return selected[0]

    def _request(self, grant: Grant, m: Mapping, kind: str) -> dict[str, object]:
        check(self._scope(grant) == m)
        token = self._token()
        check(
            type(token) is str
            and 0 < len(token) <= 4096
            and all(33 <= ord(c) <= 126 for c in token)
        )
        # Recheck after trusted token callback, before any HTTP effect.
        check(self._scope(grant) == m)
        remaining = number(grant.deadline) - number(self._clock())
        check(remaining > 0)
        reply = self._transport(
            f"/v1/{m.mount}/{kind}/{'/'.join(m.path)}",
            token,
            min(self._timeout, remaining),
        )
        check(
            type(reply) is Response
            and type(reply.status) is int
            and reply.status == 200
        )
        check(type(reply.body) is bytes and 0 < len(reply.body) <= MAX_BODY)
        data = object_value(
            json.loads(
                reply.body.decode("utf-8"),
                object_pairs_hook=pairs,
                parse_constant=reject_constant,
            )
        )
        check(self._scope(grant) == m)
        return object_value(data.get("data"))

    def read(self, grant: Grant) -> object:
        result: Handle | None = None
        try:
            with self._lock:
                m = self._scope(grant)
                check(len(self._entries) < 128)
                data = self._request(grant, m, "data")
                metadata = object_value(data.get("metadata"))
                alive(metadata)
                v = version(metadata.get("version"))
                secret = object_value(data.get("data")).get(m.field_name)
                check(type(secret) is str and 0 < len(secret.encode()) <= 16384)
                result = Handle()
                self._entries[result] = _Entry(grant, m, v, cast(str, secret))
        except Exception:
            pass
        if result is None:
            raise Denied("vault access denied")
        return result

    def _current(self, handle: object, grant: Grant) -> _Entry:
        check(type(handle) is Handle)
        entry = self._entries[cast(Handle, handle)]
        check(self._scope(grant) == entry.mapping and grant == entry.grant)
        metadata = self._request(grant, entry.mapping, "metadata")
        check(version(metadata.get("current_version")) == entry.version)
        alive(
            object_value(object_value(metadata.get("versions")).get(str(entry.version)))
        )
        return entry

    def current(self, handle: object, grant: Grant) -> bool:
        try:
            with self._lock:
                self._current(handle, grant)
                return True
        except Exception:
            self.release(handle)
        return False

    def consume(
        self, handle: object, grant: Grant, sink: Callable[[str], bool]
    ) -> bool:
        success = False
        try:
            with self._lock:
                entry = self._current(handle, grant)
                del self._entries[
                    cast(Handle, handle)
                ]  # consume before possible effect
                check(self._scope(grant) == entry.mapping)
                success = sink(entry.secret) is True
        except Exception:
            pass
        finally:
            self.release(handle)
        return success

    def release(self, handle: object) -> None:
        if type(handle) is Handle:
            with self._lock:
                self._entries.pop(handle, None)

    def forget(self) -> None:
        with self._lock:
            self._entries.clear()

"""Real stdlib HTTP parsing over invented bytes, without sockets or providers."""

from __future__ import annotations

import contextlib
import http.client
import io
import json
import socket
import traceback
import unittest
from collections.abc import Iterator
from typing import cast
from unittest.mock import patch

import browser_runtime.openbao as openbao
from browser_runtime.credentials import (
    AdapterSet,
    Fence,
    Grant,
    Observation,
    Resolver,
    Target,
)
from browser_runtime.credentials import (
    Denied as ResolverDenied,
)
from browser_runtime.effects import Binding
from browser_runtime.openbao import HTTPS, MAX_BODY, Denied, Mapping, Response, Vault

CANARY = "SYNTHETIC_HTTP_SECRET_731_\N{SNOWMAN}"
TOKEN = "SYNTHETIC_HTTP_TOKEN_267"
DATA = json.dumps(
    {
        "data": {
            "data": {"password": CANARY},
            "metadata": {"version": 1, "deletion_time": "", "destroyed": False},
        }
    },
    ensure_ascii=False,
).encode("utf-8")
METADATA = json.dumps(
    {
        "data": {
            "current_version": 1,
            "versions": {"1": {"deletion_time": "", "destroyed": False}},
        }
    }
).encode()


def wire(body: bytes, *fields: bytes) -> bytes:
    return b"HTTP/1.1 200 OK\r\n" + b"\r\n".join((*fields, b"", body))


def sized(body: bytes, extra: int = 0) -> bytes:
    return wire(body, b"Content-Length: " + str(len(body) + extra).encode())


def chunked(body: bytes) -> bytes:
    return wire(
        f"{len(body):x}\r\n".encode() + body + b"\r\n0\r\n\r\n",
        b"Transfer-Encoding: chunked",
    )


class RecordedBytes(io.BytesIO):
    def __init__(self, data: bytes) -> None:
        super().__init__(data)
        self.read_sizes: list[int | None] = []
        self.bytes_read = 0

    def read(self, size: int | None = -1) -> bytes:
        self.read_sizes.append(size)
        result = super().read(size)
        self.bytes_read += len(result)
        return result


class ByteSocket:
    def __init__(self, data: bytes) -> None:
        self.stream = RecordedBytes(data)

    def makefile(self, mode: str) -> RecordedBytes:
        if mode != "rb":
            raise ValueError("unexpected mode")
        return self.stream


class LifecycleSocket(ByteSocket):
    def __init__(self, data: bytes) -> None:
        super().__init__(data)
        self.closed = False
        self.sent: list[bytes] = []

    def sendall(self, data: bytes) -> None:
        self.sent.append(data)

    def close(self) -> None:
        # A socket's makefile owns a separate lifetime; socket close must not
        # conceal a detached response file still held by an exception traceback.
        self.closed = True


class LifecycleConnection(http.client.HTTPConnection):
    def __init__(self, sock: LifecycleSocket) -> None:
        super().__init__("vault.invalid", 443, timeout=2)
        self.sock = cast(socket.socket, sock)
        self.responses: list[http.client.HTTPResponse] = []
        self.detached_before_return = False

    def getresponse(self) -> http.client.HTTPResponse:
        response = super().getresponse()
        self.responses.append(response)
        self.detached_before_return = self.sock is None
        return response


class Connection:
    response_class: type[http.client.HTTPResponse] = http.client.HTTPResponse

    def __init__(self, peer: Peer, data: bytes) -> None:
        self.peer = peer
        self.socket = ByteSocket(data)
        peer.streams.append(self.socket.stream)
        self.response: http.client.HTTPResponse | None = None

    def request(self, method: str, path: str, *, headers: dict[str, str]) -> None:
        self.peer.requests.append((method, path))
        if headers != {"X-Vault-Token": TOKEN, "Accept": "application/json"}:
            raise ValueError("unexpected request headers")

    def getresponse(self) -> http.client.HTTPResponse:
        self.response = self.response_class(cast(socket.socket, self.socket))
        self.peer.responses.append(self.response)
        self.response.begin()
        return self.response

    def close(self) -> None:
        self.peer.closed += 1
        if self.response is not None:
            self.response.close()


class Peer:
    def __init__(self, *responses: bytes) -> None:
        self.pending = list(responses)
        self.responses: list[http.client.HTTPResponse] = []
        self.streams: list[RecordedBytes] = []
        self.requests: list[tuple[str, str]] = []
        self.closed = 0

    def connection(self, *_args: object, **_kwargs: object) -> Connection:
        if not self.pending:
            raise AssertionError("unexpected HTTP retry")
        return Connection(self, self.pending.pop(0))

    @contextlib.contextmanager
    def installed(self) -> Iterator[None]:
        with patch(
            "browser_runtime.openbao.http.client.HTTPSConnection", self.connection
        ):
            yield


def scoped_vault() -> tuple[Vault, Grant]:
    grant = Grant(
        Target(
            Binding("p", "a", "b", "t", "i", 1, "o", 1, "https://example.invalid"),
            "n",
            "f",
            "https://example.invalid",
        ),
        "password",
        20.0,
    )
    mapping = Mapping(
        "p",
        "a",
        "https://example.invalid",
        "https://example.invalid",
        "password",
        "kv",
        ("accounts", "a"),
        "password",
    )
    return (
        Vault(
            (mapping,),
            transport=HTTPS("https://vault.invalid"),
            token=lambda: TOKEN,
            authorize=lambda candidate: candidate == grant,
            clock=lambda: 10.0,
        ),
        grant,
    )


def resolver(vault: Vault, grant: Grant, effects: list[str]) -> Resolver:
    # Synthetic authority/helper seams surround the actual resolver, HTTPS
    # request/parser, Vault lifecycle and handle-consumption implementations.
    class Authority:
        @contextlib.contextmanager
        def acquire(self) -> Iterator[Fence]:
            yield self

        def admit(self, _ticket: object) -> Grant:
            return grant

        def observe(self) -> Observation:
            return Observation(grant.target, 10.0)

        def current(self, candidate: Grant) -> bool:
            return candidate == grant

    class Helper:
        def inject(self, handle: object, candidate: Grant, fence: Fence) -> bool:
            def sink(_secret: str) -> bool:
                effects.append("injection")
                return True

            return fence.current(candidate) and vault.consume(handle, candidate, sink)

    return Resolver(
        AdapterSet("a" * 64, Authority(), vault, Helper()),
        expected_digest="a" * 64,
        clock=lambda: 10.0,
    )


class HTTPFramingTests(unittest.TestCase):
    def setUp(self) -> None:
        for name in (
            "socket.create_connection",
            "socket.socket.connect",
            "socket.socket.connect_ex",
        ):
            guard = patch(name, side_effect=AssertionError("network forbidden"))
            guard.start()
            self.addCleanup(guard.stop)

    def transport(self, data: bytes) -> tuple[Response, Peer]:
        peer = Peer(data)
        with peer.installed():
            response = HTTPS("https://vault.invalid")("/v1/kv/data/a", TOKEN, 2)
        self.assertEqual(peer.closed, 1)
        self.assertEqual(len(peer.requests), 1)
        self.assertTrue(peer.responses[0].closed)
        return response, peer

    def denied_read(self, data: bytes, *, before_body: bool = False) -> Peer:
        peer = Peer(data)
        vault, grant = scoped_vault()
        output = io.StringIO()
        with (
            peer.installed(),
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(output),
        ):
            try:
                vault.read(grant)
            except Denied as error:
                self.assertEqual(str(error), "vault access denied")
                self.assertIsNone(error.__context__)
                rendered = "".join(traceback.format_exception(error))
            else:
                self.fail("malformed response issued a handle")
        self.assertNotIn(CANARY, rendered + output.getvalue())
        self.assertNotIn(TOKEN, rendered + output.getvalue())
        self.assertEqual(len(vault._entries), 0)
        self.assertEqual((len(peer.requests), peer.closed), (1, 1))
        self.assertEqual(peer.pending, [])
        self.assertTrue(peer.responses[0].closed)
        if before_body:
            self.assertEqual(peer.streams[0].read_sizes, [])
        self.assertTrue(
            all(
                type(size) is int and 0 <= size <= MAX_BODY + 1
                for size in peer.streams[0].read_sizes
            )
        )
        return peer

    def test_fixed_length_counts_encoded_bytes(self) -> None:
        self.assertGreater(len(DATA), len(DATA.decode("utf-8")))
        response, peer = self.transport(sized(DATA))
        self.assertEqual(response.body, DATA)
        self.assertTrue(
            all(
                type(size) is int and 0 <= size <= MAX_BODY + 1
                for size in peer.streams[0].read_sizes
            )
        )
        vault, grant = scoped_vault()
        peer = Peer(sized(DATA), sized(METADATA))
        effects: list[str] = []

        def sink(_secret: str) -> bool:
            effects.append("injection")
            return True

        with peer.installed():
            handle = vault.read(grant)
            self.assertTrue(vault.consume(handle, grant, sink))
        self.assertEqual(effects, ["injection"])
        self.assertEqual(len(vault._entries), 0)
        self.assertEqual(peer.closed, 2)

    def test_complete_json_in_truncated_length_body_cannot_issue_handle(self) -> None:
        self.denied_read(sized(DATA, 1))
        self.denied_read(sized(DATA, 10))

    def test_invalid_duplicate_and_conflicting_framing_denies_before_read(self) -> None:
        length = str(len(DATA)).encode()
        fields = [
            (b"Content-Length: ",),
            (b"Content-Length: -1",),
            (b"Content-Length: +1",),
            (b"Content-Length: 1.0",),
            (b"Content-Length: \xb2",),
            (b"Content-Length: 65537",),
            (b"Content-Length: " + length + b", " + length,),
            (b"Content-Length: " + length, b"content-length: " + length),
            (b"Content-Length: " + length, b"Content-Length: 1"),
            (b"Transfer-Encoding: chunked", b"Content-Length: " + length),
            (b"Transfer-Encoding: chunked", b"Content-Length: 0"),
            (b"Transfer-Encoding: chunked", b"transfer-encoding: chunked"),
            (b"Transfer-Encoding: gzip",),
            (b"Transfer-Encoding: gzip, chunked",),
            (b"Transfer-Encoding: chunked, gzip",),
            (b"Transfer-Encoding: chunked ",),
            (b"Transfer-Encoding: ",),
        ]
        for headers in fields:
            with self.subTest(headers=headers):
                self.denied_read(wire(DATA, *headers), before_body=True)

    def test_header_parser_defects_cannot_hide_content_length(self) -> None:
        for invalid in (
            b"Bad Header",
            b"Content-Length : 999",
            b": 999",
            b" orphan continuation",
        ):
            with self.subTest(invalid=invalid):
                self.denied_read(
                    wire(DATA, invalid, b"Content-Length: 999"), before_body=True
                )

    def test_chunked_and_eof_framing_preserve_valid_bytes(self) -> None:
        split = len(DATA) // 2
        chunks = b"".join(
            f"{len(part):x}\r\n".encode() + part + b"\r\n"
            for part in (DATA[:split], DATA[split:])
        )
        for data in (
            chunked(DATA),
            wire(
                chunks + b"0\r\nX-Synthetic-Trailer: yes\r\n\r\n",
                b"Transfer-Encoding: ChUnKeD",
            ),
            wire(DATA),
        ):
            with self.subTest(data=data[:60]):
                response, peer = self.transport(data)
                self.assertEqual(response.body, DATA)
                self.assertTrue(
                    all(
                        type(size) is int and 0 <= size <= MAX_BODY + 1
                        for size in peer.streams[0].read_sizes
                    )
                )

    def test_zero_content_length_is_not_eof_delimited(self) -> None:
        response, _ = self.transport(wire(DATA, b"Content-Length: 0"))
        self.assertEqual(response.body, b"")
        self.denied_read(wire(DATA, b"Content-Length: 0"))

    def test_body_cap_applies_to_all_framing_modes_with_bounded_read(self) -> None:
        for encode in (sized, chunked, wire):
            with self.subTest(framing=encode.__name__):
                response, peer = self.transport(encode(b"x" * MAX_BODY))
                self.assertEqual(len(response.body), MAX_BODY)
                self.assertTrue(
                    all(
                        type(size) is int and 0 <= size <= MAX_BODY + 1
                        for size in peer.streams[0].read_sizes
                    )
                )
                self.denied_read(
                    encode(b"x" * (MAX_BODY + 1)), before_body=encode is sized
                )

    def test_invalid_and_truncated_chunks_close_and_sanitize(self) -> None:
        for chunks in (
            b"not-hex\r\n" + DATA,
            f"{len(DATA) + 10:x}\r\n".encode() + DATA,
            f"{len(DATA):x}\r\n".encode() + DATA + b"\r\n",
        ):
            with self.subTest(chunks=chunks[:20]):
                self.denied_read(wire(chunks, b"Transfer-Encoding: chunked"))

    def test_negative_chunk_size_denies_before_underlying_body_read(self) -> None:
        for size in (b"-1", b"-01", b"-0x1", b"-1;synthetic=yes"):
            with self.subTest(size=size):
                peer = self.denied_read(
                    wire(size + b"\r\n" + b"x" * 70000, b"Transfer-Encoding: chunked"),
                    before_body=True,
                )
                self.assertEqual(peer.streams[0].bytes_read, 0)

    def test_private_read_guard_rejects_unbounded_or_oversized_requests(self) -> None:
        for size in (-1, MAX_BODY + 2, True):
            with self.subTest(size=size):
                sock = ByteSocket(sized(b"x" * 70000))
                response = openbao._BoundedHTTPResponse(cast(socket.socket, sock))
                try:
                    response.begin()
                    with self.assertRaises(ValueError):
                        response._safe_read(size)
                    self.assertEqual(sock.stream.read_sizes, [])
                    self.assertEqual(sock.stream.bytes_read, 0)
                finally:
                    response.close()

    def test_many_chunks_keep_cumulative_payload_read_bounded(self) -> None:
        # 64 complete chunks exhaust the allowed body. The parser may read only
        # one additional payload byte, never the rest of the oversized tail.
        prefix = (b"400\r\n" + b"x" * 1024 + b"\r\n") * 64
        tail = b"11170\r\n" + b"y" * 70000 + b"\r\n0\r\n\r\n"
        peer = self.denied_read(wire(prefix + tail, b"Transfer-Encoding: chunked"))
        self.assertEqual(peer.streams[0].bytes_read, MAX_BODY + 1 + 64 * 2)

    def test_deliberate_private_read_bypass_exposes_unbounded_buffer_read(self) -> None:
        peer = Peer(wire(b"-1\r\n" + b"x" * 70000, b"Transfer-Encoding: chunked"))
        vault, grant = scoped_vault()
        with (
            peer.installed(),
            patch.object(
                openbao._BoundedHTTPResponse,
                "_safe_read",
                vars(http.client.HTTPResponse)["_safe_read"],
            ),
            self.assertRaises(Denied),
        ):
            vault.read(grant)
        self.assertIn(-1, peer.streams[0].read_sizes)
        self.assertEqual(peer.streams[0].bytes_read, 70000)
        with self.assertRaises(AssertionError):
            self.assertLessEqual(peer.streams[0].bytes_read, MAX_BODY + 1)
        self.assertEqual(len(vault._entries), 0)
        self.assertEqual(peer.closed, 1)

    def test_parser_failure_closes_without_retry_or_raw_error(self) -> None:
        self.denied_read(b"SYNTHETIC_BAD_STATUS\r\n\r\n" + DATA, before_body=True)

    def test_real_getresponse_detached_response_closes_on_rejection(self) -> None:
        for data, fields in (
            (DATA, (b"Content-Length: 999", b"Connection: close")),
            (DATA, (b"Content-Length: 65537", b"Connection: close")),
            (DATA, (b"Bad Header", b"Content-Length: 999")),
            (DATA, (b"Transfer-Encoding: gzip",)),
            (
                b"-1\r\n" + b"x" * 70000,
                (b"Transfer-Encoding: chunked", b"Connection: close"),
            ),
            (b"x" * 70000, ()),
        ):
            with self.subTest(fields=fields):
                sock = LifecycleSocket(wire(data, *fields))
                connection = LifecycleConnection(sock)
                with patch(
                    "browser_runtime.openbao.http.client.HTTPSConnection",
                    return_value=connection,
                ) as factory:
                    try:
                        HTTPS("https://vault.invalid")("/v1/kv/data/a", TOKEN, 2)
                    except ValueError:
                        # The live traceback retains reply during these checks.
                        self.assertTrue(sock.closed)
                        self.assertTrue(sock.stream.closed)
                        self.assertTrue(connection.responses[0].closed)
                    else:
                        self.fail("malformed response was accepted")
                factory.assert_called_once()
                self.assertEqual(len(sock.sent), 1)
                self.assertTrue(connection.detached_before_return)

    def test_real_getresponse_preserves_valid_close_delimited_lifecycle(self) -> None:
        sock = LifecycleSocket(wire(DATA))
        connection = LifecycleConnection(sock)
        with patch(
            "browser_runtime.openbao.http.client.HTTPSConnection",
            return_value=connection,
        ) as factory:
            response = HTTPS("https://vault.invalid")("/v1/kv/data/a", TOKEN, 2)
        self.assertEqual(response.body, DATA)
        factory.assert_called_once()
        self.assertEqual(len(sock.sent), 1)
        self.assertTrue(connection.detached_before_return)
        self.assertTrue(sock.closed)
        self.assertTrue(sock.stream.closed)
        self.assertTrue(connection.responses[0].closed)

    def test_cleanup_failure_denies_without_secret_error_or_handle(self) -> None:
        response_close = http.client.HTTPResponse.close
        connection_close = Connection.close

        def bad_response_close(response: http.client.HTTPResponse) -> None:
            response_close(response)
            raise RuntimeError(CANARY)

        def bad_connection_close(connection: Connection) -> None:
            connection_close(connection)
            raise RuntimeError(TOKEN)

        for target, replacement in (
            (openbao._BoundedHTTPResponse, bad_response_close),
            (Connection, bad_connection_close),
        ):
            with (
                self.subTest(target=target.__name__),
                patch.object(target, "close", replacement),
            ):
                peer = self.denied_read(sized(DATA))
                self.assertEqual(peer.closed, 1)

    def test_cleanup_errors_do_not_mask_primary_framing_failure(self) -> None:
        response_close = http.client.HTTPResponse.close
        connection_close = Connection.close

        def bad_response_close(response: http.client.HTTPResponse) -> None:
            response_close(response)
            raise RuntimeError(CANARY)

        def bad_connection_close(connection: Connection) -> None:
            connection_close(connection)
            raise RuntimeError(TOKEN)

        peer = Peer(sized(DATA, 10))
        with (
            peer.installed(),
            patch.object(openbao._BoundedHTTPResponse, "close", bad_response_close),
            patch.object(Connection, "close", bad_connection_close),
            self.assertRaises(ValueError) as caught,
        ):
            HTTPS("https://vault.invalid")("/v1/kv/data/a", TOKEN, 2)
        self.assertEqual(caught.exception.args, ())
        self.assertIsNone(caught.exception.__context__)
        self.assertEqual(peer.closed, 1)
        self.assertTrue(peer.responses[0].closed)

    def test_resolver_denies_truncation_at_each_vault_step(self) -> None:
        for index in range(3):
            with self.subTest(step=index):
                bodies = (DATA, METADATA, METADATA)
                replies = [
                    sized(body, 10 if n == index else 0)
                    for n, body in enumerate(bodies[: index + 1])
                ]
                peer = Peer(*replies)
                vault, grant = scoped_vault()
                effects: list[str] = []
                with peer.installed(), self.assertRaises(ResolverDenied) as caught:
                    resolver(vault, grant, effects).resolve_and_inject(object())
                self.assertEqual(str(caught.exception), "credential resolution denied")
                self.assertIsNone(caught.exception.__context__)
                self.assertEqual(effects, [])
                self.assertEqual(len(vault._entries), 0)
                self.assertEqual(
                    (len(peer.requests), peer.closed), (index + 1, index + 1)
                )
                self.assertEqual(peer.pending, [])

    def test_deliberate_framing_bypass_breaks_independent_zero_effect_oracle(
        self,
    ) -> None:
        # All fields, scope and body syntax are valid except the claimed lengths.
        # Removing failed transport guards is a deliberate mutation, not a mode
        # callers can configure in the production adapter.
        rejected: list[bool] = []

        def bypass(ok: bool) -> None:
            if not ok:
                rejected.append(ok)

        peer = Peer(sized(DATA, 10), sized(METADATA, 10), sized(METADATA, 10))
        vault, grant = scoped_vault()
        effects: list[str] = []
        with peer.installed(), patch.object(openbao, "check", bypass):
            self.assertEqual(
                resolver(vault, grant, effects).resolve_and_inject(object()), "injected"
            )
        self.assertEqual(rejected, [False, False, False])
        self.assertEqual(effects, ["injection"])
        with self.assertRaises(AssertionError):
            self.assertEqual(effects, [])
        self.assertEqual(len(vault._entries), 0)
        self.assertEqual(peer.closed, 3)


if __name__ == "__main__":
    unittest.main()

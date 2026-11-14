from __future__ import annotations

import json
import unittest
from dataclasses import replace
from typing import Any, Iterator, cast
from unittest.mock import patch

from browser_runtime.credentials import Fence, Grant, Target
from browser_runtime.effects import Binding
from browser_runtime.openbao import HTTPS, Denied, Handle, Mapping, Response, Vault

CANARY = "SYNTHETIC_SECRET_927"
TOKEN = "SYNTHETIC_TOKEN_891"


def record(seen: list[str], value: str) -> bool:
    seen.append(value)
    return True


def grant() -> Grant:
    return Grant(
        Target(
            Binding("p", "a", "b", "t", "i", 1, "o", 1, "https://example.invalid"),
            "n",
            "f",
            "https://example.invalid",
        ),
        "password",
        20.0,
    )


class Fixture:
    def __init__(self) -> None:
        self.g = grant()
        self.now = 10.0
        self.allowed = True
        self.calls: list[tuple[str, float]] = []
        self.tokens = 0
        self.current = 1
        self.deleted = ""
        self.destroyed = False
        self.response: Response | Exception | None = None
        self.m = Mapping(
            "p",
            "a",
            "https://example.invalid",
            "https://example.invalid",
            "password",
            "kv",
            ("accounts", "a"),
            "password",
        )
        self.v = Vault(
            (self.m,),
            transport=self.transport,
            token=self.token,
            authorize=lambda g: self.allowed and g == self.g,
            clock=lambda: self.now,
        )

    def token(self) -> str:
        self.tokens += 1
        return TOKEN

    def transport(self, path: str, token: str, timeout: float) -> Response:
        self.calls.append((path, timeout))
        if self.response is not None:
            if isinstance(self.response, Exception):
                raise self.response
            return self.response
        if "/data/" in path:
            data: dict[str, Any] = {
                "data": {"password": CANARY},
                "metadata": {
                    "version": 1,
                    "deletion_time": self.deleted,
                    "destroyed": self.destroyed,
                },
            }
        else:
            data = {
                "current_version": self.current,
                "versions": {
                    "1": {"deletion_time": self.deleted, "destroyed": self.destroyed}
                },
            }
        return Response(200, json.dumps({"data": data}).encode())


class OpenBaoTests(unittest.TestCase):
    def test_protocol_and_one_shot_handle(self) -> None:
        f = Fixture()
        h = f.v.read(f.g)
        self.assertEqual(type(h), Handle)
        self.assertNotIn(CANARY, repr(h))
        self.assertTrue(f.v.current(h, f.g))
        seen: list[str] = []
        self.assertTrue(f.v.consume(h, f.g, lambda secret: record(seen, secret)))
        self.assertEqual(seen, [CANARY])
        self.assertFalse(f.v.consume(h, f.g, lambda _: self.fail("reused")))
        self.assertEqual(
            [c[0] for c in f.calls],
            [
                "/v1/kv/data/accounts/a",
                "/v1/kv/metadata/accounts/a",
                "/v1/kv/metadata/accounts/a",
            ],
        )
        self.assertTrue(all(c[1] == 2 for c in f.calls))

    def test_default_and_wrong_scope_deny_before_token_or_http(self) -> None:
        f = Fixture()
        f.v._authorize = None
        with self.assertRaises(Denied):
            f.v.read(f.g)
        for field, value in [
            ("account", "wrong"),
            ("principal", "wrong"),
            ("origin", "https://wrong.invalid"),
            ("epoch", True),
        ]:
            f = Fixture()
            g = replace(
                f.g,
                target=replace(
                    f.g.target,
                    binding=replace(
                        f.g.target.binding, **cast(dict[str, Any], {field: value})
                    ),
                ),
            )
            with self.assertRaises(Denied):
                f.v.read(g)
            self.assertEqual((f.tokens, f.calls), (0, []))
        f = Fixture()
        f.allowed = False
        with self.assertRaises(Denied):
            f.v.read(f.g)
        self.assertEqual((f.tokens, f.calls), (0, []))

    def test_bad_bodies_fixed_error_without_canary_context(self) -> None:
        replies: list[Response | Exception] = [
            Response(302, CANARY.encode()),
            Response(403, CANARY.encode()),
            Response(200, b"x" * 65537),
            Response(200, b"{"),
            Response(200, b'{"data":{},"data":{}}'),
            Response(True, b"{}"),
            TimeoutError(CANARY),
            Response(
                200,
                b'{"data":{"metadata":{"version":true,"destroyed":false,"deletion_time":""},"data":{"password":"x"}}}',
            ),
        ]
        for reply in replies:
            f = Fixture()
            f.response = reply
            with self.assertRaises(Denied) as caught:
                f.v.read(f.g)
            self.assertEqual(str(caught.exception), "vault access denied")
            self.assertIsNone(caught.exception.__context__)
            self.assertNotIn(CANARY, repr(caught.exception))
            self.assertNotIn(TOKEN, repr(caught.exception))
            self.assertEqual(len(f.calls), 1)
            self.assertEqual(len(f.v._entries), 0)

    def test_nonfinite_json_constants_even_in_ignored_fields_deny(self) -> None:
        for constant in ("NaN", "Infinity", "-Infinity"):
            for prefix in ('"ignored":', '"ignored":{"nested":'):
                f = Fixture()
                valid = f.transport("/v1/kv/data/a", TOKEN, 1).body
                f.calls.clear()
                suffix = b"}" if "nested" in prefix else b""
                f.response = Response(
                    200,
                    valid[:-1]
                    + b","
                    + prefix.encode()
                    + constant.encode()
                    + suffix
                    + b"}",
                )
                with self.assertRaises(Denied):
                    f.v.read(f.g)
                self.assertEqual(len(f.calls), 1)
                self.assertEqual(len(f.v._entries), 0)

    def test_rotation_deletion_destruction_expiry_and_forget(self) -> None:
        for field, value in [
            ("current", 2),
            ("deleted", "2026-01-01T00:00:00Z"),
            ("destroyed", True),
            ("now", 20.0),
            ("allowed", False),
        ]:
            f = Fixture()
            h = f.v.read(f.g)
            setattr(f, field, value)
            self.assertFalse(f.v.current(h, f.g))
            self.assertFalse(f.v.consume(h, f.g, lambda _: self.fail("injected")))
            self.assertEqual(len(f.v._entries), 0)
        f = Fixture()
        h = f.v.read(f.g)
        f.v.forget()
        self.assertFalse(f.v.current(h, f.g))
        f.v.release(h)
        self.assertFalse(f.v.current(Handle(), f.g))

    def test_callback_revocation_and_deadline_before_http_after_response(self) -> None:
        f = Fixture()

        def token() -> str:
            f.allowed = False
            return TOKEN

        f.v._token = token
        with self.assertRaises(Denied):
            f.v.read(f.g)
        self.assertEqual(f.calls, [])
        f = Fixture()
        transport = f.transport

        def late(path: str, token: str, timeout: float) -> Response:
            reply = transport(path, token, timeout)
            f.now = 21
            return reply

        f.v._transport = late
        with self.assertRaises(Denied):
            f.v.read(f.g)
        self.assertEqual(len(f.v._entries), 0)

    def test_unknown_use_error_consumes_and_sanitizes(self) -> None:
        f = Fixture()
        h = f.v.read(f.g)
        seen: list[str] = []

        def sink(secret: str) -> bool:
            seen.append(secret)
            raise RuntimeError(CANARY)

        self.assertFalse(f.v.consume(h, f.g, sink))
        self.assertFalse(f.v.consume(h, f.g, sink))
        self.assertEqual(seen, [CANARY])
        self.assertEqual(len(f.v._entries), 0)

    def test_https_adapter_real_request_code_with_fake_connection(self) -> None:
        class Reply:
            status = 200

            def getheader(self, key: str, default: str | None = None) -> str | None:
                return default

            def read(self, size: int) -> bytes:
                self.limit = size
                return b"{}"

        reply = Reply()
        calls: list[Any] = []

        class Connection:
            def __init__(self, *args: Any, **kw: Any) -> None:
                calls.append(("connection", args, kw))

            def request(self, *args: Any, **kw: Any) -> None:
                calls.append(("request", args, kw))

            def getresponse(self) -> Reply:
                return reply

            def close(self) -> None:
                calls.append(("closed",))

        with patch("browser_runtime.openbao.http.client.HTTPSConnection", Connection):
            transport = HTTPS("https://bao.example.invalid:8443")
            self.assertEqual(transport("/v1/kv/data/a", TOKEN, 1).body, b"{}")
            self.assertEqual(calls[0][1], ("bao.example.invalid", 8443))
            self.assertTrue(calls[0][2]["context"].check_hostname)
            self.assertEqual(calls[1][1], ("GET", "/v1/kv/data/a"))
            self.assertEqual(reply.limit, 65537)
            reply.status = 307
            with self.assertRaises(ValueError):
                transport("/v1/kv/data/a", TOKEN, 1)
            self.assertEqual(calls[-1], ("closed",))
        for url in [
            "https://bao.invalid:0",
            "https://bao.invalid:65536",
            "https://bao.invalid:notaport",
            "http://bao.invalid",
            "https://user:password@bao.invalid",
            "https://bao.invalid/path",
            "https://bao.invalid?x=y",
        ]:
            with patch(
                "browser_runtime.openbao.http.client.HTTPSConnection"
            ) as connection:
                with self.assertRaises(ValueError):
                    HTTPS(url)
                connection.assert_not_called()

    def test_real_resolver_composition_with_synthetic_fence_and_helper(self) -> None:
        import contextlib
        import io
        import traceback

        from browser_runtime.credentials import AdapterSet, Observation, Resolver

        f = Fixture()
        ticket = object()
        seen: list[str] = []

        class Authority:
            @contextlib.contextmanager
            def acquire(self) -> Iterator[Fence]:
                yield self

            def admit(self, candidate: object) -> Grant | None:
                return f.g if candidate is ticket else None

            def observe(self) -> Observation:
                return Observation(f.g.target, f.now)

            def current(self, g: Grant) -> bool:
                return f.allowed and g == f.g

        class Helper:
            def inject(self, handle: object, g: Grant, fence: Fence) -> bool:
                if fence.current(g) is not True:
                    return False
                return f.v.consume(handle, g, lambda value: record(seen, value))

        adapters = AdapterSet("a" * 64, Authority(), f.v, Helper())
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            result = Resolver(
                adapters, expected_digest="a" * 64, clock=lambda: f.now
            ).resolve_and_inject(ticket)
        self.assertEqual(result, "injected")
        self.assertEqual(seen, [CANARY])
        self.assertEqual(len(f.v._entries), 0)
        self.assertNotIn(CANARY, output.getvalue() + result + repr(adapters))
        f.response = RuntimeError(CANARY + TOKEN)
        try:
            Resolver(
                adapters, expected_digest="a" * 64, clock=lambda: f.now
            ).resolve_and_inject(ticket)
        except Exception:
            envelope = traceback.format_exc() + output.getvalue()
        else:
            self.fail("provider failure accepted")
        self.assertNotIn(CANARY, envelope)
        self.assertNotIn(TOKEN, envelope)
        self.assertEqual(seen, [CANARY])

    def test_deliberate_authority_guard_mutation_exposes_forbidden_http(self) -> None:
        f = Fixture()
        f.allowed = False
        with self.assertRaises(Denied):
            f.v.read(f.g)
        self.assertEqual(f.calls, [])
        # Mutation bypasses actual grant verification, independent call spy catches it.
        setattr(f.v, "_scope", lambda _: f.m)
        f.v.read(f.g)
        with self.assertRaises(AssertionError):
            self.assertEqual(f.calls, [])


if __name__ == "__main__":
    unittest.main()

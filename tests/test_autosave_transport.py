"""Actual transport method with a scripted connection, no sockets/TLS claim."""

import json
import unittest
from collections.abc import Mapping
from email.message import Message
from unittest.mock import patch

from browser_runtime.openbao import HTTPS, MAX_BODY


class Peer:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, bytes | None, Mapping[str, str] | None]] = []
        self.closed = 0
        self.status = 200
        self.body = b'{"data":{"version":1}}'
        self.headers = Message()
        self.headers["Content-Length"] = str(len(self.body))

    def request(
        self,
        method: str,
        path: str,
        body: bytes | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        self.calls.append((method, path, body, headers))

    def getresponse(self) -> "Peer":
        return self

    def getheader(self, key: str, default: str | None = None) -> str | None:
        return self.headers.get(key, default)

    def read(self, limit: int) -> bytes:
        return self.body[:limit]

    def close(self) -> None:
        self.closed += 1


class TransportTests(unittest.TestCase):
    def test_post_is_bounded_json_and_does_not_retry(self) -> None:
        peer = Peer()
        body = json.dumps(
            {"options": {"cas": 0}, "data": {"password": "synthetic"}}
        ).encode()
        with patch("http.client.HTTPSConnection", return_value=peer):
            reply = HTTPS("https://vault.invalid").request(
                "POST", "/v1/kv/data/a", "synthetic-token", 1, body
            )
        self.assertEqual(reply.status, 200)
        self.assertEqual(len(peer.calls), 1)
        self.assertEqual(peer.calls[0][:3], ("POST", "/v1/kv/data/a", body))
        headers = peer.calls[0][3]
        if headers is None:
            self.fail("request headers missing")
        self.assertEqual(headers["Content-Type"], "application/json")
        self.assertEqual(peer.closed, 2)

    def test_invalid_method_and_oversized_body_open_no_connection(self) -> None:
        with patch("http.client.HTTPSConnection") as connection:
            for method, body in [
                ("DELETE", None),
                ("POST", b"x" * (MAX_BODY + 1)),
                ("POST", None),
                ("GET", b"unexpected"),
            ]:
                with self.assertRaises(ValueError):
                    HTTPS("https://vault.invalid").request(
                        method, "/v1/kv/data/a", "token", 1, body
                    )
            connection.assert_not_called()

    def test_redirect_denied_and_closed_without_retry(self) -> None:
        peer = Peer()
        peer.status = 302
        with patch("http.client.HTTPSConnection", return_value=peer):
            with self.assertRaises(ValueError):
                HTTPS("https://vault.invalid").request(
                    "POST", "/v1/kv/data/a", "token", 1, b"{}"
                )
        self.assertEqual((len(peer.calls), peer.closed), (1, 2))

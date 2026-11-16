"""Synthetic WebSocket peers prove bounded visual-driver transport behavior."""

import base64
import hashlib
import json
import socket
import threading
import time
import unittest
from collections.abc import Callable
from unittest.mock import patch

from tools import browser_cdp

URL = "ws://127.0.0.1:9222/devtools/page/synthetic"


def handshake(peer: socket.socket) -> None:
    request = b""
    while b"\r\n\r\n" not in request:
        request += peer.recv(4096)
    key = next(
        line.split(b": ", 1)[1]
        for line in request.split(b"\r\n")
        if line.startswith(b"Sec-WebSocket-Key: ")
    )
    accept = base64.b64encode(
        hashlib.sha1(key + b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest()
    )
    peer.sendall(
        b"HTTP/1.1 101 Switching Protocols\r\nSec-WebSocket-Accept: "
        + accept
        + b"\r\n\r\n"
    )


def frame(value: dict[str, object]) -> bytes:
    payload = json.dumps(value).encode()
    if len(payload) >= 126:
        raise ValueError("test event too large")
    return bytes([0x81, len(payload)]) + payload


class BrowserDevToolsBoundsTest(unittest.TestCase):
    def run_peer(
        self,
        serve: Callable[[socket.socket], None],
        check: Callable[[socket.socket], None],
    ) -> None:
        client, server = socket.socketpair()

        def worker() -> None:
            try:
                serve(server)
            except OSError:
                pass  # The client closes at its deadline.
            finally:
                server.close()

        thread = threading.Thread(target=worker, daemon=True)
        thread.start()
        try:
            with (
                patch(
                    "tools.browser_cdp.socket.create_connection", return_value=client
                ),
                patch.object(browser_cdp, "OPERATION_TIMEOUT", 0.2),
            ):
                start = time.monotonic()
                check(client)
                self.assertLess(time.monotonic() - start, 1.0)
        finally:
            client.close()
            thread.join(timeout=1)
            self.assertFalse(thread.is_alive())

    def test_eof_during_handshake_closes_socket(self) -> None:
        def serve(peer: socket.socket) -> None:
            peer.recv(4096)

        def check(client: socket.socket) -> None:
            with self.assertRaisesRegex(RuntimeError, "handshake closed"):
                browser_cdp.DevTools(URL)
            self.assertEqual(client.fileno(), -1)

        self.run_peer(serve, check)

    def test_trickled_incomplete_handshake_has_whole_deadline(self) -> None:
        def serve(peer: socket.socket) -> None:
            for _ in range(50):
                peer.sendall(b"x")
                time.sleep(0.02)

        def check(client: socket.socket) -> None:
            with self.assertRaises(TimeoutError):
                browser_cdp.DevTools(URL)
            self.assertEqual(client.fileno(), -1)

        self.run_peer(serve, check)

    def test_unrelated_events_cannot_extend_command(self) -> None:
        def serve(peer: socket.socket) -> None:
            handshake(peer)
            for _ in range(50):
                peer.sendall(frame({"method": "Runtime.consoleAPICalled"}))
                time.sleep(0.01)

        def check(_client: socket.socket) -> None:
            client = browser_cdp.DevTools(URL)
            try:
                with self.assertRaises(TimeoutError):
                    client.call("Page.enable")
            finally:
                client.close()

        self.run_peer(serve, check)

    def test_unrelated_events_cannot_extend_page_load(self) -> None:
        def serve(peer: socket.socket) -> None:
            handshake(peer)
            for _ in range(50):
                peer.sendall(frame({"method": "Runtime.consoleAPICalled"}))
                time.sleep(0.01)

        def check(_client: socket.socket) -> None:
            client = browser_cdp.DevTools(URL)
            try:
                with self.assertRaises(TimeoutError):
                    client.wait_loaded()
            finally:
                client.close()

        self.run_peer(serve, check)

    def test_matching_reply_and_load_event_succeed(self) -> None:
        def serve(peer: socket.socket) -> None:
            handshake(peer)
            peer.recv(4096)
            peer.sendall(frame({"id": 1, "result": {"ok": True}}))
            peer.sendall(frame({"method": "Page.loadEventFired"}))
            peer.recv(4096)

        def check(_client: socket.socket) -> None:
            client = browser_cdp.DevTools(URL)
            try:
                self.assertEqual(client.call("Page.enable"), {"ok": True})
                client.wait_loaded()
                self.assertTrue(client.loaded)
            finally:
                client.close()

        self.run_peer(serve, check)


if __name__ == "__main__":
    unittest.main()

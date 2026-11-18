"""Disposable loopback-only synthetic website. Never a production Site adapter.

The HTTPS logical origin is invented; trusted tests map it to plaintext loopback
HTTP. This does not authenticate TLS, browser frames, accounts or live authority.
"""

import base64
import hashlib
import http.client
import json
import socket
import threading
from dataclasses import asdict, replace
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

from browser_runtime.effects import Binding, Readback
from browser_testing.effect_site import Site

LIMIT = 16384
TIMEOUT = 1.0


def encode(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")


class LocalSite:
    """One ephemeral test context, independent ledger and request counters."""

    def __init__(self, path: Path, *, submission="none", readback="none"):
        if submission not in ("none", "lost", "reject", "drop"):
            raise ValueError("unsupported synthetic submission")
        if readback not in ("none", "wrong-account"):
            raise ValueError("unsupported synthetic readback")
        self.ledger = Site(path, submission if submission != "drop" else "none")
        self.submission, self.readback = submission, readback
        self.submissions = self.readbacks = 0
        self.request_started = threading.Event()
        self._stopping = threading.Event()
        self._socket_lock = threading.Lock()
        self._active_socket = None
        self._server = self._thread = None

    def __enter__(self):
        owner = self

        class Server(HTTPServer):
            def get_request(self):
                stream, address = super().get_request()
                with owner._socket_lock:
                    if owner._stopping.is_set():
                        stream.close()
                        raise OSError("synthetic site stopping")
                    owner._active_socket = stream
                return stream, address

            def shutdown_request(self, request):
                try:
                    super().shutdown_request(request)
                finally:
                    with owner._socket_lock:
                        if owner._active_socket is request:
                            owner._active_socket = None

            def handle_error(self, request, address):
                if not owner._stopping.is_set():
                    super().handle_error(request, address)

        class Handler(BaseHTTPRequestHandler):
            def setup(self):
                self.request.settimeout(TIMEOUT)
                super().setup()

            def log_message(self, *args):
                pass  # No request bodies or headers in logs.

            def do_GET(self) -> None:
                if owner._stopping.is_set() or self.path != "/browser-fixture":
                    self.send_error(404)
                    return
                body = b'<!doctype html><meta charset="utf-8"><title>Owned synthetic effect fixture</title><body data-runspindle-fixture="v1">Synthetic effect fixture</body>'
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.send_header(
                    "Content-Security-Policy",
                    "default-src 'none'; connect-src 'self'; frame-ancestors 'none'",
                )
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self):
                try:
                    if owner._stopping.is_set():
                        self.close_connection = True
                        return
                    if self.path not in ("/submit", "/readback"):
                        self.send_error(404)
                        return
                    if self.headers.get("Transfer-Encoding") is not None:
                        raise ValueError
                    lengths = self.headers.get_all("Content-Length", [])
                    if len(lengths) != 1 or not lengths[0].isdigit():
                        raise ValueError
                    length = int(lengths[0])
                    if not 0 < length <= LIMIT:
                        raise ValueError
                    owner.request_started.set()
                    raw = self.rfile.read(length)
                    if len(raw) != length:
                        raise ValueError
                    value = json.loads(raw)
                    if encode(value) != raw or set(value) != {"binding", "data"}:
                        raise ValueError
                    binding = Binding(**value["binding"])
                    binding.encoded()
                    if self.path == "/submit":
                        payload = base64.b64decode(value["data"], validate=True)
                        if not 0 < len(payload) <= 4096:
                            raise ValueError
                        owner.submissions += 1
                        if owner.submission != "drop":
                            owner.ledger.submit(binding, payload)
                        result = {"ack": "transport-only"}
                    else:
                        digest = value["data"]
                        if not isinstance(digest, str) or len(digest) != 64:
                            raise ValueError
                        bytes.fromhex(digest)
                        owner.readbacks += 1
                        observed = owner.ledger.observe(binding, digest)
                        if owner.readback == "wrong-account":
                            observed = replace(
                                observed, binding=replace(binding, account="other")
                            )
                        result = asdict(observed)
                    body = encode(result)
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                except OSError:
                    # Lost response is injected only after Site commits its effect.
                    self.close_connection = True
                except (ValueError, TypeError, KeyError):
                    self.send_error(400)

        self._server = Server(("127.0.0.1", 0), Handler)
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(
            target=lambda: self._server.serve_forever(poll_interval=0.02),
            name="synthetic-loopback-site",
            daemon=True,
        )
        try:
            self._thread.start()
        except BaseException:
            self._server.server_close()
            raise
        return self

    def __exit__(self, *args):
        # Socket timeouts alone are per-read, so a dribbling client could keep a
        # handler busy. Stop new work and interrupt this fixture's owned socket.
        with self._socket_lock:
            self._stopping.set()
            active = self._active_socket
            if active is not None:
                try:
                    active.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass  # Already closed by its handler.
        try:
            self._server.shutdown()
        finally:
            self._server.server_close()
            self._thread.join(TIMEOUT + 1)
        if self._thread.is_alive():
            raise RuntimeError("synthetic site failed to stop")


class HTTPAdapter:
    """Fixed loopback transport selected only by the trusted synthetic fixture.

    No host, URL, redirect, proxy or fallback comes from a Grant or page data.
    """

    def __init__(self, port: int):
        if type(port) is not int or not 0 < port < 65536:
            raise ValueError("invalid synthetic port")
        self.port = port

    def _request(self, route: str, grant: Any, guard: Any, data: str) -> Any:
        observed = guard.observe()
        if (
            observed is None
            or observed.target != grant.target
            or guard.current(grant) is not True
        ):
            raise ValueError("synthetic guard unavailable")
        body = encode({"binding": asdict(grant.target.binding), "data": data})
        if len(body) > LIMIT:
            raise ValueError("synthetic request too large")
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=TIMEOUT)
        try:
            connection.request(
                "POST", route, body, {"Content-Type": "application/json"}
            )
            response = connection.getresponse()
            raw = response.read(LIMIT + 1)
            if response.status != 200 or not 0 < len(raw) <= LIMIT:
                raise ValueError("synthetic HTTP failure")
            value = json.loads(raw)
            if encode(value) != raw:
                raise ValueError("noncanonical synthetic response")
            return value
        finally:
            connection.close()

    def submit(self, grant, payload, guard):
        if (
            len(payload) > 4096
            or hashlib.sha256(payload).hexdigest() != grant.payload_digest
        ):
            raise ValueError("synthetic payload mismatch")
        return self._request(
            "/submit", grant, guard, base64.b64encode(payload).decode("ascii")
        )

    def readback(self, grant, guard):
        value = self._request("/readback", grant, guard, grant.payload_digest)
        if set(value) != {"binding", "payload_digest", "outcome", "evidence_digest"}:
            raise ValueError("invalid synthetic readback")
        value["binding"] = Binding(**value["binding"])
        return Readback(**value)

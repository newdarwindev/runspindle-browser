"""Disposable upstream fixtures, not Browser production services or storage.

Only the explicit isolated E2E worker starts these objects. No host trust/config
changes: TLS trust, native profile, NSS database and OpenBao HOME are temporary.
"""

from __future__ import annotations

import hashlib
import http.server
import json
import os
import secrets
import shutil
import signal
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import urllib.parse
import urllib.request
from pathlib import Path

from browser_runtime.openbao import HTTPS
from tools.browser_cdp import DevTools

BAO_SHA256 = "9c5f36287c673f386e1533e9c044169a248e4ee50dd54810fa766e95bd41b788"
CHROMIUM_PINS = {
    "32a85cb0cf284adc64c04c4059a9416750b0143488f3d623f0efad81a4aee9e1": "156.0.8078.47",
    "ce1ff960ce428a4a88b1b1c38516bdf1954a57fc24036161b7a0d8d0f8aec511": "156.0.8078.79",
}
TOKEN = "synthetic-account-e2e-root-only"
SUPERVISOR = """import json,os,selectors,signal,subprocess,sys,time
child=subprocess.Popen(json.loads(sys.argv[1]),stdin=subprocess.DEVNULL,close_fds=True)
watch=selectors.DefaultSelector();watch.register(sys.stdin,selectors.EVENT_READ)
end=time.monotonic()+90
try:
 while time.monotonic()<end:
  if os.waitid(os.P_PID,child.pid,os.WEXITED|os.WNOHANG|os.WNOWAIT) is not None: break
  if watch.select(.05) and not os.read(sys.stdin.fileno(),1): break
finally: os.killpg(os.getpgrp(),signal.SIGKILL)
"""


def require(value, message="isolated account fixture unavailable"):
    if not value:
        raise RuntimeError(message)


def isolated():
    require(os.environ.get("RUNSPINDLE_ACCOUNT_E2E") == "1")
    require(os.geteuid() != 0)
    interfaces = {
        line.split(":", 1)[0].strip()
        for line in Path("/proc/self/net/dev").read_text().splitlines()
        if ":" in line
    }
    require(interfaces == {"lo"}, "loopback-only isolated worker required")


def qualify(bao, chromium):
    isolated()
    require(
        hashlib.sha256(Path(bao).read_bytes()).hexdigest() == BAO_SHA256,
        "OpenBao executable pin mismatch",
    )
    require(
        hashlib.sha256(Path(chromium).read_bytes()).hexdigest() in CHROMIUM_PINS,
        "Chromium executable pin mismatch",
    )


def reserve_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def spawn(argv, home):
    # A parent-held pipe and fixed deadline kill the complete process group even
    # if the test worker crashes. No inherited credentials, proxies or HOME.
    return subprocess.Popen(
        ["/usr/bin/python3", "-I", "-B", "-c", SUPERVISOR, json.dumps(argv)],
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
        env={"PATH": os.defpath, "HOME": str(home), "LANG": "C.UTF-8"},
    )


def stop(process):
    if process is None:
        return
    if process.stdin:
        process.stdin.close()
    # Do not reap leader before killing its group: retain its PID ownership.
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait(timeout=5)


def until(probe, timeout=8):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        try:
            if probe():
                return
        except (OSError, ValueError, RuntimeError):
            pass
        time.sleep(0.04)
    raise RuntimeError("fixture startup/readback unavailable")


class OpenBaoFixture:
    def __init__(self, executable):
        self.executable, self.process, self.directory = executable, None, None

    def __enter__(self):
        isolated()
        require(
            hashlib.sha256(Path(self.executable).read_bytes()).hexdigest() == BAO_SHA256
        )
        self.directory = Path(tempfile.mkdtemp(prefix="account-bao-"))
        self.home = self.directory
        self.origin = f"https://127.0.0.1:{reserve_port()}"
        self.ca = self.home / "vault-ca.pem"
        try:
            self.process = spawn(
                [
                    str(self.executable),
                    "server",
                    "-dev",
                    "-dev-tls",
                    "-dev-root-token-id=" + TOKEN,
                    "-dev-listen-address=" + self.origin.removeprefix("https://"),
                    "-dev-tls-cert-dir=" + str(self.home),
                ],
                self.home,
            )
            until(lambda: self.ca.is_file())
            self.context = ssl.create_default_context(cafile=str(self.ca))
            opener = urllib.request.build_opener(
                urllib.request.ProxyHandler({}),
                urllib.request.HTTPSHandler(context=self.context),
            )

            def healthy():
                with opener.open(self.origin + "/v1/sys/health", timeout=1) as response:
                    return response.status == 200

            until(healthy)
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def __exit__(self, *args):
        # On uncertain stop, keep the fixture directory for controlled cleanup.
        # A Path has no auto-cleaning finalizer; do not delete beneath a process.
        stop(self.process)
        self.process = None
        if self.directory:
            shutil.rmtree(self.directory)
            self.directory = None

    def transport(self):
        # Fixture trust is per-client, never installed in host/system trust.
        return HTTPS(self.origin, tls_context=self.context)


class AccountSite:
    """A target site's ephemeral verifier/session/action state, not Browser data."""

    def __init__(self, certificate, key):
        self.accounts, self.sessions, self.actions = {}, {}, {}
        self.login_attempts = 0
        site = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def send(self, status, body=b"", **headers):
                self.send_response(status)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header(
                    "Content-Security-Policy",
                    "default-src 'none'; form-action 'self'; connect-src 'self'",
                )
                for name, value in headers.items():
                    self.send_header(name.replace("_", "-"), value)
                self.end_headers()
                self.wfile.write(body)

            def user(self):
                raw = self.headers.get("Cookie", "")
                fields = dict(
                    pair.strip().split("=", 1) for pair in raw.split(";") if "=" in pair
                )
                return site.sessions.get(fields.get("session"))

            def do_GET(self):
                if self.path in ("/register", "/login"):
                    page = self.path[1:]
                    self.send(
                        200,
                        (
                            f'<body data-page="{page}"><form method="post" action="/{page}">'
                            '<input name="username" autocomplete="username">'
                            '<input name="password" type="password" autocomplete="current-password">'
                            "<button>Continue</button></form></body>"
                        ).encode(),
                    )
                elif self.path == "/private":
                    user = self.user()
                    self.send(
                        200 if user else 401,
                        (
                            '<body data-page="private">Signed in</body>'
                            if user
                            else '<body data-page="denied">Not signed in</body>'
                        ).encode(),
                    )
                elif self.path == "/whoami":
                    self.send(200, json.dumps({"user": self.user()}).encode())
                elif self.path.startswith("/readback?operation="):
                    operation = self.path.split("=", 1)[1]
                    user = self.user()
                    self.send(
                        200,
                        json.dumps(
                            {
                                "confirmed": bool(
                                    user and site.actions.get(operation) == user
                                )
                            }
                        ).encode(),
                    )
                else:
                    self.send(404)

            def do_POST(self):
                if self.headers.get("Origin") != site.origin:
                    self.send(403)
                    return
                try:
                    size = int(self.headers.get("Content-Length", "0"))
                    require(0 < size <= 32768)
                    values = urllib.parse.parse_qs(
                        self.rfile.read(size).decode(), strict_parsing=True
                    )
                    require(all(len(v) == 1 for v in values.values()))
                    if self.path in ("/register", "/login"):
                        require(set(values) == {"username", "password"})
                        username, password = (
                            values["username"][0],
                            values["password"][0],
                        )
                        require(0 < len(username) <= 128 and 0 < len(password) <= 16384)
                        if self.path == "/register":
                            require(username not in site.accounts)
                            salt = secrets.token_bytes(16)
                            site.accounts[username] = (
                                salt,
                                hashlib.pbkdf2_hmac(
                                    "sha256", password.encode(), salt, 10000
                                ),
                            )
                            self.send(303, Location="/login")
                        else:
                            site.login_attempts += 1
                            salt, wanted = site.accounts.get(username, (b"", b""))
                            actual = hashlib.pbkdf2_hmac(
                                "sha256", password.encode(), salt, 10000
                            )
                            if not secrets.compare_digest(actual, wanted):
                                self.send(
                                    403, b'<body data-page="failed">Login failed</body>'
                                )
                                return
                            cookie = secrets.token_hex(24)
                            site.sessions[cookie] = username
                            self.send(
                                303,
                                Location="/private",
                                Set_Cookie=f"session={cookie}; Secure; HttpOnly; SameSite=Strict; Path=/",
                            )
                    elif self.path == "/action":
                        require(
                            set(values) == {"operation"} and self.user() is not None
                        )
                        operation = values["operation"][0]
                        require(0 < len(operation) <= 128)
                        old = site.actions.setdefault(operation, self.user())
                        require(old == self.user())
                        self.send(200, b"accepted")
                    else:
                        self.send(404)
                except (ValueError, RuntimeError):
                    self.send(400)

        class BoundedServer(http.server.ThreadingHTTPServer):
            daemon_threads = False
            block_on_close = True

            def get_request(self):
                connection, address = super().get_request()
                connection.settimeout(2)
                return connection, address

        isolated()
        self.server = BoundedServer(("127.0.0.1", 0), Handler)
        self.origin = f"https://127.0.0.1:{self.server.server_port}"
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certificate, key)
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *args):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)
        require(not self.thread.is_alive(), "site cleanup incomplete")


class AccountBrowser:
    """Fresh sandboxed Chromium profile with only fixture-local CA trust."""

    def __init__(self, executable, ca):
        self.executable, self.ca = executable, ca
        self.process, self.directory, self.client = None, None, None

    def __enter__(self):
        isolated()
        require(
            hashlib.sha256(Path(self.executable).read_bytes()).hexdigest()
            in CHROMIUM_PINS
        )
        self.directory = Path(tempfile.mkdtemp(prefix="account-chromium-"))
        home = self.directory
        try:
            nss = home / ".pki" / "nssdb"
            nss.mkdir(parents=True)
            # Only this disposable HOME's NSS DB is changed, not the host's.
            subprocess.run(
                [
                    "/usr/bin/certutil",
                    "-N",
                    "--empty-password",
                    "-d",
                    "sql:" + str(nss),
                ],
                check=True,
                timeout=5,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            subprocess.run(
                [
                    "/usr/bin/certutil",
                    "-A",
                    "-d",
                    "sql:" + str(nss),
                    "-n",
                    "synthetic-account-ca",
                    "-t",
                    "C,,",
                    "-i",
                    str(self.ca),
                ],
                check=True,
                timeout=5,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            profile = home / "profile"
            (profile / "Default").mkdir(parents=True)
            (profile / "Default" / "Preferences").write_text(
                json.dumps(
                    {
                        "credentials_enable_service": False,
                        "profile": {"password_manager_enabled": False},
                    }
                )
            )
            args = [
                str(self.executable),
                "--headless=new",
                "--no-first-run",
                "--disable-gpu",
                "--disable-background-networking",
                "--disable-extensions",
                "--disable-default-apps",
                "--disable-sync",
                "--no-proxy-server",
                "--disable-breakpad",
                "--disable-crash-reporter",
                "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1",
                "--remote-debugging-port=0",
                "--remote-debugging-address=127.0.0.1",
                "--user-data-dir=" + str(profile),
                "about:blank",
            ]
            self.process = spawn(args, home)
            port_file = profile / "DevToolsActivePort"
            until(port_file.is_file)
            raw = port_file.read_bytes()
            require(len(raw) <= 1024)
            port = int(raw.splitlines()[0])
            require(0 < port < 65536)
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with opener.open(
                f"http://127.0.0.1:{port}/json/list", timeout=2
            ) as response:
                data = response.read(16385)
            require(len(data) <= 16384)
            pages = [p for p in json.loads(data) if p.get("type") == "page"]
            require(len(pages) == 1)
            address = pages[0]["webSocketDebuggerUrl"]
            url = urllib.parse.urlsplit(address)
            require(
                url.scheme == "ws"
                and url.hostname == "127.0.0.1"
                and url.port == port
                and url.username is None
                and url.password is None
                and not url.query
                and not url.fragment
            )
            self.client = DevTools(address)
            self.client.call("Page.enable")
            self.client.call("Runtime.enable")
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def __exit__(self, *args):
        close_error = False
        try:
            if self.client:
                self.client.close()
        except BaseException:
            close_error = True
        # Stop must be confirmed before profile removal. If it raises, retain
        # the directory and process reference; never auto-delete in a finalizer.
        stop(self.process)
        self.client, self.process = None, None
        if self.directory:
            shutil.rmtree(self.directory)
            self.directory = None
        require(not close_error, "browser connection cleanup failed")

    def evaluate(self, expression):
        require(self.client is not None)
        result = self.client.call(
            "Runtime.evaluate",
            {"expression": expression, "returnByValue": True, "awaitPromise": True},
        )
        require(
            "exceptionDetails" not in result and "value" in result.get("result", {}),
            "fixture evaluation unavailable",
        )
        return result["result"]["value"]

    def navigate(self, url, page):
        require(self.client is not None)
        self.client.call("Page.navigate", {"url": url})
        until(lambda: self.evaluate("document.body?.dataset.page") == page)

    def observe_frame(self):
        require(self.client is not None)
        return self.client.call("Page.getFrameTree")["frameTree"]["frame"]

    def fill(self, username, password):
        # Only the trusted test helper handles these values; no trace/log output.
        self.evaluate(
            "document.querySelector('[name=username]').value=" + json.dumps(username)
        )
        self.evaluate(
            "document.querySelector('[name=password]').value=" + json.dumps(password)
        )

    def submit(self, expected_page):
        self.evaluate("document.querySelector('form').submit(); true")
        until(lambda: self.evaluate("document.body?.dataset.page") == expected_page)

    def request(self, route, body=None):
        require(route.startswith("/") and not route.startswith("//"))
        options = {
            "credentials": "same-origin",
            "cache": "no-store",
            "redirect": "error",
        }
        if body is not None:
            options.update(
                {
                    "method": "POST",
                    "body": urllib.parse.urlencode(body),
                    "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                }
            )
        return self.evaluate(
            "(async()=>{const r=await fetch("
            + json.dumps(route)
            + ","
            + json.dumps(options)
            + ");return [r.status,await r.text()]})()"
        )

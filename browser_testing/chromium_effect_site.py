"""Opt-in sandboxed Chromium transport to one owned synthetic loopback website.

Real renderer/network execution, synthetic account/authority/site semantics.
No production browser-session, credential or arbitrary navigation interface.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import signal
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request
from dataclasses import asdict
from pathlib import Path
from typing import Any

from browser_runtime.credentials import Target
from browser_runtime.effects import Binding, Readback
from browser_runtime.guarded_effects import Grant, Guard
from browser_testing.http_effect_site import LIMIT, encode
from tools.browser_cdp import DevTools

ENGINE = Path("/usr/lib/chromium/chromium")
ENGINE_SHA256 = "32a85cb0cf284adc64c04c4059a9416750b0143488f3d623f0efad81a4aee9e1"
ENGINE_VERSION = "Chromium 156.0.8078.47"
OPT_IN = "RUNSPINDLE_CHROMIUM_EFFECT_TESTS"
# Parent-held stdin is the liveness sentinel. Chromium never inherits it. This
# separate session therefore dies even if the test worker is killed outright.
SUPERVISOR = """import json,os,selectors,signal,subprocess,sys,time
child=subprocess.Popen(json.loads(sys.argv[1]),stdin=subprocess.DEVNULL,close_fds=True)
watch=selectors.DefaultSelector();watch.register(sys.stdin,selectors.EVENT_READ)
end=time.monotonic()+30
try:
    while time.monotonic()<end:
        if os.waitid(os.P_PID,child.pid,os.WEXITED|os.WNOHANG|os.WNOWAIT) is not None: break
        if watch.select(0.05):
            if not os.read(sys.stdin.fileno(),1): break
finally:
    os.killpg(os.getpgrp(),signal.SIGKILL)
"""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str
    ) -> None:
        raise RuntimeError("Chromium debugger redirect denied")


def qualify() -> None:
    if os.environ.get(OPT_IN) != "1" or os.geteuid() == 0:
        raise RuntimeError("explicit unprivileged Chromium fixture required")
    interfaces = {
        line.split(":", 1)[0].strip()
        for line in Path("/proc/self/net/dev").read_text().splitlines()
        if ":" in line
    }
    if interfaces != {"lo"}:
        raise RuntimeError("Chromium fixture requires loopback-only namespace")
    if (
        ENGINE.is_symlink()
        or hashlib.sha256(ENGINE.read_bytes()).hexdigest() != ENGINE_SHA256
    ):
        raise RuntimeError("Chromium fixture engine pin mismatch")
    version = (
        subprocess.check_output(
            [str(ENGINE), "--version"],
            timeout=5,
            env={"PATH": os.defpath, "LANG": "C.UTF-8"},
            stderr=subprocess.DEVNULL,
        )
        .decode()
        .strip()
    )
    if not version.startswith(ENGINE_VERSION + " ") and version != ENGINE_VERSION:
        raise RuntimeError("Chromium fixture version mismatch")


class ChromiumSite:
    """One fresh profile/page, fixed fixture target and no transport retries."""

    def __init__(self, port: int, target: Target):
        if type(port) is not int or not 0 < port < 65536:
            raise ValueError("invalid synthetic port")
        # Reuse the exact Target validation contract, without minting authority.
        if type(target) is not Target:
            raise ValueError("invalid synthetic target")
        target.validate()
        self.port, self.target = port, target
        self.url = f"http://127.0.0.1:{port}/browser-fixture"
        self._profile: tempfile.TemporaryDirectory[str] | None = None
        self._process: subprocess.Popen[bytes] | None = None
        self._client: DevTools | None = None
        self._used = False
        self._previous_term: Any = None

    def __enter__(self) -> ChromiumSite:
        if self._used:
            raise RuntimeError("Chromium fixture cannot reopen")
        self._used = True
        qualify()
        if threading.current_thread() is not threading.main_thread():
            raise RuntimeError(
                "Chromium fixture requires main-thread cancellation ownership"
            )

        def terminate(signum: int, frame: Any) -> None:
            raise SystemExit(128 + signum)

        self._previous_term = signal.signal(signal.SIGTERM, terminate)
        try:
            self._profile = tempfile.TemporaryDirectory(prefix="chromium-effect-")
            profile = self._profile.name
            arguments = [
                str(ENGINE),
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
                f"--user-data-dir={profile}",
                "--lang=en-US",
                "about:blank",
            ]
            self._process = subprocess.Popen(
                [sys.executable, "-I", "-B", "-c", SUPERVISOR, json.dumps(arguments)],
                stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
                env={
                    "PATH": os.defpath,
                    "LANG": "C.UTF-8",
                    "TZ": "UTC",
                    "HOME": profile,
                },
            )
            end = time.monotonic() + 10
            port_file = Path(profile) / "DevToolsActivePort"
            while not port_file.is_file():
                exited = os.waitid(
                    os.P_PID, self._process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT
                )
                if exited is not None or time.monotonic() >= end:
                    raise RuntimeError("sandboxed Chromium startup unavailable")
                time.sleep(0.025)
            raw_port = port_file.read_bytes()
            if len(raw_port) > 1024:
                raise RuntimeError("Chromium debugger port bounds")
            port = int(raw_port.splitlines()[0])
            if not 0 < port < 65536:
                raise RuntimeError("Chromium debugger port invalid")
            opener = urllib.request.build_opener(
                urllib.request.ProxyHandler({}), NoRedirect()
            )
            with opener.open(
                f"http://127.0.0.1:{port}/json/list", timeout=2
            ) as response:
                raw = response.read(16385)
            if len(raw) > 16384:
                raise RuntimeError("Chromium debugger inventory bounds")
            targets = json.loads(raw)
            pages = [item for item in targets if item.get("type") == "page"]
            if len(pages) != 1:
                raise RuntimeError("Chromium page ambiguous")
            debugger = pages[0]["webSocketDebuggerUrl"]
            parsed = urllib.parse.urlsplit(debugger)
            if (
                parsed.scheme != "ws"
                or parsed.hostname != "127.0.0.1"
                or parsed.port != port
                or parsed.username is not None
                or parsed.password is not None
                or parsed.query
                or parsed.fragment
                or not parsed.path.startswith("/devtools/page/")
            ):
                raise RuntimeError("Chromium debugger target escaped owned endpoint")
            self._client = DevTools(debugger)
            self._client.call("Page.enable")
            self._client.call("Runtime.enable")
            self._client.call("Page.navigate", {"url": self.url})
            # Page.enable may have queued an initial about:blank load event.
            # Observe readiness of the exact fixture; never repeat navigation.
            ready = time.monotonic() + 5
            while True:
                try:
                    self._page()
                    break
                except RuntimeError:
                    if time.monotonic() >= ready:
                        raise
                    time.sleep(0.025)
            return self
        except BaseException:
            self.close()
            raise

    def close(self) -> None:
        try:
            if self._client is not None:
                self._client.close()
                self._client = None
        finally:
            try:
                if self._process is not None:
                    # Never poll/reap the leader before killing its owned group:
                    # retaining its PID prevents reuse while descendants exit.
                    if self._process.stdin is not None:
                        self._process.stdin.close()
                    try:
                        os.killpg(self._process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    self._process.wait(timeout=5)
                    self._process = None
            finally:
                if self._profile is not None:
                    self._profile.cleanup()
                    self._profile = None
                if self._previous_term is not None:
                    signal.signal(signal.SIGTERM, self._previous_term)
                    self._previous_term = None

    def __exit__(self, *args: object) -> None:
        self.close()

    def _evaluate(self, expression: str, *, promise: bool = False) -> Any:
        if self._client is None:
            raise RuntimeError("Chromium fixture closed")
        result = self._client.call(
            "Runtime.evaluate",
            {"expression": expression, "awaitPromise": promise, "returnByValue": True},
        )
        if "exceptionDetails" in result or "value" not in result.get("result", {}):
            raise RuntimeError("Chromium fixture evaluation unavailable")
        return result["result"]["value"]

    def _page(self) -> None:
        if self._evaluate(
            "JSON.stringify([location.href,document.body?.dataset.runspindleFixture])"
        ) != json.dumps([self.url, "v1"], separators=(",", ":")):
            raise RuntimeError("Chromium fixture page changed")

    def _request(self, route: str, grant: Grant, guard: Guard, data: str) -> Any:
        if route not in ("/submit", "/readback") or grant.target != self.target:
            raise ValueError("Chromium fixture target mismatch")
        if grant.action != ("dispatch" if route == "/submit" else "reconcile"):
            raise ValueError("Chromium fixture action mismatch")
        self._page()
        observed = guard.observe()
        if (
            observed is None
            or observed.target != self.target
            or guard.current(grant) is not True
        ):
            raise ValueError("Chromium fixture guard unavailable")
        body = encode({"binding": asdict(grant.target.binding), "data": data})
        if len(body) > LIMIT:
            raise ValueError("Chromium fixture request bounds")
        expression = (
            """(async () => {
          if(location.href !== URL || document.body?.dataset.runspindleFixture !== 'v1') throw Error('page');
          const controller=new AbortController(); const timer=setTimeout(()=>controller.abort(),1500);
          try {
            const response=await fetch(ROUTE,{method:'POST',body:BODY,headers:{'Content-Type':'application/json'},
              redirect:'error',credentials:'omit',cache:'no-store',signal:controller.signal});
            if(response.status!==200 || !response.body) throw Error('response');
            const reader=response.body.getReader(); let size=0,chunks=[];
            while(true){const {value,done}=await reader.read();if(done)break;size+=value.length;
              if(size>16384){await reader.cancel();throw Error('size');}chunks.push(value);}
            const all=new Uint8Array(size);let offset=0;for(const chunk of chunks){all.set(chunk,offset);offset+=chunk.length;}
            return new TextDecoder('utf-8',{fatal:true}).decode(all);
          } finally {clearTimeout(timer);}
        })()""".replace("URL", json.dumps(self.url))
            .replace("ROUTE", json.dumps(route))
            .replace("BODY", json.dumps(body.decode("ascii")))
        )
        raw = self._evaluate(expression, promise=True)
        if not isinstance(raw, str) or not 0 < len(raw.encode()) <= LIMIT:
            raise ValueError("Chromium fixture response bounds")
        value = json.loads(raw)
        if encode(value) != raw.encode():
            raise ValueError("Chromium fixture noncanonical response")
        return value

    def submit(self, grant: Grant, payload: bytes, guard: Guard) -> object:
        if (
            type(payload) is not bytes
            or not 0 < len(payload) <= 4096
            or hashlib.sha256(payload).hexdigest() != grant.payload_digest
        ):
            raise ValueError("Chromium fixture payload mismatch")
        return self._request(
            "/submit", grant, guard, base64.b64encode(payload).decode("ascii")
        )

    def readback(self, grant: Grant, guard: Guard) -> Readback:
        value = self._request("/readback", grant, guard, grant.payload_digest)
        if set(value) != {"binding", "payload_digest", "outcome", "evidence_digest"}:
            raise ValueError("Chromium fixture readback shape")
        value["binding"] = Binding(**value["binding"])
        return Readback(**value)

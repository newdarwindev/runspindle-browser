"""Disposable, local Chrome DevTools transport for the visual evidence script."""

import base64
import hashlib
import json
import os
import socket
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, cast

PROBE = """(() => {
  const all = s => [...document.querySelectorAll(s)];
  const rects = all('.map li, .cards > li, nav a, .skip, #map-browser p');
  const outside = rects.filter(e => {
    const r = e.getBoundingClientRect();
    return r.left < -1 || r.right > innerWidth + 1 || e.scrollWidth > e.clientWidth + 1;
  }).map(e => e.id || e.tagName.toLowerCase());
  const overflowNodes = all('body *').filter(e => {
    const r = e.getBoundingClientRect();
    return r.right > innerWidth + 1 || r.left < -1;
  }).map(e => e.id || e.tagName.toLowerCase()).slice(0, 12);
  const map = all('.map li');
  const labels = map.map(e => (e.querySelector('h3')?.textContent || '').trim());
  const anchors = all('a[href^="#"]').map(e => e.getAttribute('href').slice(1));
  const missingAnchors = anchors.filter(id => !document.getElementById(id));
  const skip = document.querySelector('.skip');
  const focus = getComputedStyle(skip);
  return {
    width: innerWidth, docWidth: document.documentElement.scrollWidth,
    mapCount: map.length, labels, outside, overflowNodes, missingAnchors,
    headingCount: all('h1').length,
    focusTarget: document.activeElement === skip,
    focusOutline: focus.outlineStyle !== 'none' && parseFloat(focus.outlineWidth) >= 2,
    cards: all('#architecture .cards > li').length,
    fontReady: document.fonts.status === 'loaded',
    visibleMap: map.every(e => e.getBoundingClientRect().height > 0)
  };
})()"""
OPERATION_TIMEOUT = 5.0
ARCHITECTURE_CLIP = """(() => {
  const box = document.querySelector('#architecture-island').getBoundingClientRect();
  const x = Math.floor(box.left + scrollX), y = Math.floor(box.top + scrollY);
  return {x, y, width: Math.ceil(box.right + scrollX) - x,
          height: Math.ceil(box.bottom + scrollY) - y, scale: 1};
})()"""
FOCUSED_LINK = """(() => {
  const link = document.activeElement, style = getComputedStyle(link);
  const box = link.getBoundingClientRect();
  return {
    href: link.getAttribute('href'),
    name: link.textContent.trim(),
    focusVisible: link.matches(':focus-visible') && style.outlineStyle !== 'none'
      && parseFloat(style.outlineWidth) >= 2,
    fullyOnscreen: box.left >= 0 && box.top >= 0
      && box.right <= innerWidth && box.bottom <= innerHeight,
    unobscured: document.elementFromPoint(box.x + box.width / 2, box.y + box.height / 2)
      === link
  };
})()"""


class DevTools:
    """Small RFC 6455 client for one local Chrome page target."""

    def __init__(self, url: str) -> None:
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme != "ws" or parsed.hostname != "127.0.0.1":
            raise RuntimeError("unexpected Chrome debugger address")
        self.connection = socket.create_connection(
            (parsed.hostname, parsed.port or 80), 5
        )
        self.buffer = b""
        self.next_id = 0
        self.loaded = False
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        request = (
            f"GET {parsed.path} HTTP/1.1\r\nHost: 127.0.0.1:{parsed.port}\r\n"
            f"Upgrade: websocket\r\nConnection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
        )
        try:
            deadline = time.monotonic() + OPERATION_TIMEOUT
            self.connection.settimeout(self._remaining(deadline))
            self.connection.sendall(request.encode("ascii"))
            header = b""
            while b"\r\n\r\n" not in header:
                self.connection.settimeout(self._remaining(deadline))
                chunk = self.connection.recv(4096)
                if not chunk:
                    raise RuntimeError("Chrome WebSocket handshake closed")
                header += chunk
                if len(header) > 16384:
                    raise RuntimeError("Chrome handshake too large")
            head, self.buffer = header.split(b"\r\n\r\n", 1)
            expected = base64.b64encode(
                hashlib.sha1(
                    (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()
                ).digest()
            )
            if b" 101 " not in head.split(b"\r\n", 1)[0] or expected not in head:
                raise RuntimeError("Chrome WebSocket handshake failed")
        except BaseException:
            self.connection.close()
            raise

    def close(self) -> None:
        self.connection.close()

    @staticmethod
    def _remaining(deadline: float) -> float:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Chrome DevTools operation deadline exceeded")
        return remaining

    def _take(self, count: int, deadline: float) -> bytes:
        self._remaining(deadline)
        while len(self.buffer) < count:
            self.connection.settimeout(self._remaining(deadline))
            chunk = self.connection.recv(max(count - len(self.buffer), 4096))
            if not chunk:
                raise RuntimeError("Chrome DevTools connection closed")
            self.buffer += chunk
        result, self.buffer = self.buffer[:count], self.buffer[count:]
        return result

    def _send(self, opcode: int, data: bytes, deadline: float) -> None:
        length = len(data)
        header = bytes([0x80 | opcode])
        if length < 126:
            header += bytes([0x80 | length])
        elif length < 65536:
            header += b"\xfe" + length.to_bytes(2, "big")
        else:
            header += b"\xff" + length.to_bytes(8, "big")
        mask = os.urandom(4)
        self.connection.settimeout(self._remaining(deadline))
        self.connection.sendall(
            header
            + mask
            + bytes(byte ^ mask[index % 4] for index, byte in enumerate(data))
        )

    def _read(self, deadline: float) -> dict[str, Any]:
        while True:
            self._remaining(deadline)
            first, second = self._take(2, deadline)
            length = second & 0x7F
            if length == 126:
                length = int.from_bytes(self._take(2, deadline), "big")
            elif length == 127:
                length = int.from_bytes(self._take(8, deadline), "big")
            if second & 0x80 or length > 25_000_000:
                raise RuntimeError("unexpected Chrome WebSocket frame")
            payload = self._take(length, deadline)
            opcode = first & 0x0F
            if opcode == 9:
                self._send(10, payload, deadline)
                continue
            if opcode != 1:
                raise RuntimeError("unexpected Chrome WebSocket opcode")
            message = cast(dict[str, Any], json.loads(payload))
            if message.get("method") == "Page.loadEventFired":
                self.loaded = True
            return message

    def call(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        deadline = time.monotonic() + OPERATION_TIMEOUT
        self.next_id += 1
        identifier = self.next_id
        self._send(
            1,
            json.dumps(
                {"id": identifier, "method": method, "params": params or {}}
            ).encode(),
            deadline,
        )
        while True:
            message = self._read(deadline)
            if message.get("id") == identifier:
                if "error" in message:
                    raise RuntimeError(f"Chrome {method}: {message['error']}")
                return cast(dict[str, Any], message["result"])

    def wait_loaded(self) -> None:
        deadline = time.monotonic() + OPERATION_TIMEOUT
        while not self.loaded:
            self._read(deadline)


def evaluate(client: DevTools, expression: str) -> Any:
    result = client.call(
        "Runtime.evaluate", {"expression": expression, "returnByValue": True}
    )
    if "exceptionDetails" in result:
        raise RuntimeError("Chrome DOM probe failed")
    return result["result"]["value"]


def keypress(client: DevTools, key: str, virtual_code: int) -> None:
    for key_type in ("keyDown", "keyUp"):
        client.call(
            "Input.dispatchKeyEvent",
            {
                "type": key_type,
                "key": key,
                "code": key,
                "windowsVirtualKeyCode": virtual_code,
            },
        )


def keyboard_navigation(client: DevTools) -> dict[str, Any]:
    skip = evaluate(client, FOCUSED_LINK)
    keypress(client, "Enter", 13)
    skip_target = evaluate(client, "document.activeElement.id")
    links = []
    for _ in range(2):
        keypress(client, "Tab", 9)
        links.append(evaluate(client, FOCUSED_LINK))
    keypress(client, "Enter", 13)
    return {
        "skip": skip,
        "skipTarget": skip_target,
        "sectionLinks": links,
        "selectedFragment": evaluate(client, "location.hash"),
    }


def render(
    chrome: Path,
    source: Path,
    width: int,
    height: int,
    screenshot: Path | None = None,
    mode: str = "plain",
) -> dict[str, Any]:
    """Render a local file with a new profile and inspect its real DOM."""
    with tempfile.TemporaryDirectory(prefix="browser-cdp-") as profile:
        process = subprocess.Popen(
            [
                str(chrome),
                "--headless=new",
                "--no-first-run",
                "--disable-gpu",
                "--disable-background-networking",
                "--disable-extensions",
                "--disable-default-apps",
                "--disable-sync",
                "--no-proxy-server",
                "--host-resolver-rules=MAP * ~NOTFOUND",
                "--remote-debugging-port=0",
                f"--user-data-dir={profile}",
                "--lang=en-US",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env={**os.environ, "TZ": "UTC"},
        )
        client: DevTools | None = None
        try:
            port_file = Path(profile) / "DevToolsActivePort"
            for _ in range(100):
                if port_file.is_file():
                    break
                if process.poll() is not None:
                    raise RuntimeError("Chrome exited before debugger became ready")
                time.sleep(0.05)
            if not port_file.is_file():
                raise RuntimeError("Chrome did not expose local debugger")
            port = int(port_file.read_text().splitlines()[0])
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with opener.open(
                f"http://127.0.0.1:{port}/json/list", timeout=5
            ) as response:
                targets = cast(list[dict[str, Any]], json.load(response))
            page = next(item for item in targets if item.get("type") == "page")
            client = DevTools(cast(str, page["webSocketDebuggerUrl"]))
            client.call("Page.enable")
            client.call("Runtime.enable")
            client.call(
                "Emulation.setDeviceMetricsOverride",
                {
                    "width": width,
                    "height": height,
                    "deviceScaleFactor": 1,
                    "mobile": False,
                },
            )
            client.call("Page.navigate", {"url": source.resolve().as_uri()})
            client.wait_loaded()
            client.call(
                "Runtime.evaluate",
                {"expression": "document.fonts.ready", "awaitPromise": True},
            )
            if mode == "missing-label":
                client.call(
                    "Runtime.evaluate",
                    {
                        "expression": "document.querySelector('#map-browser h3').remove()",
                    },
                )
            if mode == "map":
                client.call(
                    "Runtime.evaluate",
                    {
                        "expression": "document.querySelector('#architecture-island').scrollIntoView()",
                    },
                )
            result: dict[str, Any] = {}
            if mode in ("probe", "missing-label", "architecture"):
                keypress(client, "Tab", 9)
                result = cast(dict[str, Any], evaluate(client, PROBE))
            if screenshot:
                options: dict[str, Any] = {
                    "format": "png",
                    "captureBeyondViewport": mode in ("full", "architecture"),
                }
                if mode == "architecture":
                    options["clip"] = evaluate(client, ARCHITECTURE_CLIP)
                elif mode == "full":
                    dimensions = client.call(
                        "Runtime.evaluate",
                        {
                            "expression": "({width:document.documentElement.scrollWidth,height:document.documentElement.scrollHeight})",
                            "returnByValue": True,
                        },
                    )["result"]["value"]
                    options["clip"] = {
                        "x": 0,
                        "y": 0,
                        "width": dimensions["width"],
                        "height": dimensions["height"],
                        "scale": 1,
                    }
                image = client.call("Page.captureScreenshot", options)["data"]
                screenshot.write_bytes(base64.b64decode(image))
            if mode == "architecture":
                result["keyboard"] = keyboard_navigation(client)
            return result
        finally:
            if client:
                client.close()
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)

#!/usr/bin/env python3
"""Bounded externally provisioned test lane; no runner admission or installation."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import selectors
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from browser_testing.account_e2e import BAO_SHA256, CHROMIUM_PINS  # noqa: E402

BWRAP_SHA256 = "263a40b4dca7b24d47c05bf2f64d05093dbefa8577c556c9a185040a173bf7b8"
CERTUTIL_SHA256 = "d5bf6c43189c977e2be9cdf50e1ae0f298585f43ed49cff459734e8a044a41ff"


def pinned(path: Path, allowed: set[str]) -> Path:
    path = path.resolve(strict=True)
    if not path.is_file() or not os.access(path, os.X_OK):
        raise ValueError("dependency unavailable")
    if hashlib.sha256(path.read_bytes()).hexdigest() not in allowed:
        raise ValueError("dependency pin mismatch")
    return path


def command(staging: Path, bao: Path, chromium: Path, certutil: Path) -> list[str]:
    """Only read-only host mounts; fixture data stays in private namespace tmpfs."""
    return [
        "/usr/bin/bwrap",
        "--unshare-net",
        "--unshare-pid",
        "--die-with-parent",
        "--tmpfs",
        "/",
        "--ro-bind",
        "/usr",
        "/usr",
        "--ro-bind",
        "/usr",
        "/host-usr",
        "--ro-bind",
        str(staging),
        "/usr/bin",
        "--ro-bind",
        str(bao),
        "/test-deps/bao",
        "--ro-bind",
        str(certutil),
        "/test-deps/certutil",
        "--ro-bind",
        str(ROOT),
        "/source",
        "--symlink",
        "usr/bin",
        "/bin",
        "--symlink",
        "usr/lib",
        "/lib",
        "--symlink",
        "usr/lib64",
        "/lib64",
        "--ro-bind",
        "/etc/ld.so.cache",
        "/etc/ld.so.cache",
        "--ro-bind",
        "/etc/fonts",
        "/etc/fonts",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--tmpfs",
        "/tmp",
        "--chdir",
        "/source",
        "--clearenv",
        "--setenv",
        "PATH",
        "/usr/bin:/bin",
        "--setenv",
        "LANG",
        "C.UTF-8",
        "--",
        "/usr/bin/python3",
        "-B",
        "/source/tools/qualify_account_e2e.py",
        "--bao",
        "/test-deps/bao",
        "--chromium",
        "/usr/lib/chromium/chromium",
    ]


class Terminated(BaseException):
    """Internal cancellation marker, never printed."""


def capture(process, timeout=300, stdout_limit=16384, stderr_limit=4096):
    """Bound allocation while reading; never buffer arbitrary child output."""
    end = time.monotonic() + timeout
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    limits = {"stdout": stdout_limit, "stderr": stderr_limit}
    with selectors.DefaultSelector() as selector:
        for name in buffers:
            selector.register(getattr(process, name), selectors.EVENT_READ, name)
        while selector.get_map():
            remaining = end - time.monotonic()
            if remaining <= 0:
                raise TimeoutError
            for key, _ in selector.select(min(remaining, 0.1)):
                data = os.read(key.fd, min(4096, limits[key.data] + 1))
                if not data:
                    selector.unregister(key.fileobj)
                    continue
                if len(buffers[key.data]) + len(data) > limits[key.data]:
                    raise ValueError("output bound exceeded")
                buffers[key.data].extend(data)
    process.wait(timeout=max(0.001, end - time.monotonic()))
    return bytes(buffers["stdout"]), bytes(buffers["stderr"])


def run(bao: Path, chromium: Path, certutil: Path) -> dict:
    if os.geteuid() == 0:
        raise ValueError("unprivileged worker required")
    pinned(Path("/usr/bin/bwrap"), {BWRAP_SHA256})
    bao = pinned(bao, {BAO_SHA256})
    chromium = pinned(chromium, set(CHROMIUM_PINS))
    # Chromium loads sibling runtime files, so use the qualified system path.
    if chromium != Path("/usr/lib/chromium/chromium"):
        raise ValueError("unsupported Chromium layout")
    certutil = pinned(certutil, {CERTUTIL_SHA256})
    paths = (bao, chromium, certutil, Path("/usr/bin/bwrap"))
    before = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
    staging = Path(tempfile.mkdtemp(prefix="account-e2e-tools-"))
    process = None
    stopped = True
    handlers = {}

    def terminated(_signum, _frame):
        raise Terminated

    try:
        for signum in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
            handlers[signum] = signal.getsignal(signum)
            signal.signal(signum, terminated)
        for item in Path("/usr/bin").iterdir():
            if item.name != "certutil":
                (staging / item.name).symlink_to("/host-usr/bin/" + item.name)
        (staging / "certutil").symlink_to("/test-deps/certutil")
        stopped = False
        process = subprocess.Popen(
            command(staging, bao, chromium, certutil),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={"PATH": os.defpath, "LANG": "C.UTF-8"},
            start_new_session=True,
        )
        raw, error = capture(process)
        stopped = True
        if process.returncode != 0 or error or len(raw) > 16384:
            raise ValueError("isolated worker failed")
        receipt = json.loads(raw)
        if type(receipt) is not dict or receipt.get("status") != "passed":
            raise ValueError("isolated receipt rejected")
        if any(
            hashlib.sha256(p.read_bytes()).hexdigest() != before[str(p)] for p in paths
        ):
            raise ValueError("dependency changed")
        return receipt
    finally:
        # Repeated cancellation cannot interrupt the bounded owned-child reap.
        for signum in handlers:
            signal.signal(signum, signal.SIG_IGN)
        try:
            if process is None or process.returncode is not None:
                stopped = True
            if process is not None and not stopped:
                # Retain PID ownership until wait. Failed wait retains staging.
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=10)
                stopped = True
            if stopped:
                shutil.rmtree(staging)
        finally:
            if stopped and process is not None:
                for stream in (process.stdout, process.stderr):
                    if stream is not None:
                        stream.close()
            for signum, handler in handlers.items():
                signal.signal(signum, handler)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bao", type=Path, required=True)
    parser.add_argument("--chromium", type=Path, required=True)
    parser.add_argument("--certutil", type=Path, required=True)
    args = parser.parse_args()
    result = None
    try:
        result = run(args.bao, args.chromium, args.certutil)
    except BaseException:
        # Never expose upstream stderr, paths, tracebacks or fixture contents.
        pass
    print(
        json.dumps(
            result or {"status": "blocked", "reason": "isolated lane unavailable"}
        )
    )
    return 0 if result is not None else 2


if __name__ == "__main__":
    raise SystemExit(main())

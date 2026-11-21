#!/usr/bin/env python3
"""Bounded F07 effect acceptance in an already isolated loopback-only namespace.

No namespace, account, credential, service or external connection is created by
this command. Actual HTTP/SQLite fixtures remain synthetic-site evidence.
"""

from __future__ import annotations

import _sqlite3
import argparse
import hashlib
import json
import os
import pathlib
import signal
import sqlite3
import subprocess
import sys
import threading
import time
import unittest
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parents[1]
SUITES = (
    "test_effect_journal.py",
    "test_effect_exceptions.py",
    "test_effect_schema.py",
    "test_guarded_effects.py",
    "test_effect_wire.py",
    "test_http_effect_site.py",
    "test_effect_qualification.py",
    "test_effect_capacity.py",
    "test_effect_acceptance_mutations.py",
)
LIMIT = 1_048_576


class QualificationUnavailable(RuntimeError):
    """A required local qualification input could not be read."""


def check(value: Any, message: str) -> None:
    if not value:
        raise RuntimeError(message)


def qualify_environment() -> dict[str, Any]:
    check(os.geteuid() != 0, "qualification worker must be unprivileged")
    try:
        network_devices = pathlib.Path("/proc/self/net/dev").read_text()
    except OSError:
        raise QualificationUnavailable(
            "qualification network namespace unavailable"
        ) from None
    interfaces = {
        line.split(":", 1)[0].strip()
        for line in network_devices.splitlines()
        if ":" in line
    }
    check(interfaces == {"lo"}, "requires isolated loopback-only network namespace")
    try:
        expected = json.loads(
            (ROOT / "docs/effect-reconciliation-toolchain.json").read_text()
        )
    except OSError:
        raise QualificationUnavailable(
            "toolchain pin unavailable: manifest unreadable"
        ) from None
    sqlite_extension = getattr(_sqlite3, "__file__", None)
    if not isinstance(sqlite_extension, str):
        raise QualificationUnavailable(
            "toolchain pin unavailable: SQLite extension is built-in"
        )
    observed = {
        "python_version": sys.version.split()[0],
        "python_sha256": toolchain_digest(pathlib.Path(sys.executable).resolve()),
        "sqlite_version": sqlite3.sqlite_version,
        "sqlite3_extension_sha256": toolchain_digest(pathlib.Path(sqlite_extension)),
        "sqlite3_library_sha256": toolchain_digest(
            pathlib.Path("/usr/lib/x86_64-linux-gnu/libsqlite3.so.0")
        ),
    }
    check(
        all(value == expected.get(key) for key, value in observed.items()),
        "toolchain pin mismatch",
    )
    return {
        **observed,
        "interfaces": sorted(interfaces),
        "source_base": expected["source_base"],
    }


def toolchain_digest(path: pathlib.Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        raise QualificationUnavailable(
            "toolchain pin unavailable: binary unreadable"
        ) from None


def inputs() -> dict[str, str]:
    paths = sorted((ROOT / "browser_runtime").glob("*.py"))
    paths += sorted((ROOT / "browser_testing").glob("*.py"))
    paths += sorted((ROOT / "tests").glob("*.py"))
    paths += [
        pathlib.Path(__file__),
        ROOT / "docs/effect-reconciliation-toolchain.json",
    ]
    return {
        str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in paths
    }


def worker() -> int:
    qualify_environment()
    sys.path.insert(0, str(ROOT))
    loader = unittest.TestLoader()
    suite = unittest.TestSuite(
        loader.discover(str(ROOT / "tests"), pattern=name) for name in SUITES
    )
    child_optimization = int(
        subprocess.check_output(
            [sys.executable, "-c", "import sys; print(sys.flags.optimize)"],
            text=True,
            timeout=5,
        ).strip()
    )
    check(child_optimization == sys.flags.optimize, "child optimization mismatch")
    expected = suite.countTestCases()
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    receipt = {
        "tests": result.testsRun,
        "optimization_level": sys.flags.optimize,
        "child_optimization_level": child_optimization,
        "expected_tests": expected,
        "skipped": len(result.skipped),
        "failures": len(result.failures),
        "errors": len(result.errors),
    }
    passed = (
        expected > 0
        and result.testsRun == expected
        and result.wasSuccessful()
        and not result.skipped
    )
    print(
        json.dumps({"status": "passed" if passed else "failed", **receipt}), flush=True
    )
    return 0 if passed else 1


def worker_command(optimized: bool) -> list[str]:
    return [
        sys.executable,
        "-I",
        "-B",
        *(["-O"] if optimized else []),
        str(pathlib.Path(__file__).resolve()),
        "--worker",
    ]


def run_mode(optimized: bool, command: list[str] | None = None) -> dict[str, Any]:
    def terminate(signum: int, frame: Any) -> None:
        raise SystemExit(128 + signum)

    previous = signal.signal(signal.SIGTERM, terminate)
    try:
        process = subprocess.Popen(
            worker_command(optimized) if command is None else command,
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            start_new_session=True,
            env={
                "PATH": os.defpath,
                "LANG": "C.UTF-8",
                "TZ": "UTC",
                "PYTHONOPTIMIZE": str(int(optimized)),
                "PYTHONDONTWRITEBYTECODE": "1",
            },
        )
    except BaseException:
        signal.signal(signal.SIGTERM, previous)
        raise
    if process.stdout is None:
        process.kill()
        process.wait(timeout=5)
        signal.signal(signal.SIGTERM, previous)
        raise RuntimeError("worker output missing")
    output = bytearray()
    overflow = threading.Event()
    stream = process.stdout

    def drain() -> None:
        while True:
            chunk = stream.read(8192)
            if not chunk:
                return
            if len(output) + len(chunk) > LIMIT:
                overflow.set()
                return
            output.extend(chunk)

    thread = threading.Thread(target=drain, daemon=True)
    try:
        thread.start()
        deadline = time.monotonic() + 120
        exited = None
        while exited is None:
            check(not overflow.is_set(), "worker output bound exceeded")
            check(time.monotonic() < deadline, "worker deadline exceeded")
            # WNOWAIT retains the owned leader PID until group cleanup. This
            # prevents PID/group reuse before killing any surviving descendants.
            exited = os.waitid(
                os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT
            )
            time.sleep(0.02)
        thread.join(2)
        check(
            not thread.is_alive() and not overflow.is_set(), "worker output incomplete"
        )
        text = output.decode("utf-8")
        check(
            exited.si_code == os.CLD_EXITED and exited.si_status == 0,
            "effect acceptance failed: " + text[-4000:],
        )
        receipt = json.loads(text.splitlines()[-1])
        check(
            receipt["optimization_level"]
            == receipt["child_optimization_level"]
            == int(optimized)
            and receipt["status"] == "passed"
            and receipt["tests"] == receipt["expected_tests"] > 0
            and receipt["skipped"] == receipt["failures"] == receipt["errors"] == 0,
            "acceptance did not pass completely",
        )
        return {
            "optimized": optimized,
            **receipt,
            "output_sha256": hashlib.sha256(output).hexdigest(),
        }
    finally:
        try:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)
            thread.join(2) if thread.ident is not None else None
            stream.close()
            check(not thread.is_alive(), "worker reader leaked")
        finally:
            signal.signal(signal.SIGTERM, previous)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--report", type=pathlib.Path)
    args = parser.parse_args()
    if args.worker:
        return worker()
    check(args.report is not None, "explicit report path required")
    environment = qualify_environment()
    before = inputs()
    results = [run_mode(False), run_mode(True)]
    check(inputs() == before, "qualification input bytes changed during run")
    report = {
        "status": "passed",
        "evidence_class": "isolated_component_and_synthetic_http_site",
        "environment": environment,
        "source_hashes": before,
        "suites": list(SUITES),
        "runs": results,
        "boundaries": {
            "journal": "actual_sqlite",
            "site": "actual_loopback_http_synthetic_service",
            "authority": "injected_synthetic",
            "browser_engine": "not_exercised",
            "profiles": "not_exercised",
            "vault": "not_exercised",
            "live_acceptance": "not_run",
        },
    }
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))
    return 0


if __name__ == "__main__":
    try:
        exit_code = main()
    except QualificationUnavailable as unavailable:
        print(json.dumps({"status": "blocked", "reason": str(unavailable)}))
        exit_code = 2
    raise SystemExit(exit_code)

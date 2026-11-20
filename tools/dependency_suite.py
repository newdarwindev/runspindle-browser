#!/usr/bin/env python3
"""Bounded dependency-suite inventory and local component integration runner.

No installs, containers, namespace changes, credentials or persistent services.
Full-stack readiness is never inferred from a component-suite pass.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import io
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import unittest
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

SUITES = (
    "test_profile_integration.py",
    "test_lease_credentials.py",
    "test_control_reconciliation.py",
    "test_http_effect_site.py",
    "test_openbao_http.py",
)
UPSTREAMS = ("bao", "pinchtab", "Xvnc")


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inventory() -> dict[str, Any]:
    from browser_testing.chromium_effect_site import ENGINE, ENGINE_SHA256

    blockers = []
    upstreams = {}
    for name in UPSTREAMS:
        executable = shutil.which(name)
        upstreams[name] = {
            "found": executable is not None,
            "executed": False,
            "integrated_by_this_suite": False,
        }
        if executable is None:
            blockers.append(f"{name}: executable unavailable")
    # Even an installed upstream cannot satisfy absent adapter/conformance work.
    blockers.extend(
        (
            "OpenBao: real server composition not implemented in this suite",
            "PinchTab: component adapter and conformance not implemented",
            "KasmVNC: real viewer input fencing and handback not implemented",
        )
    )
    engine_hash = digest(ENGINE) if ENGINE.is_file() else None
    if engine_hash != ENGINE_SHA256:
        blockers.append("Chromium: existing qualification executable pin mismatch")
    try:
        crypto = importlib.metadata.version("cryptography")
    except importlib.metadata.PackageNotFoundError:
        crypto = None
    if crypto != "50.0.2":
        blockers.append("cryptography: preferred dependency pin 50.0.2 unavailable")
    return {
        "python": sys.version.split()[0],
        "python_sha256": digest(Path(sys.executable).resolve()),
        "sqlite": sqlite3.sqlite_version,
        "cryptography": crypto,
        "chromium": {
            "observed_sha256": engine_hash,
            "required_sha256": ENGINE_SHA256,
            "executed": False,
        },
        "upstreams": upstreams,
        "full_stack_status": "blocked",
        "blockers": blockers,
    }


def require_isolation() -> None:
    if os.geteuid() == 0:
        raise RuntimeError("unprivileged worker required")
    interfaces = {
        line.split(":", 1)[0].strip()
        for line in Path("/proc/self/net/dev").read_text().splitlines()
        if ":" in line
    }
    if interfaces != {"lo"}:
        raise RuntimeError("already isolated loopback-only namespace required")


def worker() -> int:
    require_isolation()
    suite = unittest.TestSuite(
        unittest.TestLoader().discover(str(ROOT / "tests"), pattern=name)
        for name in SUITES
    )
    expected = suite.countTestCases()
    # Do not expose synthetic secret payloads from a failing test traceback.
    result = unittest.TextTestRunner(stream=io.StringIO()).run(suite)
    child_level = int(
        subprocess.check_output(
            [sys.executable, "-B", "-c", "import sys; print(sys.flags.optimize)"],
            timeout=5,
            text=True,
        ).strip()
    )
    passed = (
        expected > 0
        and result.testsRun == expected
        and result.wasSuccessful()
        and not result.skipped
        and child_level == sys.flags.optimize
    )
    print(
        json.dumps(
            {
                "status": "passed" if passed else "failed",
                "tests": result.testsRun,
                "expected_tests": expected,
                "optimization_level": sys.flags.optimize,
                "child_optimization_level": child_level,
                "skipped": len(result.skipped),
                "failures": len(result.failures),
                "errors": len(result.errors),
            }
        )
    )
    return 0 if passed else 1


def source_hashes() -> dict[str, str]:
    paths: list[Path] = []
    for directory in ("browser_runtime", "browser_testing", "tests", "tools"):
        paths.extend((ROOT / directory).glob("*.py"))
    return {str(path.relative_to(ROOT)): digest(path) for path in sorted(paths)}


def run_components() -> list[dict[str, Any]]:
    from tools.qualify_effect_reconciliation import run_mode

    require_isolation()
    before = source_hashes()
    runs = []
    for optimized in (False, True):
        command = [
            sys.executable,
            "-I",
            "-B",
            *(["-O"] if optimized else []),
            str(Path(__file__).resolve()),
            "--worker",
        ]
        runs.append(run_mode(optimized, command))
    if source_hashes() != before:
        raise RuntimeError("suite inputs changed during execution")
    return runs


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument(
        "--components",
        action="store_true",
        help="run bounded local component integrations, not full E2E",
    )
    parser.add_argument(
        "--require-full-stack",
        action="store_true",
        help="fail closed until every real upstream is integrated",
    )
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    if args.worker:
        return worker()
    if args.report is None:
        parser.error("--report is required")
    report: dict[str, object] = {
        "schema": "runspindle.browser.dependency-suite.v1",
        "inventory": inventory(),
        "source_hashes": source_hashes(),
        "components_status": "not_run",
        "runs": [],
        "coverage": {
            "profile": "real AESGCM/SQLite/filesystem; synthetic key provider",
            "effects": "real SQLite and ephemeral HTTP site; synthetic authority",
            "control": "real local lease store; synthetic backend",
            "openbao": "actual HTTP parser; fake sockets/provider",
            "browser_engine": "not_exercised",
            "pinchtab": "not_integrated",
            "kasmvnc": "not_integrated",
            "live_accounts": "none",
        },
    }
    failed = False
    if args.components:
        try:
            report["runs"] = run_components()
            report["components_status"] = "passed"
        except Exception as exc:
            report["components_status"] = "failed"
            # Error type only: never copy arbitrary subprocess output to receipts.
            report["error_type"] = type(exc).__name__
            failed = True
    report["status"] = (
        "blocked"
        if args.require_full_stack
        else ("failed" if failed else "inventory_complete")
    )
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(
        json.dumps(
            {
                "status": report["status"],
                "components_status": report["components_status"],
                "full_stack_status": "blocked",
            }
        )
    )
    return 2 if args.require_full_stack else int(failed)


if __name__ == "__main__":
    raise SystemExit(main())

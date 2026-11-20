#!/usr/bin/env python3
"""Bounded opt-in Browser-only test; no provisioning, runner registration or CI bypass."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import signal
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def worker() -> int:
    from browser_testing.account_e2e import qualify

    qualify(
        os.environ["RUNSPINDLE_BAO_BINARY"], os.environ["RUNSPINDLE_CHROMIUM_BINARY"]
    )
    component_only = os.environ.get("RUNSPINDLE_ACCOUNT_COMPONENT_ONLY") == "1"
    suite = unittest.defaultTestLoader.discover(
        str(ROOT / "tests"),
        pattern="test_account_openbao.py" if component_only else "test_account_e2e.py",
    )
    output = io.StringIO()
    result = unittest.TextTestRunner(stream=output).run(suite)
    leaked = "SYNTHETIC_E2E_CANARY" in output.getvalue()
    receipt: dict[str, object] = {
        "status": "passed"
        if result.wasSuccessful()
        and not result.skipped
        and result.testsRun == 2
        and not leaked
        else "failed",
        "tests": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "skipped": len(result.skipped),
        "private_output_canary_detected": leaked,
        "optimization": sys.flags.optimize,
        "evidence_class": "isolated_OpenBao_synthetic_capture_authority"
        if component_only
        else "isolated_real_upstreams_synthetic_authority_and_site",
    }
    receipt["error_locations"] = [
        {
            "test": test.id().split(".")[-1],
            "frames": re.findall(
                r'File "[^"\n]+/(browser_testing/account_e2e.py|tests/test_account_e2e.py|tests/test_account_openbao.py)", line (\d+), in ([A-Za-z_][A-Za-z0-9_]*)',
                detail,
            ),
            "category": "startup_or_readback_unavailable"
            if "fixture startup/readback unavailable" in detail
            else "fixture_error",
        }
        for test, detail in result.errors + result.failures
    ]
    print(json.dumps(receipt))
    return 0 if receipt["status"] == "passed" else 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--worker", action="store_true")
    parser.add_argument("--openbao-only", action="store_true")
    parser.add_argument("--bao", type=Path)
    parser.add_argument(
        "--chromium", type=Path, default=Path("/usr/lib/chromium/chromium")
    )
    args = parser.parse_args()
    if args.worker:
        try:
            return worker()
        except BaseException:
            print(
                json.dumps(
                    {
                        "status": "blocked",
                        "reason": "worker prerequisite or execution unavailable",
                    }
                )
            )
            return 2
    if args.bao is None:
        parser.error("--bao must select the pinned, pre-provisioned fixture binary")
    # Qualification occurs here AND in the worker and fixture entrypoints.
    from browser_testing.account_e2e import qualify

    os.environ["RUNSPINDLE_ACCOUNT_E2E"] = "1"
    qualify(args.bao, args.chromium)
    outcomes = []
    for optimized in (False, True):
        command = (
            [sys.executable, "-B"]
            + (["-O"] if optimized else [])
            + [str(Path(__file__).resolve()), "--worker"]
        )
        environment = {
            "PATH": os.defpath,
            "LANG": "C.UTF-8",
            "RUNSPINDLE_ACCOUNT_E2E": "1",
            "RUNSPINDLE_ACCOUNT_COMPONENT_ONLY": "1" if args.openbao_only else "0",
            "RUNSPINDLE_BAO_BINARY": str(args.bao.resolve()),
            "RUNSPINDLE_CHROMIUM_BINARY": str(args.chromium.resolve()),
        }
        process = subprocess.Popen(
            command,
            cwd=ROOT,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        receipt = {
            "status": "failed",
            "reason": "worker timeout or unavailable receipt",
        }
        try:
            raw, _ = process.communicate(timeout=120)
            if len(raw) <= 16384:
                receipt = json.loads(raw)
        except (subprocess.TimeoutExpired, ValueError):
            pass
        finally:
            # communicate() reaps a normally finished worker; never signal its
            # possibly reusable PID afterward. On timeout it remains owned.
            if process.returncode is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=5)
        outcomes.append(receipt)
    hashes = {
        p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest()
        for p in (
            "browser_testing/account_e2e.py",
            "browser_runtime/autosave.py",
            "browser_runtime/openbao.py",
            "tests/test_account_e2e.py",
            "tests/test_account_openbao.py",
            "tools/qualify_account_e2e.py",
        )
    }
    print(
        json.dumps(
            {
                "status": "passed"
                if all(x.get("status") == "passed" for x in outcomes)
                else "failed",
                "modes": outcomes,
                "source_hashes": hashes,
                "production_authority": "not_qualified",
                "ci_admission": "not_qualified",
            }
        )
    )
    return 0 if all(x.get("status") == "passed" for x in outcomes) else 1


if __name__ == "__main__":
    raise SystemExit(main())

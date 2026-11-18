#!/usr/bin/env python3
"""Real Chromium against synthetic loopback only, never live-site acceptance."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.qualify_effect_reconciliation import (  # noqa: E402
    check,
    inputs,
    qualify_environment,
    run_mode,
)

SUITES = ("test_chromium_effect_site.py", "test_http_effect_site.py")


def source_hashes() -> dict[str, str]:
    result = inputs()
    for name in ("tools/qualify_chromium_effects.py", "tools/browser_cdp.py"):
        result[name] = hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
    return result


def worker() -> int:
    qualify_environment()
    os.environ["RUNSPINDLE_CHROMIUM_EFFECT_TESTS"] = "1"
    child_level = int(
        subprocess.check_output(
            [sys.executable, "-c", "import sys; print(sys.flags.optimize)"],
            text=True,
            timeout=5,
        ).strip()
    )
    suite = unittest.TestSuite(
        unittest.TestLoader().discover(str(ROOT / "tests"), pattern=name)
        for name in SUITES
    )
    expected = suite.countTestCases()
    result = unittest.TextTestRunner(verbosity=2).run(suite)
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
        ),
        flush=True,
    )
    return 0 if passed else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    if args.worker:
        return worker()
    check(args.report is not None, "explicit report path required")
    environment = qualify_environment()
    from browser_testing.chromium_effect_site import ENGINE, ENGINE_SHA256

    engine_hash = hashlib.sha256(ENGINE.read_bytes()).hexdigest()
    check(engine_hash == ENGINE_SHA256, "Chromium executable pin mismatch")
    environment["chromium_executable_sha256"] = engine_hash
    before = source_hashes()
    results = [
        run_mode(
            optimized,
            [
                sys.executable,
                "-I",
                "-B",
                *(["-O"] if optimized else []),
                str(Path(__file__).resolve()),
                "--worker",
            ],
        )
        for optimized in (False, True)
    ]
    check(source_hashes() == before, "qualification source changed during run")
    check(
        hashlib.sha256(ENGINE.read_bytes()).hexdigest() == engine_hash,
        "Chromium executable changed during run",
    )
    report = {
        "status": "passed",
        "evidence_class": "isolated_chromium_synthetic_site",
        "environment": environment,
        "source_hashes": before,
        "suites": list(SUITES),
        "runs": results,
        "boundaries": {
            "browser_engine": "actual_sandboxed_chromium_fresh_profile",
            "site": "synthetic_loopback_http_independent_sqlite_ledger",
            "authority": "synthetic_injected",
            "account_tls_profile_custody": "not_qualified",
            "live_external_actions": "none",
            "core_temporal_engine_integration": "not_exercised",
        },
    }
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

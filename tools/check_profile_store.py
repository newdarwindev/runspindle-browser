#!/usr/bin/env python3
"""Explicit profile dependency gate and real synthetic tests; never install/skip."""

import argparse
import json
import platform
import sqlite3
import subprocess
import sys
from importlib import metadata
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PREFERRED = {"cryptography": "50.0.2", "cffi": "2.1.1", "pycparser": "3.0"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--compatibility",
        action="store_true",
        help="Explicit installed 50.0.0 compatibility evidence only; not preferred-lock qualification",
    )
    args = parser.parse_args()
    expected = dict(PREFERRED)
    if args.compatibility:
        expected["cryptography"] = "50.0.0"
    try:
        actual = {name: metadata.version(name) for name in expected}
    except metadata.PackageNotFoundError:
        print("BLOCKED: mandatory profile dependency unavailable", file=sys.stderr)
        return 2
    if actual != expected:
        print(
            json.dumps(
                {"status": "blocked", "expected": expected, "observed": actual},
                sort_keys=True,
            )
        )
        return 2
    from cryptography.hazmat.backends.openssl.backend import backend

    print(
        json.dumps(
            {
                "evidence": "installed-compatibility"
                if args.compatibility
                else "preferred-dependency-local",
                "production_qualification": "not_run",
                "dependencies": actual,
                "python": platform.python_version(),
                "sqlite": sqlite3.sqlite_version,
                "openssl": backend.openssl_version_text(),
            },
            sort_keys=True,
        ),
        flush=True,
    )
    for flags in ([], ["-O"]):
        result = subprocess.run(
            [
                sys.executable,
                *flags,
                "-m",
                "unittest",
                "discover",
                "-s",
                "tests",
                "-p",
                "test_profile_store.py",
                "-v",
            ],
            cwd=ROOT,
            timeout=120,
        )
        if result.returncode:
            return result.returncode
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

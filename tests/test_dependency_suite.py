"""Dependency-suite reporting must not turn partial component evidence into E2E."""

import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import dependency_suite as suite


class DependencySuiteTests(unittest.TestCase):
    def test_installed_binaries_do_not_imply_integration(self):
        with patch.object(suite.shutil, "which", return_value="/synthetic/bin"):
            value = suite.inventory()
        self.assertEqual(value["full_stack_status"], "blocked")
        self.assertTrue(all(x["found"] for x in value["upstreams"].values()))
        self.assertTrue(all(not x["executed"] for x in value["upstreams"].values()))
        self.assertIn(
            "PinchTab: component adapter and conformance not implemented",
            value["blockers"],
        )

    def test_inventory_never_runs_subprocesses(self):
        with patch.object(
            suite.subprocess, "Popen", side_effect=AssertionError("unexpected process")
        ):
            self.assertEqual(suite.inventory()["full_stack_status"], "blocked")

    def test_root_and_external_interfaces_fail_closed(self):
        with patch.object(os, "geteuid", return_value=0):
            with self.assertRaisesRegex(RuntimeError, "unprivileged"):
                suite.require_isolation()
        with (
            patch.object(os, "geteuid", return_value=1000),
            patch.object(Path, "read_text", return_value="lo: 0\neth0: 0\n"),
        ):
            with self.assertRaisesRegex(RuntimeError, "loopback-only"):
                suite.require_isolation()

    def invoke(self, *args, runs=None):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "report.json"
            with (
                patch.object(
                    suite.sys,
                    "argv",
                    ["dependency_suite", "--report", str(report), *args],
                ),
                patch.object(suite, "run_components", return_value=runs or []) as run,
                contextlib.redirect_stdout(io.StringIO()),
            ):
                code = suite.main()
            return code, json.loads(report.read_text()), run.call_count

    def test_default_is_inventory_only(self):
        code, report, calls = self.invoke()
        self.assertEqual(code, 0)
        self.assertEqual(calls, 0)
        self.assertEqual(report["components_status"], "not_run")
        self.assertEqual(report["coverage"]["browser_engine"], "not_exercised")

    def test_component_pass_cannot_satisfy_full_stack(self):
        code, report, calls = self.invoke("--components", "--require-full-stack")
        self.assertEqual(code, 2)
        self.assertEqual(calls, 1)
        self.assertEqual(report["components_status"], "passed")
        self.assertEqual(report["status"], "blocked")

    def test_failure_receipt_does_not_copy_exception_payload(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "report.json"
            with (
                patch.object(
                    suite.sys,
                    "argv",
                    ["dependency_suite", "--components", "--report", str(report)],
                ),
                patch.object(
                    suite,
                    "run_components",
                    side_effect=RuntimeError("SYNTHETIC_SECRET_CANARY"),
                ),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(suite.main(), 1)
            self.assertNotIn("SYNTHETIC_SECRET_CANARY", report.read_text())
            self.assertEqual(
                json.loads(report.read_text())["components_status"], "failed"
            )


if __name__ == "__main__":
    unittest.main()

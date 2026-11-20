"""Qualification prerequisites fail closed before any acceptance worker starts."""

import importlib.util
import json
import os
import pathlib
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

PATH = (
    pathlib.Path(__file__).resolve().parents[1]
    / "tools/qualify_effect_reconciliation.py"
)
SPEC = importlib.util.spec_from_file_location("effect_qualification", PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("qualification module unavailable")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class QualificationPrerequisites(unittest.TestCase):
    def test_root_is_rejected_before_network_or_fixture_access(self) -> None:
        with patch.object(MODULE.os, "geteuid", return_value=0):
            with self.assertRaisesRegex(RuntimeError, "unprivileged"):
                MODULE.qualify_environment()

    def test_nonloopback_namespace_is_rejected_before_toolchain_access(self) -> None:
        with (
            patch.object(MODULE.os, "geteuid", return_value=1000),
            patch.object(
                MODULE.pathlib.Path, "read_text", return_value="lo: data\neth0: data\n"
            ),
        ):
            with self.assertRaisesRegex(RuntimeError, "loopback-only"):
                MODULE.qualify_environment()

    def test_mismatched_toolchain_is_rejected(self) -> None:
        with (
            patch.object(MODULE.os, "geteuid", return_value=1000),
            patch.object(
                MODULE.pathlib.Path,
                "read_text",
                side_effect=[
                    "lo: data\n",
                    json.dumps(
                        {
                            "python_version": "wrong",
                            "python_sha256": "wrong",
                            "sqlite_version": "wrong",
                        }
                    ),
                ],
            ),
            patch.object(MODULE.pathlib.Path, "read_bytes", return_value=b"fixture"),
        ):
            with self.assertRaisesRegex(RuntimeError, "toolchain pin mismatch"):
                MODULE.qualify_environment()

    def test_missing_sqlite_library_is_a_blocked_prerequisite(self) -> None:
        def file_bytes(path: pathlib.Path) -> bytes:
            if path.name == "libsqlite3.so.0":
                raise FileNotFoundError("fixture library missing")
            return b"fixture"

        with (
            patch.object(MODULE.os, "geteuid", return_value=1000),
            patch.object(
                MODULE.pathlib.Path, "read_text", side_effect=["lo: data\n", "{}"]
            ),
            patch.object(
                MODULE.pathlib.Path, "read_bytes", autospec=True, side_effect=file_bytes
            ),
        ):
            with self.assertRaisesRegex(
                MODULE.QualificationUnavailable, "toolchain pin unavailable"
            ):
                MODULE.qualify_environment()

    def test_missing_network_namespace_is_a_blocked_prerequisite(self) -> None:
        with (
            patch.object(MODULE.os, "geteuid", return_value=1000),
            patch.object(
                MODULE.pathlib.Path, "read_text", side_effect=FileNotFoundError
            ),
            patch.object(MODULE.pathlib.Path, "read_bytes") as toolchain,
        ):
            with self.assertRaisesRegex(
                MODULE.QualificationUnavailable, "network namespace unavailable"
            ):
                MODULE.qualify_environment()
            toolchain.assert_not_called()

    def test_builtin_sqlite_fails_closed_with_qualification_category(self) -> None:
        with (
            patch.object(MODULE.os, "geteuid", return_value=1000),
            patch.object(MODULE._sqlite3, "__file__", None, create=True),
            patch.object(
                MODULE.pathlib.Path, "read_text", side_effect=["lo: data\n", "{}"]
            ),
        ):
            with self.assertRaisesRegex(
                MODULE.QualificationUnavailable, "toolchain pin unavailable"
            ):
                MODULE.qualify_environment()


class QualificationProcessCleanup(unittest.TestCase):
    @staticmethod
    def alive(pid: int) -> bool:
        path = pathlib.Path(f"/proc/{pid}/stat")
        return path.exists() and path.read_text().split()[2] != "Z"

    @staticmethod
    def pid(path: pathlib.Path) -> int:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if path.exists():
                return int(path.read_text())
            time.sleep(0.02)
        raise AssertionError("owned fixture child did not start")

    def test_exited_leader_cannot_leave_descendant_holding_output(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = pathlib.Path(temp) / "pid"
            code = (
                "import os,time,pathlib; pid=os.fork(); "
                f"path=pathlib.Path({str(path)!r}); "
                "path.write_text(str(os.getpid())) if pid==0 else None; "
                "time.sleep(30) if pid==0 else None"
            )
            with patch.object(
                MODULE, "worker_command", return_value=[sys.executable, "-c", code]
            ):
                with self.assertRaisesRegex(RuntimeError, "output incomplete"):
                    MODULE.run_mode(False)
            self.assertFalse(self.alive(self.pid(path)))

    def test_sigterm_cleans_running_owned_worker(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = pathlib.Path(temp) / "pid"
            child = f"import os,time,pathlib; pathlib.Path({str(path)!r}).write_text(str(os.getpid())); time.sleep(30)"
            driver = (
                "import importlib.util; "
                f"s=importlib.util.spec_from_file_location('q',{str(PATH)!r}); "
                "m=importlib.util.module_from_spec(s); s.loader.exec_module(m); "
                f"m.worker_command=lambda optimized: {[sys.executable, '-c', child]!r}; "
                "m.run_mode(False)"
            )
            process = subprocess.Popen(
                [sys.executable, "-c", driver],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
            pid = None
            try:
                pid = self.pid(path)
                process.terminate()
                self.assertEqual(process.wait(timeout=5), 143)
                self.assertFalse(self.alive(pid))
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=5)
                if pid is not None and self.alive(pid):
                    os.killpg(pid, signal.SIGKILL)


if __name__ == "__main__":
    unittest.main()

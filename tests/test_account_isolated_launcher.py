"""Offline launcher safety; does not launch namespaces or upstream binaries."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from tools import run_isolated_account_e2e as launcher


class LauncherTests(unittest.TestCase):
    def test_mount_plan_has_no_host_writable_state_or_security_bypass(self) -> None:
        argv = launcher.command(
            Path("/fixture/bin"),
            Path("/fixture/bao"),
            Path("/usr/lib/chromium/chromium"),
            Path("/fixture/certutil"),
        )
        for flag in (
            "--unshare-net",
            "--unshare-pid",
            "--die-with-parent",
            "--clearenv",
        ):
            self.assertIn(flag, argv)
        self.assertNotIn("--bind", argv)
        self.assertNotIn("--no-sandbox", argv)
        self.assertNotIn("--ignore-certificate-errors", argv)
        self.assertNotIn(str(Path.home()), argv)
        self.assertEqual(argv.count("--tmpfs"), 2)

    def test_root_rejected_before_any_process(self) -> None:
        with (
            patch.object(os, "geteuid", return_value=0),
            patch.object(subprocess, "Popen") as spawn,
        ):
            with self.assertRaises(ValueError):
                launcher.run(Path("/missing"), Path("/missing"), Path("/missing"))
            spawn.assert_not_called()

    def test_unpinned_dependency_rejected_before_process(self) -> None:
        with (
            patch.object(os, "geteuid", return_value=1000),
            patch.object(launcher, "pinned", side_effect=ValueError),
            patch.object(subprocess, "Popen") as spawn,
        ):
            with self.assertRaises(ValueError):
                launcher.run(Path("/missing"), Path("/missing"), Path("/missing"))
            spawn.assert_not_called()

    def test_pin_checks_executable_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory) / "binary"
            p.write_bytes(b"synthetic")
            p.chmod(0o700)
            with self.assertRaises(ValueError):
                launcher.pinned(p, {"0" * 64})
            self.assertEqual(
                launcher.pinned(p, {launcher.hashlib.sha256(b"synthetic").hexdigest()}),
                p,
            )

    def test_main_redacts_upstream_failures(self) -> None:
        from contextlib import redirect_stdout
        import io

        output = io.StringIO()
        with (
            patch.object(
                launcher.sys,
                "argv",
                ["test", "--bao", "/x", "--chromium", "/y", "--certutil", "/z"],
            ),
            patch.object(
                launcher,
                "run",
                side_effect=KeyboardInterrupt("SYNTHETIC_PRIVATE_CANARY"),
            ),
            redirect_stdout(output),
        ):
            self.assertEqual(launcher.main(), 2)
        self.assertNotIn("CANARY", output.getvalue())
        self.assertEqual(json.loads(output.getvalue())["status"], "blocked")


class LifecycleTests(unittest.TestCase):
    """Harmless local Python children only; no bwrap or upstream execution."""

    def invoke(self, code, *, capture_override=None):
        import sys

        real_popen = subprocess.Popen
        real_mkdtemp = tempfile.mkdtemp
        processes, stages = [], []

        def spawn(*args, **kwargs):
            child = real_popen(*args, **kwargs)
            processes.append(child)
            return child

        def stage(**_kwargs):
            path = real_mkdtemp(prefix="launcher-test-")
            stages.append(Path(path))
            return path

        patches = [
            patch.object(Path, "read_bytes", return_value=b"synthetic dependency"),
            patch.object(launcher, "pinned", side_effect=lambda p, _: p),
            patch.object(
                launcher, "command", return_value=[sys.executable, "-c", code]
            ),
            patch.object(launcher.subprocess, "Popen", side_effect=spawn),
            patch.object(launcher.tempfile, "mkdtemp", side_effect=stage),
        ]
        if capture_override is not None:
            patches.append(
                patch.object(launcher, "capture", side_effect=capture_override)
            )
        from contextlib import ExitStack

        error = None
        with ExitStack() as stack:
            for item in patches:
                stack.enter_context(item)
            try:
                launcher.run(
                    Path("/bin/true"),
                    Path("/usr/lib/chromium/chromium"),
                    Path("/bin/true"),
                )
            except BaseException as caught:
                error = type(caught)
        self.assertEqual(len(processes), 1)
        self.assertIsNotNone(processes[0].returncode)
        self.assertTrue(all(not p.exists() for p in stages))
        return error

    def test_stdout_and_stderr_overflow_kill_and_reap(self) -> None:
        for fd in (1, 2):
            error = self.invoke(
                f"import os,time; os.write({fd},b'x'*65536); time.sleep(30)"
            )
            self.assertIs(error, ValueError)

    def test_total_timeout_kills_and_reaps(self) -> None:
        real_capture = launcher.capture
        error = self.invoke(
            "import time; time.sleep(30)",
            capture_override=lambda p: real_capture(p, timeout=0.1),
        )
        self.assertIs(error, TimeoutError)

    def test_sigterm_and_sighup_enter_cleanup_and_restore_handlers(self) -> None:
        import signal

        for sig in (signal.SIGTERM, signal.SIGHUP):
            previous = signal.getsignal(sig)
            error = self.invoke(
                f"import os,signal,time; time.sleep(.1); os.kill(os.getppid(),{sig}); time.sleep(30)"
            )
            self.assertIs(error, launcher.Terminated)
            self.assertEqual(signal.getsignal(sig), previous)

    def test_confirmed_exit_never_signals_reaped_pid(self) -> None:
        with patch.object(launcher.os, "killpg") as kill:
            self.assertIsNone(self.invoke('print(\'{"status":"passed"}\')'))
            kill.assert_not_called()

    def test_uncertain_wait_retains_staging(self) -> None:
        from unittest.mock import Mock
        import shutil

        child = Mock(returncode=None, pid=12345)
        child.wait.side_effect = subprocess.TimeoutExpired("synthetic", 10)
        directory = Path(tempfile.mkdtemp(prefix="launcher-retained-"))
        self.addCleanup(lambda: shutil.rmtree(directory, ignore_errors=True))
        with (
            patch.object(Path, "read_bytes", return_value=b"synthetic dependency"),
            patch.object(launcher, "pinned", side_effect=lambda p, _: p),
            patch.object(launcher.tempfile, "mkdtemp", return_value=str(directory)),
            patch.object(launcher.subprocess, "Popen", return_value=child),
            patch.object(launcher, "capture", side_effect=TimeoutError),
            patch.object(launcher.os, "killpg") as kill,
        ):
            with self.assertRaises(subprocess.TimeoutExpired):
                launcher.run(
                    Path("/bin/true"),
                    Path("/usr/lib/chromium/chromium"),
                    Path("/bin/true"),
                )
        self.assertTrue(directory.exists())
        kill.assert_called_once()
        child.wait.assert_called_once_with(timeout=10)


if __name__ == "__main__":
    unittest.main()

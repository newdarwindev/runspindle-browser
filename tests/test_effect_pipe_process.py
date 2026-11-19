"""Real anonymous OS pipes with fixed synthetic application, not native Core."""

import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from dataclasses import asdict

from browser_runtime.effect_wire import VERSION
from tests.fixtures.effect_pipe_app import TARGET, DIGEST, PAYLOAD

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "tests/fixtures/effect_pipe_app.py"


class PipeProcessTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="pipe-target-")
        self.addCleanup(self.tmp.cleanup)
        self.site = Path(self.tmp.name) / "site-action-state"

    def exchange(self, action, *, lose=False, trailing=False, opt_in=True):
        raw = json.dumps(
            dict(
                version=VERSION,
                action=action,
                target=asdict(TARGET),
                payload_digest=DIGEST,
                payload_hex=PAYLOAD.hex() if action == "dispatch" else None,
            )
        ).encode()
        command = [
            sys.executable,
            "-B",
            *(["-O"] if sys.flags.optimize else []),
            str(APP),
            "--site-state",
            str(self.site),
            "--action",
            action,
        ]
        if lose:
            command.append("--lose-response")
        environment = {"PATH": os.defpath}
        if opt_in:
            environment["RUNSPINDLE_SYNTHETIC_PIPE_APP"] = "1"
        result = subprocess.run(
            command,
            input=struct.pack(">I", len(raw))
            + raw
            + (b"trailing" if trailing else b""),
            capture_output=True,
            timeout=10,
            env=environment,
            cwd=ROOT,
        )
        self.assertEqual(result.stderr, b"")
        outcome = None
        if result.stdout:
            self.assertGreaterEqual(len(result.stdout), 4)
            size = struct.unpack(">I", result.stdout[:4])[0]
            self.assertLessEqual(size, 4096)
            self.assertEqual(size, len(result.stdout) - 4)
            outcome = json.loads(result.stdout[4:])["outcome"]
        return result.returncode, outcome

    def test_process_dispatch_then_fresh_process_reconcile(self):
        self.assertEqual(self.exchange("dispatch"), (0, "unknown"))
        self.assertEqual(self.exchange("reconcile"), (0, "confirmed"))
        self.assertEqual(self.site.read_bytes(), b"accepted\n")

    def test_lost_response_reconcile_does_not_replay(self):
        self.assertEqual(self.exchange("dispatch", lose=True), (2, None))
        self.assertEqual(self.exchange("reconcile"), (0, "confirmed"))
        self.assertEqual(self.site.read_bytes(), b"accepted\n")

    def test_trailing_frame_rejected_before_target_effect(self):
        self.assertEqual(self.exchange("dispatch", trailing=True), (2, None))
        self.assertFalse(self.site.exists())

    def test_fixture_cannot_activate_without_explicit_opt_in(self):
        self.assertEqual(self.exchange("dispatch", opt_in=False), (2, None))
        self.assertFalse(self.site.exists())


if __name__ == "__main__":
    unittest.main()

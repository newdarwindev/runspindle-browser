"""Actual guarded Journal, synthetic exact grant/site, no network or credentials."""

import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from dataclasses import asdict, replace
from pathlib import Path
from typing import Any, Callable, cast
from unittest.mock import patch

from browser_runtime.effect_wire import (
    EVIDENCE_CLASS,
    MAX_REQUEST,
    VERSION,
    Receiver,
    decode,
)
from browser_runtime.effects import Cancelled, Denied
from tests.test_guarded_effects import DIGEST, PAYLOAD, TARGET, Fixture


def request(action: str = "dispatch") -> dict[str, Any]:
    return {
        "version": VERSION,
        "action": action,
        "target": asdict(TARGET),
        "payload_digest": DIGEST,
        "payload_hex": PAYLOAD.hex() if action == "dispatch" else None,
    }


def encoded(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


class WireTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        factory: Callable[[str], Any] = Fixture
        self.f = factory(self.tmp.name)
        self.j = self.f.journal()
        self.addCleanup(self.j.close)
        self.receiver = Receiver(self.j)

    def exchange(self, value: dict[str, Any]) -> str:
        raw = encoded(value)
        result = json.loads(self.receiver.exchange(raw, "admitted"))
        self.assertEqual(
            set(result), {"version", "request_sha256", "evidence_class", "outcome"}
        )
        self.assertEqual(result["version"], VERSION)
        self.assertEqual(result["request_sha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(result["evidence_class"], EVIDENCE_CLASS)
        return cast(str, result["outcome"])

    def test_valid_unknown_then_separate_reconcile_and_raw_byte_commitment(
        self,
    ) -> None:
        self.assertEqual(self.exchange(request()), "unknown")
        self.assertEqual(self.f.effects(), 1)
        self.f.grant = replace(self.f.grant, action="reconcile")
        self.assertEqual(self.exchange(request("reconcile")), "confirmed")
        self.assertEqual(self.f.reads, 1)
        raw = json.dumps(request("reconcile"), indent=2).encode()
        response = json.loads(self.receiver.exchange(raw, "admitted"))
        self.assertEqual(response["request_sha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(self.f.effects(), 1)

    def test_closed_malformed_duplicate_oversize_before_authority(self) -> None:
        valid = encoded(request())
        cases: list[Any] = [
            b"",
            b"{",
            valid.decode(),
            b"x" * (MAX_REQUEST + 1),
            b'{"version":1,"version":2}',
            valid.replace(b'"epoch":1', b'"epoch":1,"epoch":1'),
            valid.replace(b'"epoch":1', b'"epoch":true'),
            valid.replace(b'"epoch":1', b'"epoch":NaN'),
            valid.replace(b'"frame":"frame"', b'"frame":"\\ud800"'),
            encoded({**request(), "ticket": "SYNTHETIC-PRIVATE"}),
            b"[" * 2000 + b"]" * 2000,
        ]
        for raw in cases:
            with self.subTest(raw_type=type(raw), length=len(raw)):
                with self.assertRaises(Denied) as caught:
                    self.receiver.exchange(raw, "admitted")
                self.assertEqual(str(caught.exception), "effect wire denied")
                self.assertIsNone(caught.exception.__context__)
                self.assertIsNone(caught.exception.__cause__)
        self.assertEqual(self.f.current_calls, 0)
        self.assertEqual(self.f.effects(), 0)
        self.assertEqual(self.f.reads, 0)

    def test_target_fields_cannot_retarget_authenticated_grant(self) -> None:
        cases = []
        for field, value in [
            ("account", "other"),
            ("principal", "other"),
            ("browser", "other"),
            ("tab", "other"),
            ("intent", "other"),
            ("operation", "other"),
            ("revision", 2),
            ("epoch", 2),
            ("origin", "https://other.invalid"),
        ]:
            candidate = request()
            candidate["target"]["binding"][field] = value
            cases.append(candidate)
        for field, value in [
            ("native_session", "other"),
            ("frame", "other"),
            ("frame_origin", "https://other.invalid"),
        ]:
            candidate = request()
            candidate["target"][field] = value
            cases.append(candidate)
        for candidate in cases:
            with self.subTest(target=candidate["target"]), self.assertRaises(Denied):
                self.receiver.exchange(encoded(candidate), "admitted")
        self.assertEqual(self.f.effects(), 0)
        self.assertEqual(self.f.reads, 0)
        self.assertEqual(
            self.j._journal.db.execute("SELECT count(*) FROM operations").fetchone()[0],
            0,
        )

    def test_action_digest_payload_and_ticket_are_not_authority(self) -> None:
        candidates = [request("reconcile")]
        wrong = request()
        wrong["payload_digest"] = "b" * 64
        candidates.append(wrong)
        wrong = request()
        wrong["payload_hex"] = b"other".hex()
        wrong["payload_digest"] = hashlib.sha256(b"other").hexdigest()
        candidates.append(wrong)
        for candidate in candidates:
            with self.assertRaises(Denied):
                self.receiver.exchange(encoded(candidate), "admitted")
        with self.assertRaises(Denied):
            self.receiver.exchange(encoded(request()), "wrong-ticket")
        self.assertEqual(self.f.effects(), 0)
        self.assertEqual(self.f.reads, 0)
        self.assertEqual(
            self.j._journal.db.execute("SELECT count(*) FROM operations").fetchone()[0],
            0,
        )

    def test_reconcile_requires_exact_digest_and_target_before_readback(self) -> None:
        self.exchange(request())
        self.f.grant = replace(self.f.grant, action="reconcile")
        candidate = request("reconcile")
        candidate["payload_digest"] = "b" * 64
        with self.assertRaises(Denied):
            self.receiver.exchange(encoded(candidate), "admitted")
        candidate = request("reconcile")
        candidate["target"]["native_session"] = "other"
        with self.assertRaises(Denied):
            self.receiver.exchange(encoded(candidate), "admitted")
        self.assertEqual(self.f.reads, 0)
        self.assertEqual(self.f.effects(), 1)

    def test_payload_encoding_and_closed_nested_shapes(self) -> None:
        cases = []
        for payload in ["", "A0", "ab ", "a", "0" * (2 * 1048576 + 2), 1, None]:
            candidate = request()
            candidate["payload_hex"] = payload
            cases.append(candidate)
        candidate = request("reconcile")
        candidate["payload_hex"] = "ab"
        cases.append(candidate)
        candidate = request()
        candidate["target"]["secret"] = "canary"
        cases.append(candidate)
        candidate = request()
        del candidate["target"]["binding"]["account"]
        cases.append(candidate)
        for candidate in cases:
            with self.assertRaises(Denied):
                decode(encoded(candidate))
        self.assertEqual(self.f.effects(), 0)

    def test_lost_bridge_response_fresh_process_duplicate_never_submits(self) -> None:
        self.f.lost = True
        self.receiver.exchange(encoded(request()), "admitted")  # Discard the response.
        self.j.close()
        code = """import sys, json
sys.path.insert(0, 'tests')
from test_effect_wire import Fixture, Receiver, encoded, request
from dataclasses import replace
f=Fixture(sys.argv[1]); j=f.journal(); r=Receiver(j)
print(r.exchange(encoded(request()), 'admitted').decode())
f.grant=replace(f.grant, action='reconcile')
print(r.exchange(encoded(request('reconcile')), 'admitted').decode())
j.close()
"""
        run = subprocess.run(
            [sys.executable, "-c", code, self.tmp.name],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(
            [json.loads(line)["outcome"] for line in run.stdout.splitlines()],
            ["unknown", "confirmed"],
        )
        self.assertEqual(self.f.effects(), 1)

    def test_cancellation_and_upstream_errors_are_scrubbed(self) -> None:
        self.f.cancel = True
        with self.assertRaises(Cancelled) as caught:
            self.receiver.exchange(encoded(request()), "admitted")
        self.assertEqual(str(caught.exception), "effect wire cancelled")
        self.assertIsNone(caught.exception.__context__)
        self.assertIsNone(caught.exception.__cause__)
        self.assertEqual(self.f.effects(), 1)
        self.f.cancel = False
        self.f.exit_error = True
        with self.assertRaises(Denied) as denied:
            self.receiver.exchange(encoded(request()), "admitted")
        self.assertEqual(str(denied.exception), "effect wire denied")
        self.assertIsNone(denied.exception.__context__)
        self.assertEqual(self.f.effects(), 1)

    def test_reentrant_exchange_cannot_replace_outer_request(self) -> None:
        attempts: list[bool] = []

        def reenter() -> None:
            if attempts:
                return
            attempts.append(True)
            other = request()
            other["target"]["binding"]["account"] = "other"
            with self.assertRaises(Denied):
                self.receiver.exchange(encoded(other), "admitted")

        self.f.at_current = reenter
        self.assertEqual(self.exchange(request()), "unknown")
        self.assertEqual(self.f.effects(), 1)
        self.assertEqual(len(attempts), 1)

    def test_parser_cancellation_and_active_exception_context_are_fixed(self) -> None:
        with patch(
            "browser_runtime.effect_wire.json.loads",
            side_effect=KeyboardInterrupt("SYNTHETIC-PRIVATE"),
        ):
            with self.assertRaises(Cancelled) as caught:
                self.receiver.exchange(encoded(request()), "admitted")
        self.assertEqual(str(caught.exception), "effect wire cancelled")
        self.assertIsNone(caught.exception.__context__)
        try:
            raise RuntimeError("SYNTHETIC-PRIVATE")
        except RuntimeError:
            with self.assertRaises(Denied) as denied:
                self.receiver.exchange(b"{", "admitted")
        self.assertIsNone(denied.exception.__context__)
        self.assertIsNone(denied.exception.__cause__)
        self.assertEqual(self.f.effects(), 0)

    def test_literal_wire_vector_has_exact_response_commitment(self) -> None:
        raw = (
            b'{"version":"runspindle.browser-effect.v1","action":"dispatch",'
            b'"target":{"binding":{"principal":"principal","account":"account",'
            b'"browser":"browser","tab":"tab","intent":"intent","revision":1,'
            b'"operation":"operation","epoch":1,"origin":"https://example.invalid"},'
            b'"native_session":"session","frame":"frame","frame_origin":"https://example.invalid"},'
            b'"payload_digest":"2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881",'
            b'"payload_hex":"78"}'
        )
        self.f.grant = replace(
            self.f.grant,
            payload_digest="2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881",
        )
        expected = (
            b'{"evidence_class":"browser_guarded_effect_observation","outcome":"unknown",'
            b'"request_sha256":"676116b8037e2e3c4d32b5e5bfc6d61e3830a448819c83a4a8209723c24b7a89",'
            b'"version":"runspindle.browser-effect.v1"}'
        )
        self.assertEqual(decode(raw).payload, b"x")
        self.assertEqual(self.receiver.exchange(raw, "admitted"), expected)
        self.assertEqual(self.f.effects(), 1)

    def test_expectation_bypass_mutants_fail_named_regressions(self) -> None:
        source = Path(__file__).resolve().parents[1]
        for anchor, replacement, case in [
            (
                "expected_target != grant.target",
                "False",
                "test_target_fields_cannot_retarget_authenticated_grant",
            ),
            (
                "or expected_digest != grant.payload_digest",
                "",
                "test_reconcile_requires_exact_digest_and_target_before_readback",
            ),
        ]:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                shutil.copytree(
                    source / "browser_runtime",
                    root / "browser_runtime",
                    ignore=shutil.ignore_patterns("__pycache__"),
                )
                (root / "tests").mkdir()
                (root / "tests/__init__.py").write_text("")
                for name in ["test_effect_wire.py", "test_guarded_effects.py"]:
                    shutil.copyfile(source / "tests" / name, root / "tests" / name)
                command = [
                    sys.executable,
                    "-B",
                    "-m",
                    "unittest",
                    "-v",
                    "tests.test_effect_wire.WireTests." + case,
                ]
                baseline = subprocess.run(
                    command, cwd=root, capture_output=True, text=True, timeout=15
                )
                self.assertEqual(baseline.returncode, 0, baseline.stderr)
                self.assertIn("OK", baseline.stderr)
                module = root / "browser_runtime/guarded_peer.py"
                original = module.read_text()
                self.assertEqual(original.count(anchor), 1)
                module.write_text(original.replace(anchor, replacement))
                mutant = subprocess.run(
                    command, cwd=root, capture_output=True, text=True, timeout=15
                )
                self.assertNotEqual(mutant.returncode, 0)
                self.assertIn("FAIL: " + case, mutant.stderr)
                self.assertIn("Denied not raised", mutant.stderr)

    def test_optional_expectations_do_not_replace_legacy_api(self) -> None:
        with self.assertRaises(Denied):
            self.j.dispatch("admitted", PAYLOAD, expected_target=TARGET)
        with self.assertRaises(Denied):
            self.j.dispatch("admitted", PAYLOAD, expected_digest=DIGEST)
        self.assertEqual(self.f.effects(), 0)
        self.assertEqual(self.j.dispatch("admitted", PAYLOAD), "unknown")


if __name__ == "__main__":
    unittest.main()

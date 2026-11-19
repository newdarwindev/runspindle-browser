"""Pinned Python fixture consumption; not Rust/native/browser runtime conformance."""

import copy
import hashlib
import importlib.util
import json
import marshal
from pathlib import Path
import shutil
import subprocess
import struct
import sys
import tempfile
import unittest
from types import ModuleType
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
BUNDLE = ROOT / "fixtures/shared-v1"
PIN = {
    "component": "browser",
    "fixture_schema": "runspindle.fixture.v1",
    "repository": "newdarwindev/runspindle",
    "rights_basis": "Owner-directed reuse of original Runspindle synthetic "
    "fixtures; source bytes and notices retained; no blanket "
    "relicense.",
    "schema": "runspindle.fixture.pin.v1",
    "scope": "synthetic-fixture-consumer-only; not a runtime wire protocol or "
    "upstream qualification",
    "source_bundle_tree": "3be3d0b80358f4801dfa20e55d32b49f50e9c6ea",
    "source_commit": "e283957d80aebc48fb0bd3b6e2a600850ff6dc97",
    "source_manifest_sha256": "11ba400c1e9a82566496678104200538f7d2f9b3394d73e65b6ad75c83c2d1ed",
    "source_validator_blob": "623b1bae0c85b14563e2738259038bf53c021bae",
    "subset_manifest_sha256": "274be4d8c6845bae81d822cf34fe0b19e9f248664a23fec08620a900988bd561",
    "validator_sha256": "29857e337c30f84e673387a2ac27c7f0fc95bada1d783b346085286251f65279",
}
EXPECTED_IDENTITY = {
    "account_ref": "synthetic-account-ref",
    "attempt": 1,
    "browser_id": "synthetic-browser-id",
    "event_id": "synthetic-event-id",
    "host_id": "synthetic-host-id",
    "intent_revision": 1,
    "lease_epoch": 2,
    "native_session_id": "synthetic-native-session-id",
    "operation_id": "synthetic-operation-id",
    "policy_revision": 1,
    "sequence": 0,
    "span_id": "synthetic-span-id",
    "task_id": "synthetic-task-id",
    "trace_id": "synthetic-trace-id",
    "workspace_id": "synthetic-workspace-id",
}
EXPECTED_KIND = "browser.observed"
EXPECTED_STATE = "passive"


def checked_kit(root=ROOT):
    """Check reviewed hashes before executing any vendored Python code."""
    pin = json.loads((root / "fixtures/shared-v1.pin.json").read_text())
    if pin != PIN:
        raise ValueError("pin-mismatch")
    bundle = root / "fixtures/shared-v1"
    verified = {}
    for name, expected in [
        ("manifest.json", PIN["subset_manifest_sha256"]),
        ("fixturekit.py", PIN["validator_sha256"]),
    ]:
        verified[name] = (bundle / name).read_bytes()
        if hashlib.sha256(verified[name]).hexdigest() != expected:
            raise ValueError("pinned-file-mismatch")
    # Execute the exact verified snapshot; ignored .pyc files cannot substitute code.
    kit = ModuleType("pinned_fixturekit")
    kit.__file__ = str(bundle / "fixturekit.py")
    exec(compile(verified["fixturekit.py"], kit.__file__, "exec"), kit.__dict__)
    manifest = kit.verify_bundle(bundle)
    if manifest["origin_manifest_sha256"] != PIN["source_manifest_sha256"]:
        raise ValueError("origin-mismatch")
    if manifest["component"] != PIN["component"]:
        raise ValueError("component-mismatch")
    return kit


class ConsumerFixtures(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.network = []

        def deny(*args, **kwargs):
            raise AssertionError("unexpected network access")

        for target in [
            "socket.create_connection",
            "socket.socket.connect",
            "socket.getaddrinfo",
        ]:
            guard = patch(target, side_effect=deny)
            guard.start()
            cls.network.append(guard)
        cls.kit = checked_kit()

    @classmethod
    def tearDownClass(cls):
        for guard in reversed(cls.network):
            guard.stop()

    def envelope(self):
        fixtures = self.kit.load_json(BUNDLE / "golden.json")
        self.assertEqual(len(fixtures), 1)
        self.assertEqual(fixtures[0]["kind"], EXPECTED_KIND)
        return fixtures[0]

    def reject(self, code, callback):
        with self.assertRaises(self.kit.ContractError) as error:
            callback()
        self.assertEqual(str(error.exception), code)

    def test_fixed_pin_and_golden_identity(self) -> None:
        self.assertEqual(
            PIN["source_commit"], "e283957d80aebc48fb0bd3b6e2a600850ff6dc97"
        )
        self.assertEqual(PIN["fixture_schema"], "runspindle.fixture.v1")
        self.assertTrue(
            self.kit.assert_conforms(self.envelope(), EXPECTED_IDENTITY, EXPECTED_STATE)
        )

    def test_published_positive_and_negative_vectors(self) -> None:
        original = self.envelope()
        vectors = self.kit.load_json(BUNDLE / "vectors.json")
        self.assertGreaterEqual(len(vectors), 2)
        for vector in vectors:
            self.assertEqual(vector["kind"], EXPECTED_KIND)
            broken = copy.deepcopy(original)
            target = broken
            path = vector["mutation"]["path"]
            for part in path[:-1]:
                target = target[part]
            target[path[-1]] = vector["mutation"]["value"]
            with self.subTest(vector=vector["id"]):
                self.reject(
                    vector["expected_error"],
                    lambda: self.kit.assert_conforms(
                        broken, EXPECTED_IDENTITY, EXPECTED_STATE
                    ),
                )

    def test_changed_identity_and_unknown_outcome_cannot_pass(self) -> None:
        for key, value in EXPECTED_IDENTITY.items():
            broken = copy.deepcopy(self.envelope())
            broken["identity"][key] = (
                value + 1 if type(value) is int else "synthetic-other"
            )
            # Digest fields are absent from these native/browser fixture kinds.
            with self.subTest(identity=key):
                self.reject(
                    "identity-mismatch",
                    lambda: self.kit.assert_conforms(
                        broken, EXPECTED_IDENTITY, EXPECTED_STATE
                    ),
                )
        broken = copy.deepcopy(self.envelope())
        broken["state"] = "unknown"
        self.reject("uncertainty-is-not-success", lambda: self.kit.validate(broken))
        broken["status"] = "unknown"
        self.kit.validate(broken)
        self.reject(
            "outcome-mismatch",
            lambda: self.kit.assert_conforms(broken, EXPECTED_IDENTITY, EXPECTED_STATE),
        )

    def test_unknown_fields_and_boolean_revisions_reject(self) -> None:
        broken = copy.deepcopy(self.envelope())
        broken["identity"]["intent_revision"] = True
        self.reject("field-type-or-bound", lambda: self.kit.validate(broken))
        broken = copy.deepcopy(self.envelope())
        broken["secret"] = "synthetic-canary"
        self.reject("unknown-key", lambda: self.kit.validate(broken))

    def test_corruption_and_pin_rewrite_fail_before_loading_code(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shutil.copytree(
                ROOT / "fixtures",
                root / "fixtures",
                ignore=shutil.ignore_patterns("__pycache__"),
            )
            path = root / "fixtures/shared-v1/fixturekit.py"
            path.write_text('raise RuntimeError("must not execute")')
            with self.assertRaisesRegex(ValueError, "pinned-file-mismatch"):
                checked_kit(root)
            pin = copy.deepcopy(PIN)
            pin["source_commit"] = "0" * 40
            (root / "fixtures/shared-v1.pin.json").write_text(json.dumps(pin))
            with self.assertRaisesRegex(ValueError, "pin-mismatch"):
                checked_kit(root)

    def test_unreviewed_bytecode_cannot_replace_verified_source(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shutil.copytree(
                ROOT / "fixtures",
                root / "fixtures",
                ignore=shutil.ignore_patterns("__pycache__"),
            )
            source = root / "fixtures/shared-v1/fixturekit.py"
            with patch.object(sys, "pycache_prefix", None):
                cache = Path(importlib.util.cache_from_source(str(source)))
                cache.parent.mkdir()
                header = importlib.util.MAGIC_NUMBER + struct.pack(
                    "<III", 0, int(source.stat().st_mtime), source.stat().st_size
                )
                unreviewed = compile(
                    "raise AssertionError('unreviewed bytecode executed')",
                    str(source),
                    "exec",
                )
                cache.write_bytes(header + marshal.dumps(unreviewed))
                checked_kit(root)

    def test_standalone_with_no_sibling_and_denied_network(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shutil.copytree(
                ROOT / "fixtures",
                root / "fixtures",
                ignore=shutil.ignore_patterns("__pycache__"),
            )
            source = ROOT / "tests/test_shared_fixtures.py"
            # Load checked_kit without running unittest; no original checkout on sys.path.
            wrapper = "import socket, runpy; deny=lambda *a,**k: (_ for _ in ()).throw(RuntimeError('network denied')); socket.socket.connect=deny; socket.create_connection=deny; socket.getaddrinfo=deny; namespace=runpy.run_path('consumer.py'); namespace['checked_kit']()"
            shutil.copyfile(source, root / "consumer.py")
            # The copied consumer is one level deeper so ROOT remains the isolated root.
            (root / "tests").mkdir()
            shutil.move(str(root / "consumer.py"), str(root / "tests/consumer.py"))
            wrapper = wrapper.replace("'consumer.py'", "'tests/consumer.py'")
            process = subprocess.run(
                [sys.executable, "-I", "-c", wrapper],
                cwd=root,
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertEqual(process.returncode, 0, process.stderr)


if __name__ == "__main__":
    unittest.main()

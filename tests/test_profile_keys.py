"""Real SQLite/process custody and AEAD, synthetic material transport, no network."""

import base64
import json
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import traceback
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from browser_runtime.openbao import Response
from browser_runtime.profile_custody_schema import GATE, LEASE
from browser_runtime.profile_keys import Keys
from browser_runtime.profile_store import Adapters, Cancelled, Denied, Store
from browser_testing.profile_keys_fixtures import (
    STORE_ID,
    TOKEN,
    Peer,
    mapping,
    operation,
    provision,
)
from browser_testing.profile_store_fixtures import CANARY, KEY, Fake

ROOT = Path(__file__).resolve().parents[1]


class CustodyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.directory = self.root / "custody"
        self.m = mapping()
        self.digest = provision(self.directory, (self.m,))
        self.peer = Peer()
        self.keys = self.peer.keys(self.directory, self.digest)
        network = patch.object(
            socket.socket, "connect", side_effect=AssertionError("network forbidden")
        )
        network.start()
        self.addCleanup(network.stop)

    def states(self) -> list[str]:
        with sqlite3.connect(self.directory / GATE) as db:
            return [
                row[0]
                for row in db.execute("SELECT state FROM attempts ORDER BY rowid")
            ]

    def take(self, name: str = "first") -> None:
        with self.keys.acquire(STORE_ID, operation(name), None) as key:
            self.assertEqual(key.material, KEY)
            self.assertEqual(key.version, self.m.key_id())
            self.assertEqual(self.states()[-1], "issued")
            self.assertNotIn(base64.b64encode(KEY).decode(), repr(key))

    def test_fixed_version_material_and_durable_burn(self) -> None:
        self.take()
        self.assertEqual(self.peer.calls, ["/v1/profiles/data/synthetic/key?version=3"])
        self.assertEqual(self.states(), ["released"])
        # Fresh equivalent grant has a different deadline, not a new attempt.
        with self.assertRaises(Denied):
            self.take()
        self.assertEqual(len(self.peer.calls), 1)
        self.keys = self.peer.keys(self.directory, self.digest)
        with self.assertRaises(Denied):
            self.take()
        self.take("second")

    def test_exact_restore_version_and_no_latest_alias(self) -> None:
        for bad in (None, "latest", "3", "b" * 64):
            with (
                self.assertRaises(Denied),
                self.keys.acquire(STORE_ID, operation("bad", "restore"), bad),
            ):
                self.fail("delivered")
        self.assertEqual(self.peer.tokens, 0)
        with self.keys.acquire(
            STORE_ID, operation("restore", "restore"), self.m.key_id()
        ) as key:
            self.assertEqual(key.material, KEY)

    def test_scope_deadline_and_action_denials_before_provider(self) -> None:
        g = operation()
        targets = [
            replace(g, profile="other"),
            replace(g, deadline=0),
            replace(
                g,
                target=replace(
                    g.target, binding=replace(g.target.binding, account="other")
                ),
            ),
            replace(g, target=replace(g.target, frame_origin="https://other.example")),
            replace(g, action="forget"),
        ]
        for candidate in targets:
            with (
                self.assertRaises(Denied),
                self.keys.acquire(STORE_ID, candidate, None),
            ):
                self.fail("delivered")
        with self.assertRaises(Denied), self.keys.acquire("b" * 64, g, None):
            self.fail("delivered")
        self.assertEqual((self.peer.tokens, self.peer.calls), (0, []))

    def test_revoke_before_acquire_and_after_token_has_zero_http(self) -> None:
        self.peer.on_token = lambda: self.keys.revoke(self.m.key_id())
        with self.assertRaises(Denied):
            self.take()
        self.assertEqual(self.peer.calls, [])
        self.assertEqual(self.keys.revoke(self.m.key_id()), "new-leases-disabled")
        with self.assertRaises(Denied):
            self.take("second")
        self.assertEqual(self.peer.tokens, 1)

    def test_revoke_during_fetch_denies_issue(self) -> None:
        self.peer.on_fetch = lambda: self.keys.revoke(self.m.key_id())
        with self.assertRaises(Denied):
            self.take()
        self.assertEqual(len(self.peer.calls), 1)
        self.assertEqual(self.states(), ["released"])

    def test_issued_lease_survives_disable_new_lease_does_not(self) -> None:
        with self.keys.acquire(STORE_ID, operation(), None) as key:
            self.assertEqual(self.keys.revoke(self.m.key_id()), "new-leases-disabled")
            self.assertEqual(key.material, KEY)
        with self.assertRaises(Denied):
            self.take("second")
        self.assertEqual(len(self.peer.calls), 1)

    def test_expiry_after_fetch_denies(self) -> None:
        now = [1.0]
        self.keys = Keys(
            self.directory,
            expected_manifest=self.digest,
            transport=self.peer.transport,
            token_source=self.peer.token,
            clock=lambda: now[0],
        )
        self.peer.on_fetch = lambda: now.__setitem__(0, 3.0)
        with (
            self.assertRaises(Denied),
            self.keys.acquire(STORE_ID, replace(operation(), deadline=2), None),
        ):
            self.fail("delivered")
        self.assertEqual(self.states(), ["released"])

    def test_provider_metadata_and_canonical_key_fail_closed(self) -> None:
        replies = [
            Peer.response(version=4),
            Peer.response(version=True),
            Peer.response(destroyed=True),
            Peer.response(deletion_time="future"),
            Response(302, b"{}"),
            Response(200, b'{"data":{},"data":{}}'),
            Response(200, b"x" * 65537),
        ]
        for value in (
            base64.b64encode(b"x" * 32).decode(),
            "!" * 44,
            base64.b64encode(b"x" * 31).decode(),
            "password",
        ):
            data = json.loads(Peer.response().body)
            data["data"]["data"]["key"] = value
            replies.append(Response(200, json.dumps(data).encode()))
        for i, reply in enumerate(replies):
            self.peer.reply = reply
            with self.assertRaises(Denied):
                self.take(str(i))
        self.assertEqual(self.states(), ["released"] * len(replies))

    def test_sanitized_errors_cancellation_and_release(self) -> None:
        for i, exception in enumerate((ValueError, KeyboardInterrupt, SystemExit)):

            def fail() -> None:
                raise exception(TOKEN)

            self.peer.on_fetch = fail
            try:
                self.take(str(i))
            except (Denied, Cancelled) as error:
                self.assertIsNone(error.__context__)
                self.assertIsNone(error.__cause__)
                self.assertNotIn(TOKEN, "".join(traceback.format_exception(error)))
                self.assertEqual(
                    isinstance(error, Cancelled), exception is not ValueError
                )
            else:
                self.fail("expected rejection")
        self.peer.on_fetch = lambda: None
        self.take("after")
        self.assertEqual(self.states(), ["released"] * 4)

    def test_consumer_failure_and_recursive_use_release(self) -> None:
        with self.assertRaises(Denied), self.keys.acquire(STORE_ID, operation(), None):
            with self.assertRaises(Denied):
                self.take("nested")
            raise ValueError(TOKEN)
        self.take("after")
        self.assertEqual(len(self.peer.calls), 2)

    def test_no_provisioning_or_schema_repair(self) -> None:
        before = set(self.root.iterdir())
        with self.assertRaises(Denied):
            self.peer.keys(self.root / "missing", self.digest)
        self.assertEqual(set(self.root.iterdir()), before)
        with sqlite3.connect(self.directory / GATE) as db:
            db.execute("CREATE TABLE unexpected (a TEXT)")
        with self.assertRaises(Denied):
            self.peer.keys(self.directory, self.digest)
        with self.assertRaises(Denied):
            self.take()
        self.assertEqual(self.peer.calls, [])

    def test_manifest_pin_and_duplicate_material_scopes(self) -> None:
        with self.assertRaises(Denied):
            self.peer.keys(self.directory, "b" * 64)
        for i, extra in enumerate(
            (
                replace(self.m, store_id="b" * 64, path=("other",)),
                replace(self.m, profile="other", path=("other",)),
                replace(self.m, kv_version=4, save_key=False),
                replace(self.m, fingerprint="b" * 64, store_id="b" * 64),
            )
        ):
            folder = self.root / str(i)
            digest = provision(folder, (self.m, extra))
            with self.assertRaises(Denied):
                self.peer.keys(folder, digest)
        self.assertEqual(self.peer.tokens, 0)

    def test_registry_mutation_is_not_authority(self) -> None:
        with sqlite3.connect(self.directory / GATE) as db:
            other = replace(self.m, path=("other",))
            db.execute(
                "UPDATE registry SET config=?,key_id=?",
                (other.config(), other.key_id()),
            )
        with self.assertRaises(Denied):
            self.take()
        self.assertEqual(self.peer.tokens, 0)

    def test_path_replacement_and_symlink_deny(self) -> None:
        path = self.directory / LEASE
        path.rename(self.root / "old")
        path.symlink_to(self.root / "old")
        with self.assertRaises(Denied):
            self.take()
        self.assertEqual(self.peer.tokens, 0)

    def test_restart_after_crash_never_replays_pending_or_issued(self) -> None:
        for i, stage in enumerate(("pending", "issued")):
            folder = self.root / stage
            digest = provision(folder, (self.m,))
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "browser_testing.profile_keys_fixtures",
                    str(folder),
                    stage,
                ],
                cwd=ROOT,
                timeout=10,
                capture_output=True,
            )
            self.assertEqual(result.returncode, 41 + i, result.stderr)
            peer = Peer()
            keys = peer.keys(folder, digest)
            with self.assertRaises(Denied), keys.acquire(STORE_ID, operation(), None):
                self.fail("replayed")
            self.assertEqual(peer.calls, [])
            with keys.acquire(STORE_ID, operation("fresh"), None):
                pass
            with sqlite3.connect(folder / GATE) as db:
                self.assertEqual(
                    db.execute("SELECT state FROM attempts ORDER BY rowid").fetchall(),
                    [("abandoned",), ("released",)],
                )

    def test_real_cross_process_fence_and_concurrent_revocation(self) -> None:
        process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "browser_testing.profile_keys_fixtures",
                str(self.directory),
                "hold",
            ],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            deadline = time.monotonic() + 5
            while not (self.root / "ready").exists():
                self.assertIsNone(process.poll())
                self.assertLess(time.monotonic(), deadline)
                time.sleep(0.01)
            with self.assertRaises(Denied):
                self.take("contender")
            self.assertEqual(self.peer.calls, [])
            administrator = self.peer.keys(self.directory, self.digest)
            self.assertEqual(
                administrator.revoke(self.m.key_id()), "new-leases-disabled"
            )
            (self.root / "release").touch()
            _, stderr = process.communicate(timeout=5)
            self.assertEqual(process.returncode, 0, stderr)
            with self.assertRaises(Denied):
                self.take("after")
        finally:
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=5)

    def test_real_store_roundtrip_and_precise_forget(self) -> None:
        directory = self.root / "profiles"
        directory.mkdir(mode=0o700)
        fake = Fake()
        store = Store(directory)
        self.addCleanup(store.close)
        store_id = store._store_id
        folder = self.root / "integrated-custody"
        m = mapping(store_id)
        digest = provision(folder, (m,))
        keys = self.peer.keys(folder, digest)
        store._adapters = Adapters(fake, keys, fake)
        fake.grant = operation("save")
        self.assertEqual(store.run("trusted-ticket"), "stored")
        fake.grant = operation("restore", "restore")
        self.assertEqual(store.run("trusted-ticket"), "delivered")
        self.assertEqual(fake.received, [CANARY])
        keys.revoke(m.key_id())
        fake.grant = operation("forget", "forget")
        self.assertEqual(store.run("trusted-ticket"), "forgotten")
        self.assertEqual(len(self.peer.calls), 2)
        for path in self.root.rglob("*"):
            if path.is_file():
                content = path.read_bytes()
                for secret in (CANARY, KEY, base64.b64encode(KEY), TOKEN.encode()):
                    self.assertNotIn(secret, content, str(path))

    def test_cleanup_failure_releases_process_fence_and_burns_attempt(self) -> None:
        for i, error_type in enumerate((ValueError, KeyboardInterrupt)):
            expected = Denied if error_type is ValueError else Cancelled
            failure = patch.object(self.keys, "_gate", side_effect=error_type(TOKEN))
            try:
                with self.assertRaises(expected) as caught:
                    with self.keys.acquire(STORE_ID, operation(str(i)), None):
                        failure.start()
            finally:
                failure.stop()
            self.assertIsNone(caught.exception.__context__)
            self.assertNotIn(
                TOKEN, "".join(traceback.format_exception(caught.exception))
            )
            with self.assertRaises(Denied):
                self.take(str(i))
            self.take("after-" + str(i))

    def test_store_authority_revocation_remains_immediate(self) -> None:
        directory = self.root / "profiles"
        directory.mkdir(mode=0o700)
        fake = Fake()
        store = Store(directory)
        self.addCleanup(store.close)
        folder = self.root / "authority-custody"
        m = mapping(store._store_id)
        digest = provision(folder, (m,))
        keys = self.peer.keys(folder, digest)
        store._adapters = Adapters(fake, keys, fake)
        fake.grant = operation("authority")
        self.peer.on_fetch = lambda: setattr(fake, "allowed", False)
        with self.assertRaises(Denied):
            store.run("trusted-ticket")
        self.assertEqual((fake.captures, fake.consumes), (0, 0))

    def test_existing_https_parser_fixed_version_and_truncation(self) -> None:
        from browser_runtime.openbao import HTTPS
        from tests.test_openbao_http import TOKEN as HTTP_TOKEN
        from tests.test_openbao_http import Peer as HTTPPeer
        from tests.test_openbao_http import sized

        body = Peer.response().body
        for i, extra in enumerate((0, 1)):
            peer = HTTPPeer(sized(body, extra))
            keys = Keys(
                self.directory,
                expected_manifest=self.digest,
                transport=HTTPS("https://vault.invalid"),
                token_source=lambda: HTTP_TOKEN,
            )
            with peer.installed():
                if extra:
                    with (
                        self.assertRaises(Denied),
                        keys.acquire(STORE_ID, operation(str(i)), None),
                    ):
                        self.fail("truncated reply accepted")
                else:
                    with keys.acquire(STORE_ID, operation(str(i)), None) as key:
                        self.assertEqual(key.material, KEY)
            self.assertEqual(
                peer.requests, [("GET", "/v1/profiles/data/synthetic/key?version=3")]
            )
            self.assertEqual(peer.closed, 1)
            self.assertTrue(all(stream.closed for stream in peer.streams))

    def test_mutation_proves_revocation_issue_boundary(self) -> None:
        self.peer.on_fetch = lambda: self.keys.revoke(self.m.key_id())
        deliveries = []
        with patch.object(self.keys, "_enabled", return_value=None):
            with self.keys.acquire(STORE_ID, operation(), None) as key:
                deliveries.append(key.version)
        self.assertEqual(deliveries, [self.m.key_id()])
        # Without mutation, test_revoke_during_fetch_denies_issue delivers zero.


if __name__ == "__main__":
    unittest.main()

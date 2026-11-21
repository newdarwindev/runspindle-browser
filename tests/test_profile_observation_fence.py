"""Synthetic callback revocation with independent effect and filesystem spies."""

import json
import socket
import subprocess
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from browser_runtime.credentials import Observation
from browser_runtime.profile_directory import DirectoryProfileIO
from browser_runtime.profile_store import Denied, Store
from browser_testing.profile_store_fixtures import Fake, grant
from tests.test_profile_directory import bundle


class ObservationFenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.network = patch.object(
            socket.socket, "connect", side_effect=AssertionError("network forbidden")
        )
        self.network.start()
        self.addCleanup(self.network.stop)

    def store(self) -> tuple[Store, Fake]:
        path = self.root / str(len(list(self.root.iterdir())))
        path.mkdir(mode=0o700)
        fake = Fake()
        store = Store(path, fake.adapters())
        self.addCleanup(store.close)
        return store, fake

    def revoke_on(self, fake: Fake, at: int, field: str) -> list[int]:
        original = fake.observe
        calls = [0]

        def observe() -> Observation | None:
            calls[0] += 1
            if calls[0] == at:
                setattr(fake, field, False)
            return original()

        self.enterContext(patch.object(fake, "observe", observe))
        return calls

    def test_store_observation_cannot_cross_provider_capture_or_consume(self) -> None:
        # These are the last checks immediately before each independent effect.
        for field in ("allowed", "stopped"):
            for action, at, expected in (
                ("save", 3, (0, 0, 0)),
                ("save", 6, (1, 0, 0)),
                ("restore", 4, (0, 0, 0)),
                ("restore", 6, (1, 0, 0)),
            ):
                with self.subTest(field=field, action=action, at=at):
                    store, fake = self.store()
                    if action == "restore":
                        self.assertEqual(store.run("trusted-ticket"), "stored")
                    fake.reads = fake.captures = fake.consumes = 0
                    fake.grant = grant(action)
                    calls = self.revoke_on(fake, at, field)
                    with self.assertRaises(Denied):
                        store.run("trusted-ticket")
                    self.assertEqual(calls[0], at)
                    self.assertEqual(
                        (fake.reads, fake.captures, fake.consumes), expected
                    )
                    if action == "restore":
                        self.assertEqual(
                            store._db.execute("SELECT result FROM restores").fetchall(),
                            [("unknown",)],
                        )

    def test_pre_observation_denial_remains_fast(self) -> None:
        for field in ("allowed", "stopped"):
            store, fake = self.store()
            setattr(fake, field, False)
            with patch.object(fake, "observe") as observe, self.assertRaises(Denied):
                store.run("trusted-ticket")
            observe.assert_not_called()
            self.assertEqual(fake.reads, 0)

    def test_profile_observations_cannot_be_restamped_or_rebound(self) -> None:
        for component in ("store", "directory"):
            for change in ("timestamp", "frame"):
                with self.subTest(component=component, change=change):
                    if component == "store":
                        store, fake = self.store()
                        owner: Store | DirectoryProfileIO = store
                    else:
                        tree, fake, path = self.tree()
                        owner = tree
                        before = (path / "state.json").read_bytes()
                    fake.grant = replace(fake.grant, deadline=30.0)
                    target = fake.grant.target
                    observed = (
                        Observation(target, 0.0)
                        if change == "timestamp"
                        else Observation(replace(target, frame="different-frame"), 10.0)
                    )
                    fake.observation = observed

                    def clock() -> float:
                        if change == "timestamp":
                            object.__setattr__(observed, "observed_at", 10.0)
                        else:
                            object.__setattr__(observed, "target", target)
                        return 10.0

                    with (
                        patch.object(owner, "_clock", clock),
                        self.assertRaises(Denied),
                    ):
                        if isinstance(owner, Store):
                            owner.run("trusted-ticket")
                        else:
                            owner.consume(fake.grant, fake, bundle(fake.grant.scope()))
                    self.assertEqual(
                        (fake.reads, fake.captures, fake.consumes), (0, 0, 0)
                    )
                    if isinstance(owner, Store):
                        self.assertEqual(
                            owner._db.execute("SELECT count(*) FROM nonces").fetchone(),
                            (0,),
                        )
                    else:
                        self.assertEqual((path / "state.json").read_bytes(), before)
                        self.assertEqual(list(path.glob("g-*")), [])

    def tree(self) -> tuple[DirectoryProfileIO, Fake, Path]:
        path = self.root / str(len(list(self.root.iterdir())))
        path.mkdir(mode=0o700)
        fake = Fake()
        fake.grant = grant("restore")
        tree = DirectoryProfileIO(path, fake.grant)
        self.addCleanup(tree.close)
        return tree, fake, path

    def test_directory_observation_denies_before_claim_writes(self) -> None:
        for field in ("allowed", "stopped"):
            tree, fake, path = self.tree()
            before = (path / "state.json").read_bytes()
            self.revoke_on(fake, 2, field)  # Recheck after real flock, before claim.
            with patch.object(tree, "_write_state", wraps=tree._write_state) as write:
                with self.assertRaises(Denied):
                    tree.consume(fake.grant, fake, bundle(fake.grant.scope()))
                write.assert_not_called()
            self.assertEqual((path / "state.json").read_bytes(), before)
            self.assertEqual(list(path.glob("g-*")), [])

    def test_directory_revocation_before_publication_retains_pending_candidate(
        self,
    ) -> None:
        for field in ("allowed", "stopped"):
            tree, fake, path = self.tree()
            original = fake.observe
            triggered = []

            def observe() -> Observation | None:
                state = json.loads((path / "state.json").read_text())
                if state["phase"] == "building" and list(path.glob("g-*")):
                    setattr(fake, field, False)
                    triggered.append(True)
                return original()

            published = []
            write = tree._write_state

            def record(state: dict[str, object]) -> None:
                if state["phase"] == "cleanup":
                    published.append(True)
                write(state)

            with (
                patch.object(fake, "observe", observe),
                patch.object(tree, "_write_state", side_effect=record),
            ):
                with self.assertRaises(Denied):
                    tree.consume(fake.grant, fake, bundle(fake.grant.scope()))
            self.assertTrue(triggered)
            self.assertEqual(published, [])
            state = json.loads((path / "state.json").read_text())
            self.assertEqual(state["phase"], "building")
            self.assertIsNone(state["current"])
            self.assertEqual(len(list(path.glob("g-*"))), 1)
            # No recovery on lost authority. A fresh admitted restore can recover.
            fake.allowed = fake.stopped = True
            fake.grant = grant("restore")
            self.assertTrue(tree.consume(fake.grant, fake, bundle(fake.grant.scope())))
            self.assertEqual(
                json.loads((path / "state.json").read_text())["phase"], "ready"
            )
            self.assertEqual(len(list(path.glob("g-*"))), 1)

    def test_profile_observation_mutations_are_detected(self) -> None:
        for mutation, test in (
            (
                "current",
                "test_store_observation_cannot_cross_provider_capture_or_consume",
            ),
            (
                "current",
                "test_directory_revocation_before_publication_retains_pending_candidate",
            ),
            (
                "stamp",
                "test_profile_observations_cannot_be_restamped_or_rebound",
            ),
        ):
            with self.subTest(mutation=mutation, test=test):
                script = r"""
import importlib, pathlib, sys, unittest
module = importlib.import_module("browser_runtime.profile_store")
source = pathlib.Path(module.__file__).read_text()
if sys.argv[1] == "current":
    needle = "    require(guard.current(grant) is True and guard.quiescent(grant) is True)\n    now = clock()"
    assert source.count(needle) == 1
    source = source.replace(needle, "    now = clock()")
else:
    needle = "    stamp = _observation_stamp(observed)\n    target, observed_at = stamp\n"
    assert source.count(needle) == source.count("    now = clock()\n") == 1
    source = source.replace(needle, "").replace("    now = clock()\n", "    now = clock()\n" + needle)
exec(compile(source, module.__file__, "exec"), module.__dict__)
sys.path.insert(0, "tests")
from test_profile_observation_fence import ObservationFenceTests
result = unittest.TextTestRunner().run(unittest.TestSuite([ObservationFenceTests(sys.argv[2])]))
sys.exit(0 if result.wasSuccessful() else 1)
"""
                result = subprocess.run(
                    [
                        sys.executable,
                        *(["-O"] if sys.flags.optimize else []),
                        "-c",
                        script,
                        mutation,
                        test,
                    ],
                    cwd=Path(__file__).resolve().parents[1],
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn("FAIL:", result.stderr)
                self.assertNotIn("ERROR:", result.stderr)
                # Effect spies fail, not an import or mutation setup problem.
                self.assertIn("AssertionError:", result.stderr)

    def test_post_observation_callbacks_cannot_preserve_old_time(self) -> None:
        for component in ("store", "directory"):
            with self.subTest(component=component):
                store, fake = self.store()
                owner: Store | DirectoryProfileIO = store
                if component == "directory":
                    owner, fake, _ = self.tree()
                fake.grant = grant("restore", deadline=11)
                now = [10.0]
                calls = [0]

                def quiescent(_grant: object) -> bool:
                    calls[0] += 1
                    if calls[0] == 2:
                        now[0] = 12.0
                    return True

                with (
                    patch.object(
                        fake,
                        "observe",
                        side_effect=lambda: Observation(fake.grant.target, 10.0),
                    ),
                    patch.object(fake, "quiescent", quiescent),
                    patch.object(owner, "_clock", side_effect=lambda: now[0]),
                ):
                    with self.assertRaises(ValueError):
                        if isinstance(owner, Store):
                            owner._check(fake, fake.grant)
                        else:
                            owner._check(fake.grant, fake)
                self.assertEqual(calls[0], 2)


if __name__ == "__main__":
    unittest.main()

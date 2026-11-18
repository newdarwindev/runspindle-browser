"""Opt-in actual sandboxed renderer + synthetic guarded journal/site tests."""

from __future__ import annotations

import http.client
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from dataclasses import replace
from pathlib import Path
from typing import Any, Callable, cast
from unittest.mock import patch

from browser_runtime.guarded_effects import GuardedJournal
from browser_testing import chromium_effect_site as engine
from browser_testing.http_effect_site import LocalSite
from tests.test_guarded_effects import PAYLOAD, TARGET
from tests.test_guarded_effects import Fixture as UntypedFixture

Fixture = cast(Callable[[Path], Any], UntypedFixture)

ROOT = Path(__file__).resolve().parents[1]


class ChromiumPrerequisites(unittest.TestCase):
    def test_missing_opt_in_and_root_deny_before_engine_access(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(RuntimeError, "explicit unprivileged"):
                engine.qualify()
        with (
            patch.dict(os.environ, {engine.OPT_IN: "1"}),
            patch.object(os, "geteuid", return_value=0),
        ):
            with self.assertRaisesRegex(RuntimeError, "explicit unprivileged"):
                engine.qualify()

    def test_external_interface_denies_before_engine_access(self) -> None:
        with (
            patch.dict(os.environ, {engine.OPT_IN: "1"}),
            patch.object(os, "geteuid", return_value=1000),
            patch.object(Path, "read_text", return_value="lo: x\neth0: x\n"),
        ):
            with self.assertRaisesRegex(RuntimeError, "loopback-only"):
                engine.qualify()

    def test_invalid_port_and_target_never_start_engine(self) -> None:
        for port in (True, 0, 65536, "http://other"):
            with self.assertRaises(ValueError):
                engine.ChromiumSite(port, TARGET)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            engine.ChromiumSite(1234, replace(TARGET, frame="bad frame"))


@unittest.skipUnless(
    os.environ.get(engine.OPT_IN) == "1", "explicit isolated Chromium lane required"
)
class ActualChromiumEffects(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def child(self, port: int, mutant: bool = False) -> list[str]:
        code = """import pathlib,sys,signal
signal.signal(signal.SIGTERM,lambda signum,frame: sys.exit(128+signum))
sys.path.insert(0,sys.argv[1])
from dataclasses import replace
if sys.argv[4]=='mutant':
    import browser_runtime.effects as module
    source=pathlib.Path(module.__file__).read_text()
    needle="            return self._outcome(row[2])"
    if source.count(needle)!=1: raise RuntimeError('mutation anchor drift')
    source=source.replace(needle,"            self.submit(binding, payload)\\n"+needle)
    exec(compile(source,module.__file__,'exec'),module.__dict__)
from tests.test_guarded_effects import Fixture,PAYLOAD,TARGET
from browser_runtime.guarded_effects import GuardedJournal
from browser_runtime.effects import Denied
from browser_testing.chromium_effect_site import ChromiumSite
f=Fixture(sys.argv[2])
with ChromiumSite(int(sys.argv[3]),TARGET) as site:
    j=GuardedJournal(pathlib.Path(sys.argv[2])/'journal.sqlite',authority=f,site=site,clock=lambda:f.now)
    try:
        try: print(j.dispatch('admitted',PAYLOAD))
        except Denied:
            if sys.argv[4]!='mutant': raise
            print('denied')
        f.grant=replace(f.grant,action='reconcile')
        print(j.reconcile('admitted'))
    finally: j.close()
"""
        process = subprocess.Popen(
            [
                sys.executable,
                *(["-O"] if sys.flags.optimize else []),
                "-B",
                "-c",
                code,
                str(ROOT),
                str(self.root),
                str(port),
                "mutant" if mutant else "normal",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            out, err = process.communicate(timeout=35)
            self.assertEqual(process.returncode, 0, err[-3000:])
            return out.splitlines()
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    process.kill()
            process.wait(timeout=5)

    def test_lost_reply_new_process_new_engine_duplicate_then_readback_once(
        self,
    ) -> None:
        with LocalSite(self.root / "site.sqlite", submission="lost") as local:
            fixture = Fixture(self.root)
            with engine.ChromiumSite(local.port, TARGET) as site:
                journal = GuardedJournal(
                    self.root / "journal.sqlite",
                    authority=fixture,
                    site=site,
                    clock=lambda: fixture.now,
                )
                try:
                    self.assertEqual(journal.dispatch("admitted", PAYLOAD), "unknown")
                finally:
                    journal.close()
                self.assertEqual(
                    (local.submissions, local.readbacks, local.ledger.effects()),
                    (1, 0, 1),
                )
            self.assertEqual(self.child(local.port), ["unknown", "confirmed"])
            self.assertEqual(
                (local.submissions, local.readbacks, local.ledger.effects()), (1, 1, 1)
            )

    def test_rejection_wrong_account_and_ambiguous_readback_do_not_resubmit(
        self,
    ) -> None:
        for mode in ("reject", "wrong-account", "ambiguous"):
            with self.subTest(mode=mode):
                path = self.root / mode
                path.mkdir()
                fixture = Fixture(path)
                with (
                    LocalSite(
                        path / "site.sqlite",
                        submission="reject" if mode == "reject" else "none",
                        readback="wrong-account" if mode == "wrong-account" else "none",
                    ) as local,
                    engine.ChromiumSite(local.port, TARGET) as site,
                ):
                    journal = GuardedJournal(
                        path / "journal.sqlite",
                        authority=fixture,
                        site=site,
                        clock=lambda: fixture.now,
                    )
                    try:
                        self.assertEqual(
                            journal.dispatch("admitted", PAYLOAD), "unknown"
                        )
                        if mode == "ambiguous":
                            local.ledger.submit(TARGET.binding, PAYLOAD)
                        fixture.grant = replace(fixture.grant, action="reconcile")
                        outcome = "rejected" if mode == "reject" else "unknown"
                        self.assertEqual(journal.reconcile("admitted"), outcome)
                        fixture.grant = replace(fixture.grant, action="dispatch")
                        self.assertEqual(journal.dispatch("admitted", PAYLOAD), outcome)
                        self.assertEqual((local.submissions, local.readbacks), (1, 1))
                        self.assertEqual(
                            local.ledger.effects(),
                            0 if mode == "reject" else 2 if mode == "ambiguous" else 1,
                        )
                    finally:
                        journal.close()

    def test_stale_guard_wrong_target_and_changed_page_block_renderer_fetch(
        self,
    ) -> None:
        with (
            LocalSite(self.root / "site.sqlite") as local,
            engine.ChromiumSite(local.port, TARGET) as site,
        ):
            fixture = Fixture(self.root)
            fixture.allowed = False
            with self.assertRaises(ValueError):
                site.submit(fixture.grant, PAYLOAD, fixture)
            fixture.allowed = True
            fixture.observed = replace(TARGET, binding=replace(TARGET.binding, epoch=2))
            with self.assertRaises(ValueError):
                site.submit(fixture.grant, PAYLOAD, fixture)
            fixture.observed = TARGET
            self.assertIsNotNone(site._client)
            site._evaluate("document.body.dataset.runspindleFixture='changed'; true")
            with self.assertRaises(RuntimeError):
                site.submit(fixture.grant, PAYLOAD, fixture)
            self.assertEqual(
                (local.submissions, local.readbacks, local.ledger.effects()), (0, 0, 0)
            )

    def test_reservation_bypass_mutant_exposes_second_real_browser_effect(self) -> None:
        with LocalSite(self.root / "site.sqlite", submission="lost") as local:
            fixture = Fixture(self.root)
            with engine.ChromiumSite(local.port, TARGET) as site:
                journal = GuardedJournal(
                    self.root / "journal.sqlite",
                    authority=fixture,
                    site=site,
                    clock=lambda: fixture.now,
                )
                try:
                    self.assertEqual(journal.dispatch("admitted", PAYLOAD), "unknown")
                finally:
                    journal.close()
            # Normal fresh-engine baseline cannot resubmit.
            self.assertEqual(self.child(local.port), ["unknown", "confirmed"])
            self.assertEqual(local.ledger.effects(), 1)
            # Lost submission response means mutant may raise before duplicate
            # branch returns, but Journal still exposes the second site effect.
            self.assertEqual(self.child(local.port, mutant=True)[0], "denied")
            self.assertEqual(local.submissions, 2)
            self.assertEqual(local.ledger.effects(), 2)

    def test_fixed_page_route_and_engine_cleanup_on_test_failure(self) -> None:
        with LocalSite(self.root / "site.sqlite") as local:
            connection = http.client.HTTPConnection("127.0.0.1", local.port, timeout=1)
            try:
                connection.request("GET", "/browser-fixture?unselected=1")
                self.assertEqual(connection.getresponse().status, 404)
            finally:
                connection.close()
            site = engine.ChromiumSite(local.port, TARGET)
            pid = None
            profile = None
            with self.assertRaisesRegex(RuntimeError, "intentional fixture failure"):
                with site:
                    if site._process is None or site._profile is None:
                        self.fail("owned engine resources missing")
                    pid = site._process.pid
                    profile = Path(site._profile.name)
                    cmdline = Path(f"/proc/{pid}/cmdline").read_bytes()
                    self.assertNotIn(b"--no-sandbox", cmdline)
                    self.assertNotIn(b"--disable-setuid-sandbox", cmdline)
                    raise RuntimeError("intentional fixture failure")
            self.assertIsNotNone(pid)
            self.assertFalse(Path(f"/proc/{pid}").exists())
            self.assertIsNotNone(profile)
            self.assertFalse(cast(Path, profile).exists())

    def test_killed_worker_cannot_leave_live_engine_group(self) -> None:
        with LocalSite(self.root / "site.sqlite") as local:
            receipt = self.root / "engine-owned.json"
            code = """import json,pathlib,sys,time
sys.path.insert(0,sys.argv[1])
from browser_testing.chromium_effect_site import ChromiumSite
from tests.test_guarded_effects import TARGET
with ChromiumSite(int(sys.argv[2]),TARGET) as site:
    pathlib.Path(sys.argv[3]).write_text(json.dumps({'pid':site._process.pid,'profile':site._profile.name}))
    time.sleep(60)
"""
            worker = subprocess.Popen(
                [
                    sys.executable,
                    "-B",
                    "-c",
                    code,
                    str(ROOT),
                    str(local.port),
                    str(receipt),
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env={**os.environ, "TMPDIR": str(self.root)},
            )
            try:
                deadline = time.monotonic() + 15
                while not receipt.exists():
                    if worker.poll() is not None or time.monotonic() >= deadline:
                        self.fail("owned engine startup receipt missing")
                    time.sleep(0.025)
                owner = json.loads(receipt.read_text())
                pid = owner["pid"]
                # Unlike SIGTERM/context exit, this cannot execute worker cleanup.
                worker.kill()
                worker.wait(timeout=5)

                def live_group() -> list[int]:
                    found = []
                    for path in Path("/proc").glob("[0-9]*/stat"):
                        try:
                            fields = path.read_text().rsplit(")", 1)[1].split()
                            if int(fields[2]) == pid and fields[0] != "Z":
                                found.append(int(path.parent.name))
                        except (OSError, ValueError, IndexError):
                            pass
                    return found

                deadline = time.monotonic() + 5
                while live_group() and time.monotonic() < deadline:
                    time.sleep(0.025)
                self.assertEqual(live_group(), [])
                # A SIGKILL cannot run TemporaryDirectory.__exit__. The surviving
                # test owns this outer directory and removes the synthetic profile.
                Path(owner["profile"]).relative_to(self.root)
            finally:
                if worker.poll() is None:
                    worker.kill()
                worker.wait(timeout=5)

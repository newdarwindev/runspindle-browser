"""Real disposable HTTP transport; synthetic origin, site and authority only."""

import http.client
import socket
import subprocess
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from browser_runtime.effects import Denied
from browser_runtime.guarded_effects import GuardedJournal
from browser_testing.http_effect_site import HTTPAdapter, LocalSite
from tests.test_control_leases import AGENT, HUMAN, ControlFixture
from tests.test_guarded_effects import PAYLOAD, TARGET, Fixture

ROOT = Path(__file__).resolve().parents[1]


class HTTPTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def journal(self, site: LocalSite) -> tuple[Fixture, GuardedJournal]:
        fixture = Fixture(self.root)
        journal = GuardedJournal(
            self.root / "journal.sqlite",
            authority=fixture,
            site=HTTPAdapter(site.port),
            clock=lambda: fixture.now,
        )
        self.addCleanup(journal.close)
        return fixture, journal

    def child(self, site: LocalSite, *, mutate: bool = False) -> list[str]:
        code = r"""
import pathlib, sys
if sys.argv[3] == "mutant":
    import browser_runtime.effects as module
    source = pathlib.Path(module.__file__).read_text()
    needle = "            return self._outcome(row[2])"
    assert source.count(needle) == 1
    source = source.replace(needle, "            self.submit(binding, payload)\n" + needle)
    exec(compile(source, module.__file__, "exec"), module.__dict__)
sys.path.insert(0, "tests")
from dataclasses import replace
from test_guarded_effects import Fixture, PAYLOAD
from browser_runtime.guarded_effects import GuardedJournal
from browser_testing.http_effect_site import HTTPAdapter
f=Fixture(sys.argv[1])
j=GuardedJournal(pathlib.Path(sys.argv[1])/"journal.sqlite", authority=f,
    site=HTTPAdapter(int(sys.argv[2])), clock=lambda:f.now)
try:
    print(j.dispatch("admitted", PAYLOAD))
    f.grant=replace(f.grant, action="reconcile")
    print(j.reconcile("admitted"))
finally:
    j.close()
"""
        return subprocess.run(
            [
                sys.executable,
                *(["-O"] if sys.flags.optimize else []),
                "-c",
                code,
                str(self.root),
                str(site.port),
                "mutant" if mutate else "normal",
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=True,
            timeout=10,
        ).stdout.splitlines()

    def test_accepted_lost_reply_restart_then_reconcile_no_second_submission(
        self,
    ) -> None:
        with LocalSite(self.root / "site.sqlite", submission="lost") as site:
            fixture, journal = self.journal(site)
            self.assertEqual(journal.dispatch("admitted", PAYLOAD), "unknown")
            self.assertEqual((site.submissions, site.ledger.effects()), (1, 1))
            journal.close()
            self.assertEqual(self.child(site), ["unknown", "confirmed"])
            self.assertEqual(
                (site.submissions, site.readbacks, site.ledger.effects()), (1, 1, 1)
            )

    def test_rejected_unknown_wrong_account_and_ambiguous_readback(self) -> None:
        for mode in ("reject", "drop", "wrong-account", "ambiguous"):
            with self.subTest(mode=mode):
                # Each scenario has an independent journal and ledger.
                path = self.root / mode
                path.mkdir()
                fixture = Fixture(path)
                with LocalSite(
                    path / "site.sqlite",
                    submission=mode if mode in ("reject", "drop") else "none",
                    readback="wrong-account" if mode == "wrong-account" else "none",
                ) as site:
                    journal = GuardedJournal(
                        path / "journal.sqlite",
                        authority=fixture,
                        site=HTTPAdapter(site.port),
                        clock=lambda: fixture.now,
                    )
                    try:
                        self.assertEqual(
                            journal.dispatch("admitted", PAYLOAD), "unknown"
                        )
                        if mode == "ambiguous":
                            # Independent synthetic site event, not journal submission.
                            site.ledger.submit(TARGET.binding, PAYLOAD)
                        fixture.grant = replace(fixture.grant, action="reconcile")
                        expected = "rejected" if mode == "reject" else "unknown"
                        self.assertEqual(journal.reconcile("admitted"), expected)
                        fixture.grant = replace(fixture.grant, action="dispatch")
                        self.assertEqual(
                            journal.dispatch("admitted", PAYLOAD), expected
                        )
                        self.assertEqual((site.submissions, site.readbacks), (1, 1))
                        self.assertEqual(
                            site.ledger.effects(),
                            0
                            if mode in ("reject", "drop")
                            else 2
                            if mode == "ambiguous"
                            else 1,
                        )
                    finally:
                        journal.close()

    def test_lease_stale_holder_denies_before_http(self) -> None:
        fixture = ControlFixture(self.root)
        store = fixture.store()
        self.addCleanup(store.close)
        with LocalSite(self.root / "site.sqlite") as site:
            journal = store.journal(
                self.root / "journal.sqlite", HTTPAdapter(site.port)
            )
            try:
                fixture.transition("initialize", None, AGENT, 0)
                self.assertEqual(store.transfer("admitted"), "active")
                fixture.transition("takeover", AGENT, HUMAN, 1)
                self.assertEqual(store.transfer("admitted"), "active")
                fixture.input(AGENT, 1)
                with self.assertRaises(Denied):
                    journal.dispatch("admitted", PAYLOAD)
                self.assertEqual((site.submissions, site.ledger.effects()), (0, 0))
                fixture.input(HUMAN, 2)
                self.assertEqual(journal.dispatch("admitted", PAYLOAD), "unknown")
                self.assertEqual((site.submissions, site.ledger.effects()), (1, 1))
            finally:
                journal.close()

    def test_duplicate_reservation_bypass_exposes_second_http_effect(self) -> None:
        with LocalSite(self.root / "site.sqlite") as site:
            _, journal = self.journal(site)
            self.assertEqual(journal.dispatch("admitted", PAYLOAD), "unknown")
            journal.close()
            self.assertEqual(self.child(site, mutate=True), ["unknown", "unknown"])
            self.assertEqual((site.submissions, site.ledger.effects()), (2, 2))

    def test_fixed_routes_and_normal_shutdown_with_partial_request(self) -> None:
        site = LocalSite(self.root / "site.sqlite")
        with site:
            connection = http.client.HTTPConnection("127.0.0.1", site.port, timeout=2)
            try:
                connection.request("POST", "http://example.invalid/submit", b"{}")
                response = connection.getresponse()
                self.assertEqual(response.status, 404)
                response.read()
            finally:
                connection.close()
            # A stalled local client must not leave the server thread alive.
            stalled = socket.create_connection(("127.0.0.1", site.port), timeout=1)
            stalled.sendall(b"POST /submit HTTP/1.0\r\nContent-Length: 100\r\n\r\n{")
            self.assertTrue(site.request_started.wait(2))
        stalled.close()
        thread = site._thread
        if thread is None:
            self.fail("fixture worker was never started")
        self.assertFalse(thread.is_alive())
        self.assertEqual(
            (site.submissions, site.readbacks, site.ledger.effects()), (0, 0, 0)
        )
        with socket.socket() as probe:
            probe.settimeout(1)
            self.assertNotEqual(probe.connect_ex(("127.0.0.1", site.port)), 0)

    def test_bounded_request_and_failure_context_close_listener(self) -> None:
        site = LocalSite(self.root / "site.sqlite")
        with self.assertRaisesRegex(RuntimeError, "intentional"):
            with site:
                connection = http.client.HTTPConnection(
                    "127.0.0.1", site.port, timeout=2
                )
                try:
                    connection.request(
                        "POST", "/submit", b"x", {"Content-Length": "999999"}
                    )
                    response = connection.getresponse()
                    self.assertEqual(response.status, 400)
                    response.read()
                finally:
                    connection.close()
                self.assertEqual((site.submissions, site.ledger.effects()), (0, 0))
                raise RuntimeError("intentional test failure")
        thread = site._thread
        if thread is None:
            self.fail("fixture worker was never started")
        self.assertFalse(thread.is_alive())
        with socket.socket() as probe:
            probe.settimeout(1)
            self.assertNotEqual(probe.connect_ex(("127.0.0.1", site.port)), 0)


if __name__ == "__main__":
    unittest.main()

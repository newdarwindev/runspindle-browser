"""Opt-in actual OpenBao TLS/CAS with synthetic capture/authority, no Chromium."""

import os
import unittest
from dataclasses import replace

from browser_runtime.autosave import Autosave, Login, Writer
from browser_runtime.openbao import Vault
from browser_testing.account_e2e import OpenBaoFixture, TOKEN
from test_account_e2e import ExternalOperations
from test_autosave import Harness
from test_openbao import CANARY


@unittest.skipUnless(
    os.environ.get("RUNSPINDLE_ACCOUNT_E2E") == "1", "isolated OpenBao opt-in required"
)
class OpenBaoAccountComponent(unittest.TestCase):
    def setUp(self):
        self.bao = OpenBaoFixture(
            os.environ.get("RUNSPINDLE_BAO_BINARY", "/missing/bao")
        )
        self.bao.__enter__()
        self.addCleanup(self.bao.__exit__, None, None, None)
        self.fixture = Harness(None)
        self.operations = ExternalOperations()
        self.posts = 0
        self.http = self.bao.transport()
        self.lost = True

    def transport(self, method, path, token, timeout, body=None):
        if method == "POST":
            self.posts += 1
        reply = self.http.request(method, path, token, timeout, body)
        if method == "POST" and self.lost:
            raise TimeoutError("synthetic lost acknowledgment")
        return reply

    def service(self):
        f = self.fixture
        mapping = replace(f.m, mount="secret")
        reader = Vault(
            (mapping,),
            transport=self.http,
            token=lambda: TOKEN,
            authorize=f.current,
            clock=lambda: f.now,
        )
        return Autosave(
            self.operations,
            authority=f,
            writer=Writer(reader, self.transport),
            consent=f.consent,
            capture=f.capture,
            clock=lambda: f.now,
        )

    def test_real_tls_cas_lost_reply_update_and_reconcile_without_replay(self):
        f = self.fixture
        self.assertEqual(self.service().run(f.ticket), "saved")
        self.assertEqual(self.posts, 1)
        self.assertEqual(self.service().run(f.ticket, reconcile_only=True), "saved")
        self.assertEqual(self.posts, 1)
        f.expected = 1
        f.g = replace(
            f.g,
            target=replace(
                f.g.target, binding=replace(f.g.target.binding, operation="update")
            ),
        )
        f.observed = f.g.target
        f.capture = lambda _g: Login(f.username, "SYNTHETIC_UPDATED_6189", True)
        self.assertEqual(self.service().run(f.ticket), "saved")
        self.assertEqual(self.posts, 2)
        f.g = replace(
            f.g,
            target=replace(
                f.g.target, binding=replace(f.g.target.binding, operation="stale")
            ),
        )
        f.observed = f.g.target
        self.assertEqual(self.service().run(f.ticket), "unknown")
        self.assertEqual(self.posts, 2)
        self.assertNotIn(CANARY, repr(self.operations.rows))
        self.assertNotIn("SYNTHETIC_UPDATED_6189", repr(self.operations.rows))

    def test_no_consent_and_failed_login_have_zero_actual_write_attempts(self):
        f = self.fixture
        f.opt_in = False
        self.assertEqual(self.service().run(f.ticket), "not_saved")
        self.assertEqual(self.posts, 0)
        f.opt_in = True
        f.login_ok = False
        self.assertEqual(self.service().run(f.ticket), "unknown")
        self.assertEqual(self.posts, 0)

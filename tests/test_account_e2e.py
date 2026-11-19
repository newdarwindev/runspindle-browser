"""Opt-in real Chromium/OpenBao; external authority/state remain synthetic fixtures."""

import contextlib
import hashlib
import json
import os
import time
import unittest
from dataclasses import replace
from pathlib import Path

from browser_runtime.autosave import Autosave, Login, Writer
from browser_runtime.credentials import AdapterSet, Grant, Observation, Resolver, Target
from browser_runtime.effects import Binding
from browser_runtime.openbao import Mapping, Vault
from browser_testing.account_e2e import (
    AccountBrowser,
    AccountSite,
    OpenBaoFixture,
    TOKEN,
    qualify,
)

USER = "synthetic-account"
PASSWORD = "SYNTHETIC_E2E_CANARY_6b2579"


class ExternalOperations:
    """The test owner's operation state, not Browser-managed persistence.

    This is in-memory only; full E2E does not qualify durable owner integration.
    """

    def __init__(self):
        self.rows = {}

    def execute(
        self,
        *,
        binding,
        payload,
        target_digest,
        approve,
        submit,
        observe,
        reconcile_only,
    ):
        digest = hashlib.sha256(payload).hexdigest()
        if not approve(binding, digest):
            raise ValueError("denied")
        key = binding.operation
        identity = (binding, digest, target_digest)
        if key in self.rows:
            if self.rows[key][0] != identity:
                raise ValueError("conflict")
        elif reconcile_only:
            raise ValueError("missing")
        else:
            self.rows[key] = (identity, "unknown")
            try:
                submit(binding, payload)
            except Exception:
                pass
        observed = observe(binding, digest)
        self.rows[key] = (identity, observed.outcome)
        return observed.outcome


class Authority:
    """Single-thread test admission; NOT a production Host/Core authority."""

    def __init__(self, browser, origin, operation, session):
        self.browser = browser
        frame = browser.observe_frame()
        self.target = Target(
            Binding("fixture", USER, session, "tab", "login", 1, operation, 1, origin),
            session,
            frame["id"],
            origin,
        )
        self.grant = Grant(self.target, "account-password", time.monotonic() + 30)
        self.ticket = object()
        self.allowed = True
        self.active = False
        self.opted_in = True
        self.expected = 0

    @contextlib.contextmanager
    def acquire(self):
        self.active = True
        try:
            yield self
        finally:
            self.active = False

    def admit(self, ticket):
        return self.grant if ticket is self.ticket and self.active else None

    def observe(self):
        frame = self.browser.observe_frame()
        origin = frame["securityOrigin"]
        return Observation(
            replace(
                self.target,
                frame=frame["id"],
                frame_origin=origin,
                binding=replace(self.target.binding, origin=origin),
            ),
            time.monotonic(),
        )

    def current(self, grant):
        return self.active and self.allowed and grant == self.grant

    def consent(self, grant):
        return self.expected if self.opted_in and self.current(grant) else None


@unittest.skipUnless(
    os.environ.get("RUNSPINDLE_ACCOUNT_E2E") == "1",
    "isolated account E2E opt-in required",
)
class AccountE2E(unittest.TestCase):
    def setUp(self):
        self.bao_binary = Path(os.environ.get("RUNSPINDLE_BAO_BINARY", "/missing/bao"))
        self.chromium = Path(
            os.environ.get("RUNSPINDLE_CHROMIUM_BINARY", "/usr/lib/chromium/chromium")
        )
        qualify(self.bao_binary, self.chromium)
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.bao = self.stack.enter_context(OpenBaoFixture(self.bao_binary))
        self.site = self.stack.enter_context(
            AccountSite(
                self.bao.home / "vault-cert.pem", self.bao.home / "vault-key.pem"
            )
        )
        self.mapping = Mapping(
            "fixture",
            USER,
            self.site.origin,
            self.site.origin,
            "account-password",
            "secret",
            ("accounts", "synthetic"),
            "password",
        )
        self.posts = 0
        self.reads = 0
        self.lose_response = False
        self.transport = self.bao.transport()
        self.operations = ExternalOperations()

    def write_transport(self, method, path, token, timeout, body=None):
        if method == "POST":
            self.posts += 1
        else:
            self.reads += 1
        result = self.transport.request(method, path, token, timeout, body)
        if method == "POST" and self.lose_response:
            raise TimeoutError("synthetic lost acknowledgment")
        return result

    def vault(self, authority):
        def read(path, token, timeout):
            self.reads += 1
            return self.transport(path, token, timeout)

        return Vault(
            (self.mapping,),
            transport=read,
            token=lambda: TOKEN,
            authorize=authority.current,
        )

    def browser(self):
        return AccountBrowser(self.chromium, self.bao.ca)

    def register_and_login(self, browser, password=PASSWORD):
        browser.navigate(self.site.origin + "/register", "register")
        browser.fill(USER, password)
        browser.submit("login")
        browser.fill(USER, password)
        # Trusted test-capture seam observes the ordinary form before submission.
        captured = browser.evaluate("document.querySelector('[name=password]').value")
        browser.submit("private")
        response = browser.request("/whoami")
        self.assertEqual(json.loads(response[1])["user"], USER)
        return captured

    def save(
        self, browser, captured, *, operation="save", opted_in=True, successful=True
    ):
        authority = Authority(browser, self.site.origin, operation, "first")
        authority.opted_in = opted_in
        helper = Autosave(
            self.operations,
            authority=authority,
            writer=Writer(self.vault(authority), self.write_transport),
            consent=authority.consent,
            capture=lambda _g: Login(USER, captured, successful),
            max_age=2,
        )
        return helper.run(authority.ticket)

    def test_register_login_save_clean_context_relogin_and_action(self):
        with self.browser() as first:
            captured = self.register_and_login(first)
            self.lose_response = True
            self.assertEqual(self.save(first, captured), "saved")
            del captured
            self.assertEqual(self.posts, 1)
            self.assertNotIn(PASSWORD, repr(self.operations.rows))
        # The entire first profile is gone; no checkpoint or shared cookie state.
        with self.browser() as second:
            second.navigate(self.site.origin + "/private", "denied")
            second.navigate(self.site.origin + "/login", "login")
            self.assertEqual(
                second.evaluate("document.querySelector('[name=password]').value"), ""
            )
            authority = Authority(second, self.site.origin, "reuse", "second")
            vault = self.vault(authority)

            class Helper:
                def inject(inner, handle, grant, fence):
                    def sink(secret):
                        if (
                            not fence.current(grant)
                            or fence.observe().target != grant.target
                        ):
                            return False
                        second.fill(USER, secret)
                        return True

                    return vault.consume(handle, grant, sink)

            resolver = Resolver(
                AdapterSet("a" * 64, authority, vault, Helper()),
                expected_digest="a" * 64,
                max_age=2,
            )
            self.assertEqual(resolver.resolve_and_inject(authority.ticket), "injected")
            second.submit("private")
            result = second.request("/action", {"operation": "fixture-action"})
            self.assertEqual(result[0], 200)
            readback = second.request("/readback?operation=fixture-action")
            self.assertTrue(json.loads(readback[1])["confirmed"])
            self.assertEqual(self.site.actions, {"fixture-action": USER})
            self.assertEqual(self.site.login_attempts, 2)
            self.assertEqual(self.posts, 1)

    def test_no_opt_in_and_failed_login_leave_vault_unwritten(self):
        with self.browser() as browser:
            captured = self.register_and_login(browser)
            self.assertEqual(self.save(browser, captured, opted_in=False), "not_saved")
            self.assertEqual((self.posts, self.reads), (0, 0))
            browser.navigate(self.site.origin + "/login", "login")
            browser.fill(USER, "SYNTHETIC_WRONG_PASSWORD")
            captured = browser.evaluate(
                "document.querySelector('[name=password]').value"
            )
            browser.submit("failed")
            self.assertEqual(self.site.login_attempts, 2)
            self.assertEqual(self.save(browser, captured, successful=False), "unknown")
            self.assertEqual(self.posts, 0)
            self.assertEqual(json.loads(browser.request("/whoami")[1])["user"], USER)

"""Offline negative gates; no upstream process, browser or network is started."""

import os
import shutil
import ssl
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from browser_runtime.openbao import HTTPS
from browser_testing.account_e2e import AccountBrowser, OpenBaoFixture, isolated


class FixtureSafetyTests(unittest.TestCase):
    def test_missing_opt_in_denies_before_fixture_directory_or_process(self) -> None:
        with (
            patch.dict(os.environ, {}, clear=True),
            patch("tempfile.mkdtemp") as directory,
        ):
            for fixture in (
                OpenBaoFixture("/missing/bao"),
                AccountBrowser("/missing/chromium", "/missing/ca"),
            ):
                with self.assertRaises(RuntimeError):
                    fixture.__enter__()
            directory.assert_not_called()

    def test_non_loopback_namespace_denies(self) -> None:
        with (
            patch.dict(os.environ, {"RUNSPINDLE_ACCOUNT_E2E": "1"}),
            patch("os.geteuid", return_value=1000),
            patch.object(Path, "read_text", return_value="eth0: 0\nlo: 0"),
        ):
            with self.assertRaises(RuntimeError):
                isolated()

    def test_uncertain_stop_retains_fixture_directory(self) -> None:
        for fixture in (
            OpenBaoFixture("/unused/bao"),
            AccountBrowser("/unused/chromium", "/unused/ca"),
        ):
            directory = Path(tempfile.mkdtemp(prefix="test-quarantine-"))
            self.addCleanup(shutil.rmtree, directory)
            (directory / "synthetic-state").write_text("fixture only")
            fixture.directory = directory
            fixture.process = object()
            with patch(
                "browser_testing.account_e2e.stop",
                side_effect=RuntimeError("stop uncertain"),
            ):
                with self.assertRaises(RuntimeError):
                    fixture.__exit__(None, None, None)
            self.assertTrue((directory / "synthetic-state").exists())
            self.assertIs(fixture.directory, directory)

    def test_insecure_or_mutated_tls_context_opens_no_connection(self) -> None:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        transport = HTTPS("https://vault.invalid", tls_context=context)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with patch("http.client.HTTPSConnection") as connection:
            with self.assertRaises(ValueError):
                transport.request(
                    "POST", "/v1/secret/data/fixture", "synthetic", 1, b"{}"
                )
            connection.assert_not_called()

"""Real lease SQLite + Resolver with synthetic authority, vault and input spies."""

import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from dataclasses import replace
from pathlib import Path

from browser_runtime.control_leases import CredentialInput
from browser_runtime.credentials import Cancelled, Denied, Grant
from browser_runtime.effects import Denied as ControlDenied
from test_control_leases import AGENT, HUMAN, ControlFixture, PAYLOAD, target

PIN = "a" * 64
CANARY = "synthetic-private-credential-cancel"


class CredentialFixture(ControlFixture):
    def credential(self, holder=AGENT, epoch=1):
        self.grant = CredentialInput(
            Grant(target(epoch, "credential-input"), "credential:one", 20.0), holder
        )
        return self.grant


class CredentialAdapters:
    def __init__(self, authority):
        self.authority = authority
        self.reads = self.injections = self.releases = 0
        self.handle = object()
        self.after_read = lambda: None
        self.at_inject = lambda: None
        self.at_release = lambda: None

    def read(self, grant):
        if not self.authority.active:
            raise AssertionError("physical guard missing during read")
        self.reads += 1
        self.after_read()
        return self.handle

    def current(self, handle, grant):
        return handle is self.handle

    def inject(self, handle, grant, fence):
        if (
            not self.authority.active
            or handle is not self.handle
            or fence.current(grant) is not True
        ):
            raise AssertionError("held current lease fence missing at injection")
        self.injections += 1
        self.at_inject()
        return True

    def release(self, handle):
        if not self.authority.active or handle is not self.handle:
            raise AssertionError("physical guard missing during release")
        self.releases += 1
        self.at_release()

    def resolver(self, store, digest=PIN, expected=PIN):
        return store.credential_resolver(
            self, self, adapter_digest=digest, expected_digest=expected
        )


class LeaseCredentialTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.f = CredentialFixture(self.tmp.name)
        self.store = self.f.store()
        self.addCleanup(self.store.close)
        self.adapters = CredentialAdapters(self.f)
        self.f.transition("initialize", None, AGENT, 0)
        self.assertEqual(self.store.transfer("admitted"), "active")

    def assert_no_secret_effects(self):
        self.assertEqual(
            (self.adapters.reads, self.adapters.injections, self.adapters.releases),
            (0, 0, 0),
        )

    def test_matching_lease_uses_existing_resolver_and_is_one_attempt(self) -> None:
        self.f.credential()
        resolver = self.adapters.resolver(self.store)
        self.assertEqual(resolver.resolve_and_inject("admitted"), "injected")
        self.assertEqual(
            (self.adapters.reads, self.adapters.injections, self.adapters.releases),
            (1, 1, 1),
        )
        self.assertFalse(self.f.active)
        with self.assertRaises(Denied):
            resolver.resolve_and_inject("admitted")
        self.assertEqual(self.adapters.reads, 1)

    def test_pins_fail_before_authority_or_vault(self) -> None:
        self.f.credential()
        calls = self.f.current_calls
        for digest, expected in ((PIN, "b" * 64), ("", "")):
            with self.assertRaises(Denied):
                self.adapters.resolver(self.store, digest, expected).resolve_and_inject(
                    "admitted"
                )
        self.assertEqual(self.f.current_calls, calls)
        self.assert_no_secret_effects()

    def test_wrong_holder_epoch_and_physical_scope_deny_before_vault(self) -> None:
        for holder, epoch in ((HUMAN, 1), (AGENT, 2)):
            self.f.credential(holder, epoch)
            with self.assertRaises(Denied):
                self.adapters.resolver(self.store).resolve_and_inject("admitted")
        for field in ("account", "native_session", "frame", "frame_origin"):
            admission = self.f.credential()
            current = admission.credential.target
            if field == "account":
                changed = replace(
                    current, binding=replace(current.binding, account="other")
                )
            else:
                changed = replace(
                    current,
                    **{
                        field: "https://other.invalid"
                        if field == "frame_origin"
                        else "other"
                    },
                )
            self.f.grant = replace(
                admission, credential=replace(admission.credential, target=changed)
            )
            self.f.observed = changed
            with self.assertRaises(Denied):
                self.adapters.resolver(self.store).resolve_and_inject("admitted")
        self.assert_no_secret_effects()

    def test_effect_and_credential_admission_are_not_interchangeable(self) -> None:
        self.f.input(AGENT, 1)
        with self.assertRaises(Denied):
            self.adapters.resolver(self.store).resolve_and_inject("admitted")
        self.f.credential()
        journal = self.store.journal(Path(self.tmp.name) / "effects.sqlite", self.f)
        self.addCleanup(journal.close)
        with self.assertRaises(ControlDenied):
            journal.dispatch("admitted", PAYLOAD)
        self.assert_no_secret_effects()
        self.assertEqual(self.f.effects(), 0)

    def test_takeover_and_pending_state_block_old_and_unissued_credential_holders(self) -> None:
        self.f.transition("takeover", AGENT, HUMAN, 1)
        self.assertEqual(self.store.transfer("admitted"), "active")
        self.f.credential(AGENT, 1)
        with self.assertRaises(Denied):
            self.adapters.resolver(self.store).resolve_and_inject("admitted")
        self.f.credential(HUMAN, 2)
        self.assertEqual(
            self.adapters.resolver(self.store).resolve_and_inject("admitted"),
            "injected",
        )
        self.f.transition("handback", HUMAN, AGENT, 2)
        self.f.closed_inputs = False
        self.assertEqual(self.store.transfer("admitted"), "unknown")
        for holder, epoch in ((HUMAN, 2), (AGENT, 3)):
            self.f.credential(holder, epoch)
            with self.assertRaises(Denied):
                self.adapters.resolver(self.store).resolve_and_inject("admitted")
        self.assertEqual((self.adapters.reads, self.adapters.injections), (1, 1))

    def test_revocation_after_read_releases_without_injecting(self) -> None:
        self.f.credential()
        self.adapters.after_read = lambda: setattr(self.f, "allowed", False)
        with self.assertRaises(Denied):
            self.adapters.resolver(self.store).resolve_and_inject("admitted")
        self.assertEqual(
            (self.adapters.reads, self.adapters.injections, self.adapters.releases),
            (1, 0, 1),
        )
        self.assertFalse(self.f.active)

    def test_current_callback_cannot_extend_deadline(self) -> None:
        self.f.credential()
        self.f.at_current = lambda: setattr(self.f, "now", 20.0)
        with self.assertRaises(Denied):
            self.adapters.resolver(self.store).resolve_and_inject("admitted")
        self.assert_no_secret_effects()

    def test_cancellation_stays_sanitized_and_releases_lease(self) -> None:
        self.f.credential()

        def cancel():
            raise KeyboardInterrupt(CANARY)

        def cleanup_error():
            raise RuntimeError(CANARY)

        self.adapters.at_inject = cancel
        self.adapters.at_release = cleanup_error
        with self.assertRaises(Cancelled) as caught:
            self.adapters.resolver(self.store).resolve_and_inject("admitted")
        self.assertNotIn(CANARY, str(caught.exception))
        self.assertIsNone(caught.exception.__context__)
        self.assertEqual(
            (self.adapters.reads, self.adapters.injections, self.adapters.releases),
            (1, 1, 1),
        )
        self.assertFalse(self.f.active)
        self.f.transition("takeover", AGENT, HUMAN, 1)
        self.assertEqual(self.store.transfer("admitted"), "active")

    def test_closed_store_denies_before_vault(self) -> None:
        self.store.close()
        self.f.credential()
        with self.assertRaises(Denied):
            self.adapters.resolver(self.store).resolve_and_inject("admitted")
        self.assert_no_secret_effects()

    def test_other_process_transfer_waits_for_release_and_physical_guard_exit(self) -> None:
        code = """import sys,time,contextlib
from pathlib import Path
sys.path.insert(0,'tests')
from test_lease_credentials import CredentialFixture,CredentialAdapters
f=CredentialFixture(sys.argv[1]);s=f.store();a=CredentialAdapters(f);f.credential()
root=Path(sys.argv[1])
def hold(phase):
 (root/('entered-'+phase)).write_text('held')
 deadline=time.monotonic()+15
 while not (root/('release-'+phase)).exists():
  if time.monotonic()>deadline:raise RuntimeError('bounded fixture timeout')
  time.sleep(.01)
a.at_release=lambda: hold('handle')
@contextlib.contextmanager
def authority():
 f.active=True
 try:
  yield f
  hold('guard')
 finally:f.active=False
f.acquire=authority
try:print(a.resolver(s).resolve_and_inject('admitted'),flush=True)
finally:s.close()
"""
        process = subprocess.Popen(
            [sys.executable, "-c", code, self.tmp.name],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            for phase in ("handle", "guard"):
                marker = Path(self.tmp.name) / ("entered-" + phase)
                deadline = time.monotonic() + 5
                while not marker.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertTrue(marker.exists(), "child did not reach held " + phase)
                self.f.transition("takeover", AGENT, HUMAN, 1)
                with self.assertRaises(ControlDenied):
                    self.store.transfer("admitted")
                self.assertEqual(self.f.fences(), 1)
                (Path(self.tmp.name) / ("release-" + phase)).write_text("release")
        finally:
            for phase in ("handle", "guard"):
                (Path(self.tmp.name) / ("release-" + phase)).write_text("release")
            try:
                out, err = process.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate(timeout=5)
                raise
        self.assertEqual(process.returncode, 0, err)
        self.assertEqual(out.strip(), "injected")
        self.assertEqual(self.store.transfer("admitted"), "active")
        self.assertEqual(self.f.fences(), 2)

    def test_source_mutation_exposes_wrong_holder_vault_and_injection(self) -> None:
        source = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shutil.copytree(
                source / "browser_runtime",
                root / "browser_runtime",
                ignore=shutil.ignore_patterns("__pycache__"),
            )
            for name in (
                "test_lease_credentials.py",
                "test_control_leases.py",
                "test_guarded_effects.py",
            ):
                shutil.copyfile(source / "tests" / name, root / name)
            code = """from pathlib import Path
from test_lease_credentials import CredentialFixture,CredentialAdapters,Denied
from test_control_leases import AGENT,HUMAN
Path('data').mkdir()
f=CredentialFixture('data');s=f.store();a=CredentialAdapters(f)
f.transition('initialize',None,AGENT,0);s.transfer('admitted');f.credential(HUMAN,1)
try:a.resolver(s).resolve_and_inject('admitted')
except Denied:pass
print(a.reads,a.injections);s.close()
"""

            def run():
                result = subprocess.run(
                    [sys.executable, "-c", code],
                    cwd=root,
                    capture_output=True,
                    text=True,
                    check=True,
                    timeout=10,
                )
                return result.stdout.strip()

            self.assertEqual(run(), "0 0")
            shutil.rmtree(root / "data")
            module = root / "browser_runtime/control_leases.py"
            original = module.read_text()
            anchor = '_encode(asdict(grant.holder)),\n            "active"'
            self.assertEqual(original.count(anchor), 1)
            module.write_text(original.replace(anchor, 'row[2],\n            "active"'))
            shutil.rmtree(root / "browser_runtime/__pycache__", ignore_errors=True)
            self.assertEqual(run(), "1 1")

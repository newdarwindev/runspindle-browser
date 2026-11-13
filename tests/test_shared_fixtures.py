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
BUNDLE = ROOT / 'fixtures/shared-v1'
PIN = {'component': 'browser',
 'fixture_schema': 'runspindle.fixture.v1',
 'repository': 'newdarwindev/runspindle',
 'rights_basis': 'Owner-directed reuse of original Runspindle synthetic fixtures; source bytes '
                 'and notices retained; no blanket relicense.',
 'schema': 'runspindle.fixture.pin.v1',
 'scope': 'synthetic-fixture-consumer-only; not a runtime wire protocol or upstream '
          'qualification',
 'source_bundle_tree': '68172a671e28175af88638c6d8f1c54e1c675f37',
 'source_commit': 'e8cd5779968fede213443db13a591c992cd0e183',
 'source_manifest_sha256': '1dd35d045064056dd66e6da3619ff100549e1c3e81c928f076cfd4109a524d81',
 'source_validator_blob': '0c5189a527bcd85b4c491a869a2d0218db50dc25',
 'subset_manifest_sha256': '1aff79ae7d277a334efab9ef559c4d657afe6d667d99a6b4a3c849abc27de973',
 'validator_sha256': '1bd6d10ae7105a44a0d583a8974230dde56af603c6ed2b75f67fe3f1fb16319f'}
EXPECTED_IDENTITY = {'account_ref': 'synthetic-account-ref',
 'attempt': 1,
 'browser_id': 'synthetic-browser-id',
 'event_id': 'synthetic-event-id',
 'host_id': 'synthetic-host-id',
 'intent_revision': 1,
 'lease_epoch': 2,
 'native_session_id': 'synthetic-native-session-id',
 'operation_id': 'synthetic-operation-id',
 'policy_revision': 1,
 'sequence': 0,
 'span_id': 'synthetic-span-id',
 'task_id': 'synthetic-task-id',
 'trace_id': 'synthetic-trace-id',
 'workspace_id': 'synthetic-workspace-id'}
EXPECTED_KIND = 'browser.observed'
EXPECTED_STATE = 'passive'


def checked_kit(root=ROOT):
    """Check reviewed hashes before executing any vendored Python code."""
    pin = json.loads((root/'fixtures/shared-v1.pin.json').read_text())
    if pin != PIN:
        raise ValueError('pin-mismatch')
    bundle = root/'fixtures/shared-v1'
    verified = {}
    for name, expected in [('manifest.json',PIN['subset_manifest_sha256']),('fixturekit.py',PIN['validator_sha256'])]:
        verified[name] = (bundle/name).read_bytes()
        if hashlib.sha256(verified[name]).hexdigest() != expected:
            raise ValueError('pinned-file-mismatch')
    # Execute the exact verified snapshot; ignored .pyc files cannot substitute code.
    kit = ModuleType('pinned_fixturekit')
    kit.__file__ = str(bundle/'fixturekit.py')
    exec(compile(verified['fixturekit.py'],kit.__file__,'exec'),kit.__dict__)
    manifest = kit.verify_bundle(bundle)
    if manifest['origin_manifest_sha256'] != PIN['source_manifest_sha256']:
        raise ValueError('origin-mismatch')
    if manifest['component'] != PIN['component']:
        raise ValueError('component-mismatch')
    return kit


class ConsumerFixtures(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.network = []
        def deny(*args, **kwargs):
            raise AssertionError('unexpected network access')
        for target in ['socket.create_connection','socket.socket.connect','socket.getaddrinfo']:
            guard = patch(target,side_effect=deny);guard.start();cls.network.append(guard)
        cls.kit = checked_kit()

    @classmethod
    def tearDownClass(cls):
        for guard in reversed(cls.network): guard.stop()

    def envelope(self):
        fixtures = self.kit.load_json(BUNDLE/'golden.json')
        self.assertEqual(len(fixtures),1)
        self.assertEqual(fixtures[0]['kind'],EXPECTED_KIND)
        return fixtures[0]

    def reject(self, code, callback):
        with self.assertRaises(self.kit.ContractError) as error:
            callback()
        self.assertEqual(str(error.exception),code)

    def test_fixed_pin_and_golden_identity(self):
        self.assertEqual(PIN['source_commit'],'e8cd5779968fede213443db13a591c992cd0e183')
        self.assertEqual(PIN['fixture_schema'],'runspindle.fixture.v1')
        self.assertTrue(self.kit.assert_conforms(self.envelope(),EXPECTED_IDENTITY,EXPECTED_STATE))

    def test_published_positive_and_negative_vectors(self):
        original = self.envelope()
        vectors = self.kit.load_json(BUNDLE/'vectors.json')
        self.assertGreaterEqual(len(vectors),2)
        for vector in vectors:
            self.assertEqual(vector['kind'],EXPECTED_KIND)
            broken=copy.deepcopy(original);target=broken;path=vector['mutation']['path']
            for part in path[:-1]: target=target[part]
            target[path[-1]]=vector['mutation']['value']
            with self.subTest(vector=vector['id']):
                self.reject(vector['expected_error'],lambda:self.kit.assert_conforms(broken,EXPECTED_IDENTITY,EXPECTED_STATE))

    def test_changed_identity_and_unknown_outcome_cannot_pass(self):
        for key,value in EXPECTED_IDENTITY.items():
            broken=copy.deepcopy(self.envelope())
            broken['identity'][key]=value+1 if type(value) is int else 'synthetic-other'
            # Digest fields are absent from these native/browser fixture kinds.
            with self.subTest(identity=key):
                self.reject('identity-mismatch',lambda:self.kit.assert_conforms(broken,EXPECTED_IDENTITY,EXPECTED_STATE))
        broken=copy.deepcopy(self.envelope());broken['state']='unknown'
        self.reject('uncertainty-is-not-success',lambda:self.kit.validate(broken))
        broken['status']='unknown'
        self.kit.validate(broken)
        self.reject('outcome-mismatch',lambda:self.kit.assert_conforms(broken,EXPECTED_IDENTITY,EXPECTED_STATE))

    def test_unknown_fields_and_boolean_revisions_reject(self):
        broken=copy.deepcopy(self.envelope());broken['identity']['intent_revision']=True
        self.reject('field-type-or-bound',lambda:self.kit.validate(broken))
        broken=copy.deepcopy(self.envelope());broken['secret']='synthetic-canary'
        self.reject('unknown-key',lambda:self.kit.validate(broken))

    def test_corruption_and_pin_rewrite_fail_before_loading_code(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);shutil.copytree(ROOT/'fixtures',root/'fixtures',ignore=shutil.ignore_patterns('__pycache__'))
            path=root/'fixtures/shared-v1/fixturekit.py'
            path.write_text('raise RuntimeError("must not execute")')
            with self.assertRaisesRegex(ValueError,'pinned-file-mismatch'): checked_kit(root)
            pin=copy.deepcopy(PIN);pin['source_commit']='0'*40
            (root/'fixtures/shared-v1.pin.json').write_text(json.dumps(pin))
            with self.assertRaisesRegex(ValueError,'pin-mismatch'): checked_kit(root)

    def test_unreviewed_bytecode_cannot_replace_verified_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);shutil.copytree(ROOT/'fixtures',root/'fixtures',ignore=shutil.ignore_patterns('__pycache__'))
            source=root/'fixtures/shared-v1/fixturekit.py'
            with patch.object(sys,'pycache_prefix',None):
                cache=Path(importlib.util.cache_from_source(str(source)));cache.parent.mkdir()
                header=importlib.util.MAGIC_NUMBER+struct.pack('<III',0,int(source.stat().st_mtime),source.stat().st_size)
                unreviewed=compile("raise AssertionError('unreviewed bytecode executed')",str(source),'exec')
                cache.write_bytes(header+marshal.dumps(unreviewed))
                checked_kit(root)

    def test_standalone_with_no_sibling_and_denied_network(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);shutil.copytree(ROOT/'fixtures',root/'fixtures',ignore=shutil.ignore_patterns('__pycache__'))
            source=ROOT/'tests/test_shared_fixtures.py'
            # Load checked_kit without running unittest; no original checkout on sys.path.
            wrapper="import socket, runpy; deny=lambda *a,**k: (_ for _ in ()).throw(RuntimeError('network denied')); socket.socket.connect=deny; socket.create_connection=deny; socket.getaddrinfo=deny; namespace=runpy.run_path('consumer.py'); namespace['checked_kit']()"
            shutil.copyfile(source,root/'consumer.py')
            # The copied consumer is one level deeper so ROOT remains the isolated root.
            (root/'tests').mkdir();shutil.move(str(root/'consumer.py'),str(root/'tests/consumer.py'))
            wrapper=wrapper.replace("'consumer.py'","'tests/consumer.py'")
            process=subprocess.run([sys.executable,'-I','-c',wrapper],cwd=root,capture_output=True,text=True,timeout=10)
            self.assertEqual(process.returncode,0,process.stderr)


if __name__ == '__main__':
    unittest.main()

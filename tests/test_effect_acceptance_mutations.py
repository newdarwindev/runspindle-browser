"""F07 negative controls: effect acknowledgments and invalid readback are not success."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import cast

ROOT = Path(__file__).resolve().parents[1]
PROGRAM = r"""
import hashlib,json,pathlib,sys,tempfile
from dataclasses import replace
from browser_runtime.effects import Binding,Journal,Readback
from browser_testing.effect_site import Site
binding=Binding('principal','account','browser','tab','intent',1,'operation',1,'https://example.invalid')
payload=b'invented-action';digest=hashlib.sha256(payload).hexdigest()
with tempfile.TemporaryDirectory() as temporary:
    root=pathlib.Path(temporary);site=Site(root/'site.sqlite','lost')
    journal=Journal(root/'journal.sqlite',lambda *_:True,site.submit,site.observe)
    try:
        dispatch=journal.dispatch(binding,payload)
        if sys.argv[1]=='readback':
            journal.observe=lambda *_:Readback(replace(binding,account='other'),digest,'confirmed','a'*64)
            outcome=journal.reconcile(binding,digest)
        elif sys.argv[1]=='changed_receipt':
            receipt=Readback(binding,digest,'confirmed','a'*64)
            def observe(*_):
                def authorize(*_):
                    object.__setattr__(receipt,'evidence_digest','b'*64)
                    return True
                journal.approve=authorize
                return receipt
            journal.observe=observe
            outcome=journal.reconcile(binding,digest)
        else:outcome=dispatch
        print(json.dumps({'outcome':outcome,'effects':site.effects(),
                          'rows':journal.db.execute('SELECT outcome FROM operations').fetchall()}))
    finally:journal.close()
"""


class AcceptanceMutationControls(unittest.TestCase):
    def test_acknowledgment_and_invalid_readback_mutants_expose_false_success(
        self,
    ) -> None:
        cases = (
            (
                "ack",
                '        return "unknown"\n\n    @staticmethod\n',
                '        return "confirmed"\n\n    @staticmethod\n',
            ),
            (
                "readback",
                "or Binding.encoded(observed.binding) != encoded_binding",
                "or False",
            ),
            (
                "changed_receipt",
                "or _readback_receipt(observed, original_binding, payload_digest)\n"
                "                != receipt",
                "or False",
            ),
        )
        for name, anchor, replacement in cases:
            with self.subTest(case=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                for package in ("browser_runtime", "browser_testing"):
                    shutil.copytree(
                        ROOT / package,
                        root / package,
                        ignore=shutil.ignore_patterns("__pycache__"),
                    )
                command = [
                    sys.executable,
                    "-B",
                    *(["-O"] if sys.flags.optimize else []),
                    "-c",
                    PROGRAM,
                    name,
                ]

                def run() -> dict[str, object]:
                    result = subprocess.run(
                        command,
                        cwd=root,
                        capture_output=True,
                        text=True,
                        timeout=10,
                        env={**os.environ, "PYTHONPATH": str(root)},
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    return cast(dict[str, object], json.loads(result.stdout))

                baseline = run()
                self.assertEqual(
                    baseline,
                    {"outcome": "unknown", "effects": 1, "rows": [["unknown"]]},
                )
                path = root / "browser_runtime/effects.py"
                source = path.read_text()
                self.assertEqual(source.count(anchor), 1, "mutation anchor drift")
                path.write_text(source.replace(anchor, replacement))
                mutant = run()
                # A successful interpreter and an independently committed site
                # row distinguish a broken semantic invariant from syntax errors.
                self.assertEqual(mutant["effects"], 1)
                self.assertEqual(mutant["outcome"], "confirmed")
                self.assertEqual(
                    mutant["rows"], [["unknown" if name == "ack" else "confirmed"]]
                )

"""Preserve the existing main-push acceptance gate during hygiene changes."""

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class AcceptanceTriggerTests(unittest.TestCase):
    def test_existing_main_push_gate_is_preserved(self) -> None:
        workflow = (ROOT / ".github/workflows/gateway-test.yml").read_text()
        self.assertIn(
            "on:\n  push:\n    branches: [main]\n  workflow_dispatch:", workflow
        )


if __name__ == "__main__":
    unittest.main()

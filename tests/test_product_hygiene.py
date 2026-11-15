"""Source-only product checks stay mandatory without changing browser gates."""

import copy
import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

from tools import hygiene
from tools import partition_validation as gate
from tools.check_browser_product import ACCEPTANCE

ROOT = Path(__file__).resolve().parents[1]
CHECKERS = {
    "check-browser-product": "tools/check_browser_product.py",
    "check-credential-storage": "tools/check_credential_storage.py",
}


class ProductHygieneTests(unittest.TestCase):
    def setUp(self) -> None:
        self.partitions, self.inventory, _, _ = gate.manifests(ROOT)

    def entry(self, identifier: str) -> dict[str, Any]:
        entries = [row for row in self.inventory["checks"] if row["id"] == identifier]
        self.assertEqual(len(entries), 1)
        return dict(entries[0])

    def test_both_source_checkers_are_mandatory_exactly_once(self) -> None:
        for identifier, script in CHECKERS.items():
            entry = self.entry(identifier)
            command = ["python3", script]
            self.assertEqual(entry["command"], command)
            self.assertNotIn("not_applicable", entry)
            self.assertIn(script, entry["required_files"])
            self.assertEqual(
                sum(row.get("command") == command for row in self.inventory["checks"]),
                1,
            )
            self.assertEqual(
                self.partitions["partitions"]["component"].count(identifier), 1
            )
            self.assertEqual(
                sum(
                    ids.count(identifier)
                    for ids in self.partitions["partitions"].values()
                ),
                1,
            )

    def test_missing_checker_fails_without_execution(self) -> None:
        for identifier in CHECKERS:
            with tempfile.TemporaryDirectory() as directory:
                result = hygiene.run_entry(Path(directory), self.entry(identifier))
            self.assertEqual(result["status"], "failed")
            self.assertEqual(result["reason"], "required_file_missing")

    def test_missing_or_duplicate_partition_registration_fails(self) -> None:
        for identifier in CHECKERS:
            for action in ("remove", "duplicate"):
                data = copy.deepcopy(self.partitions)
                if action == "remove":
                    data["partitions"]["component"].remove(identifier)
                else:
                    data["partitions"]["quality"].append(identifier)
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    (root / "hygiene.json").write_text(json.dumps(self.inventory))
                    (root / "validation-partitions.json").write_text(json.dumps(data))
                    with self.assertRaises(ValueError):
                        gate.manifests(root)

    def test_entrypoint_delegates_without_duplicate_direct_calls(self) -> None:
        entrypoint = (ROOT / "tools/validate.py").read_text()
        self.assertEqual(entrypoint.count("from tools.hygiene import main"), 1)
        for script in CHECKERS.values():
            self.assertNotIn(Path(script).name, entrypoint)

    def test_rendered_keyboard_and_runtime_acceptance_remain_not_run(self) -> None:
        for key in ("rendered_desktop_mobile", "keyboard_navigation", "runtime"):
            self.assertEqual(ACCEPTANCE[key], "not_run")
        self.assertEqual(ACCEPTANCE["umbrella_mirror"], "pending")


if __name__ == "__main__":
    unittest.main()

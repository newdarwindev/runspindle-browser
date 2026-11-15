"""Keep the storage artifact checker mandatory once in hygiene validation."""

import copy
import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

from tools import hygiene
from tools import partition_validation as gate

ROOT = Path(__file__).resolve().parents[1]
CHECK_ID = "check-credential-storage"
COMMAND = ["python3", "tools/check_credential_storage.py"]


class StorageHygieneTests(unittest.TestCase):
    def setUp(self) -> None:
        self.partitions, self.inventory, _, _ = gate.manifests(ROOT)

    def entry(self) -> dict[str, Any]:
        entries = [row for row in self.inventory["checks"] if row["id"] == CHECK_ID]
        self.assertEqual(len(entries), 1)
        return dict(entries[0])

    def test_checker_is_mandatory_once_in_both_inventories(self) -> None:
        entry = self.entry()
        self.assertEqual(entry["command"], COMMAND)
        self.assertNotIn("not_applicable", entry)
        self.assertIn("tools/check_credential_storage.py", entry["required_files"])
        self.assertEqual(
            sum(row.get("command") == COMMAND for row in self.inventory["checks"]),
            1,
        )
        self.assertEqual(self.partitions["partitions"]["component"].count(CHECK_ID), 1)
        self.assertEqual(
            sum(ids.count(CHECK_ID) for ids in self.partitions["partitions"].values()),
            1,
        )

    def test_missing_checker_fails_without_attempting_execution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = hygiene.run_entry(Path(directory), self.entry())
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["reason"], "required_file_missing")

    def test_missing_or_duplicate_partition_registration_fails(self) -> None:
        for action in ("remove", "duplicate"):
            data = copy.deepcopy(self.partitions)
            if action == "remove":
                data["partitions"]["component"].remove(CHECK_ID)
            else:
                data["partitions"]["quality"].append(CHECK_ID)
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "hygiene.json").write_text(json.dumps(self.inventory))
                (root / "validation-partitions.json").write_text(json.dumps(data))
                with self.assertRaises(ValueError):
                    gate.manifests(root)

    def test_entrypoint_delegates_without_a_second_checker_call(self) -> None:
        entrypoint = (ROOT / "tools/validate.py").read_text()
        self.assertEqual(entrypoint.count("from tools.hygiene import main"), 1)
        self.assertNotIn("check_credential_storage.py", entrypoint)


if __name__ == "__main__":
    unittest.main()

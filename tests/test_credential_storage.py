"""Negative tests for the source inventory; no historical source is loaded."""

import copy
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

from tools.check_credential_storage import (
    COVERAGE,
    FILES,
    GUIDE,
    MANIFEST,
    ROOT,
    SPEC,
    Invalid,
    safe_file,
    validate,
)


class CredentialStorageArtifactTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        for name in {*FILES, MANIFEST, "STATUS.json"}:
            target = self.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)

    def read(self, name: str) -> dict[str, Any]:
        data: dict[str, Any] = json.loads((self.root / name).read_text())
        return data

    def write(self, name: str, data: dict[str, Any]) -> None:
        (self.root / name).write_text(json.dumps(data, indent=2) + "\n")

    def refresh(self) -> None:
        manifest = self.read(MANIFEST)
        for name in FILES:
            manifest["files"][name]["sha256"] = hashlib.sha256(
                (self.root / name).read_bytes()
            ).hexdigest()
        self.write(MANIFEST, manifest)

    def test_current_inventory_and_boundaries(self) -> None:
        result = validate(self.root)
        self.assertEqual(result["adapted_units"], 18)
        self.assertEqual(result["resolved_exclusions"], 8)
        self.assertEqual(result["runtime_acceptance"], "not_run")

    def test_removed_or_duplicate_requirement_fails_even_after_rehash(self) -> None:
        original = self.read(COVERAGE)
        for replacement in (
            original["units"][:-1],
            original["units"][:-1] + [original["units"][0]],
        ):
            data = copy.deepcopy(original)
            data["units"] = replacement
            self.write(COVERAGE, data)
            self.refresh()
            with self.assertRaises(Invalid):
                validate(self.root)

    def test_removed_obligation_or_changed_disposition_fails(self) -> None:
        original = self.read(COVERAGE)
        for key, value in (
            ("obligations", []),
            ("disposition", "excluded"),
            ("reason", ""),
        ):
            data = copy.deepcopy(original)
            data["units"][0][key] = value
            self.write(COVERAGE, data)
            self.refresh()
            with self.assertRaises(Invalid):
                validate(self.root)

    def test_unresolved_exclusion_or_runtime_claim_fails(self) -> None:
        original = self.read(COVERAGE)
        for key, value in (
            ("unresolved_exclusions", ["X01"]),
            ("runtime_acceptance", "passed"),
            ("scope", "all_sources"),
        ):
            data = copy.deepcopy(original)
            data[key] = value
            self.write(COVERAGE, data)
            self.refresh()
            with self.assertRaises(Invalid):
                validate(self.root)

    def test_missing_specification_anchor_or_extension_fails(self) -> None:
        original = (self.root / SPEC).read_text()
        for needle in ('<a id="r03"></a>', "## P01 "):
            (self.root / SPEC).write_text(original.replace(needle, "removed"))
            self.refresh()
            with self.assertRaises(Invalid):
                validate(self.root)

    def test_empty_exclusion_section_fails(self) -> None:
        body = (self.root / GUIDE).read_text()
        start = body.index('<a id="x01"></a>')
        end = body.index('<a id="x02"></a>')
        (self.root / GUIDE).write_text(body[:start] + '<a id="x01"></a>\n' + body[end:])
        self.refresh()
        with self.assertRaises(Invalid):
            validate(self.root)

    def test_deleted_test_method_fails_even_after_rehash(self) -> None:
        path = self.root / "tests/test_trusted_credentials.py"
        body = path.read_text()
        path.write_text(
            body.replace("def test_wrong_bindings_deny_before_read", "def removed_test")
        )
        self.refresh()
        with self.assertRaises(Invalid):
            validate(self.root)

    def test_stale_hash_missing_file_or_changed_classification_fails(self) -> None:
        path = self.root / "browser_testing/storage.py"
        original = path.read_bytes()
        path.write_bytes(original + b"\n")
        with self.assertRaises(Invalid):
            validate(self.root)
        path.unlink()
        with self.assertRaises(Invalid):
            validate(self.root)
        path.write_bytes(original)
        manifest = self.read(MANIFEST)
        manifest["files"]["browser_testing/storage.py"]["classification"] = "production"
        self.write(MANIFEST, manifest)
        with self.assertRaises(Invalid):
            validate(self.root)

    def test_unlisted_file_and_unknown_manifest_fields_fail(self) -> None:
        original = self.read(MANIFEST)
        for change in ("file", "field"):
            data = copy.deepcopy(original)
            if change == "file":
                data["files"]["../outside"] = {"sha256": "a" * 64}
            else:
                data["live_acceptance"] = "passed"
            self.write(MANIFEST, data)
            with self.assertRaises(Invalid):
                validate(self.root)

    def test_symlink_and_noncanonical_paths_fail(self) -> None:
        for name in (
            "../outside",
            "/etc/passwd",
            "docs/../STATUS.json",
            "./STATUS.json",
            "docs\\example",
        ):
            with self.assertRaises(Invalid):
                safe_file(self.root, name)
        path = self.root / SPEC
        path.unlink()
        path.symlink_to(ROOT / SPEC)
        with self.assertRaises(Invalid):
            validate(self.root)

    def test_duplicate_json_keys_and_boolean_version_fail(self) -> None:
        path = self.root / COVERAGE
        original = path.read_text()
        path.write_text(
            original.replace(
                '"source_id": "SRC-006",',
                '"source_id": "SRC-006", "source_id": "SRC-006",',
            )
        )
        with self.assertRaises(Invalid):
            validate(self.root)
        path.write_text(original)
        data = self.read(COVERAGE)
        data["schema_version"] = True
        self.write(COVERAGE, data)
        self.refresh()
        with self.assertRaises(Invalid):
            validate(self.root)

    def test_provenance_or_global_completion_inflation_fails(self) -> None:
        original = self.read("provenance.json")
        source = next(
            row for row in original["sources"] if row["source_id"] == "SRC-006"
        )
        source["runtime_acceptance"] = "passed"
        self.write("provenance.json", original)
        self.refresh()
        with self.assertRaises(Invalid):
            validate(self.root)
        shutil.copyfile(ROOT / "provenance.json", self.root / "provenance.json")
        self.refresh()
        status = self.read("STATUS.json")
        status["selected_source_migration"] = "complete"
        self.write("STATUS.json", status)
        with self.assertRaises(Invalid):
            validate(self.root)

    def test_private_locator_backstop_fails_even_after_rehash(self) -> None:
        path = self.root / GUIDE
        path.write_text(path.read_text() + "\nfile:///private-placeholder\n")
        self.refresh()
        with self.assertRaises(Invalid):
            validate(self.root)

    def test_optimized_cli_fails_closed_without_source_details(self) -> None:
        data = self.read(COVERAGE)
        data["units"][0]["id"] = "SYNTHETIC-PRIVATE-CANARY"
        self.write(COVERAGE, data)
        command = [sys.executable, "-O", "tools/check_credential_storage.py"]
        result = subprocess.run(
            command, cwd=self.root, capture_output=True, text=True, check=False
        )
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads(result.stdout)["status"], "failed")
        self.assertEqual(result.stderr, "")
        self.assertNotIn("SYNTHETIC-PRIVATE-CANARY", result.stdout)


if __name__ == "__main__":
    unittest.main()

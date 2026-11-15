"""Adversarial source checks; these tests do not launch a browser."""

from __future__ import annotations

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

from tools.check_browser_product import (
    ACCEPTANCE,
    COVERAGE,
    FILES,
    GUIDE,
    MANIFEST,
    PAGE,
    ROOT,
    Invalid,
    safe_file,
    validate,
)


class BrowserProductTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        # Copy the public document closure, not a user's filesystem or browser.
        for folder in ("docs", "specs"):
            shutil.copytree(ROOT / folder, self.root / folder)
        for name in {*FILES, "provenance.json", "STATUS.json"}:
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

    def reject_page(self, body: str) -> None:
        (self.root / PAGE).write_text(body)
        self.refresh()
        with self.assertRaises(Invalid):
            validate(self.root)

    def test_source_only_evidence_counts_and_pending_gates(self) -> None:
        result = validate(self.root)
        self.assertEqual(result["intent_units"], 25)
        self.assertEqual(result["asset_slots"], 17)
        self.assertEqual(result["resolved_exclusions"], 6)
        self.assertEqual(result["acceptance"], ACCEPTANCE)
        self.assertEqual(
            result["evidence_class"], "source_structure_not_rendered_acceptance"
        )

    def test_missing_duplicate_or_unknown_intent_rejected_after_rehash(self) -> None:
        original = self.read(COVERAGE)
        for units in (
            original["units"][:-1],
            original["units"][:-1] + [original["units"][0]],
        ):
            data = copy.deepcopy(original)
            data["units"] = units
            self.write(COVERAGE, data)
            self.refresh()
            with self.assertRaises(Invalid):
                validate(self.root)

    def test_intent_cannot_be_retargeted_or_claim_implementation(self) -> None:
        original = self.read(COVERAGE)
        for key, value in (
            ("target", PAGE + "#overview"),
            ("required_terms", []),
            ("implementation_evidence", True),
            ("disposition", "imported"),
        ):
            data = copy.deepcopy(original)
            data["units"][1][key] = value
            self.write(COVERAGE, data)
            self.refresh()
            with self.assertRaises(Invalid):
                validate(self.root)

    def test_dependency_assets_cannot_disappear_duplicate_or_be_imported(self) -> None:
        original = self.read(COVERAGE)
        for mutation in ("missing", "duplicate", "import"):
            data = copy.deepcopy(original)
            if mutation == "missing":
                data["assets"].pop()
            elif mutation == "duplicate":
                data["assets"][-1] = data["assets"][0]
            else:
                data["assets"][5]["original_imported"] = True
            self.write(COVERAGE, data)
            self.refresh()
            with self.assertRaises(Invalid):
                validate(self.root)

    def test_exclusion_requires_disposition_and_reason(self) -> None:
        original = self.read(COVERAGE)
        for key, value in (
            ("reason", ""),
            ("resolved_by", "not_reviewed"),
            ("id", "X99"),
        ):
            data = copy.deepcopy(original)
            data["exclusions"][0][key] = value
            self.write(COVERAGE, data)
            self.refresh()
            with self.assertRaises(Invalid):
                validate(self.root)

    def test_pending_gates_cannot_be_promoted(self) -> None:
        original = self.read(COVERAGE)
        for gate in ACCEPTANCE:
            data = copy.deepcopy(original)
            data["acceptance"][gate] = "passed"
            self.write(COVERAGE, data)
            self.refresh()
            with self.assertRaises(Invalid):
                validate(self.root)

    def test_meaningful_mapped_text_is_required_after_rehash(self) -> None:
        original = (self.root / PAGE).read_text()
        for old in (
            "frame-origin",
            "authenticated human release",
            "mutually exclusive",
            "same headed browser",
        ):
            self.reject_page(original.replace(old, "removed"))

    def test_duplicate_missing_and_empty_sections_rejected(self) -> None:
        original = (self.root / PAGE).read_text()
        for body in (
            original.replace('id="stack-api"', 'id="stack-secrets"'),
            original.replace('id="stack-api"', 'id="removed"'),
            original.replace('id="stack-api"', 'id=""'),
        ):
            self.reject_page(body)

    def test_scripts_network_assets_and_automatic_navigation_rejected(self) -> None:
        original = (self.root / PAGE).read_text()
        for content in (
            '<script src="remote.js"></script>',
            '<img src="remote.png" alt="diagram">',
            '<link rel="stylesheet" href="remote.css">',
            '<base href="https://example.invalid/">',
            '<meta http-equiv="refresh" content="0">',
            '<iframe src="remote.html"></iframe>',
        ):
            self.reject_page(original.replace("</head>", content + "</head>"))

    def test_event_handlers_hidden_content_and_bad_tab_order_rejected(self) -> None:
        original = (self.root / PAGE).read_text()
        for attr in (
            'onclick="act()"',
            "hidden",
            'aria-hidden="true"',
            'tabindex="2"',
            'style="display:none"',
        ):
            self.reject_page(
                original.replace('id="map-entry"', 'id="map-entry" ' + attr)
            )

    def test_semantic_list_cannot_be_collapsed_into_image_or_div(self) -> None:
        original = (self.root / PAGE).read_text()
        self.reject_page(
            original.replace('<figure class="map"', '<figure role="img" class="map"')
        )
        self.reject_page(original.replace("<ol>", "<div>").replace("</ol>", "</div>"))

    def test_malformed_html_or_duplicate_attributes_rejected(self) -> None:
        original = (self.root / PAGE).read_text()
        self.reject_page(original.replace("</figure>", "</section>"))
        self.reject_page(
            original.replace('id="map-entry"', 'id="map-entry" id="other"')
        )

    def test_focus_skip_or_mobile_rules_cannot_disappear(self) -> None:
        original = (self.root / PAGE).read_text()
        for needle in (
            "a:focus-visible",
            "flex-wrap: wrap",
            "@media (max-width: 44rem)",
            'class="skip"',
            'tabindex="-1"',
        ):
            self.reject_page(original.replace(needle, "removed"))

    def test_css_motion_hidden_or_remote_content_rejected(self) -> None:
        original = (self.root / PAGE).read_text()
        for rule in (
            '@import "remote.css";',
            "body { background: url(remote.png); }",
            ".map { display: none; }",
            ".map { opacity: 0; }",
            ".map { animation: reveal 1s; }",
        ):
            self.reject_page(original.replace("</style>", rule + "</style>"))

    def test_reviewed_css_signature_rejects_hidden_network_and_motion_syntax(
        self,
    ) -> None:
        original = (self.root / PAGE).read_text()
        rules = (
            '.map { background-image: image-set("//example.invalid/SYNTHETIC-CANARY.png" 1x); }',
            r".map { background-image: u\72l(//example.invalid/SYNTHETIC-CANARY.png); }",
            ".map { display: /* synthetic */ none; }",
            r".map { display: n\6fne; }",
            ".map { animation-name: synthetic; animation-duration: 1s; }",
            ".map { transition-property: opacity; transition-duration: 1s; }",
            "/* harmless new comment still requires review */",
            "\n",
        )
        for rule in rules:
            with self.subTest(rule=rule):
                self.reject_page(original.replace("</style>", rule + "</style>"))

    def test_reviewed_css_container_cannot_be_split_moved_or_reconfigured(self) -> None:
        original = (self.root / PAGE).read_text()
        for body in (
            original.replace("    body { margin:", "</style><style>    body { margin:"),
            original.replace("<style>", '<style id="reconfigured">'),
            original.replace("</head>", "</head><style></style>"),
        ):
            with self.subTest(body=body[:30]):
                self.reject_page(body)

    def test_escaped_css_cli_failure_is_closed_in_normal_and_optimized_modes(
        self,
    ) -> None:
        original = (self.root / PAGE).read_text()
        rule = (
            r".map { background-image: u\72l(//example.invalid/SYNTHETIC-CANARY.png); }"
        )
        (self.root / PAGE).write_text(original.replace("</style>", rule + "</style>"))
        self.refresh()
        for flags in ([], ["-O"]):
            result = subprocess.run(
                [sys.executable, *flags, "tools/check_browser_product.py"],
                cwd=self.root,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 1)
            self.assertEqual(json.loads(result.stdout)["status"], "failed")
            self.assertNotIn("SYNTHETIC-CANARY", result.stdout)
            self.assertEqual(result.stderr, "")

    def test_navigation_rejects_missing_fragment_and_external_or_encoded_target(
        self,
    ) -> None:
        original = (self.root / PAGE).read_text()
        for target in (
            "#missing",
            "https://example.invalid/",
            "//example.invalid/",
            "%2e%2e/secret",
            "javascript:act()",
            "../../../../outside",
            "index.html#unverified",
        ):
            self.reject_page(
                original.replace('href="index.html"', 'href="' + target + '"')
            )

    def test_local_link_destination_is_required(self) -> None:
        (self.root / "specs/effect-journal-v1.md").unlink()
        with self.assertRaises(Invalid):
            validate(self.root)

    def test_page_cannot_claim_rendered_or_runtime_acceptance(self) -> None:
        original = (self.root / PAGE).read_text()
        self.reject_page(
            original.replace(
                "Actual desktop/mobile rendering and keyboard behavior have not been verified",
                "Rendered acceptance passed",
            )
        )
        self.reject_page(
            original.replace(
                "live acceptance are not established", "live acceptance passed"
            )
        )

    def test_hash_file_classification_or_manifest_inventory_tampering_rejected(
        self,
    ) -> None:
        original = self.read(MANIFEST)
        for mutation in ("hash", "class", "extra", "schema"):
            data = copy.deepcopy(original)
            if mutation == "hash":
                data["files"][PAGE]["sha256"] = "0" * 64
            elif mutation == "class":
                data["files"][PAGE]["classification"] = "runtime"
            elif mutation == "extra":
                data["files"]["extra.txt"] = {}
            else:
                data["schema_version"] = True
            self.write(MANIFEST, data)
            with self.assertRaises(Invalid):
                validate(self.root)

    def test_duplicate_json_and_unknown_schema_fields_rejected(self) -> None:
        original = (self.root / COVERAGE).read_text()
        (self.root / COVERAGE).write_text(
            original.replace(
                '"source_id": "SRC-009",',
                '"source_id": "SRC-009", "source_id": "SRC-009",',
            )
        )
        with self.assertRaises(Invalid):
            validate(self.root)
        data = json.loads(original)
        data["verified"] = True
        self.write(COVERAGE, data)
        self.refresh()
        with self.assertRaises(Invalid):
            validate(self.root)

    def test_provenance_and_global_runtime_status_remain_partial(self) -> None:
        data = self.read("provenance.json")
        next(row for row in data["sources"] if row["source_id"] == "SRC-009")[
            "runtime_acceptance"
        ] = "passed"
        self.write("provenance.json", data)
        with self.assertRaises(Invalid):
            validate(self.root)
        shutil.copyfile(ROOT / "provenance.json", self.root / "provenance.json")
        data = self.read("STATUS.json")
        data["selected_source_migration"] = "complete"
        self.write("STATUS.json", data)
        with self.assertRaises(Invalid):
            validate(self.root)

    def test_no_private_locators_after_rehash(self) -> None:
        path = self.root / GUIDE
        original = path.read_text()
        for marker in (
            "file:///SYNTHETIC-CANARY",
            "/workspace/SYNTHETIC-CANARY",
            "https://example.invalid/private",
        ):
            path.write_text(original + "\n" + marker)
            self.refresh()
            with self.assertRaises(Invalid):
                validate(self.root)

    def test_symlinks_and_unsafe_paths_rejected(self) -> None:
        for path in (
            "../outside",
            "/outside",
            "docs/../STATUS.json",
            "./STATUS.json",
            "docs\\file",
        ):
            with self.assertRaises(Invalid):
                safe_file(self.root, path)
        target = self.root / PAGE
        target.unlink()
        target.symlink_to(ROOT / PAGE)
        with self.assertRaises(Invalid):
            validate(self.root)

    def test_cli_failure_is_sanitized_and_fails_under_optimization(self) -> None:
        data = self.read(COVERAGE)
        data["units"][0]["id"] = "SYNTHETIC-PRIVATE-CANARY"
        self.write(COVERAGE, data)
        for flags in ([], ["-O"]):
            result = subprocess.run(
                [sys.executable, *flags, "tools/check_browser_product.py"],
                cwd=self.root,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 1)
            self.assertEqual(json.loads(result.stdout)["status"], "failed")
            self.assertNotIn("SYNTHETIC-PRIVATE-CANARY", result.stdout)
            self.assertEqual(result.stderr, "")


if __name__ == "__main__":
    unittest.main()

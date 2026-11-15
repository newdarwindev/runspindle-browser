#!/usr/bin/env python3
"""Check SRC-009 source accounting, never rendered or runtime acceptance."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from html.parser import HTMLParser
from pathlib import Path, PurePosixPath
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
PAGE = "docs/product/browser.html"
GUIDE = "docs/product/browser-source-review.md"
COVERAGE = "docs/product/browser-coverage.json"
MANIFEST = "docs/product/browser-artifact-manifest.json"
# The only supported stylesheet is the reviewed newly authored static source.
# This is a byte-integrity boundary, not a generalized CSS parser or sanitizer.
# Any CSS edit, including whitespace, requires source review and a new signature.
REVIEWED_CSS_SHA256 = "09c2d6807a623307ea823c12b96b22e593c399c9d1bdea04d806ac82c1870824"
FILES = {
    "hygiene.json": "mandatory_check_inventory",
    "validation-partitions.json": "mandatory_partition_inventory",
    "tests/test_product_hygiene.py": "integration_regression_tests",
    "tools/validate.py": "required_validation_entrypoint",
    "provenance.json": "public_source_provenance",
    PAGE: "original_static_explanation",
    GUIDE: "source_review_and_pending_acceptance",
    COVERAGE: "source_intent_and_asset_inventory",
    "tools/check_browser_product.py": "structural_checker_not_renderer",
    "tests/test_browser_product.py": "structural_negative_tests",
    "docs/product/README.md": "canonical_source_instructions",
    "docs/product/THIRD_PARTY_NOTICES.md": "rights_and_exclusion_notice",
}
ACCEPTANCE = {
    "source_structure": "checked_separately",
    "rendered_desktop_mobile": "not_run",
    "keyboard_navigation": "not_run",
    "independent_review": "required_before_publication",
    "umbrella_mirror": "pending",
    "runtime": "not_run",
}
UNITS = {
    "P01": ("overview", ["authorized account", "bounded task", "permission"]),
    "P02": ("same-browser", ["same headed browser", "account profiles", "host"]),
    "P03": ("one-controller", ["stale lease epochs", "passive viewing", "revoke"]),
    "P04": ("durable-intent", ["durable", "reconcile", "restart"]),
    "S01": ("stack-api", ["pinchtab", "account-scoped authority", "blocked"]),
    "S02": ("stack-view", ["kasmvnc", "passive view", "unverified"]),
    "S03": ("stack-secrets", ["openbao", "kv-v2", "transit", "planned"]),
    "S04": ("stack-workflow", ["temporal", "fencing", "reconciliation"]),
    "S05": ("stack-identity", ["authelia", "pomerium", "untested"]),
    "S06": ("stack-ingress", ["caddy", "optional", "authority"]),
    "D01": ("map-entry", ["console", "core", "host", "lease epoch"]),
    "D02": ("map-workflow", ["core", "temporal", "fencing"]),
    "D03": ("map-browser", ["pinchtab", "kasmvnc", "mutually exclusive"]),
    "D04": ("map-vault", ["openbao", "frame-origin", "secret values"]),
    "D05": ("map-identity", ["authelia", "pomerium", "caddy", "separate revocation"]),
    "F01": ("flow-identify", ["principal", "account", "trusted", "cannot enlarge"]),
    "F02": ("flow-reserve", ["lease", "pinned host", "isolated profile"]),
    "F03": ("flow-operate", ["broker", "origin", "epoch", "uncertain"]),
    "F04": (
        "flow-handoff",
        ["fresh epoch", "authenticated human release", "must not silently"],
    ),
    "E01": ("evidence-local", ["synthetic", "local", "do not establish"]),
    "E02": ("evidence-runtime", ["unqualified", "no source repository", "transfers"]),
    "I01": ("map-reading", ["every role is visible", "no animation", "javascript"]),
    "I02": ("map-caption", ["all five roles", "document order", "without scripts"]),
    "I03": ("architecture-island", ["static design map", "not evidence"]),
    "I04": (
        "evidence-page",
        ["desktop/mobile", "keyboard", "not been verified", "stays open"],
    ),
}
ASSETS = {
    "A01": "adapt_intent_original_expression_excluded",
    "A02": "exclude_static_replacement",
    "A03": "adapt_intent_original_expression_excluded",
    "A04": "exclude_original_styles_new_css",
    "A05": "exclude_dependency_free_choice",
    "A06": "exclude_all_locked_dependencies",
    "A07": "exclude_dependency_free_choice",
    "A08": "adapt_intent_checks_not_executed",
    "A09": "adapt_intent_new_structural_tests",
    "A10": "adapt_intent_static_states",
    "A11": "exclude_dependency_free_choice",
    "A12": "exclude_original_styles_new_css",
    "A13": "exclude_dependency_free_choice",
    "A14": "exclude_no_publication_or_runner_import",
    "A15": "review_only_no_original_expression",
    "A16": "review_only_no_original_expression",
    "A17": "review_only_no_original_expression",
}


class Invalid(ValueError):
    """Fixed diagnostics prevent untrusted content from entering logs."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Invalid(message)


def safe_file(root: Path, name: str) -> Path:
    require(type(name) is str and bool(name), "invalid path")
    path = PurePosixPath(name)
    require(
        not path.is_absolute()
        and str(path) == name
        and not set(path.parts) & {".", ".."}
        and "\\" not in name,
        "unsafe path",
    )
    current = root
    for part in path.parts:
        current = current / part
        require(not current.is_symlink(), "symlink forbidden")
    require(current.is_file(), "file missing")
    require(current.resolve().is_relative_to(root.resolve()), "path escaped root")
    return current


def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    data: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in data, "duplicate JSON key")
        data[key] = value
    return data


def read_json(root: Path, name: str) -> dict[str, Any]:
    data = json.loads(safe_file(root, name).read_text(), object_pairs_hook=unique)
    require(type(data) is dict, "JSON object required")
    return dict(data)


class Page(HTMLParser):
    """Narrow parser for this static document, not a browser or HTML sanitizer."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.ids: dict[str, str] = {}
        self.locations: dict[str, tuple[str, str | None]] = {}
        self.stack: list[tuple[str, str | None]] = []
        self.links: list[str] = []
        self.h1 = 0
        self.language = False
        self.viewport = False
        self.css = ""
        self.style_count = 0
        self.skip = False
        self.main_focus = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        names = [name for name, _ in attrs]
        require(len(names) == len(set(names)), "duplicate HTML attribute")
        attr = dict(attrs)
        if tag == "style":
            self.style_count += 1
            require(
                self.style_count == 1
                and not attrs
                and bool(self.stack)
                and self.stack[-1][0] == "head",
                "stylesheet container changed",
            )
        require(
            set(names).issubset(
                {
                    "lang",
                    "charset",
                    "name",
                    "content",
                    "href",
                    "class",
                    "aria-label",
                    "aria-current",
                    "aria-labelledby",
                    "aria-describedby",
                    "id",
                    "tabindex",
                }
            ),
            "unreviewed HTML attribute",
        )
        require(
            tag
            in {
                "html",
                "head",
                "meta",
                "title",
                "style",
                "body",
                "a",
                "header",
                "nav",
                "main",
                "section",
                "p",
                "h1",
                "strong",
                "br",
                "h2",
                "ul",
                "li",
                "h3",
                "figure",
                "ol",
                "figcaption",
                "footer",
            },
            "active or unreviewed asset",
        )
        require(
            not any(name.startswith("on") for name in names)
            and not set(names)
            & {"src", "srcset", "hidden", "style", "autofocus", "contenteditable"},
            "unreviewed behavior",
        )
        require(attr.get("aria-hidden") not in {"true", ""}, "hidden content")
        require(attr.get("role") != "img", "semantic map hidden as image")
        if "tabindex" in attr:
            require(tag == "main" and attr["tabindex"] == "-1", "tab order changed")
            self.main_focus = True
        if tag == "html":
            self.language = attr.get("lang") == "en"
        if tag == "meta" and attr.get("name") == "viewport":
            self.viewport = attr.get("content") == "width=device-width, initial-scale=1"
        require(not (tag == "meta" and "http-equiv" in attr), "automatic navigation")
        if tag == "h1":
            self.h1 += 1
        if tag == "a":
            href = attr.get("href")
            require(type(href) is str and bool(href), "anchor lacks destination")
            self.links.append(str(href))
            if attr.get("class") == "skip" and href == "#main":
                self.skip = True
        identity = attr.get("id")
        if identity is not None:
            require(
                bool(identity) and identity not in self.ids, "duplicate or empty ID"
            )
            self.ids[identity] = ""
            self.locations[identity] = (tag, self.stack[-1][0] if self.stack else None)
        if tag not in {"meta", "br", "hr"}:
            self.stack.append((tag, identity))

    def handle_endtag(self, tag: str) -> None:
        require(bool(self.stack) and self.stack[-1][0] == tag, "unbalanced HTML")
        self.stack.pop()

    def handle_data(self, data: str) -> None:
        for tag, identity in self.stack:
            if identity is not None:
                self.ids[identity] += data
            if tag == "style":
                self.css += data


def check_page(root: Path) -> Page:
    body = safe_file(root, PAGE).read_text()
    page = Page()
    page.feed(body)
    page.close()
    require(not page.stack, "unclosed HTML")
    require(
        page.h1 == 1 and page.language and page.viewport, "document semantics missing"
    )
    require(page.skip and page.main_focus, "skip navigation missing")
    required_links = {
        "#main",
        "#architecture",
        "#architecture-island",
        "#principles",
        "#status",
    }
    require(required_links.issubset(page.links), "source navigation missing")
    for identity in (
        "map-entry",
        "map-workflow",
        "map-browser",
        "map-vault",
        "map-identity",
        "flow-identify",
        "flow-reserve",
        "flow-operate",
        "flow-handoff",
    ):
        require(
            page.locations.get(identity) == ("li", "ol"),
            "semantic reading order changed",
        )
    for href in page.links:
        require(
            not re.search(r"[:?\\%]", href) and not href.startswith("/"),
            "nonlocal or ambiguous link",
        )
        relative, separator, fragment = href.partition("#")
        if not relative:
            require(bool(separator) and fragment in page.ids, "missing local anchor")
        else:
            require(not separator, "unchecked cross-document fragment")
            target = (root / "docs/product" / relative).resolve()
            require(target.is_relative_to(root.resolve()), "link escaped root")
            safe_file(root, target.relative_to(root.resolve()).as_posix())
    # A manifest refresh must not silently approve new CSS syntax. Comparing the
    # exact text rejects comments, escapes, alternate resource functions and
    # longhand declarations without pretending to interpret arbitrary CSS.
    require(
        page.style_count == 1
        and hashlib.sha256(page.css.encode("utf-8")).hexdigest() == REVIEWED_CSS_SHA256,
        "stylesheet differs from reviewed source",
    )
    css = page.css.lower()
    for marker in (
        "a:focus-visible",
        "outline: 3px",
        "flex-wrap: wrap",
        "@media (max-width: 44rem)",
        "grid-template-columns: minmax(0, 1fr)",
    ):
        require(marker in css, "source accessibility provision missing")
    require(
        "actual desktop/mobile rendering and keyboard behavior have not been verified"
        in body.lower(),
        "rendering status inflated",
    )
    require(
        "live acceptance are not established" in body.lower(), "runtime status inflated"
    )
    return page


def check_coverage(root: Path, page: Page) -> None:
    coverage = read_json(root, COVERAGE)
    require(
        set(coverage)
        == {
            "schema_version",
            "source_id",
            "scope",
            "rendering_choice",
            "units",
            "assets",
            "exclusions",
            "unresolved_exclusions",
            "acceptance",
        },
        "coverage schema changed",
    )
    require(
        type(coverage["schema_version"]) is int and coverage["schema_version"] == 1,
        "schema version changed",
    )
    require(
        coverage["source_id"] == "SRC-009"
        and coverage["scope"] == "selected_page_and_rendering_dependency_closure",
        "source scope changed",
    )
    require(
        coverage["rendering_choice"] == "new_dependency_free_static_equivalent",
        "rendering choice changed",
    )
    require(
        coverage["acceptance"] == ACCEPTANCE
        and coverage["unresolved_exclusions"] == [],
        "acceptance or exclusion changed",
    )
    rows = coverage["units"]
    require(type(rows) is list and len(rows) == len(UNITS), "unit inventory changed")
    seen: set[str] = set()
    for row in rows:
        require(
            type(row) is dict
            and set(row)
            == {
                "id",
                "intent",
                "target",
                "required_terms",
                "disposition",
                "implementation_evidence",
            },
            "unit schema changed",
        )
        unit = row["id"]
        require(
            type(unit) is str and unit in UNITS and unit not in seen,
            "unit missing or duplicated",
        )
        seen.add(unit)
        anchor, terms = UNITS[unit]
        require(
            row["target"] == PAGE + "#" + anchor and row["required_terms"] == terms,
            "intent mapping changed",
        )
        require(
            type(row["intent"]) is str and len(row["intent"].strip()) > 12,
            "intent absent",
        )
        require(
            row["disposition"] == "adapted_intent"
            and row["implementation_evidence"] is False,
            "evidence classification changed",
        )
        require(
            anchor in page.ids and len(page.ids[anchor].strip()) >= 100,
            "source section missing",
        )
        for term in terms:
            require(term in page.ids[anchor].lower(), "mapped obligation missing")
    rows = coverage["assets"]
    require(type(rows) is list and len(rows) == len(ASSETS), "asset inventory changed")
    seen = set()
    for row in rows:
        require(
            type(row) is dict
            and set(row) == {"id", "role", "disposition", "original_imported"},
            "asset schema changed",
        )
        slot = row["id"]
        require(
            type(slot) is str and slot in ASSETS and slot not in seen,
            "asset missing or duplicated",
        )
        seen.add(slot)
        require(
            row["disposition"] == ASSETS[slot] and row["original_imported"] is False,
            "asset import changed",
        )
        require(
            type(row["role"]) is str and len(row["role"]) > 8,
            "asset description absent",
        )
    rows = coverage["exclusions"]
    require(type(rows) is list and len(rows) == 6, "exclusions changed")
    seen = set()
    for row in rows:
        require(
            type(row) is dict
            and set(row) == {"id", "subject", "reason", "resolved_by"},
            "exclusion schema changed",
        )
        exclusion = row["id"]
        require(
            type(exclusion) is str
            and exclusion in {f"X{n:02}" for n in range(1, 7)}
            and exclusion not in seen,
            "exclusion missing or duplicated",
        )
        seen.add(exclusion)
        require(
            row["resolved_by"] == "safe_exclusion"
            and type(row["reason"]) is str
            and len(row["reason"].strip()) > 80,
            "exclusion unexplained",
        )


def validate(root: Path = ROOT) -> dict[str, Any]:
    page = check_page(root)
    check_coverage(root, page)
    manifest = read_json(root, MANIFEST)
    require(
        set(manifest)
        == {
            "schema_version",
            "source_id",
            "evidence_class",
            "selected_artifact_status",
            "historical_import",
            "acceptance",
            "files",
        },
        "manifest schema changed",
    )
    require(
        type(manifest["schema_version"]) is int and manifest["schema_version"] == 1,
        "manifest version changed",
    )
    require(
        manifest["source_id"] == "SRC-009"
        and manifest["evidence_class"] == "source_structure_not_rendered_acceptance",
        "manifest evidence changed",
    )
    require(
        manifest["selected_artifact_status"]
        == "source_accounted_rendered_acceptance_pending"
        and manifest["historical_import"] == "none"
        and manifest["acceptance"] == ACCEPTANCE,
        "manifest status inflated",
    )
    require(
        type(manifest["files"]) is dict and set(manifest["files"]) == set(FILES),
        "file inventory changed",
    )
    for name, classification in FILES.items():
        record = manifest["files"][name]
        require(
            type(record) is dict and set(record) == {"classification", "sha256"},
            "file schema changed",
        )
        require(record["classification"] == classification, "file evidence changed")
        body = safe_file(root, name).read_bytes()
        require(
            hashlib.sha256(body).hexdigest() == record["sha256"], "file hash mismatch"
        )
    for name in (PAGE, GUIDE, COVERAGE, MANIFEST):
        require(
            not re.search(
                r"/(?:workspace|home|Users)/|file://|https?://|dots-",
                safe_file(root, name).read_text(),
            ),
            "private or unreviewed locator",
        )
    source = [
        row
        for row in read_json(root, "provenance.json")["sources"]
        if row["source_id"] == "SRC-009"
    ]
    require(len(source) == 1, "provenance missing or duplicated")
    require(
        source[0]["migration_status"] == "partial"
        and source[0]["selected_artifact_status"]
        == manifest["selected_artifact_status"],
        "provenance status changed",
    )
    require(
        source[0]["artifact_manifest"] == MANIFEST
        and source[0]["coverage"] == COVERAGE
        and source[0]["runtime_acceptance"] == "not_run",
        "provenance mapping changed",
    )
    status = read_json(root, "STATUS.json")
    require(
        status["selected_source_migration"] == "partial"
        and status["live_acceptance"] == "not_run",
        "global acceptance inflated",
    )
    return {
        "status": "passed",
        "source_id": "SRC-009",
        "evidence_class": "source_structure_not_rendered_acceptance",
        "intent_units": len(UNITS),
        "asset_slots": len(ASSETS),
        "resolved_exclusions": 6,
        "acceptance": ACCEPTANCE,
    }


def main() -> None:
    try:
        result = validate()
        result["commit"] = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip()
        result["tree"] = subprocess.check_output(
            ["git", "rev-parse", "HEAD^{tree}"], cwd=ROOT, text=True
        ).strip()
        result["dirty"] = bool(
            subprocess.check_output(
                ["git", "status", "--porcelain"], cwd=ROOT, text=True
            ).strip()
        )
        result["manifest_sha256"] = hashlib.sha256(
            safe_file(ROOT, MANIFEST).read_bytes()
        ).hexdigest()
    except (
        Invalid,
        OSError,
        ValueError,
        KeyError,
        TypeError,
        subprocess.CalledProcessError,
    ):
        print(
            json.dumps(
                {
                    "status": "failed",
                    "evidence_class": "source_structure_not_rendered_acceptance",
                    "runtime_acceptance": "not_run",
                },
                sort_keys=True,
            )
        )
        raise SystemExit(1) from None
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()

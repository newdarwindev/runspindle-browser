#!/usr/bin/env python3
"""Bounded local Chrome render of cleared Browser HTML; no runtime claim."""

import argparse
import base64
import hashlib
import html
import json
import platform
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from tools.browser_cdp import render

ROOT = Path(__file__).resolve().parents[1]
CANONICAL = ROOT / "docs/product/browser.html"
REFERENCE = ROOT / "docs/visual/browser-reference.html"
VIEWPORTS = (
    ("mobile-320", 320, 900),
    ("mobile-390", 390, 900),
    ("tablet-768", 768, 900),
    ("desktop-1440", 1440, 900),
)
CHROME = Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(
    chrome: Path,
    source: Path,
    width: int,
    height: int,
    screenshot: Path | None = None,
    mode: str = "plain",
) -> dict[str, Any]:
    return render(chrome, source, width, height, screenshot, mode)


def verify(result: dict[str, Any], width: int) -> bool:
    return bool(
        result["width"] == width
        and result["docWidth"] <= width + 1
        and result["mapCount"] == 5
        and len(set(result["labels"])) == 5
        and all(result["labels"])
        and result["headingCount"] == 1
        and result["cards"] == 6
        and not result["outside"]
        and not result["missingAnchors"]
        and result["focusTarget"]
        and result["focusOutline"]
        and result["fontReady"]
        and result["visibleMap"]
    )


def sheet_html(images: list[tuple[str, Path]], destination: Path) -> None:
    rows = []
    for name, path in images:
        data = base64.b64encode(path.read_bytes()).decode("ascii")
        rows.append(
            f"<figure><figcaption>{html.escape(name)}</figcaption>"
            f'<img alt="{html.escape(name)}" src="data:image/png;base64,{data}"></figure>'
        )
    destination.write_text(
        "<!doctype html><html lang='en'><meta charset='utf-8'>"
        "<style>body{font:16px system-ui;margin:16px;background:#fff}"
        "main{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}"
        "figure{margin:0;min-width:0}img{width:100%;height:520px;"
        "object-fit:contain;object-position:top;border:1px solid #555}"
        "figcaption{font-weight:bold}</style><h1>Browser #11: "
        "reference candidates and canonical renders</h1><main>"
        + "".join(rows)
        + "</main></html>"
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--chrome", type=Path, default=CHROME)
    args = parser.parse_args()
    if not args.chrome.is_file():
        raise SystemExit("blocked: pinned local Chrome unavailable")
    version = subprocess.run(
        [str(args.chrome), "--version"], capture_output=True, text=True, timeout=5
    ).stdout.strip()
    if version != "Google Chrome 157.0.8103.78":
        raise SystemExit("blocked: Chrome version differs from reviewed local pin")
    if args.output.exists() and any(args.output.iterdir()):
        raise SystemExit("blocked: output exists; use a fresh directory and compare")
    args.output.mkdir(parents=True, exist_ok=True)
    results: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="browser-visual-") as temp:
        directory = Path(temp)
        mutation = run(args.chrome, CANONICAL, 390, 900, mode="missing-label")
        if mutation["labels"][2] or verify(mutation, 390):
            raise RuntimeError("missing-label mutation escaped detection")
        zoom_proxy = run(args.chrome, CANONICAL, 195, 900, mode="probe")
        if not verify(zoom_proxy, 195):
            raise RuntimeError(f"200% layout-width proxy failed: {zoom_proxy}")
        images: list[tuple[str, Path]] = []
        for name, width, height in VIEWPORTS:
            result = run(args.chrome, CANONICAL, width, height, mode="probe")
            if not verify(result, width):
                raise RuntimeError(f"layout or DOM failure at {name}: {result}")
            reference_png = args.output / f"reference-{name}.png"
            actual_png = args.output / f"canonical-map-{name}.png"
            run(
                args.chrome,
                REFERENCE,
                width,
                height,
                screenshot=reference_png,
                mode="full",
            )
            run(
                args.chrome, CANONICAL, width, height, screenshot=actual_png, mode="map"
            )
            images.extend(
                (
                    (f"Reference candidate {name}", reference_png),
                    (f"Canonical map {name}", actual_png),
                )
            )
            results.append(
                {
                    "scenario": name,
                    "viewport": [width, height],
                    "dom": result,
                    "reference_sha256": sha(reference_png),
                    "canonical_sha256": sha(actual_png),
                }
            )
        sheet = directory / "sheet.html"
        sheet_html(images, sheet)
        contact = args.output / "contact-sheet.png"
        run(args.chrome, sheet, 1600, 1250, screenshot=contact)
    evidence = {
        "evidence_class": "local_chrome_visual_candidate",
        "chrome": version,
        "os": platform.platform(),
        "dpr": 1,
        "locale": "en-US",
        "timezone": "UTC",
        "animation": "none_on_source",
        "clock": "no_time_dependent_page_content",
        "seed": "fixed_static_fixture",
        "font_stack": "system-ui, sans-serif; exact installed font digest not pinned",
        "source_sha256": sha(CANONICAL),
        "reference_source_sha256": sha(REFERENCE),
        "driver_sha256": sha(ROOT / "tools/browser_cdp.py"),
        "generator_sha256": sha(ROOT / "tools/browser_visual.py"),
        "missing_label_mutation_detected": True,
        "scenarios": results,
        "zoom_200_percent_layout_proxy": zoom_proxy,
        "contact_sheet_sha256": sha(contact),
        "reference_review": "generated_not_reviewed",
        "canonical_render": "locally_observed_instrumented_copy",
        "pixel_baseline_comparison": "not_run_no_approved_baseline",
        "manual_keyboard_and_assistive_technology": "not_run",
        "actual_browser_zoom_200_percent": "not_run_layout_proxy_only",
        "umbrella_mirror": "not_run",
        "runtime_browser_integration": "not_run",
    }
    (args.output / "evidence.json").write_text(json.dumps(evidence, indent=2) + "\n")
    print(
        json.dumps(
            {
                "status": "passed_local_candidate",
                "scenarios": len(results),
                "mutation_detected": True,
                "chrome": version,
            }
        )
    )


if __name__ == "__main__":
    main()

"""Compare the pinned Browser architecture section and its composition copy."""

import argparse
import hashlib
import json
import platform
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from tools.browser_visual import (
    CANONICAL,
    CHROME,
    REFERENCE,
    ROOT,
    VIEWPORTS,
    run,
    sha,
    verify,
)

COMPOSITION = "1880adfa713a6eeacbc4887722a5f11d9bea263b"
CHROME_VERSION = "Google Chrome 158.0.8127.36"
RECEIPT = "docs/marketing/SRC-009-mirror.json"
MIRROR = "docs/marketing/browser.html"
REFERENCE_EVIDENCE = ROOT / "docs/visual/generated/evidence.json"
MUTATION_SCENARIO = "mobile-390"


def committed_file(repo: Path, commit: str, path: str) -> bytes:
    return subprocess.check_output(
        ["git", "-C", str(repo), "show", f"{commit}:{path}"], timeout=10
    )


def validate_keyboard(result: dict[str, Any]) -> None:
    links = [result["skip"], *result["sectionLinks"]]
    if (
        [(link["href"], link["name"]) for link in links]
        != [
            ("#main", "Skip to content"),
            ("#architecture", "Architecture"),
            ("#architecture-island", "System map"),
        ]
        or result["skipTarget"] != "main"
        or result["selectedFragment"] != "#architecture-island"
        or not all(
            link["focusVisible"] and link["fullyOnscreen"] and link["unobscured"]
            for link in links
        )
    ):
        raise RuntimeError("Skip or system-map keyboard navigation failed")


def compare(chrome: Path, composition: Path, output: Path) -> dict[str, Any]:
    version = subprocess.check_output([str(chrome), "--version"], text=True, timeout=5)
    if version.strip() != CHROME_VERSION:
        raise RuntimeError("Chrome version differs from the mirror comparison pin")
    receipt_bytes = committed_file(composition, COMPOSITION, RECEIPT)
    receipt = json.loads(receipt_bytes)
    derivative = committed_file(composition, COMPOSITION, MIRROR)
    mirror_sha = hashlib.sha256(derivative).hexdigest()
    canonical_sha = sha(CANONICAL)
    upstream = receipt["canonical"]
    reference = json.loads(REFERENCE_EVIDENCE.read_bytes())
    if (
        receipt["source_id"] != "SRC-009"
        or receipt["destination"] != MIRROR
        or receipt["destination_sha256"] != mirror_sha
        or upstream["repository"] != "newdarwindev/runspindle-browser"
        or upstream["path"] != CANONICAL.relative_to(ROOT).as_posix()
        or upstream["sha256"] != canonical_sha
        or committed_file(ROOT, upstream["commit"], upstream["path"])
        != CANONICAL.read_bytes()
        or reference["source_sha256"] != canonical_sha
        or reference["reference_source_sha256"] != sha(REFERENCE)
    ):
        raise RuntimeError("Browser art and its composition provenance disagree")
    if output.exists() and any(output.iterdir()):
        raise RuntimeError("Use a fresh output directory")
    output.mkdir(parents=True, exist_ok=True)

    observations = []
    with tempfile.TemporaryDirectory(prefix="browser-mirror-visual-") as temporary:
        directory = Path(temporary)
        mirror = directory / "browser.html"
        mirror.write_bytes(derivative)
        for name, width, height in VIEWPORTS:
            canonical_png = output / f"canonical-{name}.png"
            mirror_png = output / f"mirror-{name}.png"
            actual = run(
                chrome, CANONICAL, width, height, canonical_png, "architecture"
            )
            copied = run(chrome, mirror, width, height, mirror_png, "architecture")
            validate_keyboard(actual["keyboard"])
            if (
                not verify(actual, width)
                or actual != copied
                or canonical_png.read_bytes() != mirror_png.read_bytes()
            ):
                raise RuntimeError(f"Browser architecture comparison failed at {name}")
            observations.append(
                {
                    "scenario": name,
                    "viewport": [width, height],
                    "canonical_png_sha256": sha(canonical_png),
                    "mirror_png_sha256": sha(mirror_png),
                    "architecture_dom_and_keyboard": actual,
                }
            )

        scenario = next(
            item for item in observations if item["scenario"] == MUTATION_SCENARIO
        )
        width, height = scenario["viewport"]
        mutant = directory / "mutant.html"
        mutant.write_bytes(
            derivative.replace(
                b"</style>",
                b"#map-browser { background: #ffd8cc !important; }</style>",
                1,
            )
        )
        mutated_png = directory / "mutant.png"
        mutated = run(chrome, mutant, width, height, mutated_png, "architecture")
        if (
            mutated != scenario["architecture_dom_and_keyboard"]
            or sha(mutated_png) == scenario["mirror_png_sha256"]
        ):
            raise RuntimeError("The screenshot comparison missed a color-only change")

    return {
        "evidence_class": "local_static_source_render_comparison",
        "composition_commit": COMPOSITION,
        "composition_receipt_sha256": hashlib.sha256(receipt_bytes).hexdigest(),
        "composition_page_sha256": mirror_sha,
        "canonical": upstream,
        "reference_evidence_sha256": sha(REFERENCE_EVIDENCE),
        "comparison_sha256": sha(Path(__file__)),
        "driver_sha256": sha(ROOT / "tools/browser_cdp.py"),
        "chrome": version.strip(),
        "chrome_executable_sha256": sha(chrome),
        "os": platform.platform(),
        "python": platform.python_version(),
        "dpr": 1,
        "locale": "en-US",
        "timezone": "UTC",
        "exact_architecture_png_match": "passed",
        "keyboard_probe": "passed_programmatic_skip_and_system_map",
        "color_mutation": "detected",
        "reference_baseline_approval": "pending",
        "scenarios": observations,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--composition", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--chrome", type=Path, default=CHROME)
    args = parser.parse_args()
    evidence = compare(args.chrome, args.composition, args.output)
    (args.output / "evidence.json").write_text(json.dumps(evidence, indent=2) + "\n")
    print("Architecture pixels, DOM and keyboard matched at four viewports")


if __name__ == "__main__":
    main()

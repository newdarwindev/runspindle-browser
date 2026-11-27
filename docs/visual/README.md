# Browser #11 local visual candidate

This original, editable [reference HTML](browser-reference.html) illustrates the
reviewed **accessible static equivalent** chosen in
[SRC-009 source review](../product/browser-source-review.md). It is a synthetic
reference candidate, not the canonical page, an approved pixel baseline or a
runtime status view. Its seven roles follow the current public system contract:
Core, Host, Browser, Tether, Refinery, Console and Platform. All labels and
supported/unsupported/unknown explanations are text, without assets, motion or
hover state. The canonical page remains
[browser.html](../product/browser.html); no historical expression or dependency
was imported.

## Scenario to criterion map

| Output | Parent intent | Local result | Review state |
|---|---|---|---|
| `reference-mobile-320.png`, `reference-mobile-390.png` | #5 static-equivalent reflow and #11 mobile roles/status | Generated from synthetic reference | Not reviewed as baselines |
| `reference-tablet-768.png`, `reference-desktop-1440.png` | Seven owner roles, visible capability labels | Generated from synthetic reference | Not reviewed as baselines |
| `canonical-map-*.png` | #5 actual canonical map rendering | Chrome-rendered canonical source, map scrolled into view | Original candidate with a separate mirror comparison below |
| `contact-sheet.png` | Side-by-side human review of reference and actual map | Generated, with labels identifying source | Reviewer disposition pending |
| DOM results in `generated/evidence.json` | Map labels, local anchors, skip focus, visible outline and horizontal layout | Passed at 320/390/768/1440 CSS px; missing-label mutant detected | Programmatic component check only |
| `mirror-comparison-evidence.json` | #5 and #11 canonical-to-composition parity | Architecture pixels, DOM and keyboard matched at all four widths. A color-only mutation was detected. | Reference baseline approval remains pending |
| 195 CSS-px layout probe | 200% zoom reflow pressure at 390 physical px | Passed after heading-wrap fix | Actual browser zoom not run |

The reference and canonical map differ intentionally: the reference summarizes
seven ownership boundaries, while the reviewed canonical document explains five
architecture relationships and six proposed stack roles. Pixel equality would
be a false acceptance test. No overlay, numerical difference threshold or
baseline approval is claimed. Images carry no real account, browser session,
desktop screenshot or runtime data.

## Reproduction and limits

From a clean checkout with macOS, Google Chrome `157.0.8103.78` and Python
3.14.10, run one bounded command:

    /opt/homebrew/bin/python3.14 -m tools.browser_visual --output /tmp/browser-visual-new

The command refuses a nonempty output directory, launches only disposable local
Chrome profiles, uses loopback DevTools and denies external hostname resolution.
It waits for page/font readiness, sets DPR 1, `en-US`, UTC and fixed viewports,
then closes the browser and removes profiles. The source pages have no external
assets, animation or caret. Compare SHA-256 digests of that fresh directory to
`generated/` rather than replacing review candidates. Remove the disposable
directory after inspection. Exact source and output hashes, OS/browser pins,
viewport dimensions and DOM observations are in
[evidence.json](generated/evidence.json). Two local runs produced byte-identical
10-file output sets.

## Canonical and composition comparison

On macOS with Chrome `158.0.8127.36` and Python `3.14.10`, run from a Browser
checkout with the canonical source commit in its Git history. Supply a
composition checkout whose Git objects include the commit in the
[comparison evidence](mirror-comparison-evidence.json).

    /opt/homebrew/bin/python3.14 -m tools.browser_mirror_visual \
        --composition /prepared/runspindle --output /tmp/browser-mirror-new

The verifier reads the composition HTML and source receipt from the exact Git
commit. It confirms the published hashes, checks canonical bytes at the cited
Browser commit, and matches the existing reference evidence to the canonical
and reference source hashes. It renders both dependency-free pages in disposable
Chrome profiles and captures the complete architecture section at 320, 390,
768 and 1440 CSS pixels. The recorded pairs match byte for byte. The clipping
excludes footer and status copy that the composition source deliberately rewrites.

The keyboard probe advances to the skip link, activates it and tabs through
Architecture to System map. It checks each link's text, focus outline, viewport
position and visibility, then activates System map and verifies the fragment.
A disposable color-only change in the Browser map card keeps the DOM and
keyboard observations identical and changes the screenshot. The command writes
eight named PNGs and a JSON receipt. Compare two fresh output directories with
`diff -rq` and remove them after review.

The pages use the operating system's `system-ui` font stack. Reference baseline
approval, independent manual keyboard and assistive technology review, exact
font-file pinning, actual browser zoom, long translated labels, missing-asset
fallback on another renderer and runtime integration remain open. The canonical
page has no external rendering assets. This comparison covers static document
behavior and records its results independently of product runtime acceptance.

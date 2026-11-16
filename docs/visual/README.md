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
| `canonical-map-*.png` | #5 actual canonical map rendering | Chrome-rendered canonical source, map scrolled into view | Local candidate; comparison pending |
| `contact-sheet.png` | Side-by-side human review of reference and actual map | Generated, with labels identifying source | Reviewer disposition pending |
| DOM results in `generated/evidence.json` | Map labels, local anchors, skip focus, visible outline and horizontal layout | Passed at 320/390/768/1440 CSS px; missing-label mutant detected | Programmatic component check only |
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

    /opt/homebrew/bin/python3.14 tools/browser_visual.py --output /tmp/browser-visual-new

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

The pages use the operating system's `system-ui` font stack; an exact installed
font-file digest is not pinned. Reference review, manual keyboard and assistive
technology checks, actual browser zoom, long translated labels, missing-asset
fallback on another renderer, clean umbrella-copy comparison and runtime
integration remain open. The canonical page is dependency-free, so it has no
expected external image or script asset to fall back from. The source and visual
checks do not prove authenticated control, browser ownership, vault use, website
effects, profile recovery or deployment.

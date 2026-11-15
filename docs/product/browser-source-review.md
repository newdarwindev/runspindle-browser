# SRC-009 Browser page: source adaptation record

Status: source-only candidate, independent review required before publication.
Selected source accounting is complete with safe exclusions. Rendered acceptance,
keyboard acceptance and the composition mirror are pending. Browser issue #5
remains open. This document does not qualify a runtime or authorize deployment.

## Scope and rights decision

The selected document, architecture island, styles, bootstrap, build declaration,
locked closure and supporting component/browser/story checks were read at their
retained exact revision. Seventeen opaque asset slots in
[browser-coverage.json](browser-coverage.json) map to exact original paths, hashes
and review notes in the private source record. Public records intentionally contain
no historical repository, source path, endpoint or machine location.

No project-wide license was present in the retained source tree. Owner-selected
adaptation is not a license to redistribute original expression. We do not import
historical prose, JSX, CSS, figures, screenshots, build outputs or Git history.
Browser's new HTML prose, semantic map and CSS were independently authored from
the reviewed requirements. Names identify integration roles without endorsement.
No new project license is asserted. Existing unrelated notices are retained.

## Explicit rendering choice

The canonical artifact is [browser.html](browser.html) in runspindle-browser.
It is authored directly as UTF-8 HTML and is its own deterministic build output.
There is no compiler, package install, script, font download, image, library or
external resource request. Inline original CSS and native HTML links are the
entire rendering dependency closure. Serving is optional and not an acceptance
claim. The sibling pages and local specification/review links must travel with
this repository; copying browser.html alone retains its content but not those
navigation destinations.

The historical interactive island is replaced by an equivalent static explanation:

- All five roles and relationships appear in an ordered list, fully visible at
  entry, midway through reading and at the end. These are responsibilities, not a
  literal credential-routing chain or a measured execution trace.
- Six stack cards preserve API, visible browser, vault, workflow, identity/proxy
  and optional ingress responsibilities. Console/Core/Host names make current
  component ownership explicit without inventing implemented integration.
- Four stages preserve identity, reservation, bounded operation and handoff.
  Current contract additions explain release, cancellation and uncertain effects.
- Native architecture, system-map, principles and status anchors replace no
  controls. The source had no functional button or stateful form to port. Its
  scroll reveal and test-only progress overrides are unnecessary when all content
  is visible. Repeated navigation, reload and Back/Forward need real browser QA.
- Semantic headings/list content remain exposed instead of wrapping the map in
  an image role. A visible skip link, visible focus styling, native links and no
  positive tab order are source-level accessibility provisions, not proof of
  actual keyboard or assistive-technology behavior.
- Fluid widths, wrapping navigation and a one-column narrow-layout rule replace
  fixed desktop assumptions. No motion is present, including for reduced-motion
  preferences. Actual viewport, zoom, focus and screen-reader checks remain open.

## Asset and dependency disposition

The coverage inventory records A01–A17 separately; no file is silently omitted.
A01/A03 supply design intent. A02/A04 are replaced by direct static markup and new
CSS. A05–A07 and A11–A14 are excluded build, tool or publication machinery.
A08–A10 supply interaction/check intent, not transferable test evidence. A15–A17
were reviewed as contextual documentation and output rules, without copying text.

The version-3 lock has 405 records including the unlicensed project root and 404
non-root packages. Declared runtime dependencies were React/React DOM 19.3.1 and
Motion 14.9.0. Motion resolves through Framer Motion, motion-dom, motion-utils and
tslib; React DOM includes scheduler. Development tooling included Vite 8.3.5,
Vitest 5.0.5, Storybook 10.6.5, Testing Library, jsdom, ESLint and Playwright.
These are observations about the retained lock, not recommended/current versions.

Recorded license metadata totals: MIT 317, Apache-2.0 41, MPL-2.0 12, ISC 11,
BSD-2-Clause 9, BlueOak-1.0.0 5, BSD-3-Clause 4, MIT-0 2, CC-BY-4.0 1, CC0-1.0 1,
0BSD 1, and one missing project-root license. Metadata does not establish package
content or all notice obligations. Every package is excluded. No registry archive
was downloaded, installed, bundled or relicensed; retaining an island later would
require a new exact-package license/content review, security review and build.

## Resolved exclusions

- X01: Historical authored expression and visual design are excluded for absent
  project-wide licensing. Only original replacement prose, markup and CSS ship.
- X02: Historical prototype, SDK server and patched browser-attachment results
  are excluded. Current synthetic/component records are linked with their limits.
- X03: React bootstrap, scroll transforms, motion logic and test progress controls
  are excluded. Fully visible ordered content carries the explanatory intent.
- X04: The full locked dependency closure is excluded. License metadata is not
  presented as license clearance for code that was never imported.
- X05: Original publishing jobs and machine-specific browser harness are excluded.
  No new runner, service, browser, listener, credentials or security changes occur.
- X06: Original repository/site links, private paths and machine locations are
  excluded. Local current-document references provide safe replacements.

## Reproducible source checks

From a clean checkout using Python 3.11 or later:

    python3 tools/check_scaffold.py
    python3 tools/check_browser_product.py
    python3 -O tools/check_browser_product.py
    python3 tools/check_artifacts.py
    python3 tools/check_credential_storage.py
    python3 -m unittest discover -s tests -v
    python3 -O -m unittest discover -s tests -v

The repository's aggregate command remains `python3 tools/validate.py`; it also
requires its pinned quality tools and existing Rust toolchain. Missing Cargo is a
blocked aggregate stage, not a passing build. The existing hygiene entrypoint
runs its mandatory inventory. The product checker is registered exactly once in
that inventory and once in the component partition, beside the separately
required credential-storage checker. Neither checker is separately called by the
entrypoint. Integration tests reject missing/duplicate registration and missing
checker files. Existing workflow gates, image pins, baselines and runtime source
are unchanged. These structural checks do not render HTML or prove keyboard,
mobile or browser acceptance.

The checker verifies exact artifact hashes, complete intent/asset/exclusion
inventory, meaningful section anchors, local navigation, no active content or
network assets, and truthful pending evidence gates. CSS is accepted only as one
attribute-free style element in the document head whose exact text matches the
reviewed stylesheet signature embedded in the checker. Any CSS change, including
whitespace, requires a new source review and signature update; refreshing artifact
hashes alone cannot approve it. This is a deliberately narrow integrity contract,
not a general CSS parser or sanitizer. It rejects alternate resource functions,
escapes, comments concealing declarations and animation longhands by rejecting
every unreviewed stylesheet. Negative tests corrupt those
properties even after refreshing hashes. They fail under normal and optimized
Python without relying on assertions. This is structural source evidence, not a
replacement for independent semantic review or a browser accessibility audit.

## Remaining acceptance and publication receipt

No browser was launched for this candidate. Prior renderer access/sandbox limits
were not bypassed. Desktop/mobile and keyboard acceptance are **not run**.
Independent review is required before any publication. Check, on a permitted
renderer, at least 1280×800 and 390×844, 200% zoom, narrow overflow, text visibility,
keyboard-only skip and every link, visible focus, repeated anchors, reload,
Back/Forward, disabled JavaScript and reduced motion. Record browser/version,
viewport, exact commit and outcomes; fix problems and rerun before updating status.

Do not mark issue #5 complete until those checks pass and the umbrella mirror
matches the reviewed canonical bytes. The composition generator must stop
replacing this page with its old generic narrative. Mirror only after independent
review of this canonical candidate; do not alter unrelated product artifacts.

[browser-artifact-manifest.json](browser-artifact-manifest.json) records hashes
and classifications. The checker reports current Git HEAD, Git tree, dirty state
and manifest hash, making an uncommitted run distinguishable from a committed one.
The exact final candidate commit/tree and validation receipt are retained
separately to avoid a self-referential committed hash. A later public PR/commit
receipt must identify the reviewed immutable revision before closure.

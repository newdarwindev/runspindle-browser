# Product design narratives

Start with [browser.html](browser.html). These documents explain design intent;
none is proof of a live service or production deployment.

## Canonical Browser page

The canonical source for SRC-009 is this component's `docs/product/browser.html`.
It is newly authored dependency-free HTML, with a fully visible semantic system
map and no scripts or external assets. Read the
[source review](browser-source-review.md), [intent inventory](browser-coverage.json)
and [artifact manifest](browser-artifact-manifest.json) before changing it.
Source checks are implemented; desktop/mobile rendering, keyboard acceptance,
independent review and composition mirroring remain pending. Overall migration
remains partial and issue #5 remains open.

The composition repository must mirror reviewed canonical Browser bytes rather
than overwrite them with its older generic marketing renderer. No umbrella copy
has been updated by this source-only candidate.

## Other pages

The overview and refinery pages are still concise conceptual adaptations from the
composition repository's
[marketing renderer](https://github.com/newdarwindev/runspindle/blob/main/docs/marketing/build_documents.py).
They are not faithful historical re-renders and do not inherit historical test
success. `artifacts.json` binds each local artifact to its hash.

Retain [source notices](THIRD_PARTY_NOTICES.md) and the included MIT notice.
Use [desired intent](../../specs/desired-intent.md) to keep scoped access, session
continuity, human exceptions and evaluation connected to maintained workflows.
Separate planned capabilities, bounded tests and measured outcomes.

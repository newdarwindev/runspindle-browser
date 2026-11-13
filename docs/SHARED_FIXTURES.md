# Shared synthetic fixture consumption

This is a bounded prerequisite for [issue #1](https://github.com/newdarwindev/runspindle-browser/issues/1), which remains open. It consumes the provisional test-only `browser.observed` subset from reviewed composition merge [`e8cd5779968fede213443db13a591c992cd0e183`](https://github.com/newdarwindev/runspindle/commit/e8cd5779968fede213443db13a591c992cd0e183). This is Python fixture conformance, not an agreed runtime protocol, Rust validator, native adapter, security qualification or product acceptance.

## Reproducible checks

Python 3.9+ and Rust/Cargo are the only local prerequisites; the Python suite has no package dependencies. From this repository, with no sibling checkout or running service:

```sh
python3 -m unittest discover -s tests -v
python3 fixtures/shared-v1/fixturekit.py
python3 tools/check_scaffold.py
cargo test --offline
```

On Python 3.9.6, all six Python consumer cases and their negative subcases passed. They check an independent literal identity/state oracle, published version/host mutation vectors and a stale-epoch vector, every changed identity field, unknown outcomes, malformed/unknown keys, Boolean revisions, altered validator bytes and rewritten pins. A fresh bounded Python process checks a copy with no sibling checkout; Python socket guards deny accidental network calls. Tests time out that process after ten seconds and clean temporary state on every exit. These guards are not an OS network sandbox.

The fixture verifier and scaffold passed; `cargo test --offline` passed the existing single activation-fails-closed stub test (zero doc tests). The Rust implementation remains unchanged and unimplemented. No GitHub job result, upstream integration, authenticated authority, durable recovery, live acceptance or deployment is claimed. Component base is `0260b3cb7c41c06576b2e3805621cec65a997111`; the reviewed PR commit binds the consumer source, tests and pin. The synthetic fixture observation time is fixed at `2026-11-13T00:00:00Z`, with no live freshness claim.

## Pin and provenance

`fixtures/shared-v1.pin.json` records the exact composition source commit, bundle Git tree, validator Git blob, full source-manifest SHA-256, exported subset-manifest SHA-256 and validator SHA-256. The standalone subset manifest binds every vendored file. The consumer compares its pin and executable/manifest hashes with literals in the reviewed test source **before importing the validator**, then verifies the full subset inventory and byte hashes. No network lookup is involved. Internal hash consistency alone is not source authentication; reviewers must verify the separately pinned source commit and manifest.

The shared validator, schema and artifact bytes are preserved exactly; only golden/mutation files are filtered by the shared exporter. Original source module notices remain intact. These are owner-directed original Runspindle synthetic fixtures, not an import of selected legacy executable references or a new blanket license. Exact reuse provenance is also recorded in `provenance.json`. The fixture schema remains provisional, and consumer adoption grants no execution or credential authority.

For a deliberate upgrade, review the composition source commit, run its `fixtures/v1/fixturekit.py export browser NEW_DIRECTORY` command, independently verify source/subset hashes, update the pin and reviewed literal expectations together, then run positive and negative vectors and inspect the byte/compatibility diff. Do not edit vendored files or upgrade a floating branch silently.

## Remaining issue #1 gates

The authenticated principal/origin-observation interface, durable lease/epoch store, trusted native-session binding and exact OpenBao/PinchTab/KasmVNC pins are unresolved. The suite does not resolve secrets, inject fields, restore encrypted profiles, transfer authority, close viewer input, reconcile submissions or prove restart fencing.

A valid fixture is only structured synthetic data; the independent conformance oracle prevents mutated output from becoming the expected identity. Future adapters must route effects through default-deny injected transports and establish trusted observations independently. Fixture success must not replace unavailable runtime/store/upstream acceptance. CI workflows and fail-closed operational entrypoints are unchanged. No new credential, service, runner or deployment is introduced.

# Synthetic scoped-vault and observation fixtures

This is an original, standard-library-only test-infrastructure slice of issue #1,
not a port of SRC-007, OpenBao client, browser adapter, or core authority system.
Issues #1, #3 and #13 remain open. Runtime `activate()` remains fail-closed.

`browser_testing.vault` provides an explicitly configured in-memory FakeVault,
a finite ScriptedObservations queue, and a resolve_and_inject test harness.
Scope binds principal, account, exact HTTPS top/frame origins, operation, session
and positive epoch. The harness checks freshness and equality before the vault
read and again before the injected spy. After the second observation, it revalidates
the exact read entry and monotonic generation, its scope, expiry and vault
availability. Forgetting, rotation, same-secret replacement and forget/restore
during the second observation therefore deny injection. Exhausted observations deny rather than
reusing a stale value. Vault identity expiry is synthetic clock-controlled input,
not a new credential retention TTL. Explicit forgetting removes only the fake
credential entry; it cannot delete a browser profile or revoke a site session.

Faults are denied read, outage, timeout, malformed KV response and invalid fault
configuration. Rotation replaces a synthetic entry/version. Audit records contain
fixed event categories, never references or values. Secret/entry representations
hide values. Callback failures are re-raised with a fixed displayed error and
suppressed exception chaining. This is **not** Python-memory zeroization or a
promise that debugger/traceback objects contain no secret. Use synthetic canaries
only. Scripted callbacks are trusted test code, not untrusted requests.

BDD: Given a mismatched account/origin/operation/session/epoch or missing/stale
observation, when the harness resolves, then vault read attempts and injection
calls are zero. Given a scope change after a permitted read, when the second
observation arrives, then injection calls are zero. Given unavailable/malformed
vault data, then no injection occurs and displayed error/audit envelopes contain
neither canary nor handle. A deliberate second-check mutation produces a forbidden
injection independently counted by the spy.

## Bounded local verification

Run `python3 -m unittest discover -s tests -v` and repeat with `python3 -O`.
The tests install a socket-connect denial spy, inject fixed time/identities, use
only disposable mutation files and clean those files on exit. No process is left
running; no ports, listeners, accounts or services are used. There is no random
seed because all fixtures are explicit. Tool and source hashes are recorded in
`docs/synthetic-vault-evidence.json`.

The whole repository `tools/validate.py` still requires Rust/Cargo for its inert
Rust contract. Missing Rust is a blocked check, never a passing Python result.

## Remaining boundaries

No authenticated transport, trusted runtime observer, real vault, encryption,
durable profile/lease store, concurrency, atomic browser injection fence, viewer
handoff, website-submission reconciliation or live integration exists here.
Concurrent changes after the final revalidation are outside this sequential fake;
the checks and injection are not an atomic real browser/vault operation.
Core authority, host native identity, source-rights review and separately pinned
OpenBao/PinchTab/KasmVNC integration remain prerequisites. Tests passing cannot
establish upstream conformance or production security.

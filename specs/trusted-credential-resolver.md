# Scoped credential resolver component

Partial implementation of browser #13 and parent #6. Entrypoint:
`browser_runtime.credentials.Resolver.resolve_and_inject(ticket)`. This is original
stdlib-only runtime orchestration, separate from `browser_testing.vault`.
`Target` extends the existing effect-journal `Binding` with native session and
exact frame/origin. It does not redefine Core envelopes or claim Rust conformance.

## Trusted boundaries

Untrusted input is only an opaque admission ticket. It cannot select a vault,
reference, target, observation, helper, pin or clock. Trusted composition creates
an immutable `AdapterSet` of exact adapter instances and the expected reviewed
artifact digest. Digest equality is a configuration guard, NOT authentication or
verification of implementation bytes. The composition root must verify installed
code and identities; this repository supplies no such deployment adapter.

The authority adapter must authenticate/consume a Core-issued ticket and return
its immutable grant only while holding a guard that excludes navigation, frame
replacement, account switching, lease change and human takeover. `observe` reads
authenticated Host/browser state; a page assertion or model dictionary is never
an observation. `current` checks authenticated identity/lease expiry and revocation.
The held guard must span vault access, helper use and cleanup. Observer callbacks
are trusted application code, not proof of an authenticated browser integration.

Before vault read, and twice before use (including after vault-version checking),
the resolver requires fresh matching principal/account/browser/tab/intent/revision/
operation/epoch/top-origin/native-session/frame/frame-origin observations. Missing,
forged-shaped, future or stale observations deny. Exact origin equality is required;
redirects are not permission to broaden scope. The helper must revalidate guard,
exact destination and secret version atomically with actual injection. Sequential
Python checks alone cannot prevent an external browser TOCTOU race.

The narrow vault adapter returns only an opaque helper-owned handle. Reference
selection comes from admission, not input. No secret is returned by the resolver.
The pinned vault/helper implementation owns KV parsing, redirect refusal, transport,
least-privilege identity, bounds, secret lifetime and release. It must reject raw
responses and malformed handles, and honor deadline/cancellation without background
late writes. Python callbacks cannot be forcibly timed out here. The bounded [OpenBao protocol adapter](openbao-kv-adapter.md) now implements
KV parsing and helper-owned handles. No real provider qualification, PinchTab/KasmVNC
adapters, credentials, listeners or live network requests are supplied.

## Outcomes and recovery

Default construction denies before any effect. Every resolver instance permits
one attempt only, including denial or timeout. Exceptions become the fixed public
`credential resolution denied`, raised outside the handler with no provider
exception context. Success is the fixed `injected`; raw helper results are never
forwarded. Guard context managers suppressing an exception cannot turn a failed
attempt into success: completion requires explicit successful injection and handle
release before the guard exits. A failure after attempted injection is uncertain, not evidence that
nothing happened. Do not retry it or create a new instance to retry. Durable ticket
consumption/replay prevention and reconciliation belong to Core admission and the
existing effect-journal integration, neither supplied by this component. Process
restart does not gain retry authority. No durable credential guarantee is claimed.

The resolver calls release on each returned handle and closes the guard on normal
success, failure and cancellation. A read that raises before returning a handle
must clean up its own resources. Cancellation propagates; trusted adapters must
never put private values into cancellation exceptions. Python memory zeroization,
traceback-local secrecy, screenshots and malicious in-process code are not covered.
A privileged debugger can inspect locals; no raw exceptions should be logged.

## Evidence and remaining gates

`tests/test_trusted_credentials.py` supplies synthetic adapters and identity tickets,
independent read/injection counters and canary scans of result/error/traceback/output
and audit envelopes. It tests wrong bindings, forged/unavailable observations,
redirects, stale epochs/freshness, vault denial/timeout, version revocation,
uncertainty/no retry and cancellation cleanup. A deliberate monkeypatch removes
observation checks; the independent zero-effect invariant fails as expected.
The adapter fakes do not establish real atomic fencing or provider integration.

Run `python3 -m unittest discover -s tests -p test_trusted_credentials.py -v`.
Run the full repository checks separately; missing Cargo does not pass native tests.
Core #16 authenticated admission and composition #43 envelope conformance remain
acceptance blockers. Host authenticated observations/atomic fencing, pinned actual
vault/helper adapters and isolated native integration also remain blocked. Live
acceptance, production activation and historical-source port #3 are not completed.
See `docs/trusted-credential-evidence.json` for source/fixture/tool hashes and scope.

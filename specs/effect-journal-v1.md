# Bounded durable browser-effect journal

Original standard-library implementation for a bounded slice of issues #15/#8.
No source lift, browser automation or live website is implemented. Dependencies
#13/#14 (trusted credential resolution and encrypted profiles) remain open seams;
these issues and the parent must not close from local journal evidence alone.

## Local API and binding

`browser_runtime.effects.Journal(path, approve, submit, observe)` takes trusted
application callbacks. Missing authority, submit or readback adapters deny their
respective operation. No adapter, profile, credential or endpoint is discovered
from the environment. `Binding` contains exact principal/account/browser/tab,
intent/revision/operation, lease epoch and HTTPS origin. Payloads are nonempty
bytes capped at 1 MiB. The journal stores canonical binding, payload SHA-256,
outcome and a readback evidence digest, never the raw payload or site response.
This is a Python/storage contract, not a newly agreed core wire envelope.

The approval callback must consult current authenticated observations and deny
stale intent revisions, leases, changed account/tab/origin and unavailable
identity. It is rechecked immediately before adapter calls. A boolean supplied
by an external caller is not approval. The site adapter must enforce its own
atomic authority/origin fencing at the effect boundary; a sequential Python
callback check cannot provide a distributed lease or prevent navigation races.

## State and concurrency

`dispatch(binding, payload)` atomically reserves the operation as **unknown**
before calling the injected submit adapter. A repeated identical operation returns
its stored status and never calls submit. Changed binding/payload under the same
operation ID denies. A crash before or after the external effect preserves unknown;
restart never reconstructs permission to retry. An explicit rejection also does
not grant a retry. A distinct authorized operation is a distinct action, so core
must prevent equivalent intent from being resubmitted under a new operation ID.

SQLite memory, unnamed temporary and URI database names are rejected.
SQLite `BEGIN IMMEDIATE`, WAL and FULL synchronization persist the fence and
serialize dispatch/readback callbacks. The storage lock is held across the
synchronous adapter call, conservatively serializing all journal operations.
A readback cannot overtake an in-flight submission. Lock acquisition times out
after two seconds and denies; callbacks must be non-reentrant and bounded by the
caller. No background worker, automatic retry, retention job or deletion exists.
The caller owns storage quotas, permissions and lifecycle. Store integrity and
exclusive use of this API are assumptions; there is no hostile-store protection.

`reconcile(binding, digest)` uses only the injected site-specific readback adapter.
Exact binding/digest plus `confirmed` or `rejected` and an evidence digest can
advance unknown to terminal only after a fresh authority recheck after readback.
Revocation or authority failure during readback retains unknown. Readback bindings
are revalidated, so boolean counters cannot compare equal to integer identities.
Exceptions, malformed/mismatched/ambiguous evidence
remain unknown. Absence of a site record is unknown, not proof of rejection.
Transport acknowledgement is never confirmation. Terminal state cannot be
rewritten by later readback. Credentials and raw evidence belong outside this
journal; the adapter authenticates and validates its authoritative evidence.

## Reproducible local evidence

Run `python3 -m unittest discover -s tests -v` and repeat with `python3 -O`.
`browser_testing/effect_site.py` is an independent SQLite site model, deliberately
not idempotent: each submit inserts an effect, exposing duplicates rather than
hiding them. It is not an HTTP server or a live browser. Fresh subprocesses die
before/after the site effect and restart against actual stores. Two processes
compete for one operation; the independently queried site ledger observes one
effect. Wrong scope/authority, lock contention, insert failure, cancellation,
conflicting payloads and ambiguous/wrong-account readback are negative cases.
A deliberate duplicate-branch callback mutation produces two observed effects.

All identities/content are invented. Test time is bounded, subprocesses terminate,
files are temporary and network connects are denied in the test process. The
runtime imports no network client and opens no listener. Rust/Cargo checks remain
required by aggregate verification; unavailable Cargo is blocked, never passed.

## Explicit remaining gates

No real browser/site-specific adapter, HTTP synthetic website, distributed core
authority, authenticated frame observation, encrypted profile, native session,
actual website idempotency/reconciliation or live integration is qualified.
The default Rust activation gate is unchanged. Local SQLite evidence establishes
only this storage/callback behavior, not end-to-end exactly-once effects or any
production security guarantee. No account, credential, network/service setting,
deployment or persistent job was changed.

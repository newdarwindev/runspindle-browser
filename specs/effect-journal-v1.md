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

## SQLite schema admission

The journal now has an explicit SQLite identity: `application_id = 0x5242454A`
(`RBEJ`) and `user_version = 1`. The complete `sqlite_master` inventory must match
this implementation's original `operations` DDL, including the primary-key
index, SQL text and CHECK constraint. Unknown versions, foreign identities,
missing/extra tables, indexes, views or triggers, and unrecognized legacy DDL
are denied rather than repaired. Even equivalent differently formatted legacy
DDL is not guessed. `quick_check` must succeed; this is not a cryptographic
integrity guarantee or a comprehensive semantic validation of stored bindings.

Only an empty store with both identity fields zero, or the exact original
unversioned schema with both fields zero, may be initialized/adopted. Adoption
adds identity without rebuilding the table or rewriting rows, rowids, outcomes,
evidence or the original nullable text-primary-key semantics. Existing unknown
operations remain fenced against resubmission. A current claimed store with a
missing table cannot be reset to an empty journal.

Existing files first receive a read-only, transactional preflight. A writable
connection then repeats admission under `BEGIN IMMEDIATE`, so a schema change
between preflight and lock acquisition cannot be silently adopted. New DDL and
both identity fields commit together or roll back together. Failed/cancelled
opens close their connections. WAL is enabled only after admission commits;
FULL synchronization and the existing two-second lock timeout remain unchanged.
Constructor SQLite/storage errors become fixed-category `Denied` errors and no
authority, submit or readback callback runs during admission. There is no salvage,
backup, destructive reset, provider call or automatic retry.

Rejected, quiescent rollback-journal fixtures have byte-identical files and no
new sidecars in local tests. This is deliberately not a universal byte-preservation
promise: SQLite read-only access can perform WAL shared-memory bookkeeping, and
hot journals, concurrent external writers, path replacement or other filesystem
actors are outside that claim. A live synthetic WAL writer test separately
checks retained data and unchanged main/WAL bytes, without claiming unchanged
shared-memory bytes. Existing exclusive API use and trusted-storage assumptions
remain necessary after admission, including the interval before WAL activation.

`effects.Journal` is the only SQLite store in `browser_runtime`. The separate
`browser_testing.effect_site.Site` ledger is deliberately an independent synthetic
fixture, not a production journal or a source of schema-admission guarantees.
It is unchanged and does not share this admission implementation.

[Schema-admission evidence](../docs/effect-schema-admission-evidence.json) records
local positive/negative tests, fresh-process contention and a deliberate schema
bypass mutation. Issues #15/#8 and their browser/profile/authority integration
gates remain open.

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

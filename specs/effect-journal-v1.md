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

A nonblocking instance lock rejects nested dispatch/reconcile/close, including
calls made by a callback. A rejected nested call cannot roll back or close the
outer operation's connection. This does not change SQLite thread affinity or
provide cross-host/distributed fencing; separate cooperating connections still
serialize through the existing writer transaction.

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

## Sanitized failures and cancellation

Public Journal initialization, dispatch, reconcile and close never forward a raw
callback/storage exception, its arguments, notes, original traceback or chained
cause/context. Ordinary public failures use fixed `Denied` categories. Cancellation
uses a distinct fixed `effects.Cancelled`, derived from `BaseException`, including
when an adapter raised KeyboardInterrupt, SystemExit, GeneratorExit or a grouped
non-Exception cancellation. Callers must handle this explicit category by stopping
and reconciling. Raw interrupt types, exit codes and provider messages are not API
results. Existing successful outcome strings and ordinary submit/readback failure
semantics are unchanged: a lost reply or unusable observation still yields unknown.

Public failures are created after cleanup, outside upstream exception handlers.
Their cause and context are explicitly cleared before rethrow because Python can
otherwise inherit a caller's already-active exception even outside this component's
own handlers. Tests inspect the exception while its traceback remains attached,
including args, notes, cause/context and standard traceback formatting. This is
exception-envelope containment, not memory zeroization, debugger/frame-local
redaction, caller-source redaction or protection against raw-object inspection.
Payloads and trusted callbacks still necessarily exist in process memory.

One outer boundary handles transaction cleanup after every dispatch/reconcile
outcome, including BaseException. Ordinary rollback or close errors cannot replace
an already-observed cancellation with a normal outcome. Cleanup cancellation is
also propagated as Cancelled. A rollback failure makes the instance permanently
unusable and attempts connection close once; public close likewise marks the
instance closed before its single attempt. Later calls do not retry an uncertain
close or invoke an adapter through that instance. A connection-close fault does
not prove the operating system released every resource; fresh access can remain
blocked. Constructor admission closes its actual model/read-only/writer connection
on failure without allowing an ordinary close error to hide cancellation.

No exception proves a SQLite COMMIT did not happen. If reservation committed before
an error/cancellation, unknown survives, zero submit calls occur on that failed
dispatch, and a fresh process still cannot resend. If readback committed before a
failure, a terminal result may already be durable despite the failed return. Only
the actual stored state and authorized reconciliation establish that outcome.
There is no rollback claim for previously committed data or external site effects.
Cancellation never becomes a successful unknown return. The independent site
ledger verifies effects rather than inferring safety from returned status alone.

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

`effects.Journal` has its own SQLite schema. The separate encrypted-checkpoint
store now lives in `profile_store`/`profile_schema` with independent admission;
its evidence does not qualify this journal or vice versa. The separate
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

`tests/test_effect_exceptions.py` adds real-store failures around actual COMMIT,
ROLLBACK and close, secret-bearing cancellations and errors, active caller-context
containment, reentrant-call rejection, and fresh-process no-resubmit evidence.
These injected faults do not qualify a real provider, network or browser adapter.

All identities/content are invented. Test time is bounded, subprocesses terminate,
and files are temporary. Original callback-only tests deny network connects; the
separate HTTP fixture lane connects to its owned loopback listener. The runtime
imports no network client and opens no listener. Rust/Cargo checks remain
required by aggregate verification; unavailable Cargo is blocked, never passed.

## Explicit remaining gates

A separate [disposable HTTP synthetic site lane](http-synthetic-site-v1.md) now
exercises actual loopback requests with this journal; it remains test-only.
No real browser/site-specific adapter, distributed core authority, authenticated
frame observation, encrypted profile, native session,
actual website idempotency/reconciliation or live integration is qualified.
The default Rust activation gate is unchanged. Local SQLite evidence establishes
only this storage/callback behavior, not end-to-end exactly-once effects or any
production security guarantee. No account, credential, network/service setting,
deployment or persistent job was changed.

# Bounded effect wire receiver v1

Partial Browser #15/#8 and Core #3 integration seam, not their completion.
`effect_wire.Receiver` wraps a trusted, already configured `GuardedJournal`.
`exchange(raw_bytes, ticket)` obtains the ticket out of band. No request can select
an authority, journal path, browser adapter, endpoint or credential. The existing
held guard authenticates its one-shot grant; optional expected-target/digest
arguments narrow that grant before any Journal dispatch or readback. Older direct
GuardedJournal calls retain their default behavior.

The request is a UTF-8 JSON object with exactly these keys:

- `version`: `runspindle.browser-effect.v1`.
- `action`: `dispatch` or `reconcile`.
- `target`: exactly `binding`, `native_session`, `frame`, `frame_origin`.
- `target.binding`: exactly `principal`, `account`, `browser`, `tab`, `intent`,
  `revision`, `operation`, `epoch`, `origin`, with existing Binding validation.
- `payload_digest`: lowercase SHA-256 hex of actual payload bytes.
- `payload_hex`: nonempty lowercase even-length hex for dispatch, null for reconcile.

Payloads are at most 1 MiB; the full wire request is at most 2 MiB + 8192 bytes.
All nested objects reject unknown/missing/duplicate keys. Nonfinite numbers and
boolean integer identities deny. Object order and whitespace may vary; canonical
request encoding is not required. No external transport or frame decoder exists.
The trusted caller bounds exchange time and frames bytes before calling this API.

Response keys are exactly `version`, `request_sha256`, `evidence_class` and
`outcome`. Version is the same as the request. The hash commits to the **exact raw
request bytes**, not a canonical reconstruction. Evidence class is
`browser_guarded_effect_observation`; outcome is `unknown`, `confirmed` or
`rejected`. This is a trusted local receiver observation, not a signature,
authentication protocol, provider receipt, Tether receipt or reusable permission.
The consumer must authenticate/pin the peer and verify version, class and hash.
A response can be lost after a committed reservation or real effect. Repeat the
same operation only; the journal never resubmits it. Use separately admitted
reconcile authority for authoritative readback. New operation IDs must not be
invented as retries by Core. A new submission acknowledgement alone remains unknown; previously reconciled
terminal outcomes may be returned for exact duplicates after fresh admission.

Receiver holds no mutable per-request state. GuardedJournal retains its existing
non-reentrant lock, held browser fence, fresh checks, exact target commitment and
SQLite persistence. Changed grant/observation/native session/frame cannot rebind a
request. Error messages are fixed `effect wire denied` / `effect wire cancelled`,
without upstream exception context; cancellation never becomes ordinary denial.
No payload, ticket or raw site evidence is included in response or errors.

Tests use actual SQLite Journal and synthetic trusted callbacks/site ledger. They
cover complete target mismatch, action/digest denial before callbacks, malformed
wire, lost response followed by fresh-process duplicate/reconcile, cancellation,
error scrubbing and reentrancy. Run normal and optimized Python unittest discovery.
This is not a CLI/server, actual Core wire client, live browser/site, authenticated
issuer, distributed fence, or production acceptance. No activation gate changes.

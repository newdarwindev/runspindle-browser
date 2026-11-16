# Passive durable control status

A bounded Browser #16/#9 component extension: passive status metadata, not
screenshot streaming or viewer integration. No viewer, website, credential
provider, service, new schema or live control integration is installed. The
parent issues remain open pending their broader acceptance requirements.

## Separate authenticated observation permission

`PassiveStatus(target, deadline)` is a distinct frozen admission type, issued by
the existing trusted authority solely for `LeaseStore.status(ticket)`. Matching
caller metadata, a raw target, a stored row or a previously returned status is
not permission. The underlying authority must explicitly authenticate the whole
passive grant and its current revocation state under the held physical guard.
Transfer, Recovery, Input and CredentialInput admissions do not authorize status;
passive admission does not authorize any of their routes.

The exact physical scope is principal, account, browser, tab, native session,
frame, top origin and frame origin, using the existing lease scope encoding.
The observation must match that scope; an existing row with a different scope
fails rather than leaking its owner. Scope cannot be rebound. Intent, revision,
operation and epoch are not physical scope selectors. A fresh passive admission
may observe a newer durable epoch than the target's old epoch: it is not an
input grant or a request to make that old epoch current.

## Historical metadata, never a control capability

The frozen `ControlStatus` includes the canonical matched `scope`, `phase`,
`epoch`, `holder` and `observed_at` in the existing monotonic clock domain:

- `absent`: no scoped row exists for the selected browser; epoch and holder are
  null. This does not authorize initialization or infer a remote browser state.
- `active`: reports the durable epoch and stored Holder. It does not prove that
  the real browser remains available, fenced or authenticated after return.
- `pending`: reports the reserved durable epoch, with holder **null**. The stored
  destination is not an active holder and is never returned as one. Pending
  cannot be interpreted as resumption, successful takeover or completed handback.

`observed_at` is the clock sample after the final trusted observation/current
callbacks, validated against admission deadline and observation freshness. It
marks completion of validation of the read snapshot, not an ongoing freshness
promise. The returned value is already historical after return. Consumers must
retain its scope, request fresh status when needed, and obtain a separate freshly
authenticated admission for every effect, credential action or transfer.
Nothing in this API supplies a viewer input handle, credential reference, target
navigation, usable profile, signed permission or an implicit follow-up action.

## Read transaction and existing lifecycle

Status uses existing `_session` locking, authority cleanup and cancellation
semantics. It checks permission, opens a SQLite `BEGIN` read transaction, selects
one row, validates its scope/epoch/holder/phase, then rechecks current authority
and freshness. It never upgrades to a writer, changes a row, inspects a backend,
releases a viewer, fences input or calls site/vault helpers. The read transaction
is rolled back after the physical guard exits. A guard-exit or cleanup failure
cannot return a successful snapshot.

This read-only claim is about **the status method**. Constructing LeaseStore
retains its existing exact-schema admission transaction and can initialize an
empty database; constructor behavior is not changed or reclassified as read-only.
SQLite's existing storage recovery behavior is also unchanged. No universal
byte-preservation guarantee is made for arbitrary corrupt or hot-journal inputs.
A read transaction may briefly delay a writer's commit. Callbacks must remain
bounded and coherent under the trusted guard; no distributed lock or arbitrary
same-process adversarial memory protection is added.

## Evidence and reproduction

```
python3 -m unittest discover -s tests -p test_passive_control_status.py -v
python3 -O -m unittest discover -s tests -p test_passive_control_status.py -v
```

Eight synthetic component tests use actual local SQLite files and unchanged
runtime lease/effect/credential composition. They observe unchanged file bytes,
rows and SQLite total_changes during status; absent/active/pending distinctions;
fresh-process readback without a backend; later takeover invalidating a previous
observation; expired/revoked/wrong-scope/stale observations; post-read rechecks;
post-callback timestamping; and guard-exit denial. Negative route tests count zero
site submissions/readbacks and vault reads/injections/releases from passive
admission, with no additional backend fences. A minimal private source mutant
removes the persisted-scope comparison and exposes other-account ownership;
the independent wrong-scope denial assertion detects it.

These are synthetic grant/authority/holder and filesystem-process observations,
not a live viewer, production issuer, authenticated browser, distributed clock,
full native integration or full issue qualification. No persistent monitor,
publication hook, access setting or action scheduling is added.

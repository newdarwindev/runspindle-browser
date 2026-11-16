# Trusted effect admission around the durable Journal

Bounded partial Browser #15 / #8 implementation. The existing SQLite Journal
continues to own operation reservation, unknown outcomes and reconciliation.
`browser_runtime.guarded_effects.GuardedJournal` adds an explicit trusted browser
boundary around that same implementation, not a second effect store or transport.

## Admission and helper contract

The trusted composition root pins the `Authority` and `Site` objects. Neither a
page, caller-provided target nor an admission ticket selects an adapter. Missing
adapters deny. The authority context manager must actually hold the native
browser/account/frame/input fence until helper and journal work finishes. Its
`admit` authenticates and consumes an exact one-shot `Grant`: existing `Target`
(including native session, account, top/frame origins, browser/tab and epoch),
SHA-256 payload digest, explicit dispatch/reconcile action and monotonic deadline.
A matching structure alone is not authentication. No issuer is installed here.

The wrapper compares a fresh trusted `Observation` to the entire target and
requires `current(grant) is True`. It samples the trusted clock after both
callbacks, uses inclusive observation maximum age and exclusive grant deadline,
and rejects nonfinite/boolean time. Grant, observation and clock share one trusted
monotonic clock domain; there is no cross-machine clock synchronization claim.

The guard spans SQLite lock waits. Existing Journal approval callbacks recheck
binding/digest/current observation after the writer transaction begins and just
before helper effects; the wrapper checks once more at each site entrypoint.
The site adapter must enforce the held guard atomically at its actual input or
readback point. These Python calls alone cannot prevent an out-of-process browser
changing state between an observation and an effect. Reentrant wrapper calls deny.

`dispatch(ticket, payload)` verifies the admitted digest, then uses Journal's
committed reservation before invoking the pinned helper. Helper return values
never prove completion: accepted and lost-response submissions remain unknown.
`reconcile(ticket)` uses separately admitted reconcile authority and the existing
exact-binding/digest `Readback` checks. It never submits. Every duplicate/restart
call obtains fresh authority; durable rows do not reconstruct authorization.

Fixed Denied/Cancelled categories hide upstream error text and exception context.
A guard-exit failure cannot return a successful result; a committed operation or
real site effect remains persisted even though the public call denies/cancels.
Cancellation observed inside the context is latched before context exit, so
suppression or ordinary cleanup failure cannot turn it into a denial or result.
Payloads and grants are not stored by this wrapper. The full canonical Target
SHA-256 commitment is supplied through Journal's optional `target_digest` field.
It is serialized beside the original Binding in the existing binding column;
operation remains the unique key. A different native session/frame/origin cannot
reconcile the original operation or become a second operation. Legacy default
encoding remains byte-identical; old/direct callers conflict with contextual
rows rather than interpreting them. No schema migration or extra store is added.

## Evidence and remaining work

Run `python3 [-O] -m unittest discover -s tests -p test_guarded_effects.py -v`.
Tests compose real SQLite Journal persistence with an independently written
synthetic site ledger, fresh-process duplicate dispatch, exact-target negatives,
delayed authority/expiry, post-reservation revocation, cancellation, reentrancy,
reconcile-only authority, context-exit failure and a source mutation that removes
current-authority enforcement and exposes one forbidden site effect.

No real browser, live account, authenticated issuer, Core/Host composition,
provider/network adapter, atomic remote fence, UI takeover/handback, production
activation, distributed fencing or full issue acceptance is qualified. Parent
issues remain open. This is new original project code, not a source lift from
inert legacy references. Existing source notices/provenance remain unchanged.

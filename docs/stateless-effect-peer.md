# Stateless Browser effect peer

The approved no-storage direction moves replay and reservation policy to the
existing Core/application operation owner. `GuardedPeer` owns no path, database,
operation map or history. `Receiver` accepts this peer using unchanged
`runspindle.browser-effect.v1` bytes. The legacy `GuardedJournal` adapter reuses the
same guard implementation and remains only for existing unmigrated consumers.
No existing records, profiles or leases were copied, deleted or migrated.

## Composition contract

Core's existing BrowserRegistry must reserve an immutable target/payload and
unknown outcome **before** dispatching through its Peer interface. Its retained
state decides whether another dispatch is permitted. Browser receives a separate
trusted one-shot authority ticket, never authority constructed from wire bytes.
The full Target, digest, action, current native observation, deadline and fence
must match. The injected site adapter enforces the actual atomic input fence;
observation callbacks must remain trusted, pure and non-reentrant.

Dispatch executes the site callback and returns unknown, never interpreting its
return value as authoritative success. A lost reply or cancellation leaves Core
responsible for retaining uncertainty. Reconcile only observes, validates exact
binding/digest/evidence and rechecks current authority before returning a terminal
outcome. Duplicate/restarted dispatch prevention belongs exclusively to Core.
A caller which independently authorizes the same dispatch twice can cause two
effects: this peer deliberately does not create a second replay ledger.

Admission pins a detached copy of the full target, action, deadline and digest
before invoking later callbacks. A changed grant or observation aborts before
the next site effect. The final authority check cannot replace terminal readback
evidence. A changed or malformed receipt stays unknown, including in the
legacy journal's durable record.

No authenticated general IPC, always-allow CLI or production issuer is added.
The source aligns with Core PR57's existing wire/registry facade, but an actual
application-owned Core-to-Python transport remains unimplemented. Autosave's
separate payload/version marker contract is not silently routed through this
page-effect peer. The existing real account E2E evidence qualifies its recorded
source only, not this new native integration.

## Evidence

Seven new stateless component tests cover no SQLite construction, unchanged wire,
exact-target/authority denial, lost reply with reconcile-only recovery, explicit
external replay responsibility, invalid readback, revocation and redacted
cancellation even when a context suppresses it. Together with the legacy guarded
and wire suites, 34 tests pass in normal and optimized Python. Existing mutation
regressions now modify the relocated shared guard source, not a vacuous wrapper.
These tests use synthetic authority and site adapters; no production Core bridge,
runner admission, actual Actions run or legacy data migration is established.

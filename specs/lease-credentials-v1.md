# Credential resolution under durable exclusive control

Partial Browser #13/#6 and #16/#9 composition. This extends `LeaseStore` and the
existing `credentials.Resolver`; it does not introduce a second vault, journal,
credential issuer, browser helper or control schema. Original component code and
synthetic evidence only. No real account, credential or service is configured.

## Trusted entrypoint and pins

A trusted composition root calls
`LeaseStore.credential_resolver(vault, helper, adapter_digest=..., expected_digest=...)`.
It constructs the existing `AdapterSet` using an internal lease-bound authority
proxy plus the exact supplied vault and helper instances. The attested digest must
cover this complete composition, its underlying authority and canonical lease
store, not an unrelated unbound Resolver. The existing Resolver validates the
expected 64-hex digest before opening authority or calling a provider. Matching
strings are not authentication or attestation; trusted construction remains
responsible for checking actual code and adapter identities.

Every credential route must use this factory with the same canonical lease store
as interactive inputs. A raw Resolver/backend, a separately created lease database
or bypass input path defeats this composition and is not made safe by this API.
There is no runtime registry, production issuer, deployment or policy activation.

## Distinct exact credential admission

`CredentialInput(credential: credentials.Grant, holder: Holder)` is a new explicit
admission type. The underlying authority must authenticate and consume the exact
credential grant, including reference, full target, operation and deadline, and
its holder identity/kind. `current` rechecks that entire admission. An effect
`Input`, `Transfer`, `Recovery`, raw credential Grant or page assertion is not
converted into credential authorization. Existing issuers must explicitly add
support; unsupported types fail closed. Holding a control lease alone never
permits a vault read.

The existing physical-scope checks bind principal, account, browser, tab, native
session, frame, and both origins. The actual active durable row must match that
scope, holder and exact epoch. Pending transitions, old holders, stale epochs,
wrong targets, unavailable authority or closed stores deny before provider reads.
Trusted physical observations are normalized only to the already checked grant's
operation/epoch; page text never supplies authority. The underlying guard remains
responsible for atomic physical input/identity fencing. Observation time, deadline
and the injected clock share the existing trusted monotonic domain.

## Lock and cleanup lifetime

The private credential authority reuses `LeaseStore._session` and obtains the
actual SQLite writer transaction before credential admission. Authority and
active-row checks occur after any lock wait and repeat at Resolver checks and at
helper `fence.current(grant)` checks. The transaction spans vault read, version
validation, injection, handle release and the physical authority context's exit.
A competing takeover cannot fence or activate while those stages retain the lock.
Lock order is lease store then any provider's internal resources. Trusted callbacks
must be bounded and must not reenter the store or wait on a lease holder that is
itself waiting for them. Separate processes use separate store connections.

The original Resolver keeps its one-attempt rule, exact reference/target checks,
freshness checks after trusted callbacks, version checks, sanitized cancellation
and handle release. It never exposes the secret value through this adapter.
An uncertain injection is not retried. Fresh Resolver instances still require
new authenticated admission; durable ticket replay prevention remains the
issuer/Core obligation, not a feature of the local attempt flag.

Existing cancellation latches preserve `effects.Cancelled` through vault release
and authority cleanup errors/suppression. Lease cleanup failure poisons the store;
an uncertain close does not prove resource release. No new lease row or epoch is
created by credential resolution. No schema, workflow, dependency, permission or
service setting changes are required by this composition.

## Bounded verification and remaining work

Run `python3 -m unittest discover -s tests -p test_lease_credentials.py -v`.
The suite uses real SQLite leases with synthetic authenticated grants, provider
handles and independently counted reads/injections/releases. It checks correct
use, pin mismatch, wrong scope/holder/epoch, effect-ticket separation, pending
transfers, callback expiry, revocation after read, cancellation and closed stores.
A separate process holds the handle-release and authority-exit stages in turn;
a competing transfer times out without a fence call, then succeeds after release.
A deliberate source mutation bypassing the holder check changes independently
observed forbidden provider reads/injections from zero to one.

No real OpenBao/provider, browser injection, authenticated issuer, OS confinement,
physical input exclusivity, distributed fencing, live qualification, CI/image or
full issue completion is claimed. Tests exercise Python component composition,
not production security. Parent issues remain open. Existing provenance and
licenses apply; no third-party implementation or private material was imported.

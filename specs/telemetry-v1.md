# Browser observation producer, telemetry v1

Implemented slice: optional local Resolver completion observations compatible
with the `runspindle.telemetry.v1` vocabulary. This does not depend on unmerged
Host changes. Actual Browser OpenTelemetry SDK conversion, Collector delivery,
context propagation, metrics, control-lease and effect-journal spans remain
unimplemented. This is not fleet or live provider qualification.

Trusted construction may pass an exact `Buffer` to `Resolver(telemetry=...)`.
Default is off. It retains at most 128 records and never blocks on its lock.
Fixed operation `browser.credentials.resolve_and_inject`, start/end timestamps
and closed outcomes are the only retained data. No ticket, target, account,
secret, origin, reference, exception, digest, trace context or baggage is copied.

`acknowledged` means only the existing resolver returned `injected`: helper and
release callbacks returned successfully under the existing authority boundary.
It is not website acceptance or proof of lasting external effects. `error`
means the resolver raised `Denied`, including an injection or release failure
after a possible external effect. It does not prove no effect or authorize retry.
Cancellation remains `unknown`. Original outcomes and
exceptions are unchanged. Telemetry collection failures are swallowed only in
the observation path, never in the underlying resolver.

Records are appended after the resolver leaves its authority context, with no
injected exporter callback. The caller explicitly drains records outside the
credential operation. Contention/full capacity/crash loses observations; there
is no durability or guaranteed count, and no automatic flush/shutdown work.
The exact Buffer type excludes subclass callbacks; trusted in-process callers
still have Python mutation powers and this is not a hostile-process sandbox.
Any future exporter needs separate authorization, bounded supervision and
verification, and must not execute on this credential path.

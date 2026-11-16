# Local durable exclusive browser control

Partial Browser #16 / #9. `LeaseStore` extends the existing Target, GuardedJournal
and durable operation Journal rather than introducing another input transport.
This is original component code with synthetic adapter evidence, not a port of
the inert gateway, production authentication or live PinchTab/KasmVNC acceptance.

## Trusted composition and authority

Configure one canonical lease database for each managed browser namespace. Every
agent and human input route must use `LeaseStore.journal(...)`; a composition root
that exposes a raw backend or another unbound store can bypass this boundary.
No runtime registry, network endpoint, identity issuer, viewer, credential or
service is installed. SQLite files and backend objects are trusted local inputs;
this does not defend against an attacker modifying storage or process memory.

The trusted `Authority.acquire` context holds the physical browser/input fence.
`admit(ticket)` authenticates an exact immutable `Transfer` or `Input`, never a
page assertion. `current` checks the whole grant and its revocation state.
Observations must authenticate the same principal/account/browser/tab/native
session/frame/top and frame origin. The lease database, not browser page text,
owns the epoch. Trusted observations, deadlines and clocks share one monotonic
domain. The clock is sampled after blocking callbacks, including release checks.

A transfer specifies source/destination Holder, next target epoch, expected old
epoch, action, operation ID (in Target.binding) and deadline. Initialization is
explicit, separately authenticated epoch-zero to agent epoch-one; takeover is
agent-to-human; handback is human-to-agent. One row keyed by browser fixes the
physical identity scope; changing accounts/session/frames cannot create a second
holder or silently rebind that row. Re-enrollment is unsupported in this version.

## State and input fences

The store validates its exact schema/application/version identity, uses real
SQLite writer locking and FULL synchronous commits. Unknown stores deny; there
is no migration/salvage. A transfer obtains the writer lock, rechecks authority,
checks exact active source/epoch/scope, then commits a pending next epoch before
any external fencing effect. Pending denies all input. A second writer transaction
holds the gate while the backend fences/drains the previous inputs. Only an exact
`FenceReceipt` with `previous_inputs_closed is True`, followed by fresh authority
and observations, can commit active destination ownership.

For handback, `released(transfer)` must authenticate the exact current human
holder's release, target and epoch. It is checked before reservation and again
before backend fencing, with freshness rechecked after each callback. The backend
receipt must establish closure of *all* viewer input paths, not just a window,
network connection, timeout or local UI flag. The gate cannot itself prove a real
viewer implements that guarantee; a live backend is still missing.

Repeated identical transfer requests return retained active/unknown metadata,
never another fence call. This return is not an input capability. Every input
requires fresh exact admission, current physical observations, matching active
holder/epoch and the lease writer lock for its entire helper lifetime. The input
adapter wraps the existing GuardedJournal, retaining its one-shot durable command
reservation, full-target commitment, reconciliation and cancellation semantics.
Inputs are bounded one-shot effect operations, not a raw interactive streaming
transport; real viewer event routing remains unimplemented.
Lock order is lease store then effect journal. Each instance uses its creating
thread's SQLite connection; separate worker processes use separate instances.
Reentrant use denies. Raw state
readback/passive viewing grants no authority; no viewer API exists here.

## Uncertainty and recovery limits

Process death before/after fencing, lost replies, incomplete viewer closure,
wrong receipts or post-reservation denial retain pending and block both holders.
There is deliberately **no automatic startup recovery, timeout handback, retry,
force release, admin override or pending-transition reconciliation**. A future
separately authenticated recovery protocol must resolve actual backend state;
deleting the database is not recovery. Existing active metadata after restart
still requires fresh authorization for every input and cannot recreate a grant.

Cleanup failure poisons an instance; failed close does not prove resource release.
Cancellation is latched across authority context cleanup. An active commit whose
return is lost remains uncertain to the caller, and a fresh duplicate can read
its retained result without repeating the backend effect.

## Evidence

Run `python3 [-O] -m unittest discover -s tests -p test_control_leases.py -v`.
The suite uses real SQLite files, separate-process input contention, a file-backed
synthetic input/fence ledger, process death on both sides of the fence call,
wrong holder/scope/epoch, forged release, delayed-release expiry, incomplete or
wrong closure receipts, cancellation and a source mutation exposing forbidden
wrong-holder input. All identities and payloads are invented; no browser, account
or provider is accessed. No live physical-input exclusivity, distributed lock,
power-loss durability, trusted grant issuer, OS confinement, CI/image, complete
handoff recovery or full issue acceptance is claimed. Both parent issues remain
open. Existing pins, workflows, access and operational gates are unchanged.

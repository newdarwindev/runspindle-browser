# Scoped manual-login autosave: bounded helper implementation

This additive component implements the **trusted helper and OpenBao protocol**
part of the approved simple flow: one initial scoped opt-in, normal human login,
automatic save to the existing vault, existing Resolver for later authorized use.
It is not an installed browser extension, production credential enrollment, or
proof that arbitrary websites can be recognized. Actual capture, success/account
observations, standing-consent storage, Core admission and Host fencing remain
injected trusted adapters, exercised here only with synthetic fixtures.

## External owners, not Browser-managed stores

`browser_runtime.autosave.Autosave.run(ticket)` consumes an existing-shaped
`Grant` under `Authority.acquire()` and its `Fence`. A trusted `consent` callback
returns the authorized expected KV version (zero means create), or None to deny.
It must check the previously approved account/browser/origin and separate
store/update authority, not infer permission from a successful login. One-time
consent is a product contract; this component does not install or persist it.

A trusted `capture` callback supplies helper-private `Login` values only after
admission and the external operation owner's durable dispatch fence. `authenticated=True`
means independently verified login and selected-account success. A DOM flag,
page message or model assertion cannot supply that evidence. Unsupported/failed
login never overwrites the known credential. Passwords only; passkeys, OTPs and
SSO-only sessions must not be converted into reusable passwords.

`Writer` reuses `openbao.Mapping`, scope validation, token retrieval and response
parsing. Its private Vault has STORE authority; it must not share the Resolver's
USE authority callback. Both use the same OpenBao destination. `HTTPS.request`
adds bounded POST while the existing GET call and Resolver remain unchanged.
Browser receives an externally owned `EffectExecution` interface, not a database
path. It never creates, opens, migrates or closes operation storage. The external
Core/application owner must supply canonical replay/admission semantics; there is
no new service or second operation ledger. Passwords and usernames never enter
operation payloads, hashes, rows or public outcomes. The
payload hash commits operation/target/reference/version metadata, not a password.

## Writes and uncertainty

New records use CAS zero. Updates read the current version, require the expected
version and same username, preserve unrelated fields, then CAS-write the new
password with `_runspindle_save_operation` in the **same secret payload**. There
is no separate custom-metadata commit. Equal credentials are not written again.
An unchanged credential is confirmed using the same attempt's trusted read;
interruption before durable confirmation can leave unknown, not a retry right.
Legacy records without a username cannot be silently enrolled as a different
account. Their explicit migration is outside this slice.

A new write is confirmed by exact-version readback and matching operation marker.
The marker is not authentication; its authority comes from the authenticated
fixed provider path and grant. Lost write replies are reconciled, never blindly
resent. Version destruction, malformed replies and unavailable evidence remain
unknown. A later authorized version does not invalidate evidence that this save
committed; `saved` is not a claim that the version remains current forever.

The external owner must record unknown before capture/write. Recreating an
Autosave service with the same operation and target must not dispatch again.
Browser does not implement that persistence guarantee. Transitional tests adapt
the legacy Journal under an external fixture owner; production relocation remains
work tracked in the storage inventory.
`reconcile_only=True` never captures or writes. New attempts/operation IDs require
fresh authorized intent, not a way to evade uncertainty. External-owner qualification is separate from a distributed browser fence.
All external execution callbacks must complete synchronously under the held fence;
the owner cannot retain them for background use.

## User-facing outcomes and secret boundary

Only `saved`, `not_saved`, `unknown` or a fixed cancellation category leave the
helper. Saving is best effort and must not block the person's website login.
Vault outage does not create a plaintext disk spool. Unknown is not success or
proof that nothing was saved. Cancellation after submission requires readback.
The helper must not be called with secret values by an agent-visible tool.

Production composition must fence observation/recording as well as input during
secret entry, verify actual top/frame origins and account identity, pin the helper
and extension, and keep their private IPC out of screenshots, traces and logs.
No raw HTTP body, exception locals, password, cookie or profile enters OTel,
Temporal history or training data. Reference cleanup is not memory zeroization;
privileged local debugging and a malicious in-process adapter remain outside this
Python component's boundary.

## Evidence and follow-through

`tests/test_autosave.py` uses synthetic authority/capture and an independent
versioned protocol peer. It exercises zero writes on scope/consent/login failure,
CAS conflicts, lost acknowledgments, secret-free persistence, no replay, account
switches, cancellation and an observation-check mutation. See the acceptance
receipt for exact commands and limits. No real password or service was contacted.

This is additive to Browser #6/#13 (credential use), #7/#14 (profiles), #9/#16
(control), and #1 (fixtures); it closes none of their broader acceptance gates.
The opt-in account E2E fixture adds real Chromium and pinned disposable OpenBao
with a controlled HTTPS account site. Its capture/authority/operation-owner
adapters remain test fixtures, not production identity or persistence. Native
qualification and independent source review are recorded separately. Actual
credentials, extension permissions, workload credentials, deployment and live
qualification require their own authorization. No new recurring services or
backups are created.

Trusted callbacks must be bounded and non-reentrant. Clocks and observation
callbacks must behave as observations, not mutate authority. The final
browser/consent validation follows vault scope and token callbacks and checks
consent before fresh observations/current authority. This ordering catches the
covered callback revocation races; it is not a substitute for an actual atomic
Host/browser fence, nor protection against mutually malicious in-process adapters.

Tracked independently in [Browser #59](https://github.com/newdarwindev/runspindle-browser/issues/59).

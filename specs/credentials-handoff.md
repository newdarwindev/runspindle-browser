# Browser credentials and control transfer

Status: planned Runspindle contract adapted from existing local prototypes. No live acceptance, deployment, or credential enrollment is established by this document.

## Ownership

The browser component owns account-isolated browser sessions, OpenBao credential references, PinchTab automation adapters, and KasmVNC human viewing. Core owns Rust/Temporal job orchestration and policy decisions; host owns the actual native Codex session binding. A UI, Slack message, browser page, or optimized prompt is not an authorization source.

## Credential contract

- Bind each reference to authenticated principal, account, exact approved origins, operation, session and current lease epoch.
- Keep values inside trusted resolution and injection helpers. Temporal histories, logs, signals, receipts, screenshots and public status must not expose credentials, cookies, access handles or profiles.
- Check live top-level and target-frame origins before retrieval and immediately before use. Caller-provided origins are insufficient. Redirects, account changes and stale leases fail closed.
- Fail safely on vault outage, expired identity, malformed references or incomplete observations; no broad fallback credentials.
- Retain approved account credentials and encrypted profile checkpoints until explicit forgetting, rather than imposing an invented TTL. Cookie expiry may still require reauthentication. Define separate forget operations for stored credentials, stored profiles and target-site sessions; do not imply one operation revokes the others.
- Distinguish denied future vault reads from browser termination and target-service cookie revocation. Rotation does not by itself revoke website sessions.

## Control-transfer contract

Agent and human authority are exclusive. Passive observation uses a separately authenticated read-only capability and does not grant control. Fence existing agent commands and confirm fencing before issuing interactive control capability. Bind account, browser, target, holder and epoch throughout transfer. Human return requires authenticated release by the current holder, expected epoch, closure of all viewer inputs, and fresh trusted observations of the same target and account. Missing, changed or timed-out evidence grants no agent capability. Restart cannot silently restore authority. Reconcile uncertain external submissions before retry.

## Existing prototype and migration gaps

The reviewed OpenBao resolver permits only explicit loopback HTTP endpoints, rejects redirects and constrains KV references. This is development scope, not production workload identity or TLS readiness. Its mounted-file alternative is likewise not a production secret lifecycle.

The reviewed gateway uses in-memory handles, a process-local lock and fixture route allowlists. Its release method expects an authenticated caller supplied by surrounding infrastructure; it is not itself a production identity system. Raw backend responses and snapshots require an explicit sanitization boundary. Navigation allowlisting does not replace trusted frame-origin verification. Do not expose the fixture server or backend endpoints publicly.

Production work must implement distributed admission, durable lease fencing/recovery, trusted runtime origin observations, authenticated human release, bounded sanitized errors and reviewed transport/authentication. PinchTab and KasmVNC integration remains unverified here.

## Acceptance evidence required

Use synthetic accounts and secret canaries. Test wrong-account and wrong-origin denial before retrieval; redirects during resolution; stale epochs and cross-target commands; forged release; interrupted viewer closure; restart during takeover; provider outage/rotation; and uncertain submissions. Scan success and failure records for canaries. Record each gate separately as not run, passed, failed, blocked or unknown with exact code/configuration revision and evidence class. Prototype tests cannot establish live production acceptance.

## Selected storage specification

The complete SRC-006 requirement accounting below is a newly written adaptation.
The [disposition and evidence guide](../docs/credential-storage/README.md) separates
source coverage from synthetic checks, executable adapters and live acceptance.

## Source provenance

Adapted from owner-selected source material identified by the opaque source IDs in `../provenance.json`. Exact original locations, revisions and hashes are retained in a private provenance record. This specification does not import executable dependencies or change upstream licenses.

<a id="s01"></a>

## S01 Selected account authority

Saving a credential requires a specific selected account and permission to store it. A separate authorized workflow may use its reference. Neither possession of a reference nor storage permission authorizes account access. Secret values stay outside agent-visible state.

Obligations: save_permission, use_permission, no_values.

<a id="s02"></a>

## S02 Specification and execution boundaries

This is a requirements adaptation. The current repository has synthetic vault tests, resolver orchestration and protocol adapter code tested with injected doubles. Those are separate evidence classes, not a deployed credential lifecycle. This document enables no provider, enrollment, real secret or service. Historical staging settings and historical component passes are not asserted as current facts.

Obligations: no_activation, separate_evidence.

<a id="r01"></a>

## R01 Account specific references

Give orchestration only an opaque credential reference and the minimum sanitized metadata needed for routing. Its trusted record binds the authenticated principal, selected account and exact approved origins. Saving or using account A grants no permission for account B, even on the same site. Account and origin observations must be authenticated outside model output.

Obligations: reference, isolation, observed_account.

<a id="r02"></a>

## R02 Admission before provider access

Before any provider read, establish the authenticated principal, configured account, permitted operation, native session, browser/target, current lease epoch and unexpired identity grant. Core owns authorization and durable admission; Host supplies native identity and atomic fencing. Browser enforces this binding at retrieval and use. Missing or inconsistent fields deny access, with zero secret reads. An epoch or identity deadline expires authority, not stored data.

Obligations: principal, account, operation, session, lease, before_read.

<a id="r03"></a>

## R03 Trusted origins at field use

The trusted runtime must observe both the top-level origin and the target frame origin before retrieval, then again immediately before field injection. Page content, caller-provided URLs and navigation allowlists cannot replace observations. Keep the grant, observations and field use under the same authenticated atomic fence. An account switch, redirect, frame change, stale epoch or incomplete observation denies use. Invalidate and release any acquired handle on every exit; opaque handle release is not proof of memory zeroization.

Obligations: top_origin, frame_origin, before_read, at_use, invalidate.

<a id="r04"></a>

## R04 Secrets stay in trusted helpers

Resolve values only inside the scoped Activity or injection helper, with short-lived helper-owned handles. Temporal inputs, signals, results, errors, search attributes and logs must contain references or bounded sanitized status, never values. The same restriction covers receipts, screenshots, prompts, training exports and public projections. Tokens, cookies, control handles and profiles, including encrypted profile bytes, are not safe orchestration payloads. Scan failure records as well as successful records.

Obligations: helper, temporal_fields, tokens_cookies_profiles, all_outcomes.

<a id="r05"></a>

## R05 Rotation refresh and restart

Declare the provider version boundary for every resolution. Rotation invalidates in-flight handles from an older generation; a later authorized resolution obtains the new generation. Do not retain a usable cached value across a denied refresh or restart. Restart must rebuild authenticated current admission and observations, never reuse authority from restored storage. Report future vault-fetch permission, browser process termination and target-service session invalidation independently. None of rotation, deleting stored data, or killing a browser proves remote logout.

Obligations: version, refresh, restart, independent_status.

<a id="r06"></a>

## R06 Bounded provider failure

Deny missing scope, expired workload identity, unavailable provider, invalid reference, malformed response and disallowed redirect without exposing upstream values or exception bodies. Do not fall back to a broader credential, account, endpoint, mounted file or workload identity. A timeout or uncertain injection result requires reconciliation, not an automatic retry. Missing dependencies are blocked or not run, never a pass.

Obligations: deny, sanitized_errors, no_fallback, uncertainty.

<a id="b01"></a>

## B01 Provider restrictions remain intact

This adaptation does not expand provider endpoints, allowed redirects, reference paths or workload identity. Existing adapters keep their own explicitly reviewed interface restrictions. Local development transport and mounted-file prototypes are not production fallbacks. The resolver lift remains a separate source and integration obligation.

Obligations: endpoints, redirects, paths, identity.

<a id="b02"></a>

## B02 Infrastructure custody boundary

Production workload authentication, transport security, root and recovery custody require separate infrastructure review and validation. Neither this specification nor a passing test configures TLS, allocates credentials, enables a provider or grants a recovery role.

Obligations: authentication, transport, custody, no_configuration.

<a id="b03"></a>

## B03 Private material exclusion

Keep root or unseal material, real personal credentials and operational state out of source control, fixtures, agent-visible execution history and public projections. Tests use invented canaries and account names only. No original private snapshot is included in this artifact.

Obligations: root_material, personal_secrets, public_boundary.

<a id="a01"></a>

## A01 Isolation denial evidence

Synthetic acceptance must count provider reads and injections. A wrong account or wrong live top-level or frame origin must leave both counts at zero. A matching string supplied by the caller is not authentication.

Obligations: zero_reads, zero_injections.

<a id="a02"></a>

## A02 Resolution race evidence

Change the observed origin while resolution is pending. The operation must not inject, must invalidate the resolved value and must release the handle. Also exercise account changes and stale epochs before use. Real zeroization and the runtime atomicity fence need separate implementation evidence.

Obligations: origin_race, cleanup, limits.

<a id="a03"></a>

## A03 Success and failure privacy evidence

Use unique synthetic secret canaries to inspect successful and failed histories, errors, logs and receipts. A success-only scan is insufficient. Existing local tests inspect their own envelopes and spies; a full connected Temporal/history/log/screenshot audit remains unverified.

Obligations: success, failure, audit_gap.

<a id="a04"></a>

## A04 Rotation evidence

Verify that the declared version boundary changes later resolution and invalidates older in-flight handles. Preserve the independent site-session status through rotation, without claiming an existing cookie was revoked.

Obligations: future_resolution, stale_generation, site_status.

<a id="a05"></a>

## A05 Revocation status evidence

After vault access is denied, new fetches must fail while a previously established website session remains separately reported active unless its own invalidation has been confirmed. Unknown logout outcomes must remain unknown. Stored profile deletion and credential deletion each require their own selected operation and result.

Obligations: fetch_denied, site_independent, unknown.

<a id="a06"></a>

## A06 Provider negatives evidence

Exercise provider outage, token expiry, malicious references and redirects as explicit denials. Assert sanitized failure records and no unauthorized injection. Protocol doubles are not proof of pinned OpenBao interoperability.

Obligations: outage, expiry, reference, redirect, no_upstream_claim.

<a id="e01"></a>

## E01 Remaining implementation work

Live origin/account observations, scoped production workload identity, real outage/rotation behavior, authenticated durable fencing and connected audit coverage remain open integration gates. Existing Python resolver/protocol tests and inert references must be labeled separately. A selected specification can be fully accounted for while browser product acceptance is not run.

Obligations: trusted_adapter, identity, outage_rotation, audit, separate_acceptance.

## P01 Encrypted profile requirements

This issue-specific extension is not attributed to absent text in SRC-006.
Encrypted profile checkpoints belong to exactly one authenticated principal and
selected account. They remain in a protected store; orchestration gets only an
opaque reference. Restore requires a fresh authorized operation, current epoch
and trusted same-account/origin observations. Authenticated encryption, key
custody, corruption handling, atomic writes and deletion of every retained copy
need their own implementation and tests. Missing key, damaged ciphertext or an
incomplete write must deny restore. No mock here implements encryption.

## P02 Retention is distinct from access expiry

Keep approved stored credentials and encrypted checkpoints until explicit
forgetting. Do not add an automatic retention TTL. A cookie expiry, short-lived
lease, expired workload identity, timeout, provider outage or process restart
can block use without deleting stored material. Restoring a checkpoint or
renewing authority cannot recreate data previously forgotten.

## P03 Three independent forgetting operations

A forgetting request identifies the selected principal/account and exactly one
of credential deletion, profile deletion or site-session invalidation. Validate
its permission, operation, target and current lease before changing that state.
Credential deletion removes stored references/values and invalidates outstanding
handles; profile deletion removes retained checkpoints and does not imply remote
logout. Target-site invalidation requires its own authorized action and confirmed
readback. Browser termination is a fourth independent observation, not proof of
any of the three outcomes. For incomplete deletion or uncertain remote outcomes,
report blocked, failed or unknown rather than completed; reconcile before retry.
Do not erase other accounts, imply remote logout, or report physical erasure from
a synthetic model. Previously saved copies and backups, if any, belong to the
explicit deletion inventory; this specification neither creates nor runs backups.

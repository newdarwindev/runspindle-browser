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

## Source provenance

Adapted from owner-selected source material identified by the opaque source IDs in `../provenance.json`. Exact original locations, revisions and hashes are retained in a private provenance record. This specification does not import executable dependencies or change upstream licenses.

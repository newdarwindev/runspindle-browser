# Approved direction and migration inventory: Browser has no managed data storage

Owner correction: Browser should not own managed stores or duplicate canonical
state. The owner approved this direction. This is an inventory and migration boundary,
not a claim that
existing modules or data have been migrated. No database, profile or credential
has been deleted, copied or backed up by this work.

## Canonical ownership

| Data | Canonical owner | Browser role |
| --- | --- | --- |
| Credentials and key material | Existing externally managed OpenBao | Scoped resolve/inject/save client; no local credential persistence |
| Operation outcome, replay prevention and consent | External orchestration/state owner, integrated with Core | Submit guarded callbacks/reference-only envelopes; read outcomes |
| Native browser profile and active session | Host-managed native browser lifecycle | Use the selected session; no separate checkpoint copy |
| Control ownership and durable epoch | External Core/Host authority boundary | Enforce current input/observation grants, never issue durable authority |
| Infrastructure and dependency pins | Platform | Consume configured/pinned endpoints; no domain-state replica |

These ownership roles follow the existing system division. Complete replacement
external contracts and migration adapters are NOT implemented. The operation
owner must be selected consistently with Core's existing registry so removing the
Browser journal does not create two canonical ledgers elsewhere. Temporal history
is not itself a guarantee that an uncertain external action may safely be retried.

## Verified existing Browser-owned state requiring relocation/removal

| Current code | Existing managed state | Proposed disposition |
| --- | --- | --- |
| `browser_runtime/effects.py`, `effect_schema.py` | SQLite operations, binding/digest, unknown/confirmed/rejected readback | External single operation owner; retain no-blind-retry and operation uniqueness |
| `browser_runtime/guarded_effects.py` | Constructs `Journal(path)` | Keep browser guard, inject external operation execution |
| `browser_runtime/control_leases.py` (`LeaseStore`) | SQLite holders, epochs and transfer state | External authority owner; Browser remains an input gate |
| `browser_runtime/profile_store.py`, `profile_schema.py` | `profiles.sqlite3`: account scope/owners, encrypted checkpoints, nonce/key fingerprints, restore records | Remove Browser checkpoint ownership; use canonical Host/native profile or explicit external profile service only if separately required |
| `browser_runtime/profile_directory.py` | Staged/materialized profile directories | Host lifecycle ownership, not a Browser snapshot subsystem |
| `browser_runtime/profile_keys.py`, `profile_custody_schema.py` | `custody.sqlite3` registry/attempts and `lease.sqlite3` fence | External key custody/authority; retain only scoped OpenBao client at Browser boundary |
| `browser_runtime/autosave.py` as merged in PR60 | Creates/opens/closes effect Journal from a path | Corrective candidate accepts externally owned `EffectExecution`; no filesystem path or store lifecycle |

`openbao.Vault` currently holds short-lived in-memory secret handles. These are
transient helper working memory, not another persistent vault. Human-entered
passwords and injection buffers necessarily exist transiently; none may become
logs, model state, durable caches or duplicate account records. A target website's
password verifier belongs to that website, not a second Runspindle credential
store.

## Safe migration, not copy-and-delete

1. Agree the external canonical owner and minimal execution/authority contracts.
2. Stop adding Browser store schemas and new Browser-managed persistence paths.
3. Switch consumers to injected external interfaces; tests demonstrate no Browser
   database open/create/close and preserved unknown/reconcile behavior.
4. Inventory deployed state and existing external duplicates before any migration.
   No deployed inventory is established by this source review.
5. Only after explicit migration scope and verification, transfer ownership once
   or retire redundant copies. Existing uncertain operations must stay fenced.
6. Remove legacy implementation/modules after consumers and data are accounted
   for. Do not delete data or create backups under this draft.

## E2E impact

The approved Browser-only registration/login/save/relogin/action test uses a real
but disposable externally supplied OpenBao and synthetic external operation and
authority fixtures. Browser only calls them. First and second Chromium contexts
are disposable, not persisted checkpoints. The second starts empty to prove
vault-backed relogin. The synthetic website owns its own account verifier and
session/action state. Neither fixture is a new Browser production storage service.

Tests of a legacy Journal through an **external test adapter** are transitional
behavioral regression evidence, not proof that the old Browser storage code has
already been relocated or that a production external owner is implemented.

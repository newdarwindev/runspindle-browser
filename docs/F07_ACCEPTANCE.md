# F07 acceptance: durable, bounded website effects

This ledger maps the original [Browser #8](https://github.com/newdarwindev/runspindle-browser/issues/8)
contract to implemented code and bounded acceptance. It is not live H05,
credential/profile acceptance or a production authority claim.

## Implemented contract

| Original deliverable | Implementation and evidence |
| --- | --- |
| Trusted pre-action observations and durable states | `GuardedJournal` holds injected authority across journal/site boundaries, checks the complete target, digest, action, deadline and fresh observation; `Journal` durably reserves unknown before submitting. Confirmed/rejected require independent readback. |
| Response loss, changed account/navigation and restart | Actual SQLite journal, HTTP and Chromium fixtures cover lost replies, changed target/page, stale authority, fresh processes and before/after-effect crashes. |
| Explicit Core reconciliation | Versioned `effect_wire.py` receiver and `specs/effect-wire-v1.md`; Core durable BrowserRegistry and separate reconciliation commands. Core PR #54 adds actual Chromium through the versioned Temporal engine workflow. |
| Closed envelopes and adapter responsibility | Fixed version, closed nested fields, bounded request/response, exact raw-byte request commitment, complete target/digest/action expectations; grants are independently injected, never manufactured from request hashes. |
| Bounded storage and transport | Fixed journal capacity and retained-field bounds; bounded wire, HTTP and CDP operations; injected clock and failure points. Capacity never evicts a reservation or restores permission to resend. Schema identity is preserved, not silently migrated. |

## Acceptance and negative controls

| Original acceptance criterion | Positive/negative test evidence | Deliberate invariant-breaking control |
| --- | --- | --- |
| Accepted action plus lost response produces one effect and unknown until verified | `test_effect_journal.test_acknowledgment_is_unknown_until_independent_readback`, HTTP/Chromium lost-response fresh-process tests and Core native Temporal before/after cases | `test_effect_acceptance_mutations` changes the dispatch return into false confirmation; the independent site still has exactly one event while the retained row is unknown. |
| Duplicate/reordered requests never blindly resubmit | Journal concurrent processes and premature-readback tests; HTTP/Chromium fresh-engine duplicate tests; actual Temporal worker/server restart and replay | Existing journal, HTTP and real Chromium reservation-bypass mutants produce a second independent effect. |
| Wrong tab/account/epoch denies before action | Guarded exact-observation matrix, wire full-target matrix, stale-holder HTTP and changed-page Chromium tests; Core wrong-target update refusal | Guarded current-authority bypass exposes a forbidden site call; wire expectation-bypass mutants fail their named regressions. |
| Unresolvable outcomes remain unknown | Wrong-account/digest, malformed/ambiguous readback and before-effect recovery preserve unknown without a success receipt | `test_effect_acceptance_mutations` disables readback validation and exposes false confirmation for another account, with one independent site event. |
| Real persistence and fresh-process claims | Actual SQLite, fresh Python/Core processes, actual Temporal SQLite server restart, actual Chromium profiles; independent stores/counters remain the oracle | Durable reservation-bypass mutants demonstrate recovery would otherwise resubmit. Missing real production authority is never replaced with a success stub. |
| Capacity/retained state bounds | `test_effect_capacity` saturation, duplicate/reconcile at capacity, retained-field denial and fresh-process contention cases | Capacity-limit mutation exposes an additional forbidden independent effect. |

## Scope that remains open elsewhere

This component contract explicitly uses invented accounts/identities and synthetic
sites with injected authority. It does not require publishing to a live website.
The effect journal, independent synthetic website and closed wire are real
implementations of that bounded contract, not mock substitutes for their own
persistence or transport. Real Chromium and Temporal lanes add isolated
integration evidence without changing the authority classification.

Credential resolution, actual account/native-frame observations and encrypted
profile custody remain with Browser #13/#14 and their parents. This lane does not
read vaults, inject credentials, restore profiles or grant authority from stored
journal state. H05 and composition acceptance remain open for their wider
journeys. Closing F07 does not close those issues, waive their prerequisites, or
claim live-site selectors/semantics, distributed exactly-once execution,
filesystem quotas, malicious-storage protection or power-loss durability.

Core integration receipts pin their exact Browser sources. A newer Browser
capacity implementation does not retroactively qualify an older pinned consumer;
any updated cross-component claim must identify its refreshed pin and new receipt.

## Reproduction and evidence classes

Use `tools/qualify_effect_reconciliation.py --report docs/f07-acceptance.json`
inside an unprivileged loopback-only namespace as described in
[F07 child acceptance](F07_CHILD15_ACCEPTANCE.md). This includes actual journal,
guard, wire, HTTP, capacity and mutation tests in normal and optimized Python.
Run the separate `tools/qualify_chromium_effects.py` lane for actual renderer
integration. Neither runner silently treats missing prerequisites or skipped
engine tests as success.

Exact reports, source hashes, regression counts and aggregate static-quality
status are recorded for the final candidate, not inferred from this ledger.

## Verified candidate results

The [bounded F07 receipt](f07-acceptance.json) passed 101/101 tests in each mode,
with zero skips, failures or errors. This includes seven capacity/schema-bound
tests and the independent false-confirmation mutation controls. The separate
[Chromium receipt](f07-chromium-tests.json) passed 15/15 per mode, with zero skips.
Full default Browser discovery passed 521 tests in each mode; its six explicit
engine opt-in skips were separately exercised above.

Independent review verified all 70 F07 source hashes and 72 Chromium receipt
hashes. [Static comparison](f07-static-comparison.json) is unchanged from the
merged base: 541 diagnostics, zero added. Aggregate static still fails against
the historical baseline (78 recorded entries, 463 absent from that old baseline).
No baseline or gate was relaxed. Scoped new/changed code lint and strict type
checks pass; existing SQLite ResourceWarnings and unqualified crypto-wheel
closure are not relabeled as resolved.

Final issue closure additionally requires the refreshed Core engine source pin
and its exact native integration receipt. The issue's completion comment must
link that receipt; the older Core integration cannot stand in for this step.

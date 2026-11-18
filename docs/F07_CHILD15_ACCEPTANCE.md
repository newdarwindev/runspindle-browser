# Browser #15: bounded durable website-effect acceptance

This is the acceptance ledger for [implementation child #15](https://github.com/newdarwindev/runspindle-browser/issues/15), not closure of [parent F07/#8](https://github.com/newdarwindev/runspindle-browser/issues/8) or [H05](https://github.com/newdarwindev/runspindle/issues/12).

## Original scope and conclusion

The child requests a durable operation journal, trusted pre-action binding, a
site-specific reconciliation interface, and **a local synthetic website with an
independent effect ledger**. It does not require a real browser engine or a live
website to satisfy that bounded scenario. The existing implementation supplies
all four: actual SQLite persistence, guarded admission, a separately invoked
readback interface, and an owned loopback HTTP website with its own SQLite ledger.
No replacement runtime or new effect path is needed to complete this child.

This audit reconciled GitHub main and the implementation checkout at
`b3edadf12af74cd5b5d27a486ef0a4a64d5a1594`; the owner PR listing returned no open
Browser PRs. The closeout changes evidence tooling/documentation rather than
claiming a newly implemented browser engine. Exact candidate source/toolchain,
checks and statuses belong to the qualification receipt, not merely this source
inspection. Close #15 only with a passing receipt for the published candidate.

## Implementation and observable boundaries

| Original deliverable | Actual implementation | What remains synthetic or outside this child |
| --- | --- | --- |
| Durable operation journal | `browser_runtime/effects.py`: `Journal.dispatch`, `_dispatch`, `reconcile`, `_reconcile`; `browser_runtime/effect_schema.py` admits the actual SQLite schema. Reservation commits before submission; uncertain outcomes do not restore dispatch rights. | Storage-device power loss, malicious storage actors and distributed exactly-once execution are not qualified. |
| Trusted pre-action binding | `browser_runtime/guarded_effects.py`: `GuardedJournal` admits an exact `Target`, digest, action and deadline through injected trusted authority; the held guard and current observation are checked again at effect boundaries. | Tickets, native observations and the browser/input fence are synthetic adapters in this lane, not a production authenticated issuer. |
| Site-specific reconciliation interface | The guarded `Site` interface and journal `Readback` validation bind outcome/evidence to the original operation, complete binding and payload digest. Reconciliation is a distinct operation that never submits. | No production website's selectors, DOM semantics, receipt semantics or account identity are inferred. |
| Local synthetic website | `browser_testing/http_effect_site.py`: `LocalSite` and `HTTPAdapter`, fixed loopback `/submit` and `/readback`; `browser_testing/effect_site.py`: independent SQLite site ledger. | Logical HTTPS origins map to an owned numeric loopback port in the fixture. This is not TLS, actual browser-origin evidence or an internet service. |
| Observable external effects | Independent HTTP submission/readback counters and independent site rows; the site deliberately does not deduplicate submissions. | These are invented payloads/accounts and local synthetic effects, not provider transactions. |

## Original BDD and required-test ledger

All names below are actual test functions, not proposed examples. The bounded
qualification runs the complete six suites in normal and optimized Python;
individual mappings explain what each original requirement observes.

| Original requirement | Existing tests | Independent acceptance oracle |
| --- | --- | --- |
| Site accepts, response is lost, duplicates/restart retain unknown and reconcile before another effect | `test_http_effect_site.py::test_accepted_lost_reply_restart_then_reconcile_no_second_submission`; `test_effect_journal.py::test_lost_reply_and_explicit_rejection_never_resubmit`; `test_guarded_effects.py::test_lost_reply_fresh_process_and_authenticated_reconciliation` | Before readback: unknown and one effect. Fresh client process reopens the journal; duplicate sends no HTTP request. Final HTTP counts are one submission, one readback, one effect. |
| Reordering and no blind retry | `test_effect_journal.py::test_acknowledgment_is_unknown_until_independent_readback`, `test_lost_reply_and_explicit_rejection_never_resubmit`, `test_inflight_transaction_prevents_premature_readback`; `test_http_effect_site.py::test_rejected_unknown_wrong_account_and_ambiguous_readback` | Late dispatch after reconciliation cannot create another effect; an in-flight writer prevents premature readback. These are explicit orderings, not a claim of exhaustive arbitrary message permutations. |
| Rejection | `test_effect_journal.py::test_lost_reply_and_explicit_rejection_never_resubmit`; HTTP readback matrix above | Submission acknowledgement stays unknown; only matching readback establishes rejection. Repeating dispatch does not add a submission or effect. |
| Ambiguous and wrong-account readback | `test_effect_journal.py::test_ambiguous_wrong_account_or_malformed_readback_stays_unknown`, `test_readback_boolean_revision_is_not_exact_binding`; HTTP readback matrix above | Unknown remains unknown. Independent seeded conflicting events are distinguished from HTTP submissions; wrong binding/digest/malformed evidence cannot confirm. |
| Concurrent callers | `test_effect_journal.py::test_concurrent_processes_make_one_effect`; `test_effect_schema.py::test_fresh_processes_initialize_or_adopt_and_keep_one_effect` | Two fresh processes use the actual store; independent site count is one, not an in-memory mock call assertion alone. |
| Crashes before and after effect | `test_effect_journal.py::test_fresh_process_crashes_before_and_after_effect_remain_fenced`; `test_effect_exceptions.py::test_fresh_process_after_uncertain_commit_does_not_submit` | Real child process death and reopened stores preserve the reservation. Independent effect state distinguishes before-effect from after-effect uncertainty; recovery does not submit. |
| Trusted binding and forbidden calls | `test_guarded_effects.py::test_wrong_ticket_payload_action_and_exact_observation_deny`, `test_revocation_at_durable_dispatch_boundary_prevents_site_call`, `test_persisted_full_target_rejects_changed_session_frame_and_origin`; `test_http_effect_site.py::test_lease_stale_holder_denies_before_http` | Wrong ticket, payload/action, target, stale lease or revoked authority observes zero forbidden site/HTTP effects. Restart cannot reconstruct authority from a durable row. |
| Deliberate invariant-breaking mutation | `test_effect_journal.py::test_deliberate_duplicate_effect_mutation_is_observed`; `test_http_effect_site.py::test_duplicate_reservation_bypass_exposes_second_http_effect`; `test_guarded_effects.py::test_source_mutation_exposes_forbidden_site_effect` | Bypassing reservation causes two independent effects/HTTP submissions. Bypassing current authority exposes a forbidden effect. A mutant failing to compile is not this oracle. |
| Storage/error/cancellation cleanup | `test_effect_exceptions.py` and `test_effect_schema.py`; HTTP `test_fixed_routes_and_normal_shutdown_with_partial_request` and `test_bounded_request_and_failure_context_close_listener` | Actual stores reject incompatible/tampered schema without repair; public error categories do not inherit canary-bearing causes. Child-process cleanup is bounded. Owned HTTP sockets/listener close and worker stops even on test failure or stalled request. |
| Versioned bounded Core-facing wire | `test_effect_wire.py`, `browser_runtime/effect_wire.py`, `specs/effect-wire-v1.md` | Closed bounded requests, exact target/digest/action checks, raw-request response binding and separate reconciliation. This is additional coverage, not a substitute for the original HTTP-site and persistence criteria. |

## Dependency disposition: #13 and #14 remain open

The original dependency links are retained. They are not marked completed,
waived for their own acceptance, or replaced by simulated production evidence.

- [#13, trusted scoped credential resolution](https://github.com/newdarwindev/runspindle-browser/issues/13):
  this child reuses the complete `Target` contract and requires an injected trusted
  authority/observation/fence interface. Its invented synthetic site needs no
  secret, resolver, vault read or credential injection. The fixture supplies
  synthetic trusted admission explicitly. This qualifies the journal's behavior
  under that contract, not the real browser/issuer/vault implementation promised
  by #13. Missing real authenticated observations, atomic browser fencing and
  helper/provider qualification still block credential-backed/browser-wide claims.
- [#14, encrypted profiles and forgetting](https://github.com/newdarwindev/runspindle-browser/issues/14):
  this scenario neither saves/restores a browser profile nor loads cookies,
  decrypts checkpoints or forgets credentials. The operation journal and
  independent website ledger are not the profile store. There is consequently no
  profile prerequisite consumed by the isolated acceptance path. Profile restore,
  custody, browser compatibility, deletion scopes and their integrated authority
  requirements remain owned by #14 and its parent; this receipt does not qualify
  them or assert that a restored profile grants action permission.

Thus the linked unfinished prerequisites block the **affected integrated claims**,
not this child's expressly local synthetic-site journal scenario. Closing #15
means that its original bounded implementation and tests are delivered. It does
not mean that #13/#14 are closed or that their broader prerequisites have been
satisfied. This disposition must accompany the issue closeout and parent update,
not silently narrow either dependency's scope.

## Reproduction and source-bound evidence

`tools/qualify_effect_reconciliation.py` supplies the bounded combined entrypoint.
It runs these suites in normal and optimized Python:

- `test_effect_journal.py`
- `test_effect_exceptions.py`
- `test_effect_schema.py`
- `test_guarded_effects.py`
- `test_http_effect_site.py`
- `test_effect_wire.py`
- `test_effect_qualification.py` (runner prerequisites and real subprocess cleanup)

The [toolchain manifest](effect-reconciliation-toolchain.json) pins Python bytes,
Python version, SQLite version, Python SQLite extension bytes and SQLite shared-library bytes. From this checkout on the qualified local
Linux runner, execute one bounded command (no downloads or persistent service):

```sh
sudo -n unshare --net --fork sh -c 'ip link set lo up; exec runuser -u "$1" -- "$2" "$3/tools/qualify_effect_reconciliation.py" --report "$3/docs/effect-reconciliation-acceptance.json"' sh "$(id -un)" "$(command -v python3)" "$PWD"
```

Only the new disposable network namespace receives a loopback interface; host
network configuration is not changed. Tests run as the invoking non-root user.
The runner refuses root, extra network interfaces or mismatched toolchain pins.
The [recorded receipt](effect-reconciliation-acceptance.json) identifies exact source, fixture/configuration, toolchain/dependency bytes,
commands, stdout/stderr digests and per-run outcomes. The selected lane uses an
isolated local network namespace with loopback only; no external network is
needed. The tests use real Python, SQLite, filesystem/process behavior and local
HTTP, with synthetic authority/account/site semantics. This Python-only child
lane does not report unrelated Rust/native/product tests as passed.

A source audit is not a passing execution result. Preserve failed, blocked,
not-run and unknown statuses rather than inferring success from a document or a
process start. Normal and optimized runs must independently pass, including the
mutation checks and cleanup assertions. Source changes after qualification require
fresh evidence or an explicit unchanged-source verification.

## Completion boundary

No originally named bounded implementation/test category is missing from the
source mapped above. Successful exact-candidate qualification supports closing
#15 and linking its PR and receipt to #15 and #8. The child adds no claim of
real browser-engine input, authenticated native frame/account observations,
production credential/profile integration, live website reconciliation,
distributed fencing, power-loss guarantees or full H05/composition acceptance.
Those remain open under their existing owners. No live accounts, paid calls,
credentials, persistent service, deployment, security setting or backup is part
of this closeout.

## Verified result

The recorded isolated run passed 93 tests in each mode: six behavior suites
(88 tests) plus five runner prerequisite/cleanup negatives. No failures, errors
or skips occurred. Worker and child optimization levels were independently
recorded as 0 in normal mode and 1 in optimized mode.

Aggregate repository static quality remains failing on historical debt: the
[unchanged source base and candidate comparison](effect-reconciliation-static-comparison.json)
shows 550 diagnostics in each, including
472 absent from the older debt baseline. This change adds zero diagnostics and
does not refresh or relax that baseline. New runner/tests pass scoped pinned
Ruff formatting/lint and strict mypy. This is not a claim of green repository CI.

The broader Python regression suite also passed 504 tests in normal mode and 504
in optimized mode in loopback-only namespaces. It emitted SQLite ResourceWarnings;
this is not a claim that all repository diagnostic debt is resolved. Those broader
runs used the installed cryptography 49.0.0; they do not qualify the separately
preferred 50.0.2 wheel closure. The focused effect lane above does not consume
cryptography, vault access or profile persistence.

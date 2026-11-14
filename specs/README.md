# browser specification

Status: planned contract, implementation and live acceptance not verified.

## Responsibility

Scoped credentials, encrypted profiles and fenced browser handoff.

## Shared identifiers

Correlate task, intent revision, selected host, native session, browser instance, lease epoch, trace/span, artifact digest and Slack destination without placing credentials or raw private content in public receipts.

## Required behavior

Preserve explicit authority and unknown outcomes. Distinguish request admission, execution, validation, acceptance and delivery. Exact state transitions belong in component-specific specs added beside this file.

## Acceptance

1. Unit/contract tests with synthetic data.
2. Isolated integration tests against pinned upstream dependencies.
3. Bounded live acceptance in an authorized target.
4. Failure, restart, uncertain-effect reconciliation and rollback evidence.

None of these product gates has been run for this scaffold.

Detailed adaptation: [credentials-handoff.md](credentials-handoff.md).

A pinned [shared synthetic fixture subset](../docs/SHARED_FIXTURES.md) now has
standalone Python consumer checks. Native/Rust adapter behavior and upstream
compatibility remain unimplemented; these fixture checks are separate evidence.

## Engineering direction

[Desired intent](desired-intent.md) connects this component to scoped access,
managed sessions, explicit human exceptions and evaluated maintained workflows.
It adds design and verification obligations without changing runtime schemas,
existing acceptance results or operational permissions.

## Synthetic vault fixtures

[Scoped vault and scripted observation fixtures](synthetic-vault-fixtures.md)
provide a bounded issue #1 test harness. This is synthetic evidence, not trusted
credential resolution, live browser integration or selected-source migration.

## Durable effect journal

[Local effect journal](effect-journal-v1.md) persists uncertainty before an
injected stateful action and blocks blind duplicate dispatch. SQLite/process
recovery tests are separate from real browser, authority and profile integration.

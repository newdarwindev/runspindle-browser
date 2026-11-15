# Selected credential-storage specification

Scope: SRC-006 only, [Browser issue 2](https://github.com/newdarwindev/runspindle-browser/issues/2).
This is an original requirements adaptation with complete selected-source
accounting, not an executable source port or a live security acceptance result.
The canonical contract is [credentials-handoff](../../specs/credentials-handoff.md).
The machine-readable [coverage map](coverage.json) records each substantive
source unit, review disposition, obligations, current target and synthetic cases.

## Source and rights review

The exact retained source matches its privately recorded original revision/path
and SHA-256. The selected Markdown contains six stories, six acceptance bullets,
scoping and implementation caveats, and eight navigation/code references. Titles,
section labels and table scaffolding carry no separate behavioral obligation.
The private receipt maps every nonblank source line, including that structure.
No embedded dependency code, binary, image or license notice is present in the
selected document. The retained provenance reports no project-wide source license;
no blanket license or third-party permission is inferred.

Only newly written requirements and original synthetic checks are added. No
historical expression, linked document body, original code, operational snapshot,
private account, original URL or historical test result is republished. Existing
notices remain untouched. Eight source locators are resolved safe exclusions
below, not unreviewed omissions. SRC-007 and SRC-008 retain their separate source,
rights and executable/integration review obligations. New profile, retention and
forgetting elaboration P01-P03 comes from the current issue and existing contract,
not a claim that those details appeared in the selected historical document.

## Evidence classes and coordination

- Historical reference: no new reference bytes imported by this change. Existing
  inert resolver/gateway references remain inert and separately manifested.
- Adapted content: 18 source units rewritten, eight locator exclusions resolved.
  Source accounting can complete without completing other selected sources.
- Executable implementation: existing resolver/protocol modules are unchanged.
  The new lifecycle model has only synthetic status flags. It performs no I/O,
  credential resolution, encryption, authentication, browser action or deletion.
- Verified behavior: local deterministic tests exercise model state separation
  and existing synthetic resolver boundaries. A checker validates inventory,
  links, hashes and test names, not natural-language correctness or live behavior.
- Live acceptance, real provider compatibility, distributed fencing, profile
  encryption/erasure, real workload identity and full connected audit: not run.

[Issue 1](https://github.com/newdarwindev/runspindle-browser/issues/1) remains open
for the full isolated browser/handoff/profile harness. Reuse its existing vault
and resolver tests rather than duplicating them. The narrow lifecycle model is a
reusable addition, not completion of its encryption, viewer or restart gates.
[Issue 3](https://github.com/newdarwindev/runspindle-browser/issues/3) retains the
resolver source lift and pinned provider lane; [issue 4](https://github.com/newdarwindev/runspindle-browser/issues/4)
retains gateway source migration and durable authority. Neither is closed by this
specification. Global selected-source migration stays partial in STATUS.json.

## Reproducible checks

Run from the repository root with Python 3.12 (standard library only):

- `python3 tools/check_credential_storage.py`
- `python3 -O tools/check_credential_storage.py`
- `python3 -m unittest discover -s tests -v`
- `python3 -O -m unittest discover -s tests -v`
- `python3 tools/check_scaffold.py`
- `python3 tools/validate.py` (also requires the repository's pinned quality and Rust tools)

The hygiene entrypoint delegates to its existing mandatory inventory. The
storage artifact checker is registered once in `hygiene.json` and once in the
component partition of `validation-partitions.json`; it is not separately run
by the entrypoint. Integration tests reject missing/duplicate coverage and
missing checker files. Existing gates, image pins and static debt baselines
remain unchanged.

The standard-library test run covers existing isolation, stale-epoch, redirect,
expiry, cleanup, rotation and canary cases plus explicit forgetting, retention
and independent site status. Deterministic fixture IDs use invented `.test`
origins; no random seed, real accounts, profile bytes or provider dependency is
needed. Model tests reject any attempted outbound connection. Checker mutation
tests reject erased requirements, unresolved exclusions, stale hashes, broken
test links, unsafe paths and inflated acceptance claims.

For the new Python modules use pinned Ruff 0.14.5 and mypy 1.18.2:
`ruff check --select E,F,I,UP,B,SIM --ignore E501 browser_testing/storage.py tools/check_credential_storage.py tests/test_storage_lifecycle.py tests/test_credential_storage.py`,
`ruff format --check` on those same four files, and
`mypy --strict --explicit-package-bases` on those same four files.

The manifest records public file hashes and evidence classes. It deliberately
cannot contain its own final commit hash: review/publication receipts bind this
manifest's hash and the immutable resulting commit/tree after freeze. The private
receipt preserves original identity and line hashes. A later public PR receipt
must record the actual published commit, check outcomes, skips and unresolved
gates. Do not infer a CI pass from a local test command or a source hash.

## Resolved exclusions

<a id="x01"></a>

### X01 Historical goal navigation

The selected link or code locator is omitted. Its navigation role is replaced by specs/README.md. Linked bodies, historical results, operational details and implementation bytes are not part of this specification lift. No permission to import or execute them is inferred.

<a id="x02"></a>

### X02 Historical repository guidance

The selected link or code locator is omitted. Its navigation role is replaced by AGENTS.md. Linked bodies, historical results, operational details and implementation bytes are not part of this specification lift. No permission to import or execute them is inferred.

<a id="x03"></a>

### X03 Historical regression summary

The selected link or code locator is omitted. Its navigation role is replaced by docs/credential-storage/README.md. Linked bodies, historical results, operational details and implementation bytes are not part of this specification lift. No permission to import or execute them is inferred.

<a id="x04"></a>

### X04 Historical boundary review

The selected link or code locator is omitted. Its navigation role is replaced by specs/credentials-handoff.md. Linked bodies, historical results, operational details and implementation bytes are not part of this specification lift. No permission to import or execute them is inferred.

<a id="x05"></a>

### X05 Historical acceptance row references

The selected link or code locator is omitted. Its navigation role is replaced by docs/credential-storage/coverage.json. Linked bodies, historical results, operational details and implementation bytes are not part of this specification lift. No permission to import or execute them is inferred.

<a id="x06"></a>

### X06 Historical implementation path

The selected link or code locator is omitted. Its navigation role is replaced by specs/trusted-credential-resolver.md. Linked bodies, historical results, operational details and implementation bytes are not part of this specification lift. No permission to import or execute them is inferred.

<a id="x07"></a>

### X07 Historical account workflow issue

The selected link or code locator is omitted. Its navigation role is replaced by https://github.com/newdarwindev/runspindle-browser/issues/1. Linked bodies, historical results, operational details and implementation bytes are not part of this specification lift. No permission to import or execute them is inferred.

<a id="x08"></a>

### X08 Historical infrastructure issue

The selected link or code locator is omitted. Its navigation role is replaced by specs/credentials-handoff.md. Linked bodies, historical results, operational details and implementation bytes are not part of this specification lift. No permission to import or execute them is inferred.

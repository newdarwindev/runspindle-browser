# Browser-only synthetic account E2E

Status: the complete synthetic Chromium/OpenBao chain passed a bounded isolated
manual Strix run. Actions CI and production authority remain unqualified. This is
not the full Runspindle system or an installed browser capture extension.

The opt-in worker starts real OpenBao 2.7.2 in disposable TLS development/in-memory
mode and a synthetic HTTPS account site. Chromium uses two fresh native profiles.
The first registers, logs in through ordinary HTML forms, captures only the known
synthetic form in a trusted test helper, and saves through the actual Autosave
writer. The second has no first-profile cookies or checkpoint, is denied access,
then uses the existing Resolver/Vault injection path to log in and perform one
protected page action with independent site readback. A lost vault write reply
must reconcile without a second POST. No-opt-in and unsuccessful capture negatives
must leave the vault unwritten. Additional account/origin/CAS/cancellation cases
remain in the fast helper suite.

## No Browser-owned stores

OpenBao owns the credential. The synthetic target site owns its account verifier,
session and action state. The test/application fixture supplies external operation
state and authority. Browser itself receives references and the `EffectExecution`
port, not a database path. The E2E operation fixture is in-memory, so this test
does not qualify a durable production Core adapter or distributed authority.
The approved broader storage migration is tracked separately; legacy Browser
store modules have not yet been relocated or deleted.

## Explicit prerequisites

Run only in an already admitted, unprivileged, loopback-only isolated worker:

```
python3 tools/qualify_account_e2e.py --bao /preprovisioned/bao --chromium /usr/lib/chromium/chromium
```

There is no installation, namespace creation, runner registration, network access
expansion or hosted fallback. The launcher runs normal and optimized workers,
each bounded at 120 seconds; upstream process groups have independent 90-second
parent-pipe watchdogs. Fixture socket reads time out and thread cleanup is checked.
Uncertain process cleanup retains its temporary directory rather than deleting
files beneath a potentially running process. No backup or migration is performed.

OpenBao is an external test dependency, not a Browser service. Its dev token and
TLS files exist only in its temporary fixture HOME, never user credentials.
Chromium trusts the generated CA only in its disposable HOME's NSS database.
Python HTTPS uses an explicitly injected verified SSLContext, requiring hostname
validation and CERT_REQUIRED on every request. No host trust store or browser
security setting is changed, and sandbox/certificate checks are not disabled.
Native browser password saving is disabled in the disposable profile so OpenBao
is the only credential store for the test.

## Pins and provenance

Official upstream release:
https://github.com/openbao/openbao/releases/tag/v2.7.2

Archive `openbao_2.7.2_linux_amd64.tar.gz` has SHA256
`582b1f3c2fdc5afd443b2d57a225ef654de75adea609fdb66731fd582a9cbc96`,
checked against the release's `checksums.txt`. Extracted executable SHA256 is
`9c5f36287c673f386e1533e9c044169a248e4ee50dd54810fa766e95bd41b788`.
No upstream binary/source is vendored. Runtime source is original test glue.
Chromium 156.0.8078.47 and 156.0.8078.79 executable hashes are explicit in
`browser_testing/account_e2e.py`; supporting a pin is not proof it runs here.

## CI boundary

`.github/workflows/account-e2e.yml` is manual, main-only, repository-bound, requires
an explicit owner-controlled admission variable and the existing isolated Strix lane,
and keeps contents permission read-only. It provisions nothing and does not
qualify the fleet. No repository variable, runner, credentials or permissions
were changed. Until the lane is safely admitted, this CI gate remains blocked.
The worker reports sanitized counts and source hashes only, never raw tracebacks,
HTTP bodies, screenshots or passwords. A source-only/unit pass is not E2E PASS.

## Observed bounded execution (2026-11-18)

The real OpenBao-only path (`--openbao-only`) passed two tests in both normal and
optimized Python, using verified TLS and actual KV v2 requests. This covers CAS
create/update, lost-reply exact-version reconciliation without another POST,
stale-version rejection, and no-consent/failed-login zero-write negatives. Capture,
account authority and external operation ownership remain synthetic fixtures.
It does not prove installed capture, Core persistence, or browser interaction.

The full Chromium path was attempted in both modes and failed before DevTools
startup in this worker. An independent bounded sandboxed startup probe identified
a denied namespace operation. No sandbox bypass was used. The full chain therefore
has no passing registration/login/relogin/page-action receipt. Cleanup inspection
found no matching fixture processes and no retained fixture directories.

The default Python suite passed 568 tests with 10 explicit opt-in skips; focused
autosave tests passed 25 normal and optimized, and fixture safety passed 4 in both
modes. This is not an aggregate CI qualification: Cargo and the qualified Actions
lane remain unavailable. The built-in SQLite extension case now fails native
qualification closed with a bounded diagnostic instead of an AttributeError;
this does not relax toolchain pins. See `account-openbao-evidence.json` for the
component execution source hashes and remaining qualification boundaries.


## Isolated Strix execution (2026-11-18)

After the cloud startup failure, the exact reviewed source was exercised once on
Strix inside a separately reviewed, unprivileged bubblewrap network/PID namespace.
Both full-flow tests passed in normal and optimized Python: registration, ordinary
login, actual OpenBao save with lost-ack reconciliation, fresh-profile Resolver
relogin, protected page action and readback, plus no-opt-in/failed-login negatives.
The run returned zero, stderr was empty, and no private-output canary was detected.
Post-run inspection found no fixture processes, changed source hashes or changed
input binaries. Fixture files lived only in namespace tmpfs. Extracted official
OpenBao/NSS dependencies were staged without host installation or trust changes.
No sandbox or certificate bypass was used.

`account-strix-evidence.json` records the exact source tree, executable pins,
reviewed launcher hash and sanitized receipt. The final source default Python
suite also passed 569 tests with 10 explicit opt-in skips. This is manual isolated
synthetic evidence, not a GitHub Actions result, installed browser helper,
production Core operation owner, durable recovery or fleet qualification.

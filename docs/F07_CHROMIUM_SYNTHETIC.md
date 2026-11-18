# F07: actual Chromium, synthetic website

This lane extends [the durable synthetic effect acceptance](F07_CHILD15_ACCEPTANCE.md)
with a real sandbox-enabled Chromium renderer. It is a bounded local integration,
not deployed browser automation or live website acceptance. Browser #8 remains
open. Credential and profile integration under #13/#14 is not qualified here.

## Boundary

`browser_testing.chromium_effect_site.ChromiumSite` implements the guarded site
interface using a new disposable Chromium profile and an owned loopback website.
Only the fixed synthetic page, `/submit` and `/readback` routes are available to
its API. Caller payload is data, not JavaScript or a destination URL. Requests
execute in the Chromium renderer with redirects disabled and credentials omitted.
The independent website SQLite ledger, rather than a transport acknowledgement,
is the source of reconciliation evidence. The existing durable journal reserves
an operation before dispatch and does not blindly resend unknown effects.

The constructor fixes the complete synthetic target. Guard checks and actual
page checks reject a changed target or page. This does **not** authenticate the
logical HTTPS origin, account, native session, frame identity or profile custody:
the trusted test fixture explicitly maps that logical target onto plaintext HTTP
loopback. No real credentials, cookies, persistent profile, external website,
model/provider quota or production deployment is involved.

## Isolation and reproduction

The adapter refuses root and a network namespace with any interface other than
loopback. It uses the pinned `/usr/lib/chromium/chromium` executable and never
passes `--no-sandbox`. No namespace or host network configuration is changed by
the adapter or qualification script. The following command creates only a new
bounded namespace and then drops privileges; it does not change the host's
interfaces:

```sh
sudo -n unshare --net --fork sh -c 'ip link set lo up; exec runuser -u "$1" -- "$2" "$3/tools/qualify_chromium_effects.py" --report "$3/docs/chromium-effect-tests.json"' sh "$(id -un)" "$(command -v python3)" "$PWD"
```

Python/SQLite pins reuse `docs/effect-reconciliation-toolchain.json`. Chromium is
156.0.8078.47, executable SHA-256
`32a85cb0cf284adc64c04c4059a9416750b0143488f3d623f0efad81a4aee9e1`.
That executable pin is not a closure of all shared libraries or Chromium data
files, nor the separately qualified Mac browser image.

The runner executes normal and optimized Python in separate workers, requires
zero skips/errors/failures, records exact source hashes, and verifies unchanged
input bytes. Each mode has a 120-second deadline and bounded captured output.
The worker process group is terminated on every exit path, retaining its owned
leader PID until cleanup. Engine contexts own only their fresh profile and
process group, not any user's existing browser. A separate bounded supervisor
watches a parent-held pipe: EOF after a killed owner, engine exit, or its own
30-second deadline kills the engine group. Normal, error and SIGTERM context
exits also remove the profile. A SIGKILL cannot run the owner's cleanup; the
forced-death test's surviving owner removes its private temporary directory.
This distinguishes process containment from hard-kill filesystem cleanup.

Default test discovery does not silently launch a browser. Engine tests require
`RUNSPINDLE_CHROMIUM_EFFECT_TESTS=1`; the qualification worker sets it explicitly
and rejects skips. Default-suite skips are not engine qualification evidence.

## Remaining scope

This does not connect the real engine to the existing Core/Temporal synthetic
Browser lane. Production site-specific DOM interactions, account/frame and
credential authority, profile restoration, live reconciliation, broader H05
acceptance and Browser journal capacity remain separate outstanding work.
Historical aggregate static-quality debt is not waived by passing this focused
lane. See the accompanying exact-candidate report and PR for verified results
and unavailable or failing aggregate checks.

## Verified results

[Exact-source qualification](chromium-effect-tests.json) passed 15/15 tests in
each mode with no skips, failures or errors. This includes six actual-engine
scenarios, three fail-closed prerequisite tests and six HTTP fixture regressions.
The independent ledger proves one accepted effect after lost response and
fresh-process/fresh-engine recovery, no resend on duplicates, and a second effect
when the deliberate reservation-bypass mutation breaks that invariant. Rejection,
wrong-account and ambiguous readback remain distinct; stale guard or changed page
produces zero website calls. A killed owning worker leaves no live engine-group
members in the forced-death regression.

The full default Python suite passed 513 tests in each mode, with six explicit
engine opt-in skips. Those six were separately exercised without skips above.
Existing SQLite ResourceWarnings and use of cryptography 49.0.0 do not establish
the separate preferred crypto wheel closure or clean global diagnostics.

[Static comparison](chromium-static-comparison.json) found 541 diagnostics versus
550 on untouched main, zero added and nine resolved. The older committed debt
baseline still leaves aggregate static quality failing; no baseline or gate was
relaxed. New adapter/tests/harness pass scoped pinned Ruff and strict mypy.

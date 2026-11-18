# Ephemeral dependency suite: partial component lane

This runner is a test foundation, **not full-stack Browser E2E acceptance**.
It does not install dependencies, start upstream daemons, change networking, or
use real accounts. Run it in an already isolated, unprivileged loopback-only
Linux environment:

```sh
python3 -B tools/dependency_suite.py --components --require-full-stack \
  --report /tmp/browser-dependency-suite.json
```

Exit 2 is intentional: full-stack remains blocked. The JSON separately reports
whether the bounded component lane passed. Omit `--components` for inventory
only; omit `--require-full-stack` to run this partial developer lane without
asserting complete dependency integration.

## What executes

Five existing integration suites run in separate normal and optimized Python
workers. The inherited bounded worker supervisor limits runtime and output,
kills its owned process group and joins its reader before returning. Existing
fixtures own temporary databases, directories and loopback listeners. No Docker,
OpenBao, PinchTab or KasmVNC process is started by this runner.

| Surface | Real | Synthetic or missing |
| --- | --- | --- |
| Encrypted profile lifecycle | AESGCM, SQLite, filesystem, crash subprocesses | Key provider and authority |
| Credential/control composition | Resolver, durable local leases | Trusted observations and viewer backend |
| Website effects | HTTP server/client and independent SQLite effect ledger | Site and account semantics, no renderer |
| OpenBao protocol | stdlib HTTP parsing and resolver | Socket/provider responses, no OpenBao server |
| Chromium | Inventory against existing executable hash pin only | Not launched by this lane |
| PinchTab/KasmVNC | Presence inventory only | Product adapters and end-to-end conformance absent |

A binary on PATH is not an integration. A component pass never changes
`full_stack_status` from `blocked`. Existing Chromium qualification remains
separate; this runner does not override its pin, isolation check or sandbox.

## Observed development run

At base `28a2b1e0df8ff390278e2a27e663cacdf7e4c991`, the five component
suites passed **63 tests in each mode**, zero skips. Six reporting/isolation
regressions also passed in normal and optimized Python. See
`dependency-suite-evidence.json` for measured environment and source hashes.

Available development dependencies differ from preferred qualification pins:
cryptography 50.0.0 rather than 50.0.2; installed Chromium executable differs
from the pinned 156.0.8078.47 build. OpenBao, PinchTab and Xvnc were unavailable.
These are explicit blockers, not silently substituted dependencies.

## Remaining all-dependency work

1. Provision exact reviewed upstream binaries/images in an approved ephemeral
   runner without changing host security settings or persistent services.
2. Connect the real OpenBao KV-v2 service to the existing resolver with synthetic
   material and test version/revocation, TLS, cancellation and no-secret output.
3. Implement the PinchTab and KasmVNC component boundaries before claiming their
   healthchecks qualify navigation, exclusive input, drain or handback.
4. Compose credential/profile state, the actual browser, viewer fencing and the
   fake website in one scenario; verify independent effects across restart.
5. Qualify complete startup/failure/cancellation teardown for every upstream.
   The current worker cleanup is not evidence of cleanup for unstarted services.

No persistent services, new credentials, live sites, source deprecation,
production activation or deployment is authorized by this test result.

## Aggregate limits in this development environment

The complete Python discovery ran 532 tests with six explicit Chromium skips and
one existing toolchain-prerequisite error: this interpreter embeds `_sqlite3`
without `__file__`, while `qualify_environment` expects an extension file. The
new 63-test component lane does not invoke that release-toolchain qualification
and reports measured dependencies rather than claiming a pinned image.
New files pass Ruff 0.14.5 checks/formatting and focused mypy. Repository-wide
validation is not green: the default interpreter lacks pinned static-quality
packages and Cargo is unavailable. No baseline, pin or acceptance gate was
weakened to hide these limits.

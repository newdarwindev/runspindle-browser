# Disposable HTTP submission and reconciliation fixture

A test-only Browser #15/#8 lane, not a production browser adapter or deployment.
`browser_testing.http_effect_site.LocalSite` exposes fixed POST `/submit` and
`/readback` routes during one test context. It delegates site acceptance/readback
to the existing independent, deliberately non-idempotent SQLite `effect_site.Site`.
There is no fixture-level deduplication to conceal a journal duplicate.

The listener binds only `127.0.0.1` on an ephemeral port. Its matching test adapter
accepts only that numeric port, not a host or URL, and uses fixed loopback HTTP
with no proxy, redirect, DNS-name or alternate-service fallback. Grant origins
remain invented HTTPS origins under the unchanged runtime validation contract.
The trusted test fixture maps that logical origin to loopback transport; this
mapping does not establish authenticated origin, TLS, browser or frame evidence.
No account, credential, real profile or public network endpoint participates.

Messages use bounded canonical JSON with base64 synthetic payloads (4 KiB), a
16 KiB request/response limit and 1-second socket timeouts. Unknown routes,
absolute request targets, transfer-encoded bodies and invalid lengths deny.
The single server worker owns at most one accepted socket. Socket timeouts are
per read, not a total request deadline: context exit therefore marks stopping,
refuses new accepted work and interrupts the owned socket before shutting down
the server, closing its listener and joining/checking the worker. Both normal
exit (including an already accepted stalled body) and raised test failure are
checked for a stopped thread and refused subsequent loopback connection. The
fixture is disposable test code, not a persistent service or general HTTP server.

## Reproduction and independent observations

Run from the repository root:

```
python3 -m unittest discover -s tests -p test_http_effect_site.py -v
python3 -O -m unittest discover -s tests -p test_http_effect_site.py -v
```

Six tests cover real socket exchange and local SQLite storage with synthetic
trusted guards. HTTP submissions/readbacks are counted separately from committed
site effects, directly queried through the independent ledger:

- Accepted submit with intentionally lost response: journal stays UNKNOWN;
  one HTTP submission, one committed effect. A fresh client process reopens the
  journal, duplicate dispatch sends nothing, and explicit readback confirms:
  final counts **1 submission / 1 readback / 1 effect**.
- A transport ACK also remains UNKNOWN until explicit reconciliation. Rejection
  yields REJECTED only from readback, while dropped submission, wrong-account
  receipt or ambiguous site events remain UNKNOWN. Repeated dispatch does not
  submit again. A separately seeded duplicate event is distinguished from HTTP
  submission counts.
- The existing real local lease store denies a stale holder before any HTTP
  request or effect, then admits the current human holder under synthetic guard
  authority. This is not actual viewer/browser input fencing qualification.
- A private source mutant adds a callback at the journal's duplicate branch.
  It produces **2 HTTP submissions / 2 effects**, making readback ambiguous.
  This proves the non-idempotent fixture exposes duplicate execution rather than
  treating a transport response as exactly-once evidence.

Client-process restart here is a new Python process opening the real journal
following a lost response. It is not a browser crash/restart or OS power-loss test.
The server remains alive only inside the parent test context. Existing runtime,
origin policy, activation gates, dependencies and schemas are unchanged. No live
website-specific reconciliation, distributed authority, encrypted profile/native
session integration, production reliability or full issue acceptance is claimed.

# Stateless passive Browser observation

`browser_runtime.passive_peer.PassivePeer.observe(ticket, expected=target)`
provides a read-only physical observation for the stateless Browser component.
Core's BrowserRegistry owns retained control and transition history. Browser
supplies admitted physical observation metadata.
[H09](https://github.com/newdarwindev/runspindle/issues/16),
[control separation](https://github.com/newdarwindev/runspindle-browser/issues/16),
[external storage ownership](https://github.com/newdarwindev/runspindle-browser/issues/61).

The application supplies the exact selected target and an opaque admission.
The authority must authenticate and consume a `PassiveStatus` ticket under
a guard scoped to that exact selection. The peer checks current permission
before reading the browser and again under the same guard afterward. The
physical browser must independently match the selected principal, account,
browser, tab, native session, frame, top origin, and frame origin. The
application grant binds intent, revision, operation, and epoch. These fields
in a physical browser observation supply no control authority.

`PassiveObservation` contains four fields.

| Field | Meaning |
| --- | --- |
| `selection_sha256` | SHA-256 of the complete selected `Target`, using sorted compact ASCII-escaped JSON. Compare with `selection_digest(current_target)` before applying a response. |
| `scope_sha256` | SHA-256 of the canonical physical scope as used by Core's BrowserRegistry. |
| `observed_at` | Original trusted physical observation timestamp. |
| `checked_at` | Clock sample after successful guard cleanup. |

All timestamps use the guard's trusted monotonic clock domain. Within the same
selection and clock domain, a consumer can use the original observation
timestamp to reject an older result. The checked timestamp records validation
time. Each result is historical upon return and supplies no ongoing liveness
promise, lease, control handle, credential, or permission for a later action.

Missing, future or over-age timestamps, an expired or revoked admission, a
changed physical observation or grant, and guard or cleanup failure deny the
request. Freshness is checked under the guard and again after cleanup. The
default age limit is five seconds. The maximum configurable age is 300 seconds.
Trusted adapters must bound their own blocking calls to the admission deadline.
The peer reports fixed denial and cancellation categories without leaking adapter
exceptions or retrying. Its authority port exposes only passive admission,
currentness, and physical observation. It opens no database, sockets, or
subprocesses.

## Local evidence

```sh
python3 -m unittest discover -s tests -p test_passive_peer.py -v
python3 -O -m unittest discover -s tests -p test_passive_peer.py -v
```

Scripted admissions and physical observations verify selection changes,
wrong account/origin/frame/session, missing and stale observations, revocation,
cleanup delays, and cancellation. The tests count read and forbidden control
calls and detect the deliberate removal of the physical-scope check. The
component lane uses no real browser, viewer, provider, or retained lease store.
Authenticated application wiring, native desktop streaming, and the H09
composition pin and integration gate still need separate evidence.

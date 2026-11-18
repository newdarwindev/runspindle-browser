# Application-owned effect pipe endpoint

`effect_pipe.serve_once(reader, writer, receiver, ticket)` adds one framed exchange
to the unchanged Browser effect wire. It launches nothing and stores nothing.
The application supplies both a trusted Receiver/GuardedPeer and an opaque
one-shot authority ticket separately from the request bytes.

Framing is a four-byte unsigned big-endian length followed by exactly that many
bytes and EOF. Request bound is `2 * 1048576 + 8192`; response bound is 4096,
matching Core's existing codec. The parent must close child stdin after its
request, and accept only one complete response followed by EOF and exit status
zero. The child application must close output and exit nonzero when `serve_once`
returns false. No raw exception or stderr logging is added.

The owning Core process must commit its canonical reservation before launching
this exchange. It must supervise a total deadline, terminate/reap the process
group on failure, and retain unknown on partial I/O, cancellation, lost response
or nonzero exit. The endpoint's blocking reads are not independently timed: it
is only for this bounded application-owned pipe, not an arbitrary network socket.
No wire data may mint authority or choose adapters, credentials or executable.

Seven normal/optimized component tests cover actual Receiver execution with
synthetic authority, no SQLite construction, truncated/oversize/trailing frame
rejection before effects, partial I/O, external ticket denial and redacted
cancellation. The Rust OwnedChildPeer counterpart and cross-process execution
are separate qualification work; these BytesIO tests do not claim production
transport, actual Core-backed recovery, Actions CI or native E2E acceptance.

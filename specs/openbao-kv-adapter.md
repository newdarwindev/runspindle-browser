# Bounded OpenBao KV-v2 adapter

Partial browser #13/#6. Original Python stdlib implementation, not the historical
resolver port tracked by #3. No actual OpenBao endpoint or real credential was used.

## Protocol and configuration

Protocol reviewed against the official [OpenBao KV-v2 API documentation](https://openbao.org/docs/api/secret/kv/kv-v2/),
[pinned documentation source](https://github.com/openbao/openbao/blob/92de51f7a0586759215d299bc79118874ea54fb1/website/content/docs/api/secret/kv/kv-v2.mdx)
(blob a9988500aa060361c1dfd5fc40051cc13c4c700a). No upstream implementation copied.
Supported subset: GET /v1/{mount}/data/{path} reads latest data; nested data.metadata
contains version, deletion_time and destroyed. GET /v1/{mount}/metadata/{path}
returns current_version and versions indexed by decimal version string. All calls
require HTTP 200. Deny missing/malformed/duplicate JSON fields, boolean versions,
deleted or destroyed entries and any current-version change. Any nonempty deletion
time is conservatively denied, including future scheduled deletion. Missing fields,
KV-v1 envelopes, redirects and denial/outage responses have no compatibility fallback.

Trusted construction supplies a fixed HTTPS origin, mappings from principal/account/
top-origin/frame-origin/reference to mount/path/field, token callback and independent
current-grant authorization callback. No mapping or authority is discovered from
page/agent input or environment variables. Paths accept bounded safe segments only.
The verifier defaults to absent/deny, must authenticate the complete Grant including
native session, frame, operation and epoch, and must not merely trust its shape.
Both token and HTTP effects follow scope and authority checks. Token callback is
followed by another authority/deadline check. Tokens are never placed in URLs.

`HTTPS` uses verified TLS, a direct stdlib connection, no proxy discovery, redirect
following or retries. It bounds body bytes to 64 KiB and socket inactivity to at most
10 seconds (default 2), further bounded by remaining grant time. DNS and trusted
callbacks do not have a hard total timeout in this implementation; trusted composition
must supply those execution bounds. Expired return values are rejected. The concrete
transport is an internal trusted helper dependency, not an agent-facing API; Vault
sanitizes its exceptions before returning an outcome.

### HTTP body framing

Reject header-parser defects rather than treating hidden framing fields as an
EOF-delimited response. A present Content-Length must be a single ASCII decimal
value no greater than 64 KiB; duplicate or comma-joined lengths deny even when
equal. The received body must contain exactly that many encoded bytes, not Unicode
characters. A complete JSON object inside a prematurely closed length-framed body
still denies. A zero length means an empty body, never an EOF fallback.

Transfer-Encoding is admitted only as one case-insensitive `chunked` value without
Content-Length. Other codings, duplicate fields and conflicting framing deny
before the body read. When neither framing header is present, the existing
close-delimited response behavior remains. The bounded `MAX_BODY + 1` read detects
oversized bodies in each mode; the connection closes after one response without
retry or interpretation of bytes beyond a declared body as another response.
Cleanup explicitly closes the returned response file as well as the connection:
the stdlib may already have detached a close-delimited response from its connection
before returning it. A rejection must not leave that file open through a traceback.
Both close operations are attempted. An ordinary cleanup error denies an otherwise
valid response with a fixed error category and does not mask a prior framing error;
failed cleanup is not reported as successful resource release.

The connection selects a narrow stdlib HTTPResponse subclass whose `_safe_read`
guard rejects negative or oversized read requests before reading the underlying
buffer. This prevents a negative chunk size accepted by the stdlib integer parser
from becoming an unbounded `read(-1)`. The stdlib still owns HTTP/chunk parsing;
this is not a replacement parser. Tests qualify the private hook on CPython
3.12.14, so other interpreter/toolchain versions need the same qualification.
No dependency or runner-toolchain pin is changed by this fix.

This does not claim complete RFC syntax enforcement: the retained stdlib parser
is permissive about some chunk delimiter bytes and final trailer termination.
The body limit is not a total wire-byte, trailer-count or wall-clock limit. DNS,
socket inactivity and trusted callback limits remain as described above. Error
sanitization is provided by Vault/Resolver, not by exposing this internal
transport's raw exceptions.

## Handle lifecycle and helper contract

`Vault.read/current/release` implements the existing resolver protocol. Handles carry
no plaintext fields and are accepted only by identity in their creating instance.
At most 128 handles are retained. Secret field size is limited to 16 KiB. Grant deadline
bounds handle usability only, not OpenBao credential retention or server TTL.
`current` re-reads metadata; failure removes the handle. `consume` re-reads metadata,
checks grant, removes the handle before calling the trusted helper sink, and never
retries an uncertain sink effect. `release` is idempotent; `forget` clears all local
entries. Resolver always releases its returned handle. Direct trusted callers must
release on abandonment or forget on teardown; no background sweeper is installed.
Process restart loses handles and does not authorize replay. No durable credential
store or remote secret deletion is implemented.

The sink is a pinned trusted injection helper running under the existing atomic
browser/lease fence. It alone receives plaintext. Metadata reread is not an atomic
remote rotation fence: rotation after observation remains possible. Production use
requires the missing authority, browser fencing and version/use policy integrations.
Callbacks must be bounded and non-reentrant. The process lock serializes handle
operations but is not isolation from malicious in-process Python. Dropping references
is not memory zeroization; privileged debugging/traceback locals remain outside scope.
No raw exceptions, response bodies or secrets belong in receipts/logs/screenshots.

## Evidence

Tests exercise actual request construction, JSON decoding, metadata transitions,
real Resolver composition and handle lifecycle with synthetic byte transport and
synthetic authority/injection seams. HTTPSConnection is replaced by a scripted peer
while the actual HTTP client method is exercised; no socket or live endpoint runs.
Independent HTTP/token/injection observations cover wrong scope, denied authority,
revocation during callback, late response, redirects, malformed data, rotation,
deletion, expiry, forget, uncertain use and one-shot consumption. Canary scans cover
public result/error/traceback/output; a deliberate authority bypass violates the
independent zero-HTTP invariant. Native provider interoperability, TLS/DNS integration,
Core/Host authority, production deployment and full issue acceptance remain blocked.

Run `python3 -m unittest discover -s tests -p test_openbao.py -v` and the optimized
variant, then the repository validation command. Missing Cargo remains a failed gate,
not a skip or a synthetic substitute.

The framing regressions in `tests/test_openbao_http.py` feed invented HTTP bytes
through the configured response class and real stdlib parser over in-memory
buffers. Actual HTTPConnection request/getresponse tests separately exercise
detached-response cleanup without coupling socket close to file close. Tests
record underlying byte reads, connection closure and independent
injection effects; network calls are forbidden. Read, current-version validation
and consume each reject truncated replies without a remaining handle or injection.
Deliberate framing and private-read guard mutations violate the corresponding
zero-effect and bounded-read observations. These tests do not qualify TLS, sockets,
OpenBao interoperability or real authority. Commands and hashes are recorded in
[the framing evidence](../docs/openbao-http-framing-evidence.json).

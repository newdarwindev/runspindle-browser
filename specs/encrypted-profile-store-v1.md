# Local encrypted checkpoint BLOB store

This is an original Python component slice of Browser #14/#7, using the existing
Python runtime and SQLite stack. It implements real authenticated encryption and
persistence, not the separate synthetic lifecycle model. It does **not** implement
browser directory capture/restoration, production custody, trusted observations,
distributed fencing or full issue acceptance. Browser #13 remains an integration
dependency. No live data, provider, account, deployment or backup is used.

## Trusted API and supported boundary

`browser_runtime.profile_store.Store(directory, adapters).run(ticket)` accepts
only an opaque admission ticket. Its trusted, pinned composition root supplies
`Adapters(authority, keys, io)`. There is no environment discovery, default key,
network client, browser launch, CLI activation or usable fallback adapter.
`Grant` carries the existing `credentials.Target`, profile ID, action (`save`,
`restore`, `forget`), opaque checkpoint reference and authority deadline. Every
operation validates the exact Target and fresh authenticated observations under
the same guard. All identifiers are opaque routing metadata, not secret values.
Saving or restoring a cookie does not authorize any website action.

The shared Grant vocabulary also recognizes an explicit `discard` action for
the separate MaterializedStore directory component. Base Store rejects that
action without key/IO calls or ciphertext changes. Only that combined component
may return `discarded`; it binds the reference to an exact materialized generation
rather than a checkpoint. See [the discard contract](profile-discard-v1.md).
Existing ticket producers must not infer or reuse authorization for this action.

The authority guard must actually authenticate admission and atomically maintain
current principal/account/origin/session/browser/epoch and browser quiescence
until exit. Its `current`, `quiescent` and `observe` methods are trusted adapter
code, not caller booleans. Their results must be mutually consistent under that
atomic guard. Sequential checks cannot make a dishonest guard safe or substitute
for a real browser fence. Time is sampled after those callbacks so blocking work
does not preserve an earlier freshness/deadline observation. Checks repeat after
writer lock acquisition, key acquisition, capture/decryption/consumption and
before store commit. Path identity checks repeat with those checks.

Only `io.capture` and `io.consume` handle plaintext. They run under the trusted
guard and the local writer lock; `consume` must independently honor the guard.
No database column contains plaintext. No returned object or receipt exposes
plaintext or ciphertext.
The result is a fixed `stored`, `delivered`, `unknown` or `forgotten` string.
A successful consumer result means that callback completed, not that a real
browser directory was atomically restored or website authority resumed.

## Storage, account and authenticated-data binding

The store accepts one pre-provisioned POSIX directory owned by the process UID
with mode 0700. It never changes existing permissions. It uses only the fixed
`profiles.sqlite3` and SQLite's `profiles.sqlite3-journal`; files must be regular,
mode 0600, single-link and owned by that UID. Symlink directory components, file
symlinks, hardlinks, unexpected files, relative paths and `..` are rejected.
Directory/database inode replacement is checked at each operation boundary.

This is a private local filesystem contract with cooperative exclusive API use,
not a defense against malicious same-UID code, root, an attacker replacing
ancestors during a check/open race, or unsupported network filesystem locking.
SQLite opens filenames rather than a supplied preopened descriptor. The actual
lifecycle owner must prevent namespace replacement. No archive paths or browser
file paths are ever accepted, and the store creates no plaintext temporary files.

`profile_schema` assigns application ID `0x52425053` (RBPS), schema version 1 and
an exact seven-table/index inventory. Only an empty unclaimed file can initialize;
unknown identities, versions, schemas and failed integrity checks deny, without
migration, salvage or schema repair. SQLite may recover its own hot rollback
journal before exact admission under `BEGIN IMMEDIATE`; therefore rejected or
crashed stores do not have a universal byte-preservation promise. A forced-spill
crash test exercises this real recovery path. Metadata requires one valid store
UUID. Corrupt ciphertext is rejected by authenticated decryption.

Profile identity is canonical JSON of `[principal, account, profile]`. Its scope
also includes the exact top-level and frame origins; it cannot change scope in
place. Forget tombstones the identity, so changing origins cannot recreate it.
AAD is canonical ASCII JSON of:

`["runspindle.profile.aes256gcm.v1", store_uuid, scope, checkpoint_reference, key_version]`

`scope` is the canonical JSON string `[identity, top_origin, frame_origin]`, where
`identity` is itself that canonical JSON string. This nested representation is
intentional and versioned. Current browser/session/epoch is **not** stored in AAD:
fresh authenticated admission may use a retained checkpoint in a new session.
Changing the account, origin, checkpoint reference, store UUID, key version,
nonce or ciphertext cannot silently retarget decryption.

## Keys and nonce lifecycle

The mandatory library is PyCA `cryptography`; encryption uses its `AESGCM` API
with a 32-byte random key, 12-byte nonce and full 16-byte tag. No algorithm, KDF,
password encryption or crypto primitive is implemented here. Plaintext is
nonempty and capped at 16 MiB, and ciphertext length is bounded before decryption.

The injected key provider receives the store UUID, full grant and optional
immutable key version. It must authorize the scope, keep key custody valid until
context exit and use a distinct key namespace for every independent store UUID.
It must not use a password/credential as a key. No real provider is implemented.
Tests deliberately use a public deterministic test key, not a provisioning recipe.

Each version is permanently bound to SHA-256 of its actual 256-bit key material.
An existing version returning different material denies before capture/decryption.
Version aliases with identical material share one nonce namespace. A random
nonce is inserted into a unique `(key_fingerprint, nonce)` ledger and committed
**before** encryption. A collision denies; there is no hidden random retry.
Failure or cancellation after reservation burns it permanently. Reservations and
version mappings survive forget and have no retention TTL. The fingerprint is
internal store metadata and must not be projected publicly.

A key provider may rotate to a new immutable version for later saves. It must
retain separately authorized old versions for retained checkpoints or deny those
restores. No broader-key or latest-key fallback exists. Missing/revoked keys
block access without deleting ciphertext. Reusing keys in independent stores,
copying/reverting a database or restoring an old store snapshot breaks the
monotonic nonce/fencing assumptions and is unsupported. Store UUID in AAD alone
does not solve global nonce uniqueness or rollback attacks. Production custody,
key rotation/destruction and rollback-resistant storage require separate review.

## Transactions, writer fencing and uncertainty

The new store uses DELETE rollback journaling, `synchronous=EXTRA`,
`secure_delete=ON`, `temp_store=MEMORY` and `trusted_schema=OFF`, with readback of
settings. Existing effect-journal behavior is unchanged. SQLite writer acquisition
has a 200 ms timeout; timeout denies. `BEGIN IMMEDIATE` serializes cooperating
processes across callbacks. No claim of actual power-cut, kernel, firmware or
network filesystem durability follows from subprocess crash tests.

Persisted profile ownership is native-session/browser identity plus lease epoch.
A different owner requires a strictly newer epoch; all older epochs deny. The
actual authority guard must authenticate epochs: passing a larger integer is not
permission. Ownership and nonce reservation commit before capture; owner/epoch,
scope and tombstone are rechecked after acquiring the second writer transaction.
Checkpoint references are globally unique and immutable; an opaque reference
ledger commits with ciphertext and survives forget to prevent reuse under a new
profile. All saved checkpoints
remain retained until explicit profile forget. There is no TTL, automatic eviction
or overwrite of an older checkpoint.

All callbacks must be bounded, synchronous and non-reentrant. The instance lock
is nonblocking: same-instance recursive run/close denies immediately. Recursive
access through another instance/process times out on SQLite instead of waiting
indefinitely; tests observe zero nested capture. A trusted callback that catches
that denial can still finish its outer operation. The component cannot impose a
total timeout on arbitrary trusted Python callback code.

Restore records the exact operation/binding as `unknown` and commits **before**
key access/decryption/consumption. A repeated admitted identical operation returns
its stored status without re-running the consumer. It remains unknown after key
failure, corruption, cancellation, rejected consumer output or a crash during
consumption. Even failures known to occur before consumption are conservatively
burned; there is no automatic retry or reconciliation implementation. A distinct
operation is not a retry authorization: Core must reconcile and authorize it.
Only explicit successful consumption plus a fresh guard check can commit
`delivered`. A crash after consumption but before that commit remains unknown.

Context-manager cleanup can fail after a commit. The public result then denies
or raises sanitized cancellation; this does **not** mean the commit rolled back.
A saved checkpoint stays saved and a terminal restore marker stays delivered.
All ordinary/cancellation error categories are fixed, raised outside the original
handler, and do not retain upstream exception cause/context. This is not Python
memory zeroization, protection against debugger/local-variable capture, swap or
process core dumps. Suppressing guard/key contexts cannot synthesize success.

### Cleanup failure and instance lifetime

Rollback cleanup preserves cancellation precedence: a cancellation from the
operation, transaction-state inspection, rollback or attempted close produces the
fixed `Cancelled` category even when a later ordinary cleanup error occurs.
Ordinary cleanup failure produces fixed `Denied`, never a successful result.
A failure inspecting transaction state or rolling back marks this Store instance
unusable before attempting connection close once. Later `run` calls deny before
acquiring authority or invoking key/capture/consume callbacks; later `close` calls
are no-ops. The failed rollback and uncertain close are never retried. Explicit
`close` also marks the instance unusable before touching the connection and
sanitizes its failure/cancellation. Successful rollback leaves the instance usable
under fresh ordinary admission.

This fence is process-local instance state, not a durable poison marker. A failed
close may leave the underlying connection, transaction or lock alive; the component
does not claim successful resource release. It must not be interpreted as permission
to open another instance or replay uncertain consumption. Existing committed
checkpoint, nonce and restore records remain authoritative: a failure reported
after commit does not undo the commit. Reopening still requires the existing
trusted construction/admission and uncertainty rules. No new salvage, retry,
recovery authority, browser operation or storage format is introduced.

`tests/test_profile_cleanup.py` covers real temporary SQLite with synthetic
adapters and fault wrappers. It separately checks pre/post-rollback faults,
transaction-state inspection, close failure, cancellation precedence, no later
adapter acquisition, successful rollback reuse and retained committed/unknown
records. Deliberate cancellation-loss and closed-admission mutations must fail the
independent assertions. Run `python3 -m unittest discover -s tests -p
 test_profile_cleanup.py -v` (without the line break), and repeat with `python3 -O`.
On macOS, set `TMPDIR=/private/tmp` so synthetic temporary directories do not traverse
symlink ancestors; the production path checks remain unchanged. This evidence is
not live browser, production custody, power-loss or runtime-image qualification.

## Precise logical forgetting

Fresh authorized profile forget atomically deletes every checkpoint row for the
selected principal/account/profile and writes a terminal tombstone. It does not
call the key provider, consumer, credential deletion or any website. Other
accounts remain intact. Repeated fresh authorized forget is idempotent; old
checkpoint references and re-saving the forgotten profile ID stay denied. New
profile enrollment must use a separately authorized new profile identity.

Nonce/version/reference histories, minimal tombstones and restore-uncertainty records stay
retained to preserve safety. This is logical deletion of this store's retained
ciphertext, **not** physical-media erasure, key destruction, deletion of copies or
backups, live profile cleanup, browser termination or remote logout. SQLite's
secure-delete setting does not establish those properties. External copies and
live browser directories require a separately explicit inventory/integration.

## Dependencies and reproducible component evidence

`requirements-profile.txt` records preferred cryptography 50.0.2, cffi 2.1.1 and
pycparser 3.0 wheels for CPython 3.12 / Linux x86_64. Hashes were read from the
[official cryptography metadata](https://pypi.org/pypi/cryptography/50.0.2/json),
[cffi metadata](https://pypi.org/pypi/cffi/2.1.1/json) and
[pycparser metadata](https://pypi.org/pypi/pycparser/3.0/json) on 2026-11-15.
No wheel was downloaded, installed or vendored. Runtime dependencies have their
own Apache-2.0 OR BSD-3-Clause, MIT-0 and BSD-3-Clause license metadata; no new
project-wide license is asserted. Qualified runner provisioning is unchanged.

Run `python3 tools/check_profile_store.py` for the preferred exact dependency gate
and tests. Missing/mismatched dependencies fail explicitly, never skip tests.
On the presently installed 50.0.0 environment, use the deliberate compatibility
command `python3 tools/check_profile_store.py --compatibility`; it records actual
Python/SQLite/OpenSSL/package versions and runs the tests normally and under
`python -O`. That evidence does not qualify the preferred lock or a runner image.
The existing aggregate unittest discovery includes these mandatory tests, so an
unprovisioned lane fails rather than silently reporting success.

Tests use invented identities/canaries, real encrypted SQLite files, independently
observed capture/key/consumer counts and subprocess death. They cover durability
boundaries, forced hot-journal recovery, competing processes, scope/ciphertext/key
corruption, ownership epochs, nonce reuse through version aliases, terminal
forget, cancellation/cleanup, suppression and bounded reentrancy. Plaintext scans
include temporary store files and consumer markers (which hold only test digests).
A deliberate authentication-bypass mutation makes the independent consumer spy
observe a forbidden callback, proving the negative assertion is meaningful.
Network connection attempts are denied in the component tests and subprocesses;
no runtime adapter opens a connection or listener.

Primary design references: [PyCA AESGCM](https://cryptography.io/en/50.0.0/hazmat/primitives/aead/),
[release changes](https://cryptography.io/en/50.0.2/changelog/),
[SQLite transactions](https://sqlite.org/lang_transaction.html),
[SQLite durability and deletion settings](https://sqlite.org/pragma.html).

## Observation-discovered revocation

Each profile check retains fast current/quiescent denial before observation and
rechecks both immediately after `observe`, before sampling the clock. A matching
target observation is not proof that the guard remains current or the browser
remains stopped: observation can discover lost authority or a resumed writer.
Neither key acquisition, plaintext capture/consumption nor directory metadata
publication may cross that known loss merely because a later check would deny.
Time is sampled after the second callbacks, so their delay cannot preserve an
expired admission or stale observation. This is not universal TOCTOU immunity;
trusted bounded callbacks and an atomic, coherent guard are still required.

`tests/test_profile_observation_fence.py` exercises invented guards and keys with
real temporary SQLite/filesystem state. Negative effect spies cover key reads,
capture, consume, directory claim and candidate publication. Lost authority after
candidate rename leaves BUILDING pending without publishing CLEANUP; only fresh
admission recovers it. Source mutants deleting either post-observation gate fail
the corresponding independent effect assertions. This is local synthetic
component evidence, not browser/provider/distributed authority qualification.

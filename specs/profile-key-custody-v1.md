# Local profile-key custody leases

Original bounded component work for Browser #14, building on #13's reviewed
OpenBao transport. Real SQLite/process fencing and version-specific key parsing;
synthetic accounts and material only. No production provisioning, credentials,
provider activation, browser authority or complete issue acceptance is implied.

## Separate authority domains

`profile_keys.Keys` implements the existing `profile_store.Keys` protocol.
The pinned trusted composition root is its only caller, under the Store's existing
authenticated authority/quiescence guard. A matching Grant is not authentication.
No model-facing API, discovery, fallback, default provider or service is installed.
The browser guard's account/origin/epoch/revocation and deadline checks are
unchanged. A profile-key lease cannot preserve revoked browser authority.

This is a separate key-custody domain, not `openbao.Vault` or a credential handle.
R05/A04/P03 in credentials-handoff retain their credential rotation/deletion
invalidation requirements. The encrypted-store specification permits separately
authorized retained key versions; the custody rule below applies only to this
explicit adapter. Existing credential latest-version behavior is unchanged.

Custody admission is non-retroactive: an issued local lease remains valid through
its operation context. `revoke(key_id)` returns `new-leases-disabled` only after
committing a terminal local disabled bit. It prevents new leases; it neither
cancels issued leases nor deletes a key, credential, profile or website session.
A revoked/missing key denies a new acquisition without deleting ciphertext.
Remote OpenBao deletion/rotation may deny subsequent fetches but cannot erase
already admitted local bytes. No immediate remote-invalidation claim is made.

The administrative method is trusted internal code, not self-authenticating from
the key ID. Its invocation requires separately authorized administrative intent;
ordinary save/restore/forget never calls it. There is no re-enable method.

## Immutable registry and unsupported enrollment

The caller supplies an absolute, pre-provisioned POSIX directory and the expected
SHA-256 manifest digest. Neither database nor schema is created at runtime. The
fixed `custody.sqlite3` and `lease.sqlite3` files must already exist. Unknown schemas,
application IDs, versions, corrupt metadata or manifest mismatches deny without
migration, repair, enrollment or salvage. SQLite may perform its own journal
recovery; rejection is not a promise that recovery made no disk writes.

Registry records bind store UUID, principal/account/profile, exact top and frame
origins, safe mount/path/field segments, one positive numeric KV version, expected
key fingerprint and a fixed save-key flag. Canonical JSON SHA-256 is the immutable
Store key-version identity. The external manifest digest pins all immutable
records; disabled bits and attempt state are the only runtime mutations. Secrets
and tokens are absent. At most 256 records and one save key per scope are accepted.
No caller-controlled URL/path/version alias is interpreted. Restore selects an
exact registered key ID; save selects the one configured save key or denies.

The whole registry rejects duplicate fingerprints, duplicate remote material
coordinates and ambiguous save selections, even across independent store scopes.
This intentionally rejects aliases more strictly than Store's nonce ledger.
Every independent store in this local custody domain must share this registry.
Cross-domain key uniqueness cannot be discovered here: the external provisioner
must prevent reuse across registries. Copied/reverted registries or profile stores
are unsupported. A manifest digest is an integrity pin, not proof of authorization
unless the trusted root independently pins the intended registry.

A reviewed external provisioner must establish random 256-bit key provenance and
namespace ownership. Length/fingerprint checks cannot prove entropy. No production
enrollment tool, key generation, token provisioning, rotation or deletion API is
provided. `browser_testing/profile_keys_fixtures.py` creates only invented temporary
registries using public test bytes; it is not a production provisioning recipe.
Changing a registry or rotating its manifest requires separate review/integration.

## Real local serialization and durable attempts

Two databases are necessary. `lease.sqlite3` holds a `BEGIN IMMEDIATE` writer
transaction for the entire key context, serializing cooperating local processes.
It contains only an exact singleton fence schema. Same-instance recursive acquire
denies immediately; other process/instance contenders time out after 200 ms.

`custody.sqlite3` uses short independent `BEGIN IMMEDIATE` transactions. Thus an
administrator can commit disablement while another process owns an issued lease.
Constructor validation uses a read transaction on the fence database, so an
administrator need not have constructed its adapter before that active lease.
Acquisition ordering is Store lock, lease writer, then short admission writer;
revocation takes only the admission writer and never calls back into Store.

The attempt identity is SHA-256 of the store UUID and full canonical authenticated
Grant attempt. Deadline renewal does not generate a new identity. No separate
caller-supplied lease ID or retry token is accepted. A different operation still
requires fresh authenticated admission; it is not automatic retry authority.

1. Validate scope/action/version/deadline and obtain the real lease writer lock.
2. Under the admission transaction, verify the pinned registry and enablement;
   mark unfinished predecessors abandoned and insert a unique pending attempt.
   Commit before token or provider effects. Existing attempts cannot be replayed.
3. Recheck the gate before token retrieval and again after the token callback.
   Perform one exact-version GET, with no retries, then validate the response.
4. Recheck gate and deadline in another admission transaction and durably set
   the attempt to issued. This commit is the custody-admission boundary.
5. Yield the validated key while retaining the lease writer lock. Store separately
   checks current browser authority/deadline before its effects.
6. Drop internal references, mark the attempt released and close the lease
   connection on success, failure and cancellation. Released means custody ended,
   not that an external operation succeeded. Cleanup failure denies; it cannot
   roll back a Store commit or consumer effect that already happened.

Disablement before issuance prevents delivery, including while a fetch is in
flight. An already admitted pending fetch may complete after a concurrent disable;
its response still cannot issue a lease. There is no atomic remote request-cancel
claim. Disablement after issuance blocks later leases, not this operation.

A crash releases the process lock. A later lock holder can mark unfinished rows
abandoned because that exclusive lock proves no cooperating predecessor remains
active; the old attempt remains burned. No PID-liveness heuristic, expiry-based
reclaim, replay, timeout reaper or background job exists. Restoration uncertainty
continues to be recorded by Store before key acquisition.

Both databases use DELETE journals, `synchronous=EXTRA`, `secure_delete=ON`,
`temp_store=MEMORY`, `trusted_schema=OFF`, exact schema inventory and integrity
checks. Directories must be owned 0700; files/journals owned single-link regular
0600 files. Symlinks, unexpected files and inode replacement deny. Runtime never
changes permissions. This is cooperative local filesystem/process serialization,
not hostile same-UID defense, distributed fencing or rollback-resistant custody.
Forking while holding an active lease or using inherited SQLite connections is
unsupported; subprocess tests start fresh processes and fresh adapters.

## Material source and privacy

The existing reviewed `openbao.HTTPS` remains the transport, with its strict body
framing, verified TLS, bounded bodies, no redirects/proxy discovery/retries and
connection cleanup. The new reader uses its strict JSON helpers and rejects
malformed/duplicate envelopes, non-200 status, noncanonical base64, wrong sizes,
wrong fingerprints, boolean/wrong versions and deleted/destroyed versions.
The fixed request is `GET /v1/{mount}/data/{safe_path}?version={positive_integer}`.
It never retrieves a credential and reinterprets it as an encryption key.

This exact-version GET follows the [OpenBao KV-v2 API](https://openbao.org/docs/api/secret/kv/kv-v2/).
The existing credential adapter still reads latest and validates current version;
its implementation and tests are unchanged. A fixed-version response need not be
the latest remote version, provided the independent profile-key registry admitted
that exact version. No latest/broader-key fallback exists.

No key/token/raw envelope is persisted, logged or returned to orchestration.
`Key` is yielded only to the trusted Store internals. Public errors are fixed,
without original exception cause/context. Cancellation remains a distinct fatal
category. Python bytes, debugger locals, swap and core dumps are not securely
erased; reference release is not memory-zeroization proof.

All callbacks remain bounded, synchronous and non-reentrant. Socket inactivity
and remaining-grant limits do not bound DNS or arbitrary trusted callbacks.
Deadlines are checked after callbacks and before/after issuance/use, but there is
no hard wall-clock termination guarantee. No watchdog or service is installed.

## Reproduction and limits

Run `python3 -m unittest discover -s tests -p test_profile_keys.py -v`, then the
same command with `python3 -O`. Run the existing full unittest discovery, scaffold
and aggregate validators. Mandatory Store crypto dependencies must be present;
no installation or successful skip substitutes for missing dependencies.

Tests exercise real metadata files, cross-process contention, subprocess death,
revocation races, burned replay, fixed-version HTTP parsing, real AES-GCM Store
roundtrip and precise forget. HTTP payloads, authority and key material are
synthetic; actual sockets are denied. A deliberate disabled-gate mutation permits
one key delivery that the ordinary revocation test forbids.

Production registry enrollment, real workload authentication, live OpenBao
interoperability, browser observations, hard callback preemption, physical erasure,
rollback resistance, qualified images and complete #13/#14 acceptance remain
unqualified. See the separate evidence record rather than earlier source hashes
for this slice. Nothing enables a service, scheduled job, backup or deployment.

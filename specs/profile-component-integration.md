# Local-only profile component composition

This bounded integration joins the original runtime bytes from held Browser
PR #30 and PR #31 in one synthetic fixture. It does not authorize either merge,
publication of this integration, production activation, or issue completion.
The public branches remain separate. No new production runtime behavior or
browser-authority protocol is introduced.

## Constituents and real boundary

Directory runtime, its existing tests and specification match public PR #30 head
`65514e5a7c76d9404d3a90bbdfb7e3a5d9f4e9d3` byte-for-byte. Custody, Store and their
existing tests match PR #31; its latest documentation-only head is
`bec69b3de7c9f3ad9829dc96b39988305d7abf20`. The original independently reviewed
custody source is unchanged by its later evidence-only commits.

The new fixture composes `MaterializedStore`, `DirectoryProfileIO` and
`profile_keys.Keys`. SQLite transactions, custody process locking, AES-GCM,
descriptor-relative filesystem capture/materialization and fsync are real.
The existing test authority, admission ticket, identities, provider replies and
key bytes are synthetic. Direct synthetic directory seeding and registry creation
are test preparation only, not new production enrollment APIs.

Independent test receipts count provider fetches, issued custody contexts,
directory preparations, capture/consumer calls and plaintext-write crash points.
Assertions inspect actual files, generations, store/custody metadata and canary
presence. Scans cover raw/base64 profile canaries, raw/base64 keys and tokens;
an explicit probe verifies detection of an unencrypted canonical bundle. Fixed
markers contain no keys, cookies or raw provider responses.

## Semantics exercised

- A complete real directory save/restore roundtrip retains empty entries and
  replaces old bytes. No plaintext canary appears in ciphertext or custody stores.
- Disabled custody denies fresh decryption/materialization. The wrapper may first
  prepare/recover an already existing private tree under fresh browser authority.
  Recovery writes are not mislabeled forbidden new materialization or key access.
- Disablement during a provider fetch denies issuance and consumption. Disablement
  after issuance permits the already-admitted lease to finish, while later leases
  deny. Browser authority loss after issuance still prevents consumption.
- Process death during pending/issued key acquisition leaves the Store restore
  unknown. Repeating that operation performs only directory preparation, not
  another provider read or plaintext-consumer call.
- Crashes in BUILDING, after a plaintext write and after CLEANUP publication can
  leave private plaintext until recovery. With custody disabled, repeated unknown
  restore repairs the old/new existing generation without decryption or replay.
- A crash after the ciphertext tombstone but before directory forgetting leaves
  an explicitly partial state. Restore is rejected before any directory
  preparation or provider/key effect. Fresh forget completes cleanup without keys.
- Ordinary errors and cancellation during plaintext writes release custody,
  retain restore uncertainty and do not leak canaries through public errors.
- A deliberate enabled-gate bypass allows forbidden real materialization after
  fetch-time disablement; the independent consumer count and actual file bytes
  expose that mutation. The normal case observes zero consume and retains old bytes.

Lock order remains the existing Store writer followed by custody and directory
locks, except the wrapper's separately completed preparation phase. Revocation
uses only the custody admission database; forgetting never acquires a key.
No new lock order or background recovery service is installed.

## Reproduction and limitations

Run `python3 -m unittest discover -s tests -p test_profile_integration.py -v`
and repeat under `python3 -O`. Existing constituent and full tests remain required.
All subprocesses are fresh synthetic test processes; network connects are denied.
No live browser/profile, OpenBao service, credential, backup, system setting,
installation, deployment or public branch operation is part of these tests.

This local integration's crypto evidence uses the installed 50.0.0 compatibility
environment. Prior separate custody preferred-50.0.2 checks do not qualify this
new integrated suite. Real authenticated browser authority, browser compatibility,
physical erasure, rollback resistance, distributed fencing, required CI and
runner-image/fleet qualification remain separate and unclaimed.

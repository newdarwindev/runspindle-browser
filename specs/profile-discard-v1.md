# Explicit plaintext discard with retained checkpoints

An original, bounded source/component extension of Browser #14, dependency-held
on the directory component. No real browser, profile, provider, deployment or
backup is used. Custody/composition and full issue acceptance remain separate.

## Separate authority and exact target

`MaterializedStore.run(ticket)` accepts a separately authenticated `discard`
operation, returning `discarded` only after contained cleanup, durable empty
READY publication and final authority checks. This is a new operation capability,
not another spelling of `save`, `restore` or permanent `forget`. Grant producers
must explicitly support and authorize it; existing approvals/tickets must never
be reinterpreted as discard permission. Base `Store` recognizes the action but
rejects it without a key call, IO callback or ciphertext deletion. The directory
helper alone remains trusted internal code, not an alternative admission route.

The reference has operation-specific semantics: save/restore select an opaque
checkpoint reference; discard selects the **exact current generation**, a
32-character lowercase hexadecimal token. Trusted admission must pin that token
from its scoped state, not treat model-provided metadata as authority. This
component adds no path discovery, generation selection, launcher or usable-profile
capability. A checkpoint token is not implicitly converted into a generation.

Discard requires a previously enrolled, non-forgotten encrypted profile and a
matching directory scope, native-session/browser owner and epoch. The existing
authenticated current/quiescent guard must cover the entire operation. Acquire
the encrypted Store SQLite writer before the nonblocking directory lock. Accept
only READY with that current generation, or a pending DISCARDING with the same
generation. BUILDING/CLEANUP require their existing authorized restore recovery;
discard neither guesses their outcome nor adopts a candidate. Unknown objects,
links, unsupported modes or malformed metadata fail closed under the existing
containment rules. Only that root's explicitly named current generation is removed.

## Durable nonterminal cleanup

1. Check the permanent encrypted tombstone and local writer fence before any
   directory operation. Do not request a key, decrypt, capture, consume or invoke
   a credential/site/provider helper.
2. Persist DISCARDING, retaining the exact current generation and its digest,
   before the first unlink/rmdir. It has no candidate or retired generation.
3. Remove that generation with the existing bounded descriptor-relative helper,
   fsync removals, and publish empty READY with all generation/digest fields null.
4. Recheck authority and commit the Store owner fence before `discarded`.

All ciphertext, reference/nonce/key-version histories and restore outcomes remain
unchanged. Profile ownership may advance under a freshly authorized newer epoch;
discard never tombstones the encrypted profile. A later, independently admitted
restore with a new operation identity can materialize the retained checkpoint.
A previously delivered restore still reports its historical result without
replaying consumption; it does **not** prove a current materialization exists.
The original discard reference cannot delete a newly generated restore.

After interruption, DISCARDING blocks save/restore before directory recovery.
Only a fresh exact discard admission resumes that cleanup, or explicit permanent
forget may transition it to FORGOTTEN. Existing descriptor construction/close do
not perform cleanup. No background worker, timer or automatic browser-exit hook
exists. If the same action is still authorized, normal exception cleanup may
finish under its current guard; if authority is lost or the process is killed,
plaintext can remain until fresh admission. A completed empty READY rejects a
replayed discard: if success was lost after empty publication, the caller must
reconcile rather than infer a fresh success or select another generation.

An exception, cancellation, cleanup error, unlock failure or Store commit failure
does not prove that deletion was rolled back. Public failure stays sanitized and
must be treated as uncertain. No rollback transaction is claimed across SQLite
and directory metadata. Tests cover process death before/after each observed
directory fsync, including already-published empty states; actual power-loss,
firmware ordering, malicious same-UID mutation and physical erasure remain
unqualified. Deleted names can have open handles or copies elsewhere. This is not
browser termination, credential forgetting, logout, cookie invalidation, remote
revocation, secure-media erasure or a guarantee about browser-compatible files.

## Compatibility and evidence

This adds a recognized DISCARDING phase to the existing version-1 field layout;
there is no silent schema migration or new database. Older directory readers
reject that unknown pending phase. New consumers must deploy the action-aware
dispatcher and directory reader together, and no producer should issue discard
to an older component. Shared Grant/Result unions include the new variants, so
downstream exhaustive dispatchers need explicit review rather than an else branch
that equates any unknown action with forgetting. Existing custody admits only
save/restore and is not involved in discard.

Run `python3 -m unittest discover -s tests -p test_profile_discard.py -v`, also with
`python3 -O`. Tests use invented keys/admissions/cookies, actual temporary POSIX
directories, the real SQLite/AES checkpoint store, fresh subprocesses, independent
file/row observations and network-denying fixtures. They verify retained ciphertext
and a later restore, zero discard key reads, unrelated-profile survival, scope and
epoch rejection, stale replay, pending fences, lock contention, terminal forget,
tombstone ordering, failure sanitation and explicit close behavior. They do not
qualify real browser/quiescence authority or active-session integration.

## Authority between recursive removals

The legacy directory helper rechecks the exact current and quiescent guard
before every file unlink and directory removal. This applies to explicit discard,
permanent forget and the existing recovery paths that clean up staged or retired
generations. If authority is lost after a removal, the helper leaves the rest of
the tree alone and keeps the recorded phase. Fresh exact admission can resume
the existing cleanup. Permanent forget keeps its separate ciphertext tombstone.
These checks rely on the trusted guard for current authority and quiescence.

The regressions withdraw authority immediately after the first successful
plaintext unlink. The discard case independently sees a remaining sibling file,
preserved encrypted state and successful cleanup in a fresh process. The forget
case independently sees the empty nested directory retained, the terminal
tombstone and later cleanup under renewed authority. Removing either pre-removal
guard separately fails the corresponding regression.

Run `python3 -B -m unittest discover -s tests -p 'test_profile*.py'` and repeat
with `-O`. Local verification against
`fe5647c18e1b48962a51e0e993f61e37d4dbfae2` used Python 3.13.18 on macOS arm64,
`TMPDIR=/private/tmp`, cryptography 50.0.2, cffi 2.1.1 and pycparser 3.0.
All 127 profile tests passed in both modes. Ruff, static quality and scaffold
passed. Full discovery ran 616 tests in each mode, with 604 passes, 10 skips
and two errors reproduced on the unchanged base. The errors concern the
Linux SQLite library path and the committed-test diagnostics fixture.
The profile fixtures use disposable files, real local SQLite and synthetic authority.
Physical erasure, cross-machine guarantees and Host profile relocation remain
separate qualification work.

```text
d400b023d237b6749d0f63a01f7801e7023b614886cfed8fa594ee3ba9e89678  browser_runtime/profile_directory.py
84a05387f70d241a8d2ecbd1cb8ebdff3f24d08ed11616268e8d1e6e883b7bba  tests/test_profile_discard.py
96f356c53e8b8c4fb2f8dca5d1a31036148e3004996467a55b238291812ae252  requirements-profile.txt
```

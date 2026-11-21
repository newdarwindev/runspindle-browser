# Bounded profile directory capture and materialization

Original Python/POSIX component for another bounded slice of Browser #14/#7.
`profile_directory.DirectoryProfileIO` implements real filesystem capture and
materialization for the encrypted checkpoint Store's trusted IO interface.
`MaterializedStore` adds explicitly ordered ciphertext-plus-directory forgetting.
No real browser, account, profile, credential provider, launcher or deployment
was accessed. Both issues remain open. This is not Chrome/Firefox compatibility.

## Composition and authority

Construct a DirectoryProfileIO with a pre-provisioned private directory and a
trusted `Grant` selecting exactly one principal, account, profile, top-level
origin and frame origin. The static scope is persisted and immutable. That
constructor selection is configuration, not permission to access account data.
Use the existing authenticated `Guard` and `MaterializedStore` for all operations.
There are no discovered directories, default adapters, environment credentials,
service endpoints, browser process calls or returned browser/path capabilities.

Every operation requires a valid exact scope and fresh current/quiescent guard.
Checks repeat after locking, during file writes, before pointer publication,
through recovery and before successful return. The actual guard must atomically
maintain authenticated identity, observations, lease and quiescence. Sequential
checks do not make a dishonest guard safe. Persisted native-session/browser
ownership and monotonically increasing epoch reject stale or competing owners;
a bigger caller-controlled integer is not authority.

The helper is trusted internal code, not an independently authorized endpoint.
Its private recovery routine returns no usable-profile result. No active path or
launcher API exists. A future launcher must first check the encrypted store's
permanent tombstone under fresh authority, resolve only a READY generation and
supply its own actual browser/quiescence integration. Merely reading directory
metadata must never grant control or establish that a website session is usable.

## Root and file containment

The root must already exist, be POSIX, owned by the process UID, mode 0700, and
empty or contain this exact recognized state. Construction walks directory
components with directory descriptors and O_NOFOLLOW. Later operations re-open
and compare the configured root identity. All child opens, creates, renames,
unlinks and removals are descriptor-relative. No caller or metadata field is
used as an unrestricted filesystem path.

Fixed root files are `profile.lock`, `state.json` and an optional incomplete
`state.next`. Generated directories are `stage-<32 lowercase hex digits>` and
`g-<32 lowercase hex digits>`. Metadata has an exact versioned field inventory,
maximum 8192 bytes, an immutable scope, validated generation tokens and bounded
owner/epoch. Unknown root objects, schemas, phases or scope fail closed. No
salvage, auto-adoption of existing browser data, permission repair or guessed
recursive deletion is provided. Metadata temporary files contain no file bytes.

Profile entries must be regular files with one link, mode 0600, or directories
with mode 0700, owned by the same UID and on the same device. Symlinks, hardlinks,
FIFOs, sockets, devices and unsupported names deny the operation. Opens use
O_NOFOLLOW and nonblocking file opens avoid waiting on a substituted FIFO.
Creation uses exclusive filenames; no existing user file is overwritten in place.
Fstat identity is compared with the observed entry before reads and checked again
afterward. Capture repeats the entire metadata walk to detect changed earlier
files or directory membership. Atime changes are irrelevant to this comparison.

This is a cooperative private namespace boundary. Hostile same-UID/root actors,
concurrent ancestor replacement, mount manipulation, copied/rolled-back state and
unsupported network filesystem locking are not qualified. Descriptors prevent
ordinary symlink traversal but cannot turn trusted local process memory or the
same-UID namespace into a hostile isolation boundary. Actual browser lock files,
OS-protected cookie keys, database/WAL rules, permissions, caches and portability
require separate reviewed integration; no unsupported entry is silently filtered.

## Bounded snapshot format

Capture returns canonical ASCII JSON bytes only to the trusted encrypted helper.
The envelope contains version 1, exact scope, sorted directory paths, and sorted
file paths with strict base64 contents. Paths are arrays of individual nonempty
printable UTF-8 segments, each at most 128 encoded bytes. Dot, dot-dot, slashes,
backslashes, control characters, duplicate paths and file/directory prefix
conflicts deny. Parents must be explicitly represented. There are no archive
links, tar/ZIP extraction, compression, executable hooks or stored source paths.

Limits are 512 total nodes, depth 8, 8 MiB aggregate raw file data and the existing
Store's 16 MiB envelope ceiling. Metadata reading and directory enumeration are
bounded too. The entire payload and path inventory validate before any plaintext
write. Only paired canonical output is accepted. Empty directories and empty
files are preserved. Capturing a live, changing browser is not supported;
metadata race checks are a backstop, not a substitute for verified quiescence.

## Durable phase protocol

An instance lock and nonblocking `flock` serialize cooperating local users of one
root. The fixed lock file is never replaced. Its named inode is rechecked against
the held descriptor, and an existing root with a missing lock file denies rather
than silently creating a different lock. Nested same-instance use denies
immediately, and another instance/process cannot wait indefinitely on the tree
lock. Lock order is encrypted Store SQLite writer, then directory lock; directory
code never calls back into Store. All trusted callbacks still must be bounded.

Every metadata update writes an exclusive `state.next`, fsyncs it, replaces the
fixed state filename and fsyncs the containing directory. Only that metadata
reference publication is atomic. This is not an atomic replacement of a nonempty
browser directory, and two directory renames are never represented as one atomic
operation.

1. Persist BUILDING with the prior current generation and a fresh candidate ID
   before creating any candidate plaintext. New admission cannot use BUILDING.
2. Create the private staging tree. Write and fsync every file, its containing
   directory and the stage root. Recheck current authority while constructing it.
3. Rename the completed stage to its generated final name and fsync the root.
   Until publication it remains an uncommitted candidate, not an active profile.
4. Atomically publish metadata in CLEANUP: the new current generation and the
   recorded old generation awaiting deletion. This grants no browser authority.
5. Verify the newly published tree against its intended bundle digest, remove the
   old generation using contained operations and fsync removals. Publish READY
   only after cleanup finishes. A later authorized browser may mutate the READY
   generation, so that original installation digest is not a permanent assertion
   about future browser contents.

Fresh authenticated/quiescent recovery discards an uncommitted BUILDING candidate
and retains the previous current tree. For CLEANUP it verifies the new generation
and finishes the explicitly recorded retirement before READY. Unknown objects or
malformed state remain blocked; recovery does not invent a safe interpretation.
This preparation is internal and never resumes browser execution or authority.

A normal exception/cancellation attempts cleanup while the same scope remains
valid. If authority expires, cleanup fails, or the process is killed, plaintext
can remain in private staging/retiring directories until a fresh admitted process
recovers. Tests explicitly observe that interval. There is **no** claim of zero
plaintext immediately after SIGKILL. Successful recovery leaves one complete
old/new current tree and no abandoned generation; successful forgetting leaves no
materialized file bytes. Existing current plaintext and temporary plaintext are
different inventories. Closing Python descriptors alone does not delete a profile.
An explicit admitted end-of-session discard is implemented in
[the discard contract](profile-discard-v1.md). It is never implied by `close()`,
destruction of an object, elapsed time or a browser exit.

## Exact forgetting and crash gap

The base encrypted Store's `forget` behavior stays unchanged: ciphertext deletion
and a permanent profile tombstone, without an IO callback. Use MaterializedStore
when explicitly requesting the combined component behavior:

1. Validate fresh forget admission and compare its exact scope to the configured
   directory's immutable scope before committing the encrypted Store's permanent
   tombstone and ciphertext deletion. A mismatch leaves both stores intact.
2. Under the same trusted guard, persist the directory's terminal FORGOTTEN state.
3. Remove all explicitly inventoried current, candidate and retiring generations,
   fsync the removals, and persist the empty terminal state.
4. Recheck authority before returning `forgotten`. Any failure is partial/unknown,
   not completed forgetting, and requires reconciliation/fresh forget admission.

Crashing between steps 1 and 2 leaves ciphertext forgotten while old directory
metadata may still say READY. The wrapper therefore checks the encrypted profile
tombstone and checkpoint binding under SQLite's writer transaction **before any**
directory preparation, including when a prior restore attempt is already unknown.
Tests kill the process in that exact gap and assert zero directory preparation on
a later restore. A fresh authorized forget may finish plaintext cleanup. The
standalone trusted IO helper must never be treated as an alternative admission
route, usable-session result or launcher.

The directory scope precheck compares principal, account, profile, top-level
origin and frame origin in memory. Directory health and cleanup are checked
after the encrypted tombstone commits, so failures there still require fresh
forget admission. The mismatched-directory regression checks persisted profile
and checkpoint rows through a separate SQLite connection and observes zero
directory forget calls. A correctly bound restore and forget follow the denial.

FORGOTTEN persists even if recursive cleanup stops. The same root/profile cannot
be re-enrolled or restored. It is not credential deletion, site-session revocation,
browser termination, destruction of copies elsewhere or physical-media erasure.
No backup is created or run. Retiring a generation is an in-place namespace
transition during replacement, not a separately retained archival copy.

## Failures and evidence limits

Fsync, disk-space, malformed-state, permission, lock and key failures deny. An IO
error after atomic metadata replacement does not prove the replacement rolled
back. Store's durable restore attempt remains unknown when materialization or
cleanup fails, even if a complete new directory already exists. Duplicate unknown
restores prepare only safe recovery, without replaying the plaintext consumer.
Errors and cancellation are fixed categories raised outside upstream exception
handlers, without carrying secret-bearing cause/context. No memory zeroization,
swap/core-dump protection, open-descriptor erasure or power-cut/firmware behavior
is established by these tests.

Run `python3 -m unittest discover -s tests -p test_profile_directory.py -v` and
repeat with `python3 -O`. Tests use real temporary directories and the existing
real AEAD/SQLite store with public invented canaries and an injected test key.
They kill fresh processes before/after every observed directory fsync and the
stage rename, verify complete recovered trees, exercise every forget sync and the
cross-store tombstone gap, and count forbidden preparation calls. A deliberate
tombstone-gate bypass makes the independent spy detect that forbidden call.
They also cover links/FIFOs/path traversal, source mutation, cleanup/IO failures,
real process lock contention, scope/epoch mismatches, unknown-state denial and
plaintext scans. Network connects are denied in relevant test processes; runtime
code has no network or browser client.

No dependency is installed. This slice adds only Python standard-library use;
the real encrypted-store tests still use the separately recorded installed
cryptography 50.0.0 compatibility environment. Preferred 50.0.2 package/image
qualification and Rust validation retain their existing independent blockers.
No qualified runner, persistent service, host setting or source license changed.

Primary implementation references: [Python descriptor-relative filesystem APIs](https://docs.python.org/3.12/library/os.html),
[nonblocking flock](https://docs.python.org/3.12/library/fcntl.html), and
[file and directory fsync requirements](https://man7.org/linux/man-pages/man2/fsync.2.html).

## Observation-discovered revocation

Each profile check retains fast current/quiescent denial before observation and
rechecks both immediately after `observe`, before sampling the clock. A matching
target observation is not proof that the guard remains current or the browser
remains stopped: observation can discover lost authority or a resumed writer.
Neither key acquisition, plaintext capture/consumption nor directory metadata
publication may cross that known loss merely because a later check would deny.
Time is sampled after the second callbacks, so their delay cannot preserve an
expired admission or stale observation. Both adapters use the same check. It
captures the exact observed target and timestamp before the second callbacks,
then verifies that the observation and grant still match their captured values.
Later callbacks cannot refresh a stale timestamp or substitute a frame.
This is not universal TOCTOU immunity;
trusted bounded callbacks and an atomic, coherent guard are still required.

`tests/test_profile_observation_fence.py` exercises invented guards and keys with
real temporary SQLite/filesystem state. Negative effect spies cover key reads,
capture, consume, directory claim and candidate publication. Lost authority after
candidate rename leaves BUILDING pending without publishing CLEANUP; only fresh
admission recovers it. Source mutants deleting either post-observation gate fail
the corresponding independent effect assertions. This is local synthetic
component evidence, not browser/provider/distributed authority qualification.

## Cancellation during failure recovery

If an ordinary directory operation error is followed by cancellation in its
best-effort recovery call, cancellation takes precedence as the existing fixed
profile `Cancelled` category. Recovery failures never claim completed cleanup;
locks still release and durable pending state retains its existing interpretation.
A new operation requires fresh explicit admission, not an automatic retry.
Public directory lifecycle `Denied`/`Cancelled` exits clear cause/context even
inside a caller's active exception handler. Tests use only synthetic trees and
callbacks. Arbitrary deeper filesystem-helper cleanup replacement, raw Store
constructor cancellation, real browser integration and physical erasure are not
qualified by this bounded change. See the encrypted-store cancellation contract
and `tests/test_profile_cancellation.py`.

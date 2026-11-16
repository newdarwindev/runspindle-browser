"""Real encrypted checkpoint BLOBs. Trusted construction; no browser/filesystem restore.

Only synthetic component evidence qualifies this module. Authority, quiescence,
key custody and plaintext capture/consumption MUST be supplied by trusted code.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, ContextManager, Literal, Protocol, cast

from browser_runtime.credentials import Observation, Target
from browser_runtime.profile_schema import Location, open_store, require, token

MAX_BYTES = 16 * 1024 * 1024
Action = Literal["save", "restore", "forget"]
Result = Literal["stored", "delivered", "unknown", "forgotten"]


class Denied(ValueError):
    """Fixed public category; no upstream message, traceback chain or material."""


class Cancelled(BaseException):
    """Sanitized cancellation; callers must stop, not blindly retry consumption."""


class DependencyUnavailable(RuntimeError):
    """Mandatory crypto dependency is absent; verification cannot silently skip."""


def encoded(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


@dataclass(frozen=True)
class Grant:
    target: Target
    profile: str
    action: Action
    reference: str
    deadline: float

    def validate(self) -> None:
        require(type(self.target) is Target)
        self.target.validate()
        token(self.profile)
        token(self.reference)
        require(
            type(self.action) is str and self.action in ("save", "restore", "forget")
        )
        require(type(self.deadline) in (int, float) and math.isfinite(self.deadline))

    def identity(self) -> str:
        binding = self.target.binding
        return encoded([binding.principal, binding.account, self.profile])

    def scope(self) -> str:
        return encoded(
            [self.identity(), self.target.binding.origin, self.target.frame_origin]
        )

    def owner(self) -> str:
        return encoded([self.target.native_session, self.target.binding.browser])

    def attempt(self) -> str:
        return encoded(
            [
                self.target.binding.encoded(),
                self.target.native_session,
                self.target.frame,
                self.target.frame_origin,
                self.profile,
                self.action,
                self.reference,
            ]
        )


class Guard(Protocol):
    def admit(self, ticket: object) -> Grant | None: ...
    def observe(self) -> Observation | None: ...
    def current(self, grant: Grant) -> bool: ...
    def quiescent(self, grant: Grant) -> bool:
        """Authenticated stopped writer/consumer boundary under this same guard."""
        ...


class Authority(Protocol):
    def acquire(self) -> ContextManager[Guard]: ...


@dataclass(frozen=True, repr=False)
class Key:
    version: str
    material: bytes = field(repr=False)


class Keys(Protocol):
    def acquire(
        self, store_id: str, grant: Grant, version: str | None
    ) -> ContextManager[Key]:
        """Authorize scoped immutable version; None selects current save key.

        Use a distinct key namespace for this store_id. Independent stores must not
        share keys; restoring copied store state is not supported.
        Keep it valid under a custody guard until exit; do not return a credential
        value as a key. Use random 256-bit keys, not passwords. Release on all exits.
        """
        ...


class ProfileIO(Protocol):
    def capture(self, grant: Grant, guard: Guard) -> bytes: ...
    def consume(self, grant: Grant, guard: Guard, plaintext: bytes) -> bool: ...


@dataclass(frozen=True)
class Adapters:
    authority: Authority = field(repr=False)
    keys: Keys = field(repr=False)
    io: ProfileIO = field(repr=False)


class Store:
    """Bounded local component, not a vault or a source of action authority.

    All callbacks must be bounded, non-reentrant trusted implementations pinned
    by the composition root. Locks serialize cooperating processes on one store;
    they do not authenticate an epoch, implement distributed fencing or stop a
    live browser. No adapters are discovered or installed by default.
    """

    def __init__(
        self,
        directory: str | Path,
        adapters: Adapters | None = None,
        *,
        clock: Callable[[], float] = time.monotonic,
        max_age: float = 1.0,
    ) -> None:
        available = True
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        except ImportError:
            available = False
        if not available:
            raise DependencyUnavailable("profile cryptography dependency unavailable")
        self._cipher = AESGCM
        self._lock = threading.Lock()
        self._adapters = adapters
        self._clock = clock
        self._max_age = max_age
        self._closed = False
        success = False
        try:
            require(
                type(max_age) in (int, float)
                and math.isfinite(max_age)
                and max_age >= 0
            )
            self._location = Location(directory)
            self._db = open_store(self._location)
            self._store_id = self._db.execute(
                "SELECT store_id FROM metadata"
            ).fetchone()[0]
            success = True
        except Exception:
            pass
        if not success:
            raise Denied("profile store unavailable")

    def close(self) -> None:
        if not self._lock.acquire(blocking=False):
            raise Denied("profile store busy")
        failed = False
        cancelled = False
        try:
            if not self._closed:
                self._closed = True  # Never retry an uncertain connection close.
                try:
                    self._db.close()
                except BaseException as error:
                    failed = True
                    cancelled = not isinstance(error, Exception)
        finally:
            self._lock.release()
        if cancelled:
            raise Cancelled("profile close cancelled")
        if failed:
            raise Denied("profile close failed")

    def _check(self, guard: Guard, grant: Grant) -> None:
        # Trusted callbacks may block. Sample observation/time only after the
        # authority/quiescence callbacks, never reuse a pre-callback timestamp.
        require(guard.current(grant) is True and guard.quiescent(grant) is True)
        observed = guard.observe()
        now = self._clock()
        require(type(now) in (int, float) and math.isfinite(now))
        require(type(observed) is Observation and type(observed.target) is Target)
        observed = cast(Observation, observed)
        require(
            type(observed.observed_at) in (int, float)
            and math.isfinite(observed.observed_at)
        )
        observed.target.validate()
        require(observed.target == grant.target)
        require(
            0 <= now - observed.observed_at <= self._max_age and now < grant.deadline
        )
        self._location.check()

    def _begin(self, guard: Guard, grant: Grant) -> None:
        self._location.check()
        self._db.execute("BEGIN IMMEDIATE")
        # Waiting for another writer never preserves old admission.
        self._check(guard, grant)

    def _claim(
        self, grant: Grant, *, create: bool = False, forgetting: bool = False
    ) -> None:
        identity, scope, owner = grant.identity(), grant.scope(), grant.owner()
        epoch = grant.target.binding.epoch
        row = self._db.execute(
            "SELECT scope,owner,epoch,forgotten FROM profiles WHERE identity=?",
            (identity,),
        ).fetchone()
        if row is None:
            require(create)
            self._db.execute(
                "INSERT INTO profiles VALUES (?,?,?,?,0)",
                (identity, scope, owner, epoch),
            )
            return
        require(row[0] == scope and (row[3] == 0 or forgetting))
        require(type(row[2]) is int and epoch >= row[2])
        require(epoch > row[2] or owner == row[1])
        self._db.execute(
            "UPDATE profiles SET owner=?,epoch=? WHERE identity=?",
            (owner, epoch, identity),
        )

    def _key(self, key: Key, version: str | None = None) -> bytes:
        require(
            type(key) is Key and type(key.material) is bytes and len(key.material) == 32
        )
        token(key.version)
        require(version is None or key.version == version)
        fingerprint = hashlib.sha256(key.material).digest()
        row = self._db.execute(
            "SELECT fingerprint FROM key_versions WHERE version=?", (key.version,)
        ).fetchone()
        if row is None:
            require(version is None)
            self._db.execute(
                "INSERT INTO key_versions VALUES (?,?)", (key.version, fingerprint)
            )
        else:
            require(row[0] == fingerprint)
        return fingerprint

    def _aad(self, grant: Grant, version: str) -> bytes:
        return encoded(
            [
                "runspindle.profile.aes256gcm.v1",
                self._store_id,
                grant.scope(),
                grant.reference,
                version,
            ]
        ).encode("ascii")

    def _checkpoint(self, grant: Grant) -> tuple[str, bytes, bytes]:
        row = self._db.execute(
            "SELECT version,nonce,ciphertext,profile FROM checkpoints WHERE reference=?",
            (grant.reference,),
        ).fetchone()
        require(row is not None and row[3] == grant.identity())
        require(
            self._db.execute(
                "SELECT 1 FROM checkpoint_refs WHERE reference=?", (grant.reference,)
            ).fetchone()
            is not None
        )
        token(row[0])
        require(type(row[1]) is bytes and len(row[1]) == 12)
        require(type(row[2]) is bytes and 17 <= len(row[2]) <= MAX_BYTES + 16)
        return row[0], row[1], row[2]

    def _save(self, adapters: Adapters, guard: Guard, grant: Grant) -> Result:
        self._begin(guard, grant)
        self._claim(grant, create=True)
        require(
            self._db.execute(
                "SELECT 1 FROM checkpoint_refs WHERE reference=?", (grant.reference,)
            ).fetchone()
            is None
        )
        self._check(guard, grant)
        completed = False
        with adapters.keys.acquire(self._store_id, grant, None) as key:
            self._check(guard, grant)
            fingerprint = self._key(key)
            nonce = os.urandom(12)
            # The namespace is keyed by actual key fingerprint, including aliases.
            # A collision denies instead of retrying or reusing a pair.
            self._db.execute("INSERT INTO nonces VALUES (?,?)", (fingerprint, nonce))
            self._db.execute("COMMIT")  # Burn nonce before *any* encryption.
            self._begin(guard, grant)
            self._claim(grant)
            require(
                self._db.execute(
                    "SELECT 1 FROM checkpoint_refs WHERE reference=?",
                    (grant.reference,),
                ).fetchone()
                is None
            )
            self._check(guard, grant)
            plaintext = adapters.io.capture(grant, guard)
            require(type(plaintext) is bytes and 1 <= len(plaintext) <= MAX_BYTES)
            self._check(guard, grant)
            ciphertext = self._cipher(key.material).encrypt(
                nonce, plaintext, self._aad(grant, key.version)
            )
            self._check(guard, grant)
            self._db.execute(
                "INSERT INTO checkpoint_refs VALUES (?)", (grant.reference,)
            )
            self._db.execute(
                "INSERT INTO checkpoints VALUES (?,?,?,?,?)",
                (grant.reference, grant.identity(), key.version, nonce, ciphertext),
            )
            self._db.execute("COMMIT")
            completed = True
        require(completed)
        return "stored"

    def _restore(self, adapters: Adapters, guard: Guard, grant: Grant) -> Result:
        self._begin(guard, grant)
        self._claim(grant)
        self._checkpoint(grant)
        operation, binding = grant.target.binding.operation, grant.attempt()
        old = self._db.execute(
            "SELECT binding,result FROM restores WHERE operation=?", (operation,)
        ).fetchone()
        if old is not None:
            require(old[0] == binding and old[1] in ("unknown", "delivered"))
            self._check(guard, grant)
            self._db.execute("COMMIT")
            return cast(Result, old[1])
        self._db.execute(
            "INSERT INTO restores VALUES (?,?,'unknown')", (operation, binding)
        )
        self._db.execute("COMMIT")  # Never replay uncertain plaintext consumption.
        self._begin(guard, grant)
        self._claim(grant)
        version, nonce, ciphertext = self._checkpoint(grant)
        self._check(guard, grant)
        completed = False
        with adapters.keys.acquire(self._store_id, grant, version) as key:
            self._check(guard, grant)
            fingerprint = self._key(key, version)
            require(
                self._db.execute(
                    "SELECT 1 FROM nonces WHERE fingerprint=? AND nonce=?",
                    (fingerprint, nonce),
                ).fetchone()
                is not None
            )
            plaintext = self._cipher(key.material).decrypt(
                nonce, ciphertext, self._aad(grant, version)
            )
            self._check(guard, grant)
            require(adapters.io.consume(grant, guard, plaintext) is True)
            self._check(guard, grant)
            self._db.execute(
                "UPDATE restores SET result='delivered' WHERE operation=?", (operation,)
            )
            self._db.execute("COMMIT")
            completed = True
        require(completed)
        return "delivered"

    def _forget(self, guard: Guard, grant: Grant) -> Result:
        self._begin(guard, grant)
        self._claim(grant, create=True, forgetting=True)
        self._check(guard, grant)
        self._db.execute("DELETE FROM checkpoints WHERE profile=?", (grant.identity(),))
        self._db.execute(
            "UPDATE profiles SET forgotten=1 WHERE identity=?", (grant.identity(),)
        )
        self._check(guard, grant)
        self._db.execute("COMMIT")
        # Key, nonce and uncertainty records survive; no key/site/credential call.
        return "forgotten"

    def run(self, ticket: object) -> Result:
        if not self._lock.acquire(blocking=False):
            raise Denied("profile store busy")
        result: Result | None = None
        cancelled = False
        try:
            try:
                require(not self._closed and type(self._adapters) is Adapters)
                adapters = cast(Adapters, self._adapters)
                completed: Result | None = None
                with adapters.authority.acquire() as guard:
                    grant = guard.admit(ticket)
                    require(type(grant) is Grant)
                    grant = cast(Grant, grant)
                    grant.validate()
                    self._check(guard, grant)
                    if grant.action == "save":
                        completed = self._save(adapters, guard, grant)
                    elif grant.action == "restore":
                        completed = self._restore(adapters, guard, grant)
                    else:
                        completed = self._forget(guard, grant)
                require(
                    completed is not None
                )  # Suppressing guards cannot fake success.
                result = completed
            except BaseException as error:
                cancelled = not isinstance(error, Exception)
            finally:
                if not self._closed:
                    try:
                        if self._db.in_transaction:
                            self._db.execute("ROLLBACK")
                    except BaseException as error:
                        result = None
                        cancelled = cancelled or not isinstance(error, Exception)
                        # Failed cleanup leaves transaction state uncertain. Fence
                        # this instance before attempting close, once only.
                        self._closed = True
                        try:
                            self._db.close()
                        except BaseException as error:
                            cancelled = cancelled or not isinstance(error, Exception)
        finally:
            self._lock.release()
        # Outside handlers: even __context__ does not retain upstream material.
        if cancelled:
            raise Cancelled("profile operation cancelled")
        if result is None:
            raise Denied("profile operation denied")
        return result

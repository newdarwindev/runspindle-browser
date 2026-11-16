"""Local durable exclusive control, with injected authenticated fencing adapters.

No identity issuer, viewer, browser backend or service is installed. Every real
input path must be routed through this boundary by a trusted composition root.
"""

from __future__ import annotations

import json
import math
import re
import sqlite3
import threading
import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable, ContextManager, Iterator, NoReturn, Protocol, cast

from browser_runtime.credentials import (
    AdapterSet, Grant as CredentialGrant, Helper, Observation, Resolver, Target, Vault,
)
from browser_runtime.effects import Cancelled, Denied, Outcome
from browser_runtime.guarded_effects import Grant as EffectGrant
from browser_runtime.guarded_effects import GuardedJournal, Site


def _encode(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _scope(target: Target) -> str:
    target.validate()
    data = asdict(target)
    for key in ("intent", "revision", "operation", "epoch"):
        del data["binding"][key]
    return _encode(data)


def _identifier(value: str) -> None:
    if type(value) is not str or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", value) is None:
        raise ValueError


def _time(value: object) -> float:
    if type(value) not in (int, float) or not math.isfinite(cast(float, value)):
        raise ValueError
    return float(cast(float, value))


def _fail(cancelled: bool) -> NoReturn:
    try:
        if cancelled:
            raise Cancelled("control operation cancelled")
        raise Denied("control operation denied")
    except (Denied, Cancelled) as error:
        error.__cause__ = error.__context__ = None
        raise


@dataclass(frozen=True)
class Holder:
    kind: str
    identity: str

    def validate(self) -> None:
        if type(self.kind) is not str or self.kind not in ("agent", "human"):
            raise ValueError
        _identifier(self.identity)


@dataclass(frozen=True)
class Transfer:
    target: Target
    action: str
    source: Holder | None
    destination: Holder
    expected_epoch: int
    deadline: float

    def validate(self) -> None:
        if type(self.target) is not Target or type(self.destination) is not Holder:
            raise ValueError
        self.target.validate()
        self.destination.validate()
        if type(self.expected_epoch) is not int or self.expected_epoch < 0:
            raise ValueError
        if self.target.binding.epoch != self.expected_epoch + 1:
            raise ValueError
        if type(self.action) is not str:
            raise ValueError
        if self.action == "initialize":
            if self.expected_epoch != 0 or self.source is not None or self.destination.kind != "agent":
                raise ValueError
        else:
            if type(self.source) is not Holder:
                raise ValueError
            self.source.validate()
            kinds = (self.source.kind, self.destination.kind)
            if (self.action, kinds) not in (
                ("takeover", ("agent", "human")),
                ("handback", ("human", "agent")),
            ):
                raise ValueError
        _time(self.deadline)


@dataclass(frozen=True)
class Recovery:
    """Fresh readback authority for one immutable, already reserved transfer."""
    transfer: Transfer
    deadline: float

    def validate(self) -> None:
        if type(self.transfer) is not Transfer:
            raise ValueError
        self.transfer.validate()
        _time(self.deadline)


@dataclass(frozen=True)
class FenceObservation:
    transfer: Transfer
    previous_inputs_closed: bool
    observed_at: float


@dataclass(frozen=True)
class Input:
    effect: EffectGrant
    holder: Holder


@dataclass(frozen=True)
class CredentialInput:
    """Distinct exact credential admission; effect tickets confer no vault rights."""
    credential: CredentialGrant
    holder: Holder


@dataclass(frozen=True)
class PassiveStatus:
    """Fresh observation permission only; never input or transition authority."""
    target: Target
    deadline: float

    def validate(self) -> None:
        if type(self.target) is not Target:
            raise ValueError
        self.target.validate()
        _time(self.deadline)


@dataclass(frozen=True)
class ControlStatus:
    """Historical durable metadata, not a lease or usable control capability."""
    phase: str
    epoch: int | None
    holder: Holder | None
    observed_at: float
    scope: str


@dataclass(frozen=True)
class FenceReceipt:
    transfer: Transfer
    previous_inputs_closed: bool


class Guard(Protocol):
    def admit(self, ticket: object) -> Transfer | Recovery | Input | CredentialInput | PassiveStatus | None: ...
    def current(self, grant: Transfer | Recovery | Input | CredentialInput | PassiveStatus) -> bool: ...
    def observe(self) -> Observation | None: ...
    def released(self, transfer: Transfer | Recovery) -> bool:
        """Authenticate release by the exact source holder, target and epoch."""
        ...


class Authority(Protocol):
    def acquire(self) -> ContextManager[Guard]: ...


class Backend(Protocol):
    def fence(self, transfer: Transfer, guard: Guard) -> FenceReceipt:
        """Stop/drain all previous input paths, including viewer inputs on handback."""
        ...


class Inspector(Protocol):
    def inspect(self, recovery: Recovery, guard: Guard) -> FenceObservation | None:
        """Read exact current closure evidence without input, navigation or fencing."""
        ...


DDL = """CREATE TABLE leases (
    browser TEXT PRIMARY KEY NOT NULL, scope TEXT NOT NULL,
    epoch INTEGER NOT NULL CHECK(epoch > 0), holder TEXT NOT NULL,
    phase TEXT NOT NULL CHECK(phase IN ('pending','active')),
    transition TEXT NOT NULL
)"""
APP_ID = 0x5242434C


class LeaseStore:
    """One local SQLite writer lock covers each admitted helper/input lifetime.

    A transfer first durably blocks inputs, then invokes its fence at most once.
    Crashed/uncertain pending transfers remain blocked unless separately admitted
    readback proves closure. No automatic timeout, admin override or fence retry.
    """

    def __init__(
        self, path: str | Path, *, authority: Authority | None = None,
        backend: Backend | None = None, inspector: Inspector | None = None,
        clock: Callable[[], float] = time.monotonic,
        max_age: float = 1.0,
    ) -> None:
        self._lock = threading.Lock()
        self._authority = authority
        self._backend = backend
        self._inspector = inspector
        self._clock = clock
        self._max_age = _time(max_age)
        self._closed = True
        db: sqlite3.Connection | None = None
        failed = cancelled = False
        try:
            if not 0 < self._max_age <= 60 or not str(path) or str(path) == ":memory:" or str(path).startswith("file:"):
                raise ValueError
            db = sqlite3.connect(path, isolation_level=None, timeout=2)
            db.execute("PRAGMA synchronous=FULL")
            db.execute("BEGIN IMMEDIATE")
            inventory = db.execute("SELECT type,name,sql FROM sqlite_master ORDER BY name").fetchall()
            identity = (db.execute("PRAGMA application_id").fetchone()[0],
                        db.execute("PRAGMA user_version").fetchone()[0])
            if not inventory and identity == (0, 0):
                db.execute(DDL)
                db.execute(f"PRAGMA application_id={APP_ID}")
                db.execute("PRAGMA user_version=1")
            else:
                expected = [("table", "leases", DDL),
                            ("index", "sqlite_autoindex_leases_1", None)]
                if identity != (APP_ID, 1) or inventory != expected:
                    raise ValueError
            if db.execute("PRAGMA quick_check").fetchall() != [("ok",)]:
                raise ValueError
            db.execute("COMMIT")
            self._db = db
            self._closed = False
        except BaseException as error:
            failed = True
            cancelled = not isinstance(error, Exception)
            if db is not None:
                try:
                    db.close()
                except BaseException as cleanup:
                    cancelled = cancelled or not isinstance(cleanup, Exception)
        if failed:
            _fail(cancelled)

    def _check(self, guard: Guard, grant: Transfer | Recovery | Input | CredentialInput | PassiveStatus) -> float:
        if type(grant) is Transfer:
            grant.validate()
            target, deadline = grant.target, grant.deadline
        elif type(grant) is Recovery:
            grant.validate()
            target, deadline = grant.transfer.target, grant.deadline
        elif type(grant) is PassiveStatus:
            grant.validate()
            target, deadline = grant.target, grant.deadline
        elif type(grant) in (Input, CredentialInput):
            if type(grant.holder) is not Holder:
                raise ValueError
            grant.holder.validate()
            if type(grant) is Input:
                if type(grant.effect) is not EffectGrant:
                    raise ValueError
                target, deadline = grant.effect.target, grant.effect.deadline
            else:
                if type(grant.credential) is not CredentialGrant:
                    raise ValueError
                target, deadline = grant.credential.target, grant.credential.deadline
            if type(target) is not Target:
                raise ValueError
            target.validate()
        else:
            raise ValueError
        observed = guard.observe()
        if type(observed) is not Observation or type(observed.target) is not Target:
            raise ValueError
        # Physical identity is observed independently; this store owns the lease
        # epoch. Never infer a grant from a browser's claimed epoch or page text.
        if _scope(observed.target) != _scope(target):
            raise ValueError
        observed_at = _time(observed.observed_at)
        current = guard.current(grant)
        now = _time(self._clock())
        if current is not True or not 0 <= now - observed_at <= self._max_age or now >= _time(deadline):
            raise ValueError
        return now

    def _row(self, target: Target) -> tuple[object, ...] | None:
        return self._db.execute(
            "SELECT scope,epoch,holder,phase,transition FROM leases WHERE browser=?",
            (target.binding.browser,),
        ).fetchone()

    def _input(self, grant: Input | CredentialInput) -> None:
        target = grant.effect.target if type(grant) is Input else grant.credential.target
        row = self._row(target)
        if row is None or row[:4] != (
            _scope(target), target.binding.epoch, _encode(asdict(grant.holder)), "active"
        ):
            raise ValueError

    @contextmanager
    def _session(self) -> Iterator[Guard]:
        if not self._lock.acquire(blocking=False):
            _fail(False)
        cancelled = failed = False
        try:
            try:
                if self._closed or self._authority is None:
                    raise ValueError
                with self._authority.acquire() as guard:
                    try:
                        yield guard
                    except BaseException as error:
                        failed = True
                        cancelled = not isinstance(error, Exception)
                        raise
            except BaseException as error:
                failed = True
                cancelled = cancelled or not isinstance(error, Exception)
        finally:
            try:
                if not self._closed and self._db.in_transaction:
                    self._db.execute("ROLLBACK")
            except BaseException as error:
                failed = True
                cancelled = cancelled or not isinstance(error, Exception)
                self._closed = True
                try:
                    self._db.close()
                except BaseException as cleanup:
                    cancelled = cancelled or not isinstance(cleanup, Exception)
            finally:
                self._lock.release()
        if failed or cancelled:
            _fail(cancelled)

    def status(self, ticket: object) -> ControlStatus:
        """Read exact-scope metadata without input, provider or backend callbacks.

        A passive target does not select an epoch: the snapshot reports the
        observed durable epoch. No status object is an admission or authority.
        """
        with self._session() as guard:
            grant = guard.admit(ticket)
            if type(grant) is not PassiveStatus:
                raise ValueError
            self._check(guard, grant)
            self._db.execute("BEGIN")  # Read transaction only; never upgrade.
            row = self._row(grant.target)
            phase: str = "absent"
            epoch: int | None = None
            holder: Holder | None = None
            if row is not None:
                if (row[0] != _scope(grant.target) or type(row[1]) is not int
                        or row[1] <= 0 or type(row[3]) is not str
                        or row[3] not in ("active", "pending")
                        or type(row[2]) is not str):
                    raise ValueError
                data = json.loads(row[2])
                stored_holder = Holder(**data)
                stored_holder.validate()
                if _encode(asdict(stored_holder)) != row[2]:
                    raise ValueError
                phase, epoch = cast(str, row[3]), cast(int, row[1])
                if phase == "active":
                    holder = stored_holder
                # Pending's stored destination is not an active holder.
            # Sampled after the final observation/current callbacks and checked
            # against the deadline; read waits cannot retain old permission.
            observed_at = self._check(guard, grant)
            result = ControlStatus(phase, epoch, holder, observed_at, _scope(grant.target))
        return result  # _session rolls back the read transaction after guard exit.

    def transfer(self, ticket: object) -> str:
        outcome = "unknown"
        with self._session() as guard:
            grant = guard.admit(ticket)
            if type(grant) is not Transfer or self._backend is None:
                raise ValueError
            self._check(guard, grant)
            encoded = _encode(asdict(grant))
            self._db.execute("BEGIN IMMEDIATE")
            self._check(guard, grant)
            row = self._row(grant.target)
            if row is not None and row[4] == encoded:
                return "active" if row[3] == "active" else "unknown"
            if row is None:
                if grant.action != "initialize":
                    raise ValueError
            elif row[:4] != (
                _scope(grant.target), grant.expected_epoch,
                _encode(asdict(grant.source)), "active",
            ):
                raise ValueError
            if grant.action == "handback":
                if guard.released(grant) is not True:
                    raise ValueError
                self._check(guard, grant)  # Release authentication can block.
            self._db.execute(
                "INSERT INTO leases VALUES (?,?,?,?,?,?) ON CONFLICT(browser) DO UPDATE SET scope=excluded.scope,epoch=excluded.epoch,holder=excluded.holder,phase=excluded.phase,transition=excluded.transition",
                (grant.target.binding.browser, _scope(grant.target), grant.target.binding.epoch,
                 _encode(asdict(grant.destination)), "pending", encoded),
            )
            self._db.execute("COMMIT")  # Burn transition before the external fence.
            self._db.execute("BEGIN IMMEDIATE")
            self._check(guard, grant)
            if grant.action == "handback":
                if guard.released(grant) is not True:
                    raise ValueError
                self._check(guard, grant)  # Release authentication can block.
            receipt = self._backend.fence(grant, guard)
            self._check(guard, grant)
            if (type(receipt) is FenceReceipt and type(receipt.transfer) is Transfer
                    and receipt.transfer == grant and receipt.previous_inputs_closed is True):
                self._db.execute("UPDATE leases SET phase='active' WHERE browser=?",
                                 (grant.target.binding.browser,))
                self._db.execute("COMMIT")
                outcome = "active"
        return outcome

    def reconcile_transfer(self, ticket: object) -> str:
        """Never resend a fence: activate only from fresh exact closure readback."""
        outcome = "unknown"
        with self._session() as guard:
            grant = guard.admit(ticket)
            if type(grant) is not Recovery or self._inspector is None:
                raise ValueError
            self._check(guard, grant)
            transfer = grant.transfer
            self._db.execute("BEGIN IMMEDIATE")
            self._check(guard, grant)  # A writer wait cannot preserve old authority.
            row = self._row(transfer.target)
            expected = (
                _scope(transfer.target), transfer.target.binding.epoch,
                _encode(asdict(transfer.destination)),
            )
            if (row is None or row[:3] != expected
                    or row[4] != _encode(asdict(transfer))):
                raise ValueError
            if row[3] == "active":
                return "active"  # Retained metadata, not a new input capability.
            if row[3] != "pending":
                raise ValueError
            if transfer.action == "handback":
                if guard.released(grant) is not True:
                    raise ValueError
                self._check(guard, grant)
            observed = self._inspector.inspect(grant, guard)
            self._check(guard, grant)
            if (type(observed) is not FenceObservation
                    or type(observed.transfer) is not Transfer
                    or observed.transfer != transfer
                    or observed.previous_inputs_closed is not True):
                return "unknown"
            if transfer.action == "handback":
                if guard.released(grant) is not True:
                    raise ValueError
                self._check(guard, grant)
            now = _time(self._clock())
            if not 0 <= now - _time(observed.observed_at) <= self._max_age:
                raise ValueError  # Stale closure is not activation authority.
            if now >= _time(grant.deadline):
                raise ValueError
            self._db.execute("UPDATE leases SET phase='active' WHERE browser=?",
                             (transfer.target.binding.browser,))
            self._db.execute("COMMIT")
            outcome = "active"
        return outcome

    def journal(self, path: str | Path, site: Site) -> GuardedJournal:
        """Route both agent/human effects through the existing guarded Journal."""
        return GuardedJournal(path, authority=_InputAuthority(self), site=site,
                              clock=self._clock, max_age=self._max_age)

    def credential_resolver(
        self, vault: Vault, helper: Helper, *, adapter_digest: str, expected_digest: str,
    ) -> Resolver:
        """Trusted composition only: pin this lease-bound authority/vault/helper set.

        The digest must attest this composition, not an unrelated raw resolver.
        Matching strings do not authenticate adapters. Resolver retains its own
        one-attempt rule, pin checks, scoped reference checks and handle cleanup.
        """
        return Resolver(
            AdapterSet(adapter_digest, _CredentialAuthority(self), vault, helper),
            expected_digest=expected_digest, clock=self._clock, max_age=self._max_age,
        )

    def close(self) -> None:
        if not self._lock.acquire(blocking=False):
            _fail(False)
        failed = cancelled = False
        try:
            if not self._closed:
                self._closed = True
                try:
                    self._db.close()
                except BaseException as error:
                    failed = True
                    cancelled = not isinstance(error, Exception)
        finally:
            self._lock.release()
        if failed:
            _fail(cancelled)


class _InputAuthority:
    def __init__(self, store: LeaseStore) -> None:
        self.store = store

    @contextmanager
    def acquire(self) -> Iterator[_InputGuard]:
        with self.store._session() as guard:
            self.store._db.execute("BEGIN IMMEDIATE")
            yield _InputGuard(self.store, guard)


class _InputGuard:
    def __init__(self, store: LeaseStore, guard: Guard) -> None:
        self.store, self.guard = store, guard
        self.grant: Input | None = None

    def admit(self, ticket: object) -> EffectGrant | None:
        grant = self.guard.admit(ticket)
        if type(grant) is not Input:
            return None
        self.store._check(self.guard, grant)
        self.store._input(grant)
        self.grant = grant
        return grant.effect

    def current(self, effect: EffectGrant) -> bool:
        grant = self.grant
        if grant is None or grant.effect != effect:
            return False
        self.store._check(self.guard, grant)
        self.store._input(grant)
        return True

    def observe(self) -> Observation | None:
        observed = self.guard.observe()
        grant = self.grant
        if (grant is None or type(observed) is not Observation
                or type(observed.target) is not Target
                or _scope(observed.target) != _scope(grant.effect.target)):
            return None
        # Epoch comes from the locked durable authority row, not the page.
        self.store._input(grant)
        return Observation(grant.effect.target, observed.observed_at)


class _CredentialAuthority:
    def __init__(self, store: LeaseStore) -> None:
        self.store = store

    @contextmanager
    def acquire(self) -> Iterator[_CredentialGuard]:
        with self.store._session() as guard:
            self.store._db.execute("BEGIN IMMEDIATE")
            yield _CredentialGuard(self.store, guard)


class _CredentialGuard:
    def __init__(self, store: LeaseStore, guard: Guard) -> None:
        self.store, self.guard = store, guard
        self.grant: CredentialInput | None = None

    def admit(self, ticket: object) -> CredentialGrant | None:
        grant = self.guard.admit(ticket)
        if type(grant) is not CredentialInput:
            return None
        self.store._check(self.guard, grant)
        self.store._input(grant)
        self.grant = grant
        return grant.credential

    def current(self, credential: CredentialGrant) -> bool:
        grant = self.grant
        if grant is None or grant.credential != credential:
            return False
        self.store._check(self.guard, grant)
        self.store._input(grant)
        return True

    def observe(self) -> Observation | None:
        observed = self.guard.observe()
        grant = self.grant
        if (grant is None or type(observed) is not Observation
                or type(observed.target) is not Target
                or _scope(observed.target) != _scope(grant.credential.target)):
            return None
        self.store._input(grant)
        return Observation(grant.credential.target, observed.observed_at)

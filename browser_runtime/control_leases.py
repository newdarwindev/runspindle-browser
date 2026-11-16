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

from browser_runtime.credentials import Observation, Target
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
class Input:
    effect: EffectGrant
    holder: Holder


@dataclass(frozen=True)
class FenceReceipt:
    transfer: Transfer
    previous_inputs_closed: bool


class Guard(Protocol):
    def admit(self, ticket: object) -> Transfer | Input | None: ...
    def current(self, grant: Transfer | Input) -> bool: ...
    def observe(self) -> Observation | None: ...
    def released(self, transfer: Transfer) -> bool:
        """Authenticate release by the exact source holder, target and epoch."""
        ...


class Authority(Protocol):
    def acquire(self) -> ContextManager[Guard]: ...


class Backend(Protocol):
    def fence(self, transfer: Transfer, guard: Guard) -> FenceReceipt:
        """Stop/drain all previous input paths, including viewer inputs on handback."""
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
    Crashed/uncertain pending transfers remain blocked; this version intentionally
    has no automatic timeout, startup recovery, admin override or fence retry.
    """

    def __init__(
        self, path: str | Path, *, authority: Authority | None = None,
        backend: Backend | None = None, clock: Callable[[], float] = time.monotonic,
        max_age: float = 1.0,
    ) -> None:
        self._lock = threading.Lock()
        self._authority = authority
        self._backend = backend
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

    def _check(self, guard: Guard, grant: Transfer | Input) -> None:
        if type(grant) is Transfer:
            grant.validate()
            target, deadline = grant.target, grant.deadline
        elif type(grant) is Input and type(grant.effect) is EffectGrant and type(grant.holder) is Holder:
            grant.holder.validate()
            target, deadline = grant.effect.target, grant.effect.deadline
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

    def _row(self, target: Target) -> tuple[object, ...] | None:
        return self._db.execute(
            "SELECT scope,epoch,holder,phase,transition FROM leases WHERE browser=?",
            (target.binding.browser,),
        ).fetchone()

    def _input(self, grant: Input) -> None:
        target = grant.effect.target
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

    def journal(self, path: str | Path, site: Site) -> GuardedJournal:
        """Route both agent/human effects through the existing guarded Journal."""
        return GuardedJournal(path, authority=_InputAuthority(self), site=site,
                              clock=self._clock, max_age=self._max_age)

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

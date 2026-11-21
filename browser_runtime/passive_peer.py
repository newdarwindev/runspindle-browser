"""Stateless verification of scoped physical Browser observations."""

from __future__ import annotations

import hashlib
import time
from dataclasses import asdict, dataclass
from typing import Callable, ContextManager, Protocol

from browser_runtime.control_leases import PassiveStatus, _encode, _time
from browser_runtime.control_peer import core_scope
from browser_runtime.credentials import Observation, Target
from browser_runtime.effects import Cancelled, Denied, _fail


class PassiveGuard(Protocol):
    def admit(self, ticket: object) -> PassiveStatus | None:
        """Authenticate and consume a passive-only ticket under this guard."""
        ...

    def current(self, grant: PassiveStatus) -> bool:
        """Verify this exact admission remains current under the same guard."""
        ...

    def observe(self) -> Observation | None:
        """Read trusted physical metadata without any browser input."""
        ...


class PassiveAuthority(Protocol):
    def acquire(self) -> ContextManager[PassiveGuard]: ...


def selection_digest(target: Target) -> str:
    """Bind the result to the caller's complete selection, including revision."""
    if type(target) is not Target:
        raise ValueError
    target.validate()
    return hashlib.sha256(_encode(asdict(target)).encode("utf-8")).hexdigest()


def _scope_digest(target: Target) -> str:
    if type(target) is not Target:
        raise ValueError
    return hashlib.sha256(core_scope(target)).hexdigest()


def _grant_snapshot(grant: PassiveStatus) -> tuple[str, float]:
    grant.validate()
    return selection_digest(grant.target), _time(grant.deadline)


def _physical_snapshot(value: object) -> tuple[str, float]:
    if type(value) is not Observation:
        raise ValueError
    return _scope_digest(value.target), _time(value.observed_at)


@dataclass(frozen=True)
class PassiveObservation:
    """Historical physical metadata with no capability or ownership claim."""

    selection_sha256: str
    scope_sha256: str
    observed_at: float
    checked_at: float


class PassivePeer:
    """Read physical metadata only. The application owns control state."""

    def __init__(
        self,
        authority: PassiveAuthority,
        *,
        clock: Callable[[], float] = time.monotonic,
        max_age: float = 5.0,
    ) -> None:
        self._authority = authority
        self._clock = clock
        self._max_age = _time(max_age)
        if not 0 < self._max_age <= 300:
            raise ValueError

    def observe(self, ticket: object, *, expected: Target) -> PassiveObservation:
        """Match an authenticated observation to the application's exact selection."""
        result = None
        cancelled = False
        validated = False
        try:
            selection = selection_digest(expected)
            expected_scope = _scope_digest(expected)
            with self._authority.acquire() as guard:
                try:
                    grant = guard.admit(ticket)
                    if type(grant) is not PassiveStatus:
                        raise ValueError
                    admitted = _grant_snapshot(grant)
                    wanted, deadline = admitted
                    if wanted != selection or guard.current(grant) is not True:
                        raise ValueError
                    started = _time(self._clock())
                    if started >= deadline or _grant_snapshot(grant) != admitted:
                        raise ValueError
                    physical = guard.observe()
                    snapshot = _physical_snapshot(physical)
                    scope, observed_at = snapshot
                    if (
                        scope != expected_scope
                        or _grant_snapshot(grant) != admitted
                        or guard.current(grant) is not True
                    ):
                        raise ValueError
                    verified_at = _time(self._clock())
                    if (
                        not started <= verified_at < deadline
                        or not 0 <= verified_at - observed_at <= self._max_age
                        or _physical_snapshot(physical) != snapshot
                        or _grant_snapshot(grant) != admitted
                    ):
                        raise ValueError
                    validated = True
                except BaseException as error:
                    cancelled = not isinstance(error, Exception)
                    raise
            # Also check after guard cleanup, which can delay, fail or change
            # callback-owned objects. A suppressed exception cannot reach here
            # with a complete observation and current grant.
            if not validated:
                raise ValueError
            checked_at = _time(self._clock())
            if (
                checked_at < verified_at
                or checked_at >= deadline
                or not 0 <= checked_at - observed_at <= self._max_age
                or selection_digest(expected) != selection
                or _grant_snapshot(grant) != admitted
                or _physical_snapshot(physical) != snapshot
            ):
                raise ValueError
            result = PassiveObservation(selection, scope, observed_at, checked_at)
        except BaseException as error:
            cancelled = cancelled or not isinstance(error, Exception)
        if result is None:
            if cancelled:
                _fail(Cancelled, "passive observation cancelled")
            _fail(Denied, "passive observation denied")
        return result

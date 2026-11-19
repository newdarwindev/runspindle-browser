"""Stateless trusted browser execution under external operation ownership.

Adapters are pinned by the trusted composition root, not selected by a ticket.
No production authentication, browser adapter or background service is installed.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import threading
import time
from dataclasses import asdict, dataclass
from typing import Callable, ContextManager, NoReturn, Protocol, cast

from browser_runtime.credentials import Observation, Target
from browser_runtime.effects import (
    Binding,
    Cancelled,
    Denied,
    Outcome,
    Readback,
)


@dataclass(frozen=True)
class Grant:
    target: Target
    payload_digest: str
    action: str
    deadline: float


class Guard(Protocol):
    def admit(self, ticket: object) -> Grant | None:
        """Authenticate a one-shot exact target/digest/action admission."""
        ...

    def observe(self) -> Observation | None: ...

    def current(self, grant: Grant) -> bool: ...


class Authority(Protocol):
    def acquire(self) -> ContextManager[Guard]:
        """Hold the actual browser/account/input fence through helper completion."""
        ...


class Site(Protocol):
    def submit(self, grant: Grant, payload: bytes, guard: Guard) -> object:
        """Use the held fence atomically at the input point; never navigate/fallback."""
        ...

    def readback(self, grant: Grant, guard: Guard) -> Readback:
        """Observe this exact target under the fence, without submitting anything."""
        ...


def _target_digest(grant: Grant) -> str:
    encoded = json.dumps(asdict(grant.target), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _time(value: object) -> float:
    if type(value) not in (int, float) or not math.isfinite(cast(float, value)):
        raise ValueError
    return float(cast(float, value))


def _fail(cancelled: bool) -> NoReturn:
    # Also clear an exception already active in the caller, not only our handlers.
    try:
        if cancelled:
            raise Cancelled("guarded effect cancelled")
        raise Denied("guarded effect denied")
    except (Denied, Cancelled) as error:
        error.__cause__ = None
        error.__context__ = None
        raise


class GuardedPeer:
    """No store, reservation or replay policy: the external owner controls dispatch.

    Only a trusted composition root may connect this peer to Core's retained
    operation registry and one-shot authority. Repeating an authorized dispatch
    can repeat an effect; wire bytes never supply that authority. Site adapters
    enforce the real atomic fence. Callbacks are trusted pure/non-reentrant
    observations, not a substitute for atomic browser control.
    """

    def __init__(
        self,
        *,
        authority: Authority | None = None,
        site: Site | None = None,
        clock: Callable[[], float] = time.monotonic,
        max_age: float = 1.0,
    ) -> None:
        self._lock = threading.Lock()
        self._authority = authority
        self._site = site
        self._clock = clock
        self._max_age = _time(max_age)
        if not 0 < self._max_age <= 60:
            raise Denied("invalid observation age")
        self._grant: Grant | None = None
        self._guard: Guard | None = None

    def _check(self) -> tuple[Grant, Guard]:
        grant, guard = self._grant, self._guard
        if type(grant) is not Grant or guard is None:
            raise ValueError
        if type(grant.target) is not Target:
            raise ValueError
        grant.target.validate()
        if (
            type(grant.payload_digest) is not str
            or re.fullmatch(r"[0-9a-f]{64}", grant.payload_digest) is None
            or type(grant.action) is not str
            or grant.action not in ("dispatch", "reconcile")
        ):
            raise ValueError
        deadline = _time(grant.deadline)
        observation = guard.observe()
        if type(observation) is not Observation or observation.target != grant.target:
            raise ValueError
        if type(observation.target) is not Target:
            raise ValueError
        observation.target.validate()
        observed_at = _time(observation.observed_at)
        current = guard.current(grant)
        now = _time(self._clock())  # Both trusted callbacks may block.
        if (
            current is not True
            or not 0 <= now - observed_at <= self._max_age
            or now >= deadline
        ):
            raise ValueError
        return grant, guard

    def _approve(self, binding: Binding, digest: str) -> bool:
        grant, _ = self._check()
        return binding == grant.target.binding and digest == grant.payload_digest

    def _submit(self, binding: Binding, payload: bytes) -> object:
        grant, guard = self._check()
        if (
            self._site is None
            or grant.action != "dispatch"
            or binding != grant.target.binding
            or hashlib.sha256(payload).hexdigest() != grant.payload_digest
        ):
            raise ValueError
        return self._site.submit(grant, payload, guard)

    def _readback(self, binding: Binding, digest: str) -> Readback:
        grant, guard = self._check()
        if (
            self._site is None
            or grant.action != "reconcile"
            or binding != grant.target.binding
            or digest != grant.payload_digest
        ):
            raise ValueError
        return self._site.readback(grant, guard)

    def _execute(self, action: str, grant: Grant, payload: bytes | None) -> Outcome:
        if action == "dispatch":
            if payload is None:
                raise ValueError
            try:
                self._submit(grant.target.binding, payload)
            except Exception:
                # The owner already reserved unknown before calling this peer.
                # Neither a return value nor a lost reply proves the site effect.
                pass
            self._check()
            return "unknown"
        try:
            observed = self._readback(grant.target.binding, grant.payload_digest)
            valid = (
                type(observed) is Readback
                and type(observed.binding) is Binding
                and observed.binding == grant.target.binding
                and observed.payload_digest == grant.payload_digest
                and type(observed.outcome) is str
                and observed.outcome in ("confirmed", "rejected")
                and type(observed.evidence_digest) is str
                and re.fullmatch(r"[0-9a-f]{64}", observed.evidence_digest) is not None
            )
        except Exception:
            valid = False
        self._check()
        return observed.outcome if valid else "unknown"

    def _run(
        self,
        ticket: object,
        action: str,
        payload: bytes | None,
        expected_target: Target | None = None,
        expected_digest: str | None = None,
    ) -> Outcome:
        if not self._lock.acquire(blocking=False):
            _fail(False)
        result: Outcome | None = None
        cancelled = False
        try:
            try:
                if self._authority is None or self._site is None:
                    raise ValueError
                with self._authority.acquire() as guard:
                    try:
                        self._guard = guard
                        self._grant = guard.admit(ticket)
                        grant, _ = self._check()
                        if grant.action != action:
                            raise ValueError
                        # Optional caller expectation narrows authenticated admission;
                        # it never supplies authority or selects an adapter.
                        if expected_target is not None or expected_digest is not None:
                            if type(expected_target) is not Target:
                                raise ValueError
                            expected_target.validate()
                            if (
                                type(expected_digest) is not str
                                or expected_target != grant.target
                                or expected_digest != grant.payload_digest
                            ):
                                raise ValueError
                        if action == "dispatch":
                            if (
                                type(payload) is not bytes
                                or hashlib.sha256(payload).hexdigest()
                                != grant.payload_digest
                            ):
                                raise ValueError
                        result = self._execute(action, grant, payload)
                    except BaseException as error:
                        cancelled = cancelled or not isinstance(error, Exception)
                        raise
            except BaseException as error:
                result = None
                cancelled = cancelled or not isinstance(error, Exception)
        finally:
            self._grant = None
            self._guard = None
            self._lock.release()
        if result is None or cancelled:
            _fail(cancelled)
        return result

    def dispatch(
        self,
        ticket: object,
        payload: bytes,
        *,
        expected_target: Target | None = None,
        expected_digest: str | None = None,
    ) -> Outcome:
        return self._run(ticket, "dispatch", payload, expected_target, expected_digest)

    def reconcile(
        self,
        ticket: object,
        *,
        expected_target: Target | None = None,
        expected_digest: str | None = None,
    ) -> Outcome:
        return self._run(ticket, "reconcile", None, expected_target, expected_digest)

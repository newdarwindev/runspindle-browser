"""Stateless Core-owned control executor; no reservation store or grant issuer.

The trusted application supplies retained Core transition bytes on reconciliation,
and an independent opaque native admission ticket. Wire bytes cannot mint either.
Core commits/deduplicates before dispatch; this peer intentionally cannot do so.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import asdict
from typing import Callable, ContextManager, Protocol, cast

from browser_runtime.control_leases import (
    Backend,
    FenceObservation,
    Inspector,
    Recovery,
    Transfer,
    _fail,
    _scope,
    _time,
)
from browser_runtime.credentials import Observation, Target
from browser_runtime.effect_wire import (
    EVIDENCE_CLASS,
    VERSION,
    _closed,
    _constant,
    _pairs,
    decode,
)

DOMAIN = "runspindle.browser-control.v1"
MAX_TRANSITION = 16384


class ControlGuard(Protocol):
    def admit(self, ticket: object) -> Transfer | Recovery | None: ...
    def current(self, grant: object) -> bool: ...
    def observe(self) -> Observation | None: ...
    def released(self, grant: Transfer | Recovery) -> bool: ...

    def initialization_proven(self, transfer: Transfer) -> bool:
        """Fresh native proof; not absence of a record or page-provided identity."""
        ...


class ControlAuthority(Protocol):
    def acquire(self) -> ContextManager[ControlGuard]: ...


def _closure_snapshot(observed: object) -> tuple[dict[str, object], float] | None:
    if (
        type(observed) is not FenceObservation
        or type(observed.transfer) is not Transfer
        or observed.previous_inputs_closed is not True
    ):
        return None
    try:
        observed.transfer.validate()
        return asdict(observed.transfer), _time(observed.observed_at)
    except (TypeError, ValueError):
        return None


def core_scope(target: Target) -> bytes:
    """Core serde_json canonical map bytes; leave legacy _scope unchanged."""
    target.validate()
    value = asdict(target)
    for key in ("intent", "revision", "operation", "epoch"):
        del value["binding"][key]
    raw = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    if len(raw) > 8192:
        raise ValueError
    return raw


def matches(payload: bytes, transfer: Transfer) -> None:
    """Validate typed Core payload against the independently authenticated grant."""
    transfer.validate()
    if type(payload) is not bytes or not 0 < len(payload) <= MAX_TRANSITION:
        raise ValueError
    value = _closed(
        json.loads(payload, object_pairs_hook=_pairs, parse_constant=_constant),
        {"version", "action", "source", "destination", "predecessor"},
    )
    binding = transfer.target.binding
    expected_intent = (
        "browser-control:" + hashlib.sha256(core_scope(transfer.target)).hexdigest()
    )
    if (
        value["version"] != DOMAIN
        or value["action"] != transfer.action
        or value["source"] != (asdict(transfer.source) if transfer.source else None)
        or value["destination"] != asdict(transfer.destination)
        or binding.intent != expected_intent
        or binding.revision != binding.epoch
    ):
        raise ValueError
    previous = value["predecessor"]
    if transfer.action == "initialize":
        if previous is not None:
            raise ValueError
    else:
        previous = _closed(previous, {"operation", "payload_digest", "generation"})
        if (
            type(previous["operation"]) is not str
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", previous["operation"])
            is None
            or previous["operation"] == binding.operation
            or type(previous["payload_digest"]) is not str
            or re.fullmatch(r"[0-9a-f]{64}", previous["payload_digest"]) is None
            or type(previous["generation"]) is not int
            or not 0 <= previous["generation"] <= 2**63 - 1
        ):
            raise ValueError
    # The predecessor's actual retained state is checked only by canonical Core.
    # This peer must not create a competing chain ledger.


class ControlPeer:
    def __init__(
        self,
        authority: ControlAuthority,
        backend: Backend,
        inspector: Inspector,
        *,
        clock: Callable[[], float] = time.monotonic,
        max_age: float = 5.0,
    ) -> None:
        self._authority = authority
        self._backend = backend
        self._inspector = inspector
        self._clock = clock
        self._max_age = _time(max_age)
        if not 0 < self._max_age <= 300:
            raise ValueError

    def _check(
        self,
        guard: ControlGuard,
        grant: Transfer | Recovery,
        admitted: dict[str, object],
    ) -> float:
        grant.validate()
        if asdict(grant) != admitted:
            raise ValueError
        transfer = grant if type(grant) is Transfer else cast(Recovery, grant).transfer
        if transfer.action == "handback" and guard.released(grant) is not True:
            raise ValueError
        if (
            transfer.action == "initialize"
            and guard.initialization_proven(transfer) is not True
        ):
            raise ValueError
        # Trusted pure observations under the real native fence, not independent
        # callbacks that mutate session state. Core's DB lock is not that fence.
        if guard.current(grant) is not True:
            raise ValueError
        observed = guard.observe()
        if type(observed) is not Observation or type(observed.target) is not Target:
            raise ValueError
        observed.target.validate()
        if _scope(observed.target) != _scope(transfer.target):
            raise ValueError
        now: float = _time(self._clock())
        if not 0 <= now - _time(observed.observed_at) <= self._max_age or now >= _time(
            grant.deadline
        ):
            raise ValueError
        grant.validate()
        if asdict(grant) != admitted:
            raise ValueError
        return now

    def exchange(self, raw: bytes, ticket: object, *, retained_payload: bytes) -> bytes:
        """One constrained request; Core supplies canonical bytes out of band.

        This is not a daemon or installed transport. Repeated authorized dispatch
        requests can repeat a fence: Core reservation is a mandatory predecessor.
        """
        request = decode(raw)
        failed = True
        cancelled = False
        outcome = "unknown"
        try:
            if (
                type(retained_payload) is not bytes
                or not 0 < len(retained_payload) <= MAX_TRANSITION
                or hashlib.sha256(retained_payload).hexdigest()
                != request.payload_digest
                or (
                    request.action == "dispatch" and request.payload != retained_payload
                )
            ):
                raise ValueError
            with self._authority.acquire() as guard:
                try:
                    admitted = guard.admit(ticket)
                    expected_type = (
                        Transfer if request.action == "dispatch" else Recovery
                    )
                    if type(admitted) is not expected_type:
                        raise ValueError
                    grant = cast(Transfer | Recovery, admitted)
                    transfer = (
                        grant
                        if type(grant) is Transfer
                        else cast(Recovery, grant).transfer
                    )
                    grant.validate()
                    if transfer.target != request.target:
                        raise ValueError
                    matches(retained_payload, transfer)
                    admitted_binding = asdict(grant)
                    admitted_transfer = asdict(transfer)
                    self._check(guard, grant, admitted_binding)
                    if request.action == "dispatch":
                        self._backend.fence(transfer, guard)
                        self._check(guard, grant, admitted_binding)
                        # Submission evidence never activates ownership here.
                    else:
                        observation = self._inspector.inspect(
                            cast(Recovery, grant), guard
                        )
                        closure = _closure_snapshot(observation)
                        now = self._check(guard, grant, admitted_binding)
                        if (
                            closure is not None
                            and closure[0] == admitted_transfer
                            and 0 <= now - closure[1] <= self._max_age
                            and _closure_snapshot(observation) == closure
                        ):
                            outcome = "confirmed"
                    failed = False
                except BaseException as error:
                    cancelled = cancelled or not isinstance(error, Exception)
                    raise
        except BaseException as error:
            failed = True
            cancelled = cancelled or not isinstance(error, Exception)
        if failed or cancelled:
            _fail(cancelled)
        return json.dumps(
            {
                "version": VERSION,
                "request_sha256": hashlib.sha256(raw).hexdigest(),
                "evidence_class": EVIDENCE_CLASS,
                "outcome": outcome,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

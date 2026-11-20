"""Opt-in lossy observations, never an authority record or exporter callback.

This producer is dependency-free. Actual OTel conversion/collector delivery is a
separate consumer boundary, not implemented by this Browser slice.
"""

from collections import deque
from dataclasses import dataclass
from enum import Enum
from threading import Lock
from time import time_ns

VERSION = "runspindle.telemetry.v1"
CAPACITY = 128


class Outcome(Enum):
    ACKNOWLEDGED = "acknowledged"
    ERROR = "error"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class Observation:
    outcome: Outcome
    started_ns: int
    ended_ns: int

    @property
    def operation(self) -> str:
        return "browser.credentials.resolve_and_inject"


class Buffer:
    """Trusted composition-root object; fixed capacity, no arbitrary callbacks.

    Contention/capacity loses records. No exact dropped counter is promised under
    contention. Drain is explicit and never invoked by credential operations.
    """

    def __init__(self) -> None:
        self._lock = Lock()
        self._records: deque[Observation] = deque()

    def _record(self, outcome: Outcome, started_ns: int) -> None:
        if not self._lock.acquire(blocking=False):
            return
        try:
            if len(self._records) < CAPACITY:
                self._records.append(Observation(outcome, started_ns, time_ns()))
        finally:
            self._lock.release()

    def drain(self) -> tuple[Observation, ...]:
        if not self._lock.acquire(blocking=False):
            return ()
        try:
            records = tuple(self._records)
            self._records.clear()
            return records
        finally:
            self._lock.release()

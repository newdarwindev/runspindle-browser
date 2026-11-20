"""Legacy durable compatibility adapter; new composition uses stateless GuardedPeer.

Existing journal files remain untouched until explicit migration/reconciliation.
"""

import time
from collections.abc import Callable
from pathlib import Path

from browser_runtime.effects import Journal, Outcome
from browser_runtime.guarded_peer import (
    Authority,
    Grant,
    Guard,
    GuardedPeer,
    Site,
    _fail,
    _target_digest,
)


class GuardedJournal(GuardedPeer):
    """Legacy owner adapter, not a second ledger for Core-owned operations."""

    def __init__(
        self,
        path: str | Path,
        *,
        authority: Authority | None = None,
        site: Site | None = None,
        clock: Callable[[], float] = time.monotonic,
        max_age: float = 1.0,
    ) -> None:
        super().__init__(authority=authority, site=site, clock=clock, max_age=max_age)
        self._journal = Journal(path, self._approve, self._submit, self._readback)

    def _execute(self, action: str, grant: Grant, payload: bytes | None) -> Outcome:
        if action == "dispatch":
            if payload is None:
                raise ValueError
            return self._journal.dispatch(
                grant.target.binding, payload, target_digest=_target_digest(grant)
            )
        return self._journal.reconcile(
            grant.target.binding,
            grant.payload_digest,
            target_digest=_target_digest(grant),
        )

    def close(self) -> None:
        if not self._lock.acquire(blocking=False):
            _fail(False)
        try:
            self._journal.close()
        finally:
            self._lock.release()


__all__ = ["Authority", "Grant", "Guard", "GuardedJournal", "Site"]

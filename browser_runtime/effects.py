"""Durable no-blind-retry journal with injected trusted site boundaries.

The journal never discovers credentials, opens network connections or infers
success from a submission acknowledgment. Adapters are trusted application code.
"""

import hashlib
import json
import re
import sqlite3
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable, Literal
from urllib.parse import urlsplit

from browser_runtime.effect_schema import SchemaRejected, open_journal

Outcome = Literal["unknown", "confirmed", "rejected"]


class Denied(ValueError):
    """Fixed-category error, never containing raw site responses or payloads."""


@dataclass(frozen=True)
class Binding:
    principal: str
    account: str
    browser: str
    tab: str
    intent: str
    revision: int
    operation: str
    epoch: int
    origin: str

    def encoded(self) -> str:
        for name in ("principal", "account", "browser", "tab", "intent", "operation"):
            value = getattr(self, name)
            if (
                type(value) is not str
                or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", value) is None
            ):
                raise Denied("invalid binding")
        for value in (self.revision, self.epoch):
            if type(value) is not int or not 1 <= value <= 2**63 - 1:
                raise Denied("invalid binding")
        value = urlsplit(self.origin)
        if (
            value.scheme != "https"
            or not value.hostname
            or value.username
            or value.password
            or value.path
            or value.query
            or value.fragment
        ):
            raise Denied("invalid origin")
        try:
            value.port
        except ValueError:
            raise Denied("invalid origin") from None
        return json.dumps(asdict(self), sort_keys=True, separators=(",", ":"))


@dataclass(frozen=True)
class Readback:
    binding: Binding
    payload_digest: str
    outcome: Outcome
    evidence_digest: str


class Journal:
    """One actual SQLite store serializes dispatch and readback adapter calls.

    One writer may call submit for a given operation. Crashes leave unknown;
    reopening never recovers a right to resend. The caller must bound adapter
    time and keep callbacks non-reentrant. This is not an atomic remote effect.
    """

    def __init__(
        self,
        path: str | Path,
        approve: Callable[[Binding, str], bool] | None = None,
        submit: Callable[[Binding, bytes], object] | None = None,
        observe: Callable[[Binding, str], Readback] | None = None,
    ) -> None:
        if not str(path) or str(path) == ":memory:" or str(path).startswith("file:"):
            raise Denied("persistent file required")
        self.approve = approve
        self.submit = submit
        self.observe = observe
        try:
            self.db = open_journal(path)
        except SchemaRejected:
            raise Denied("journal schema rejected") from None
        except (sqlite3.Error, OSError):
            raise Denied("journal unavailable") from None

    def close(self) -> None:
        self.db.close()

    def _authorized(self, binding: Binding, digest: str) -> None:
        try:
            if self.approve is None or self.approve(binding, digest) is not True:
                raise Denied("authority unavailable")
        except Exception:
            raise Denied("authority unavailable") from None

    def _begin(self) -> None:
        try:
            self.db.execute("BEGIN IMMEDIATE")
        except sqlite3.Error:
            raise Denied("journal unavailable") from None

    def dispatch(self, binding: Binding, payload: bytes) -> Outcome:
        encoded = binding.encoded()
        if type(payload) is not bytes or not payload or len(payload) > 1048576:
            raise Denied("invalid payload")
        digest = hashlib.sha256(payload).hexdigest()
        self._authorized(binding, digest)
        if self.submit is None:
            raise Denied("site adapter unavailable")
        self._begin()
        try:
            row = self.db.execute(
                "SELECT binding,digest,outcome FROM operations WHERE operation=?",
                (binding.operation,),
            ).fetchone()
            if row is not None:
                if (row[0], row[1]) != (encoded, digest):
                    raise Denied("conflicting operation")
                self.db.execute("ROLLBACK")
                return self._outcome(row[2])
            self.db.execute(
                "INSERT INTO operations VALUES (?,?,?,'unknown',NULL)",
                (binding.operation, encoded, digest),
            )
            # Durable fence precedes *every* possible external call.
            self.db.execute("COMMIT")
        except BaseException:
            if self.db.in_transaction:
                self.db.execute("ROLLBACK")
            raise
        self._begin()
        try:
            row = self.db.execute(
                "SELECT outcome FROM operations WHERE operation=?", (binding.operation,)
            ).fetchone()
            if row is None:
                raise Denied("journal changed")
            outcome = self._outcome(row[0])
            if outcome != "unknown":
                return outcome
            self._authorized(binding, digest)
            try:
                self.submit(binding, payload)
            except Exception:
                # Including accepted-but-lost replies: never infer retry/success.
                pass
            return "unknown"
        finally:
            self.db.execute("ROLLBACK")

    @staticmethod
    def _outcome(value: object) -> Outcome:
        if value == "confirmed":
            return "confirmed"
        if value == "rejected":
            return "rejected"
        if value == "unknown":
            return "unknown"
        raise Denied("invalid journal state")

    def reconcile(self, binding: Binding, payload_digest: str) -> Outcome:
        encoded = binding.encoded()
        if re.fullmatch(r"[0-9a-f]{64}", payload_digest) is None:
            raise Denied("invalid digest")
        self._authorized(binding, payload_digest)
        if self.observe is None:
            raise Denied("readback adapter unavailable")
        self._begin()
        try:
            row = self.db.execute(
                "SELECT binding,digest,outcome FROM operations WHERE operation=?",
                (binding.operation,),
            ).fetchone()
            if row is None or (row[0], row[1]) != (encoded, payload_digest):
                raise Denied("unknown or conflicting operation")
            outcome = self._outcome(row[2])
            if outcome != "unknown":
                return outcome
            self._authorized(binding, payload_digest)
            try:
                observed = self.observe(binding, payload_digest)
                if (
                    type(observed) is not Readback
                    or type(observed.binding) is not Binding
                    or observed.binding.encoded() != encoded
                    or observed.payload_digest != payload_digest
                    or type(observed.outcome) is not str
                    or observed.outcome not in ("confirmed", "rejected")
                    or re.fullmatch(r"[0-9a-f]{64}", observed.evidence_digest) is None
                ):
                    return "unknown"
            except Exception:
                return "unknown"
            self._authorized(binding, payload_digest)
            self.db.execute(
                "UPDATE operations SET outcome=?, evidence=? WHERE operation=?",
                (observed.outcome, observed.evidence_digest, binding.operation),
            )
            self.db.execute("COMMIT")
            return observed.outcome
        finally:
            if self.db.in_transaction:
                self.db.execute("ROLLBACK")

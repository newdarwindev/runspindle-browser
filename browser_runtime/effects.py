"""Durable no-blind-retry journal with injected trusted site boundaries.

The journal never discovers credentials, opens network connections or infers
success from a submission acknowledgment. Adapters are trusted application code.
"""

import hashlib
import json
import re
import sqlite3
import threading
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable, Literal, NoReturn
from urllib.parse import urlsplit

from browser_runtime.effect_schema import (
    MAX_BINDING_BYTES,
    MAX_OPERATIONS,
    MAX_ORIGIN_BYTES,
    SchemaRejected,
    open_journal,
    retained_count,
    validate_retained,
)

Outcome = Literal["unknown", "confirmed", "rejected"]


class Denied(ValueError):
    """Fixed-category error, never containing raw site responses or payloads."""


class Cancelled(BaseException):
    """Fixed cancellation category. Stop and reconcile; never infer retry rights."""


def _fail(category: type[Denied] | type[Cancelled], message: str) -> NoReturn:
    # A caller may invoke us while already handling a secret-bearing exception.
    # Even a fresh raise outside our handlers would inherit that active context.
    try:
        raise category(message)
    except (Denied, Cancelled) as sanitized:
        sanitized.__cause__ = None
        sanitized.__context__ = None
        raise


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
        if (
            type(self.origin) is not str
            or len(self.origin) > MAX_ORIGIN_BYTES
            or len(self.origin.encode("utf-8")) > MAX_ORIGIN_BYTES
            or any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in self.origin)
        ):
            raise Denied("invalid origin")
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
        self._lock = threading.Lock()
        self._closed = True
        self.approve = approve
        self.submit = submit
        self.observe = observe
        failed = "journal unavailable"
        cancelled = False
        try:
            if (
                not str(path)
                or str(path) == ":memory:"
                or str(path).startswith("file:")
            ):
                raise Denied("persistent file required")
            self.db = open_journal(path)
            self._closed = False
        except SchemaRejected:
            failed = "journal schema rejected"
        except BaseException as error:
            cancelled = not isinstance(error, Exception)
        # Outside exception handlers: from None hides display, not __context__.
        if cancelled:
            _fail(Cancelled, "journal initialization cancelled")
        if self._closed:
            _fail(Denied, failed)

    def close(self) -> None:
        if not self._lock.acquire(blocking=False):
            _fail(Denied, "journal busy")
        failed = False
        cancelled = False
        try:
            if not self._closed:
                self._closed = True  # Never retry an uncertain connection close.
                try:
                    self.db.close()
                except BaseException as error:
                    failed = True
                    cancelled = not isinstance(error, Exception)
        finally:
            self._lock.release()
        if cancelled:
            _fail(Cancelled, "journal close cancelled")
        if failed:
            _fail(Denied, "journal close failed")

    def _run(self, operation: Callable[[], Outcome]) -> Outcome:
        if not self._lock.acquire(blocking=False):
            _fail(Denied, "journal busy")
        result: Outcome | None = None
        cancelled = False
        try:
            try:
                if self._closed:
                    raise Denied("journal closed")
                result = operation()
            except BaseException as error:
                cancelled = not isinstance(error, Exception)
            finally:
                if not self._closed:
                    try:
                        if self.db.in_transaction:
                            self.db.execute("ROLLBACK")
                    except BaseException as error:
                        result = None
                        cancelled = cancelled or not isinstance(error, Exception)
                        # Failed cleanup cannot leave this instance usable or
                        # release a callback into an uncertain transaction.
                        self._closed = True
                        try:
                            self.db.close()
                        except BaseException as error:
                            cancelled = cancelled or not isinstance(error, Exception)
        finally:
            self._lock.release()
        if cancelled:
            _fail(Cancelled, "journal operation cancelled")
        if result is None:
            _fail(Denied, "journal operation denied")
        return result

    def _authorized(self, binding: Binding, digest: str) -> None:
        try:
            if self.approve is None or self.approve(binding, digest) is not True:
                raise Denied("authority unavailable")
        except Exception:
            raise Denied("authority unavailable") from None

    def _begin(self) -> None:
        try:
            self.db.execute("BEGIN IMMEDIATE")
            validate_retained(self.db)
        except sqlite3.Error:
            raise Denied("journal unavailable") from None

    @staticmethod
    def _encoded(binding: Binding, target_digest: str | None) -> str:
        encoded = binding.encoded()
        if target_digest is None:
            return encoded  # Preserve legacy rows and callers exactly.
        if (
            type(target_digest) is not str
            or re.fullmatch(r"[0-9a-f]{64}", target_digest) is None
        ):
            raise Denied("invalid target commitment")
        wrapped = json.dumps(
            {"binding": json.loads(encoded), "target_digest": target_digest},
            sort_keys=True,
            separators=(",", ":"),
        )
        if len(wrapped.encode("utf-8")) > MAX_BINDING_BYTES:
            raise Denied("binding capacity")
        return wrapped

    def dispatch(
        self, binding: Binding, payload: bytes, *, target_digest: str | None = None
    ) -> Outcome:
        return self._run(lambda: self._dispatch(binding, payload, target_digest))

    def _dispatch(
        self, binding: Binding, payload: bytes, target_digest: str | None
    ) -> Outcome:
        encoded = self._encoded(binding, target_digest)
        if type(payload) is not bytes or not payload or len(payload) > 1048576:
            raise Denied("invalid payload")
        digest = hashlib.sha256(payload).hexdigest()
        self._authorized(binding, digest)
        if self.submit is None:
            raise Denied("site adapter unavailable")
        self._begin()
        row = self.db.execute(
            "SELECT binding,digest,outcome FROM operations WHERE operation=?",
            (binding.operation,),
        ).fetchone()
        if row is not None:
            if (row[0], row[1]) != (encoded, digest):
                raise Denied("conflicting operation")
            return self._outcome(row[2])
        if retained_count(self.db) >= MAX_OPERATIONS:
            raise Denied("journal capacity")
        self.db.execute(
            "INSERT INTO operations VALUES (?,?,?,'unknown',NULL)",
            (binding.operation, encoded, digest),
        )
        # Durable fence precedes *every* possible external call.
        self.db.execute("COMMIT")
        self._begin()
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

    @staticmethod
    def _outcome(value: object) -> Outcome:
        if value == "confirmed":
            return "confirmed"
        if value == "rejected":
            return "rejected"
        if value == "unknown":
            return "unknown"
        raise Denied("invalid journal state")

    def reconcile(
        self, binding: Binding, payload_digest: str, *, target_digest: str | None = None
    ) -> Outcome:
        return self._run(
            lambda: self._reconcile(binding, payload_digest, target_digest)
        )

    def _reconcile(
        self, binding: Binding, payload_digest: str, target_digest: str | None
    ) -> Outcome:
        encoded = self._encoded(binding, target_digest)
        if re.fullmatch(r"[0-9a-f]{64}", payload_digest) is None:
            raise Denied("invalid digest")
        self._authorized(binding, payload_digest)
        if self.observe is None:
            raise Denied("readback adapter unavailable")
        self._begin()
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
                or observed.binding.encoded() != binding.encoded()
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

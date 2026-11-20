"""Scoped manual-login save using KV mappings and external effect execution.

Trusted composition only. No browser extension, authority or capture adapter is
installed by default. Page/model dictionaries must never implement these seams.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from dataclasses import asdict, dataclass, field
from typing import Callable, Protocol, cast

from browser_runtime.credentials import Authority, Fence, Grant, Observation
from browser_runtime.effects import Binding, Cancelled, Outcome, Readback
from browser_runtime.openbao import (
    MAX_BODY,
    Mapping,
    Response,
    Vault,
    alive,
    check,
    number,
    object_value,
    pairs,
    reject_constant,
    version,
)

MARKER = "_runspindle_save_operation"


@dataclass(frozen=True, repr=False)
class Login:
    """Helper-private captured values, never an orchestration payload."""

    username: str = field(repr=False)
    password: str = field(repr=False)
    authenticated: bool = False


class Writer:
    """Reuses the existing mapping, scope, token and bounded JSON contracts.

    The supplied Vault is a private helper configured with STORE authority,
    separate from the Resolver's USE-authorized Vault. Both address the same
    OpenBao, not separate stores. transport is HTTPS.request or a synthetic peer.
    """

    def __init__(
        self,
        vault: Vault,
        transport: Callable[[str, str, str, float, bytes | None], Response],
    ) -> None:
        self.vault, self.transport = vault, transport

    def _request(
        self,
        grant: Grant,
        mapping: Mapping,
        method: str,
        body: bytes | None = None,
        expected: int | None = None,
        *,
        validate: Callable[[], None],
    ) -> dict[str, object]:
        validate()
        check(self.vault._scope(grant) == mapping)
        token = self.vault._token()
        check(
            type(token) is str
            and 0 < len(token) <= 4096
            and all(33 <= ord(c) <= 126 for c in token)
        )
        validate()
        check(self.vault._scope(grant) == mapping)
        validate()  # Last browser/consent gate follows all vault callbacks.
        remaining = number(grant.deadline) - number(self.vault._clock())
        check(remaining > 0)
        path = f"/v1/{mapping.mount}/data/{'/'.join(mapping.path)}"
        if expected is not None:
            version(expected)
            path += f"?version={expected}"
        reply = self.transport(
            method, path, token, min(self.vault._timeout, remaining), body
        )
        check(
            type(reply) is Response
            and type(reply.status) is int
            and reply.status == 200
            and type(reply.body) is bytes
            and 0 < len(reply.body) <= MAX_BODY
        )
        data = object_value(
            json.loads(
                reply.body.decode(),
                object_pairs_hook=pairs,
                parse_constant=reject_constant,
            )
        )
        validate()
        check(self.vault._scope(grant) == mapping)
        return object_value(data.get("data"))

    def write(
        self,
        grant: Grant,
        expected: int,
        marker: str,
        login: Login,
        validate: Callable[[], None],
    ) -> bool:
        # Called only inside Autosave's held authenticated browser fence.
        check(type(expected) is int and 0 <= expected < 2**63 - 1)
        check(type(login) is Login and login.authenticated is True)
        check(
            type(marker) is str
            and len(marker) == 64
            and all(c in "0123456789abcdef" for c in marker)
        )
        check(type(login.username) is str and 0 < len(login.username.encode()) <= 1024)
        check(type(login.password) is str and 0 < len(login.password.encode()) <= 16384)
        mapping = self.vault._scope(grant)
        check(mapping.field_name not in ("username", MARKER))
        values: dict[str, object] = {}
        if expected:
            previous = self._request(grant, mapping, "GET", validate=validate)
            metadata = object_value(previous.get("metadata"))
            alive(metadata)
            check(version(metadata.get("version")) == expected)
            values = object_value(previous.get("data")).copy()
            # A changed username is an account change, not an automatic update.
            check(values.get("username") == login.username)
            if values.get(mapping.field_name) == login.password:
                validate()
                return False  # Existing credential, no redundant vault version.
        values.update(
            {
                "username": login.username,
                mapping.field_name: login.password,
                MARKER: marker,
            }
        )
        body = json.dumps(
            {"options": {"cas": expected}, "data": values}, separators=(",", ":")
        ).encode()
        check(len(body) <= MAX_BODY)
        result = self._request(grant, mapping, "POST", body, validate=validate)
        check(version(result.get("version")) == expected + 1)
        return True

    def committed(
        self, grant: Grant, expected: int, marker: str, validate: Callable[[], None]
    ) -> bool:
        mapping = self.vault._scope(grant)
        # Read the exact candidate version even if a later authorized write won.
        result = self._request(
            grant, mapping, "GET", expected=expected + 1, validate=validate
        )
        metadata = object_value(result.get("metadata"))
        alive(metadata)
        check(version(metadata.get("version")) == expected + 1)
        return object_value(result.get("data")).get(MARKER) == marker


class EffectExecution(Protocol):
    """Externally owned persistence/admission; Browser owns no database lifecycle.

    The implementation must durably reserve the exact binding/payload commitment
    before calling submit, never replay an uncertain submission, and reconcile
    through observe. All callbacks run synchronously under the caller's fence;
    they may not be retained or invoked after execute returns. Secrets never
    enter payload. No default implementation, path, schema or storage is supplied.
    """

    def execute(
        self,
        *,
        binding: Binding,
        payload: bytes,
        target_digest: str,
        approve: Callable[[Binding, str], bool],
        submit: Callable[[Binding, bytes], None],
        observe: Callable[[Binding, str], Readback],
        reconcile_only: bool,
    ) -> Outcome: ...


class Autosave:
    """Normal login with standing scoped opt-in, no per-login dialog.

    consent returns the authorized expected KV version or None (deny). It must
    authenticate stored opt-in, selected account and create/update authority.
    capture runs in the trusted helper, never in agent orchestration. The owner
    injects durable effect execution; Browser never opens or manages its storage.
    """

    def __init__(
        self,
        effects: EffectExecution,
        *,
        authority: Authority,
        writer: Writer,
        consent: Callable[[Grant], int | None],
        capture: Callable[[Grant], Login],
        clock: Callable[[], float] = time.monotonic,
        max_age: float = 1.0,
    ) -> None:
        self.effects, self.authority, self.writer = effects, authority, writer
        self.consent, self.capture = consent, capture
        self.clock, self.max_age = clock, max_age

    def _check(self, fence: Fence, grant: Grant, expected: int) -> None:
        grant.target.validate()
        selected = self.consent(grant)
        check(type(selected) is int and selected == expected)
        observation = fence.observe()
        check(type(observation) is Observation and observation.target == grant.target)
        observation = cast(Observation, observation)
        check(fence.current(grant) is True)
        now = number(self.clock())
        check(0 <= number(self.max_age) <= 10)
        check(0 <= now - number(observation.observed_at) <= self.max_age)
        check(now < number(grant.deadline))

    def run(self, ticket: object, *, reconcile_only: bool = False) -> str:
        result = "not_saved"
        cancelled = False
        completed = False
        try:
            with self.authority.acquire() as fence:
                try:
                    admitted = fence.admit(ticket)
                    check(type(admitted) is Grant)
                    grant = cast(Grant, admitted)
                    selected = self.consent(grant)
                    check(type(selected) is int and 0 <= selected < 2**63 - 1)
                    expected = cast(int, selected)
                    self._check(fence, grant, expected)
                    # Secret-free commitment binds full native/frame target/reference
                    # and expected version; never a password digest.
                    payload = json.dumps(
                        {
                            "kind": "credential-save-v1",
                            "target": asdict(grant.target),
                            "reference": grant.reference,
                            "expected": expected,
                        },
                        sort_keys=True,
                        separators=(",", ":"),
                    ).encode()
                    marker = hashlib.sha256(payload).hexdigest()
                    binding = grant.target.binding

                    def approved(b: object, digest: str) -> bool:
                        self._check(fence, grant, expected)
                        return b == binding and digest == marker

                    unchanged = False

                    def submit(b: object, data: bytes) -> None:
                        nonlocal unchanged
                        check(b == binding and data == payload)
                        self._check(fence, grant, expected)
                        login = self.capture(grant)
                        try:
                            self._check(fence, grant, expected)
                            unchanged = not self.writer.write(
                                grant,
                                expected,
                                marker,
                                login,
                                lambda: self._check(fence, grant, expected),
                            )
                        finally:
                            # Reference cleanup, not a claim of memory zeroization.
                            del login

                    def observe(b: object, digest: str) -> Readback:
                        check(b == binding and digest == marker)
                        self._check(fence, grant, expected)
                        outcome: Outcome = "unknown"
                        if unchanged or self.writer.committed(
                            grant,
                            expected,
                            marker,
                            lambda: self._check(fence, grant, expected),
                        ):
                            outcome = "confirmed"
                        return Readback(binding, marker, outcome, marker)

                    callbacks_open = True
                    callback_thread = threading.get_ident()

                    def callback_scope() -> None:
                        check(
                            callbacks_open and threading.get_ident() == callback_thread
                        )

                    def guarded_approve(b: Binding, digest: str) -> bool:
                        nonlocal cancelled
                        try:
                            callback_scope()
                            return approved(b, digest)
                        except BaseException as error:
                            cancelled = cancelled or not isinstance(error, Exception)
                            raise

                    def guarded_submit(b: Binding, data: bytes) -> None:
                        nonlocal cancelled
                        try:
                            callback_scope()
                            submit(b, data)
                        except BaseException as error:
                            cancelled = cancelled or not isinstance(error, Exception)
                            raise

                    def guarded_observe(b: Binding, digest: str) -> Readback:
                        nonlocal cancelled
                        try:
                            callback_scope()
                            return observe(b, digest)
                        except BaseException as error:
                            cancelled = cancelled or not isinstance(error, Exception)
                            raise

                    # The external owner controls persistence and its lifecycle.
                    # Browser supplies only the guarded helper operations.
                    result = "unknown"
                    try:
                        outcome = self.effects.execute(
                            binding=binding,
                            payload=payload,
                            target_digest=marker,
                            approve=guarded_approve,
                            submit=guarded_submit,
                            observe=guarded_observe,
                            reconcile_only=reconcile_only,
                        )
                    finally:
                        callbacks_open = False
                    check(not cancelled)
                    check(outcome in ("confirmed", "rejected", "unknown"))
                    if outcome == "confirmed":
                        result = "saved"
                    self._check(fence, grant, expected)
                    completed = True
                except BaseException as error:
                    cancelled = cancelled or not isinstance(error, Exception)
                    raise
            check(completed)
            return result
        except BaseException as error:
            cancelled = cancelled or not isinstance(error, Exception)
        if cancelled:
            try:
                raise Cancelled("credential save cancelled; reconcile required")
            except Cancelled as error:
                error.__context__ = error.__cause__ = None
                raise
        # A transport/capture failure must not prevent the human's login.
        return "unknown" if result != "not_saved" else "not_saved"

"""Scoped resolver orchestration. No usable adapters are installed by default.

Construction is a trusted composition-root operation, never agent input. Concrete
adapters must implement authenticated admission and an atomic lease/browser fence.
An opaque vault handle, not plaintext, crosses into the pinned injection helper.
"""

import math
import re
from dataclasses import dataclass, field
from time import time_ns
from typing import Callable, ContextManager, NoReturn, Protocol, cast

from browser_runtime.effects import Binding, Cancelled
from browser_runtime.telemetry import Buffer, Outcome


class Denied(ValueError):
    """Fixed public error without provider exception context."""


def _fail(cancelled: bool = False) -> NoReturn:
    try:
        if cancelled:
            raise Cancelled("credential resolution cancelled")
        raise Denied("credential resolution denied")
    except (Cancelled, Denied) as error:
        error.__cause__ = error.__context__ = None
        raise


@dataclass(frozen=True)
class Target:
    binding: Binding
    native_session: str
    frame: str
    frame_origin: str

    def validate(self) -> None:
        if type(self.binding) is not Binding:
            raise ValueError
        self.binding.encoded()
        for value in (self.native_session, self.frame):
            if (
                type(value) is not str
                or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", value) is None
            ):
                raise ValueError
        # Reuse the runtime's origin contract, not the synthetic vault model.
        from dataclasses import replace

        replace(self.binding, origin=self.frame_origin).encoded()


@dataclass(frozen=True)
class Grant:
    target: Target
    reference: str = field(repr=False)
    deadline: float


def _time(value: object) -> float:
    if type(value) not in (int, float) or not math.isfinite(cast(float, value)):
        raise ValueError
    return float(cast(float, value))


def _target_binding(target: Target) -> tuple[str, str, str, str]:
    if type(target) is not Target or type(target.frame_origin) is not str:
        raise ValueError
    target.validate()
    return (
        target.binding.encoded(),
        target.native_session,
        target.frame,
        target.frame_origin,
    )


@dataclass(frozen=True, repr=False)
class _GrantBinding:
    target: tuple[str, str, str, str]
    reference: str
    deadline: float


def _grant_binding(grant: Grant) -> _GrantBinding:
    if type(grant) is not Grant or type(grant.reference) is not str:
        raise ValueError
    return _GrantBinding(
        _target_binding(grant.target), grant.reference, _time(grant.deadline)
    )


@dataclass(frozen=True)
class Observation:
    target: Target
    observed_at: float


class Fence(Protocol):
    """Trusted atomic guard against account, frame, navigation and epoch changes."""

    def admit(self, ticket: object) -> Grant | None:
        """Authenticate and consume the exact scoped one-shot admission ticket."""
        ...

    def observe(self) -> Observation | None:
        """Read authenticated host/browser state, never caller/page assertions."""
        ...

    def current(self, grant: Grant) -> bool:
        """Recheck revocation, lease and identity expiry under the same guard."""
        ...


class Authority(Protocol):
    def acquire(self) -> ContextManager[Fence]: ...


class Vault(Protocol):
    def read(self, grant: Grant) -> object:
        """Return an opaque helper-owned handle; no plaintext or raw response."""
        ...

    def current(self, handle: object, grant: Grant) -> bool: ...

    def release(self, handle: object) -> None: ...


class Helper(Protocol):
    def inject(self, handle: object, grant: Grant, fence: Fence) -> bool:
        """Atomically validate guard/target/version and use once; no redirects."""
        ...


@dataclass(frozen=True)
class AdapterSet:
    """Instances pinned by trusted construction; digest is a deployment pin.

    Matching strings do not authenticate code. The composition root must attest
    the digest and identities of these exact instances before creating this set.
    """

    digest: str
    authority: Authority = field(repr=False)
    vault: Vault = field(repr=False)
    helper: Helper = field(repr=False)


class Resolver:
    """One instance = one attempt, including denial, timeout and uncertainty.

    Restart/replay protection belongs to durable Core admission, not this flag.
    The resolver does not retry adapters or expose secret values/results.
    """

    def __init__(
        self,
        adapters: AdapterSet | None = None,
        *,
        expected_digest: str = "",
        clock: Callable[[], float] | None = None,
        max_age: float = 1.0,
        telemetry: Buffer | None = None,
    ) -> None:
        import time

        if telemetry is not None and type(telemetry) is not Buffer:
            raise TypeError("invalid telemetry buffer")
        self._telemetry = telemetry
        self._adapters = adapters
        self._expected_digest = expected_digest
        self._clock = clock if clock is not None else time.monotonic
        self._max_age = max_age
        self._attempted = False
        import threading

        self._lock = threading.Lock()

    def _check(self, fence: Fence, grant: Grant, binding: _GrantBinding) -> None:
        if _grant_binding(grant) != binding:
            raise ValueError
        observation = fence.observe()
        if (
            type(observation) is not Observation
            or _target_binding(observation.target) != binding.target
        ):
            raise ValueError
        observed_at = _time(observation.observed_at)
        # Both trusted callbacks may block. Preserve observe -> current order,
        # but never carry a pre-callback freshness/deadline sample into vault use.
        current = fence.current(grant)
        now = _time(self._clock())
        if (
            not 0 <= now - observed_at <= self._max_age
            or now >= binding.deadline
            or current is not True
            or _grant_binding(grant) != binding
        ):
            raise ValueError

    def resolve_and_inject(self, ticket: object) -> str:
        # No observer callback/exporter runs within the credential fence. Fixed
        # metadata only; exceptions/outcomes remain the original resolver's.
        buffer = self._telemetry
        if buffer is None:
            return self._resolve_and_inject(ticket)
        try:
            started = time_ns()
        except BaseException:
            return self._resolve_and_inject(ticket)
        outcome = Outcome.UNKNOWN
        try:
            result = self._resolve_and_inject(ticket)
            outcome = Outcome.ACKNOWLEDGED
            return result
        except Denied:
            outcome = Outcome.ERROR
            raise
        finally:
            try:
                Buffer._record(buffer, outcome, started)
            except BaseException:
                # Observation failure must never alter effect or cancellation.
                pass

    def _resolve_and_inject(self, ticket: object) -> str:
        # Serialize admission before any adapter callback; recursive use denies.
        with self._lock:
            attempted = self._attempted
            self._attempted = True
        if attempted:
            _fail()
        success = False
        completed = False
        cancelled = False
        try:
            adapters = self._adapters
            if (
                type(adapters) is not AdapterSet
                or type(self._expected_digest) is not str
                or re.fullmatch(r"[0-9a-f]{64}", self._expected_digest) is None
                or adapters.digest != self._expected_digest
                or _time(self._max_age) < 0
            ):
                raise ValueError
            with adapters.authority.acquire() as fence:
                try:
                    grant = fence.admit(ticket)
                    if type(grant) is not Grant:
                        raise ValueError
                    binding = _grant_binding(grant)
                    if (
                        re.fullmatch(
                            r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", binding.reference
                        )
                        is None
                    ):
                        raise ValueError
                    self._check(fence, grant, binding)
                    handle = adapters.vault.read(grant)
                    try:
                        try:
                            # Check after retrieval AND version validation. No caller may
                            # replace target/ref/epoch or supply its own observations.
                            self._check(fence, grant, binding)
                            if adapters.vault.current(handle, grant) is not True:
                                raise ValueError
                            self._check(fence, grant, binding)
                            if adapters.helper.inject(handle, grant, fence) is not True:
                                raise ValueError
                        except BaseException as error:
                            cancelled = not isinstance(error, Exception)
                            raise
                    finally:
                        adapters.vault.release(handle)
                    # A guard may suppress exceptions. Only explicit injection AND
                    # successful handle release can establish completion.
                    completed = True
                except BaseException as error:
                    cancelled = cancelled or not isinstance(error, Exception)
                    raise
            success = completed
        except BaseException as error:
            cancelled = cancelled or not isinstance(error, Exception)
        # Raised outside the handler: provider exception is not __context__.
        if cancelled:
            _fail(True)
        if not success:
            _fail()
        return "injected"

"""Scoped resolver orchestration. No usable adapters are installed by default.

Construction is a trusted composition-root operation, never agent input. Concrete
adapters must implement authenticated admission and an atomic lease/browser fence.
An opaque vault handle, not plaintext, crosses into the pinned injection helper.
"""

import math
import re
from dataclasses import dataclass, field
from typing import Callable, ContextManager, Protocol, cast

from browser_runtime.effects import Binding


class Denied(ValueError):
    """Fixed public error without provider exception context."""


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
    ) -> None:
        import time

        self._adapters = adapters
        self._expected_digest = expected_digest
        self._clock = clock if clock is not None else time.monotonic
        self._max_age = max_age
        self._attempted = False
        import threading

        self._lock = threading.Lock()

    @staticmethod
    def _time(value: object) -> float:
        if type(value) not in (int, float) or not math.isfinite(cast(float, value)):
            raise ValueError
        return float(cast(float, value))

    def _check(self, fence: Fence, grant: Grant) -> None:
        observation = fence.observe()
        now = self._time(self._clock())
        if (
            type(observation) is not Observation
            or type(observation.target) is not Target
            or observation.target != grant.target
            or not 0 <= now - self._time(observation.observed_at) <= self._max_age
            or now >= self._time(grant.deadline)
            or fence.current(grant) is not True
        ):
            raise ValueError
        observation.target.validate()

    def resolve_and_inject(self, ticket: object) -> str:
        # Serialize admission before any adapter callback; recursive use denies.
        with self._lock:
            attempted = self._attempted
            self._attempted = True
        if attempted:
            raise Denied("credential resolution denied")
        success = False
        completed = False
        try:
            adapters = self._adapters
            if (
                type(adapters) is not AdapterSet
                or type(self._expected_digest) is not str
                or re.fullmatch(r"[0-9a-f]{64}", self._expected_digest) is None
                or adapters.digest != self._expected_digest
                or self._time(self._max_age) < 0
            ):
                raise ValueError
            with adapters.authority.acquire() as fence:
                grant = fence.admit(ticket)
                if type(grant) is not Grant or type(grant.target) is not Target:
                    raise ValueError
                grant.target.validate()
                if (
                    type(grant.reference) is not str
                    or re.fullmatch(
                        r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", grant.reference
                    )
                    is None
                ):
                    raise ValueError
                self._check(fence, grant)
                handle = adapters.vault.read(grant)
                try:
                    # Check after retrieval AND version validation. No caller may
                    # replace target/ref/epoch or supply its own observations.
                    self._check(fence, grant)
                    if adapters.vault.current(handle, grant) is not True:
                        raise ValueError
                    self._check(fence, grant)
                    if adapters.helper.inject(handle, grant, fence) is not True:
                        raise ValueError
                finally:
                    adapters.vault.release(handle)
                # A guard may suppress exceptions. Only explicit injection AND
                # successful handle release can establish completion.
                completed = True
            success = completed
        except Exception:
            pass
        # Raised outside the handler: provider exception is not __context__.
        if not success:
            raise Denied("credential resolution denied")
        return "injected"

"""Offline synthetic vault and observation fixtures. Never use real secrets.

Scope values are test configuration, not authenticated caller authority. This
module opens no listener, resolves no real credentials and performs no I/O.
"""

from collections import deque
from dataclasses import dataclass, field
from typing import Callable
from urllib.parse import urlsplit


class Denied(ValueError):
    """A bounded synthetic operation was denied; messages contain no input."""


def origin(value: str) -> None:
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        raise Denied("invalid synthetic origin")
    try:
        parsed.port
    except ValueError:
        raise Denied("invalid synthetic origin") from None


@dataclass(frozen=True)
class Scope:
    principal: str
    account: str
    top_origin: str
    frame_origin: str
    operation: str
    session: str
    epoch: int

    def validate(self) -> None:
        for value in (self.principal, self.account, self.operation, self.session):
            if not isinstance(value, str) or not value or len(value) > 128:
                raise Denied("invalid synthetic identity")
        origin(self.top_origin)
        origin(self.frame_origin)
        if type(self.epoch) is not int or self.epoch < 1:
            raise Denied("invalid synthetic epoch")


@dataclass(frozen=True)
class Observation:
    scope: Scope
    at: int


@dataclass(frozen=True)
class Secret:
    value: str = field(repr=False)
    version: int


@dataclass(frozen=True)
class Entry:
    scope: Scope
    secret: Secret = field(repr=False)
    expires_at: int


@dataclass(frozen=True)
class _Read:
    entry: Entry = field(repr=False)
    generation: int


class ScriptedObservations:
    """Explicit finite observations; exhaustion never repeats old identity."""

    def __init__(self, observations: list[Observation | None]) -> None:
        self.remaining = deque(observations)
        self.calls = 0

    def __call__(self) -> Observation | None:
        self.calls += 1
        return self.remaining.popleft() if self.remaining else None


class FakeVault:
    """Test-memory store; expiry belongs to synthetic identity, not retention."""

    def __init__(self, clock: Callable[[], int]) -> None:
        self.clock = clock
        self.entries: dict[str, Entry] = {}
        self._generations: dict[str, int] = {}
        self.audit: list[str] = []
        self.fault = "none"

    def put(self, reference: str, entry: Entry) -> None:
        entry.scope.validate()
        if (
            not reference
            or type(entry.secret.version) is not int
            or entry.secret.version < 1
        ):
            raise Denied("invalid synthetic fixture")
        self.entries[reference] = entry
        self._generations[reference] = self._generations.get(reference, 0) + 1

    def read(self, reference: str, scope: Scope) -> object:
        self.audit.append("read_attempt")
        entry = self.entries.get(reference)
        if entry is None or entry.scope != scope or self.clock() >= entry.expires_at:
            raise Denied("synthetic vault denial")
        if self.fault in ("denied", "outage", "timeout"):
            raise Denied("synthetic vault unavailable")
        if self.fault == "malformed":
            return {"unexpected": entry.secret.value}
        if self.fault != "none":
            raise Denied("invalid synthetic fault")
        self.audit.append("read_allowed")
        return _Read(entry, self._generations[reference])

    def revalidate(self, reference: str, scope: Scope, read: _Read) -> None:
        """Fence sequential forgetting, rotation and expiry during observations."""
        now = self.clock()
        current = self.entries.get(reference)
        if (
            current is not read.entry
            or self._generations.get(reference) != read.generation
            or current.scope != scope
            or type(now) is not int
            or now >= current.expires_at
            or self.fault != "none"
        ):
            raise Denied("synthetic vault changed")

    def forget(self, reference: str) -> None:
        self.entries.pop(reference, None)
        self._generations[reference] = self._generations.get(reference, 0) + 1
        self.audit.append("credential_forgotten")


def resolve_and_inject(
    expected: Scope,
    reference: str,
    observe: Callable[[], Observation | None],
    vault: FakeVault,
    inject: Callable[[Secret], None],
    clock: Callable[[], int],
    max_age: int = 1,
) -> str:
    """Synthetic harness only. Callbacks are trusted test dependencies.

    No atomic browser/lease fence or secret zeroization is provided. Real use
    requires authenticated observers, a trusted helper and core/host integration.
    """
    try:
        expected.validate()
        if type(max_age) is not int or max_age < 0:
            raise Denied("invalid observation freshness")

        def observation() -> Observation:
            value = observe()
            now = clock()
            if (
                type(value) is not Observation
                or type(value.at) is not int
                or type(now) is not int
                or not 0 <= now - value.at <= max_age
            ):
                raise Denied("synthetic observation unavailable")
            value.scope.validate()
            return value

        first = observation()
        if first.scope != expected:
            raise Denied("synthetic scope mismatch")
        read = vault.read(reference, first.scope)
        if type(read) is not _Read:
            raise Denied("synthetic vault malformed")
        secret = read.entry.secret
        if (
            type(secret) is not Secret
            or type(secret.value) is not str
            or not secret.value
            or type(secret.version) is not int
            or secret.version < 1
        ):
            raise Denied("synthetic vault malformed")
        second = observation()
        if second.scope != expected:
            raise Denied("synthetic destination changed")
        vault.revalidate(reference, expected, read)
        inject(secret)
        return "injected"
    except Exception:
        # Do not propagate a callback's message, response, reference or traceback.
        raise Denied("synthetic resolution denied") from None

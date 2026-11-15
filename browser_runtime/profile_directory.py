"""Bounded POSIX directory IO for encrypted profiles, never a browser launcher.

Trusted helper only. All use goes through MaterializedStore so its permanent
ciphertext tombstone is checked before directory preparation/capture/consumption.
"""

from __future__ import annotations

import base64
import fcntl
import hashlib
import json
import math
import os
import re
import stat
import threading
import time
from pathlib import Path
from typing import Callable, TypeVar, cast

from browser_runtime.credentials import Observation
from browser_runtime.profile_schema import require, token
from browser_runtime.profile_store import (
    MAX_BYTES,
    Adapters,
    Authority,
    Cancelled,
    Denied,
    Grant,
    Guard,
    Keys,
    Result,
    Store,
    encoded,
)

MAX_DATA = 8 * 1024 * 1024
MAX_NODES = 512
MAX_DEPTH = 8
STATE = "state.json"
NEXT = "state.next"
LOCK = "profile.lock"
T = TypeVar("T")
Node = tuple[tuple[str, ...], bytes | None]
FIELDS = {
    "version",
    "scope",
    "phase",
    "owner",
    "epoch",
    "current",
    "candidate",
    "retired",
    "digest",
    "candidate_digest",
}


def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def segment(value: object) -> str:
    require(type(value) is str)
    name = cast(str, value)
    require(name not in ("", ".", "..") and len(name.encode("utf-8")) <= 128)
    require(name.isprintable() and "/" not in name and "\\" not in name)
    return name


def generation(value: object) -> str:
    require(type(value) is str and re.fullmatch(r"[0-9a-f]{32}", value) is not None)
    return cast(str, value)


def digest(value: object) -> str:
    require(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None)
    return cast(str, value)


def root_fd(directory: Path) -> int:
    raw = str(directory)
    require(directory.is_absolute() and ".." not in raw.split("/"))
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in directory.parts[1:]:
            new = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = new
        return fd
    except BaseException:
        os.close(fd)
        raise


def stamp(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_uid,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


class DirectoryProfileIO:
    """One immutable scope/root binding. Descriptor-relative operations only.

    Pending transitions deny further use until scoped recovery succeeds. Same-UID
    hostile actors, power-cut durability and real browser compatibility are not
    qualified. Generations may contain plaintext until cleanup/recovery completes.
    """

    def __init__(
        self,
        directory: str | Path,
        selection: Grant,
        *,
        clock: Callable[[], float] = time.monotonic,
        max_age: float = 1.0,
    ) -> None:
        self._mutex = threading.Lock()
        self._closed = False
        self._fd = -1
        self._lock_fd = -1
        ok = False
        cancelled = False
        try:
            require(os.name == "posix")
            selection.validate()
            self._scope = selection.scope()
            self._path = Path(directory)
            self._clock, self._max_age = clock, max_age
            require(
                type(max_age) in (int, float)
                and math.isfinite(max_age)
                and max_age >= 0
            )
            self._fd = root_fd(self._path)
            self._root_stat = os.fstat(self._fd)
            self._safe(self._root_stat, directory=True)
            names = set(self._names(self._fd, 8))
            require(not names or LOCK in names)
            self._lock_fd = self._open_file(LOCK, os.O_RDWR | os.O_CREAT)
            fcntl.flock(self._lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            try:
                names = set(self._names(self._fd, 8))
                if STATE not in names:
                    require(names <= {LOCK, NEXT})
                    if NEXT in names:
                        pending = self._read_state(NEXT)
                        require(pending == self._initial())
                    self._write_state(self._initial())
                self._read_state()
            finally:
                fcntl.flock(self._lock_fd, fcntl.LOCK_UN)
            ok = True
        except BaseException as error:
            cancelled = not isinstance(error, Exception)
        if not ok:
            for fd in (self._lock_fd, self._fd):
                if fd >= 0:
                    try:
                        os.close(fd)
                    except BaseException as error:
                        cancelled = cancelled or not isinstance(error, Exception)
            self._closed = True
            if cancelled:
                raise Cancelled("profile directory initialization cancelled")
            raise Denied("profile directory unavailable")

    def _safe(self, info: os.stat_result, *, directory: bool) -> None:
        require(info.st_uid == os.getuid() and info.st_dev == self._root_stat.st_dev)
        if directory:
            require(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700)
        else:
            require(
                stat.S_ISREG(info.st_mode)
                and stat.S_IMODE(info.st_mode) == 0o600
                and info.st_nlink == 1
            )

    @staticmethod
    def _names(fd: int, limit: int = MAX_NODES) -> list[str]:
        names: list[str] = []
        with os.scandir(fd) as entries:
            for entry in entries:
                names.append(entry.name)
                require(len(names) <= limit)
        return names

    def _open_file(self, name: str, flags: int, parent: int | None = None) -> int:
        fd = os.open(
            name,
            flags | os.O_NOFOLLOW | os.O_NONBLOCK,
            0o600,
            dir_fd=self._fd if parent is None else parent,
        )
        try:
            self._safe(os.fstat(fd), directory=False)
            return fd
        except BaseException:
            os.close(fd)
            raise

    def _directory(self, name: str, parent: int | None = None) -> int:
        fd = os.open(
            name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=self._fd if parent is None else parent,
        )
        try:
            self._safe(os.fstat(fd), directory=True)
            return fd
        except BaseException:
            os.close(fd)
            raise

    def _initial(self) -> dict[str, object]:
        return dict(
            version=1,
            scope=self._scope,
            phase="ready",
            owner=None,
            epoch=0,
            current=None,
            candidate=None,
            retired=None,
            digest=None,
            candidate_digest=None,
        )

    def _read_state(self, name: str = STATE) -> dict[str, object]:
        fd = self._open_file(name, os.O_RDONLY)
        try:
            data = os.read(fd, 8193)
            require(len(data) <= 8192)
        finally:
            os.close(fd)
        self._check_lock()
        state = json.loads(data, object_pairs_hook=unique_object)
        require(type(state) is dict and set(state) == FIELDS)
        require(
            type(state["version"]) is int
            and state["version"] == 1
            and state["scope"] == self._scope
        )
        require(type(state["epoch"]) is int and 0 <= state["epoch"] <= 2**63 - 1)
        require(
            state["owner"] is None
            or (type(state["owner"]) is str and len(state["owner"]) <= 512)
        )
        require((state["epoch"] == 0) == (state["owner"] is None))
        if state["owner"] is not None:
            owner = json.loads(state["owner"])
            require(type(owner) is list and len(owner) == 2)
            for item in owner:
                token(item)
            require(encoded(owner) == state["owner"])
        for key in ("current", "candidate", "retired"):
            if state[key] is not None:
                generation(state[key])
        ids = [
            state[k]
            for k in ("current", "candidate", "retired")
            if state[k] is not None
        ]
        require(len(ids) == len(set(ids)))
        for key in ("digest", "candidate_digest"):
            if state[key] is not None:
                digest(state[key])
        require((state["current"] is None) == (state["digest"] is None))
        require((state["candidate"] is None) == (state["candidate_digest"] is None))
        phase = state["phase"]
        require(
            type(phase) is str
            and phase in ("ready", "building", "cleanup", "forgotten", "discarding")
        )
        if phase == "ready":
            require(
                state["candidate"] is None
                and state["retired"] is None
                and state["candidate_digest"] is None
            )
        if phase == "building":
            require(
                state["candidate"] is not None
                and state["candidate_digest"] is not None
                and state["retired"] is None
            )
        if phase == "cleanup":
            require(
                state["current"] is not None
                and state["candidate"] is None
                and state["candidate_digest"] is None
            )
        if phase == "discarding":
            require(
                state["current"] is not None
                and state["candidate"] is None
                and state["retired"] is None
                and state["candidate_digest"] is None
            )
        self._inventory(state)
        return cast(dict[str, object], state)

    def _inventory(self, state: dict[str, object]) -> None:
        allowed = {LOCK, STATE, NEXT}
        for key in ("current", "retired"):
            if state[key] is not None:
                allowed.add("g-" + generation(state[key]))
        if state["candidate"] is not None:
            candidate = generation(state["candidate"])
            allowed.update(("stage-" + candidate, "g-" + candidate))
        names = set(self._names(self._fd, 8))
        require(names <= allowed)
        if state["candidate"] is not None:
            identifier = generation(state["candidate"])
            require(not {"stage-" + identifier, "g-" + identifier} <= names)
        for name in self._names(self._fd, 8):
            info = os.stat(name, dir_fd=self._fd, follow_symlinks=False)
            self._safe(info, directory=name.startswith(("g-", "stage-")))

    def _write_state(self, state: dict[str, object]) -> None:
        data = encoded(state).encode("ascii")
        require(len(data) <= 8192)
        # A previous incomplete metadata replacement contains no profile bytes.
        if NEXT in self._names(self._fd, 8):
            fd = self._open_file(NEXT, os.O_RDONLY)
            os.close(fd)
            os.unlink(NEXT, dir_fd=self._fd)
        fd = self._open_file(NEXT, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
        try:
            self._write(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(NEXT, STATE, src_dir_fd=self._fd, dst_dir_fd=self._fd)
        os.fsync(self._fd)

    @staticmethod
    def _write(fd: int, data: bytes) -> None:
        offset = 0
        while offset < len(data):
            written = os.write(fd, data[offset:])
            require(written > 0)
            offset += written

    def _check(self, grant: Grant, guard: Guard) -> None:
        grant.validate()
        require(grant.scope() == self._scope)
        require(guard.current(grant) is True and guard.quiescent(grant) is True)
        observed = guard.observe()
        now = self._clock()
        require(type(now) in (int, float) and math.isfinite(now))
        require(type(observed) is Observation and observed.target == grant.target)
        observed = cast(Observation, observed)
        require(
            type(observed.observed_at) in (int, float)
            and math.isfinite(observed.observed_at)
        )
        require(
            0 <= now - observed.observed_at <= self._max_age and now < grant.deadline
        )
        fd = root_fd(self._path)
        try:
            info = os.fstat(fd)
            self._safe(info, directory=True)
            require(
                (info.st_dev, info.st_ino)
                == (self._root_stat.st_dev, self._root_stat.st_ino)
            )
        finally:
            os.close(fd)
        self._check_lock()

    def _check_lock(self) -> None:
        named = os.stat(LOCK, dir_fd=self._fd, follow_symlinks=False)
        held = os.fstat(self._lock_fd)
        self._safe(named, directory=False)
        self._safe(held, directory=False)
        require((named.st_dev, named.st_ino) == (held.st_dev, held.st_ino))

    def _claim(self, grant: Grant) -> dict[str, object]:
        state = self._read_state()
        if grant.action == "discard":
            require(
                state["phase"] in ("ready", "discarding")
                and state["current"] == generation(grant.reference)
            )
        require(state["phase"] != "discarding" or grant.action in ("discard", "forget"))
        epoch = cast(int, state["epoch"])
        require(grant.target.binding.epoch >= epoch)
        require(grant.target.binding.epoch > epoch or grant.owner() == state["owner"])
        require(state["phase"] != "forgotten" or grant.action == "forget")
        state.update(owner=grant.owner(), epoch=grant.target.binding.epoch)
        self._write_state(state)
        return state

    def _run(
        self, grant: Grant, guard: Guard, action: str, operation: Callable[[], T]
    ) -> T:
        if not self._mutex.acquire(blocking=False):
            raise Denied("profile directory busy")
        result: T | None = None
        success = False
        locked = False
        entered = False
        cancelled = False
        try:
            try:
                require(not self._closed and grant.action == action)
                self._check(grant, guard)
                fcntl.flock(self._lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                locked = True
                self._check(grant, guard)
                self._claim(grant)
                entered = True
                if action not in ("forget", "discard"):
                    self._recover(grant, guard)
                result = operation()
                self._check(grant, guard)
                success = True
            except BaseException as error:
                cancelled = not isinstance(error, Exception)
                if entered:
                    try:
                        self._recover(grant, guard)
                    except BaseException:
                        pass  # Cleanup failure is pending, never successful erasure.
            finally:
                if locked:
                    try:
                        fcntl.flock(self._lock_fd, fcntl.LOCK_UN)
                    except BaseException as error:
                        cancelled = cancelled or not isinstance(error, Exception)
                        success = False
        finally:
            self._mutex.release()
        if cancelled:
            raise Cancelled("profile directory operation cancelled")
        if not success:
            raise Denied("profile directory operation denied")
        return cast(T, result)

    def _walk(
        self,
        parent: int,
        parts: tuple[str, ...],
        nodes: list[Node],
        stamps: dict[tuple[str, ...], tuple[int, ...]],
        *,
        contents: bool,
    ) -> None:
        require(len(parts) <= MAX_DEPTH)
        stamps[parts] = stamp(os.fstat(parent))
        for raw in sorted(self._names(parent)):
            path = (*parts, segment(raw))
            require(len(path) <= MAX_DEPTH and len(stamps) <= MAX_NODES)
            before = os.stat(raw, dir_fd=parent, follow_symlinks=False)
            if stat.S_ISDIR(before.st_mode):
                fd = self._directory(raw, parent)
                try:
                    require(stamp(os.fstat(fd)) == stamp(before))
                    nodes.append((path, None))
                    self._walk(fd, path, nodes, stamps, contents=contents)
                finally:
                    os.close(fd)
            else:
                fd = self._open_file(raw, os.O_RDONLY, parent)
                try:
                    require(
                        stamp(os.fstat(fd)) == stamp(before)
                        and before.st_size <= MAX_DATA
                    )
                    data = b""
                    if contents:
                        chunks: list[bytes] = []
                        total = 0
                        while True:
                            chunk = os.read(fd, min(65536, MAX_DATA + 1 - total))
                            if not chunk:
                                break
                            chunks.append(chunk)
                            total += len(chunk)
                            require(total <= MAX_DATA)
                        data = b"".join(chunks)
                        require(len(data) == before.st_size)
                    require(stamp(os.fstat(fd)) == stamp(before))
                    stamps[path] = stamp(before)
                    nodes.append((path, data))
                finally:
                    os.close(fd)
            require(len(nodes) <= MAX_NODES)
            if contents:
                require(
                    sum(len(value) for _, value in nodes if value is not None)
                    <= MAX_DATA
                )
        require(stamp(os.fstat(parent)) == stamps[parts])

    def _bundle(self, identifier: object, grant: Grant, guard: Guard) -> bytes:
        fd = self._directory("g-" + generation(identifier))
        try:
            nodes: list[Node] = []
            stamps: dict[tuple[str, ...], tuple[int, ...]] = {}
            self._walk(fd, (), nodes, stamps, contents=True)
            final: dict[tuple[str, ...], tuple[int, ...]] = {}
            self._walk(fd, (), [], final, contents=False)
            require(stamps == final)
        finally:
            os.close(fd)
        self._check(grant, guard)
        bundle = {
            "version": 1,
            "scope": self._scope,
            "directories": [list(p) for p, value in nodes if value is None],
            "files": [
                [list(p), base64.b64encode(value).decode("ascii")]
                for p, value in nodes
                if value is not None
            ],
        }
        data = encoded(bundle).encode("ascii")
        require(len(data) <= MAX_BYTES)
        return data

    def _decode(self, data: bytes) -> list[Node]:
        require(type(data) is bytes and 0 < len(data) <= MAX_BYTES)
        bundle = json.loads(data, object_pairs_hook=unique_object)
        require(
            type(bundle) is dict
            and set(bundle) == {"version", "scope", "directories", "files"}
        )
        require(
            type(bundle["version"]) is int
            and bundle["version"] == 1
            and bundle["scope"] == self._scope
        )
        require(type(bundle["directories"]) is list and type(bundle["files"]) is list)
        require(len(bundle["directories"]) + len(bundle["files"]) <= MAX_NODES)
        nodes: dict[tuple[str, ...], bytes | None] = {}
        total = 0
        for raw, value in [(path, None) for path in bundle["directories"]] + [
            (item[0], item[1])
            for item in bundle["files"]
            if type(item) is list and len(item) == 2
        ]:
            require(type(raw) is list and 1 <= len(raw) <= MAX_DEPTH)
            path = tuple(segment(p) for p in raw)
            require(path not in nodes)
            content = None
            if value is not None:
                require(type(value) is str)
                content = base64.b64decode(value, validate=True)
                require(base64.b64encode(content).decode("ascii") == value)
                total += len(content)
                require(total <= MAX_DATA)
            nodes[path] = content
        require(len(nodes) == len(bundle["directories"]) + len(bundle["files"]))
        require(
            sum(value is not None for value in nodes.values()) == len(bundle["files"])
        )
        for path in nodes:
            for length in range(1, len(path)):
                require(path[:length] in nodes and nodes[path[:length]] is None)
        require(bundle["directories"] == sorted(bundle["directories"]))
        require(bundle["files"] == sorted(bundle["files"], key=lambda item: item[0]))
        require(encoded(bundle).encode("ascii") == data)
        return sorted(nodes.items(), key=lambda item: (len(item[0]), item[0]))

    def _remove(
        self,
        name: str,
        parent: int | None = None,
        *,
        depth: int = 0,
        count: list[int] | None = None,
    ) -> None:
        require(depth <= MAX_DEPTH)
        if count is None:
            count = [0]
        directory = self._fd if parent is None else parent
        if name not in self._names(directory):
            return
        fd = self._directory(name, directory)
        try:
            for child in self._names(fd):
                count[0] += 1
                require(count[0] <= MAX_NODES)
                segment(child)
                info = os.stat(child, dir_fd=fd, follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    self._remove(child, fd, depth=depth + 1, count=count)
                else:
                    stream = self._open_file(child, os.O_RDONLY, fd)
                    os.close(stream)
                    os.unlink(child, dir_fd=fd)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.rmdir(name, dir_fd=directory)
        os.fsync(directory)

    def _recover(self, grant: Grant, guard: Guard) -> None:
        self._check(grant, guard)
        state = self._read_state()
        phase = state["phase"]
        # Only a fresh, exact discard admission may resume nonterminal cleanup.
        # In particular, failed save/restore admission cannot delete plaintext.
        if phase == "discarding":
            require(
                grant.action == "discard"
                and state["current"] == generation(grant.reference)
            )
        if phase in ("building", "forgotten"):
            if state["candidate"] is not None:
                candidate = generation(state["candidate"])
                self._remove("stage-" + candidate)
                self._remove("g-" + candidate)
            state.update(candidate=None, candidate_digest=None)
        if phase == "cleanup":
            require(
                hashlib.sha256(self._bundle(state["current"], grant, guard)).hexdigest()
                == state["digest"]
            )
        if phase in ("cleanup", "forgotten") and state["retired"] is not None:
            self._remove("g-" + generation(state["retired"]))
            state["retired"] = None
        if phase in ("forgotten", "discarding") and state["current"] is not None:
            self._remove("g-" + generation(state["current"]))
            state.update(current=None, digest=None)
        if phase in ("building", "cleanup", "discarding"):
            state["phase"] = "ready"
        self._check(grant, guard)
        self._write_state(state)
        self._inventory(state)

    def capture(self, grant: Grant, guard: Guard) -> bytes:
        return self._run(
            grant,
            guard,
            "save",
            lambda: self._bundle(self._read_state()["current"], grant, guard),
        )

    def consume(self, grant: Grant, guard: Guard, plaintext: bytes) -> bool:
        def materialize() -> bool:
            nodes = self._decode(plaintext)  # All validation before plaintext writes.
            state = self._read_state()
            require(state["phase"] == "ready")
            candidate = os.urandom(16).hex()
            require(
                "g-" + candidate not in self._names(self._fd, 8)
                and "stage-" + candidate not in self._names(self._fd, 8)
            )
            state.update(
                phase="building",
                candidate=candidate,
                candidate_digest=hashlib.sha256(plaintext).hexdigest(),
            )
            self._check(grant, guard)
            self._write_state(state)
            os.mkdir("stage-" + candidate, 0o700, dir_fd=self._fd)
            os.fsync(self._fd)
            fd = self._directory("stage-" + candidate)
            try:
                for path, data in nodes:
                    self._check(grant, guard)
                    parent = os.dup(fd)
                    try:
                        for part in path[:-1]:
                            nested = self._directory(part, parent)
                            os.close(parent)
                            parent = nested
                        if data is None:
                            os.mkdir(path[-1], 0o700, dir_fd=parent)
                        else:
                            stream = self._open_file(
                                path[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL, parent
                            )
                            try:
                                self._write(stream, data)
                                os.fsync(stream)
                            finally:
                                os.close(stream)
                        os.fsync(parent)
                    finally:
                        os.close(parent)
                os.fsync(fd)
            finally:
                os.close(fd)
            self._check(grant, guard)
            os.rename(
                "stage-" + candidate,
                "g-" + candidate,
                src_dir_fd=self._fd,
                dst_dir_fd=self._fd,
            )
            os.fsync(self._fd)
            state.update(
                phase="cleanup",
                current=candidate,
                retired=state["current"],
                digest=state["candidate_digest"],
                candidate=None,
                candidate_digest=None,
            )
            self._check(grant, guard)
            self._write_state(
                state
            )  # Atomic reference publication, not browser activation.
            self._recover(grant, guard)
            return True

        return self._run(grant, guard, "restore", materialize)

    def _prepare(self, grant: Grant, guard: Guard) -> None:
        # Only MaterializedStore calls this, after checking its SQLite tombstone.
        self._run(grant, guard, "restore", lambda: None)

    def forget(self, grant: Grant, guard: Guard) -> None:
        def discard() -> None:
            state = self._read_state()
            state["phase"] = "forgotten"
            self._check(grant, guard)
            self._write_state(
                state
            )  # Deny resurrection even if recursive cleanup fails.
            self._recover(grant, guard)

        self._run(grant, guard, "forget", discard)

    def discard(self, grant: Grant, guard: Guard) -> None:
        def discard_current() -> None:
            state = self._read_state()
            require(
                state["phase"] in ("ready", "discarding")
                and state["current"] == generation(grant.reference)
            )
            state["phase"] = "discarding"
            self._check(grant, guard)
            self._write_state(state)  # Record the exact target before any removal.
            self._recover(grant, guard)

        self._run(grant, guard, "discard", discard_current)

    def close(self) -> None:
        if not self._mutex.acquire(blocking=False):
            raise Denied("profile directory busy")
        failed = False
        cancelled = False
        try:
            if not self._closed:
                self._closed = True
                # Never retry an uncertain close: the descriptor may be reused.
                for fd in (self._lock_fd, self._fd):
                    try:
                        os.close(fd)
                    except BaseException as error:
                        failed = True
                        cancelled = cancelled or not isinstance(error, Exception)
        finally:
            self._mutex.release()
        if cancelled:
            raise Cancelled("profile directory close cancelled")
        if failed:
            raise Denied("profile directory close failed")


class MaterializedStore(Store):
    """Explicit combined component; no active-path or browser-launch capability.

    Restore checks the encrypted tombstone before even directory recovery. Forget
    commits ciphertext deletion first; a crash before directory cleanup is partial,
    blocks restore, and needs fresh forget admission. Base Store forgetting is unchanged.
    Explicit discard removes only one admitted materialization and retains every
    encrypted checkpoint; it never grants a browser/path capability.
    """

    def __init__(
        self,
        directory: str | Path,
        authority: Authority,
        keys: Keys,
        tree: DirectoryProfileIO,
    ) -> None:
        self._tree = tree
        super().__init__(directory, Adapters(authority, keys, tree))

    def _restore(self, adapters: Adapters, guard: Guard, grant: Grant) -> Result:
        self._begin(guard, grant)
        self._claim(grant)  # Mandatory encrypted tombstone gate before tree recovery.
        self._checkpoint(grant)
        self._tree._prepare(grant, guard)
        self._check(guard, grant)
        self._db.execute("COMMIT")
        return super()._restore(adapters, guard, grant)

    def _forget(self, guard: Guard, grant: Grant) -> Result:
        super()._forget(guard, grant)  # Durable permanent tombstone precedes all IO.
        self._tree.forget(grant, guard)
        self._check(guard, grant)
        return "forgotten"

    def _discard(self, guard: Guard, grant: Grant) -> Result:
        self._begin(guard, grant)
        self._claim(grant)  # No cleanup of unenrolled or permanently forgotten data.
        self._tree.discard(grant, guard)
        self._check(guard, grant)
        self._db.execute("COMMIT")
        return "discarded"

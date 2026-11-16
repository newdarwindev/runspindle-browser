"""Local profile-key leases with a version-pinned OpenBao material source.

Trusted internal composition only. Not credential Vault, browser authority,
provisioning, distributed fencing, or immediate remote key revocation.
"""

from __future__ import annotations

import base64
import hashlib
import json
import sqlite3
import threading
import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterator, cast

from browser_runtime import openbao
from browser_runtime.effects import Binding
from browser_runtime.profile_custody_schema import GATE, LEASE, Location
from browser_runtime.profile_schema import require, token
from browser_runtime.profile_store import Cancelled, Denied, Grant, Key, encoded


@dataclass(frozen=True, repr=False)
class Mapping:
    store_id: str
    principal: str
    account: str
    profile: str
    origin: str
    frame_origin: str
    mount: str
    path: tuple[str, ...]
    field_name: str
    kv_version: int
    fingerprint: str = field(repr=False)
    save_key: bool

    def config(self) -> str:
        return str(encoded(asdict(self)))

    def key_id(self) -> str:
        return hashlib.sha256(self.config().encode("ascii")).hexdigest()

    def scope(self) -> str:
        return str(
            encoded(
                [
                    encoded([self.principal, self.account, self.profile]),
                    self.origin,
                    self.frame_origin,
                ]
            ),
        )

    def validate(self) -> None:
        token(self.store_id, hexadecimal=True)
        token(self.fingerprint, hexadecimal=True)
        for value in (self.principal, self.account, self.profile):
            token(value)
        for origin in (self.origin, self.frame_origin):
            require(type(origin) is str)
            Binding("p", "a", "b", "t", "i", 1, "o", 1, origin).encoded()
        require(type(self.path) is tuple and 0 < len(self.path) <= 8)
        for value in (self.mount, self.field_name, *self.path):
            openbao.segment(value)
        openbao.version(self.kv_version)
        require(type(self.save_key) is bool)


def manifest_digest(mappings: tuple[Mapping, ...]) -> str:
    return hashlib.sha256(
        encoded(sorted((m.key_id(), m.config()) for m in mappings)).encode("ascii")
    ).hexdigest()


class Keys:
    """Concrete cooperative local custody; no usable default or enrollment API.

    The trusted root pins the immutable registry digest and this exact instance.
    Only Store under its authenticated authority may call acquire. revoke is a
    separate trusted administrative API: it disables *new* leases, not issued
    ones, credentials or website sessions. All callbacks must be bounded.
    """

    def __init__(
        self,
        directory: str | Path,
        *,
        expected_manifest: str,
        transport: Callable[[str, str, float], openbao.Response],
        token_source: Callable[[], str],
        clock: Callable[[], float] = time.monotonic,
        timeout: float = 2.0,
    ) -> None:
        success = False
        try:
            token(expected_manifest, hexadecimal=True)
            require(0 < openbao.number(timeout) <= 10)
            self._location = Location(directory)
            self._expected = expected_manifest
            self._transport = transport
            self._token = token_source
            self._clock = clock
            self._timeout = timeout
            self._lock = threading.Lock()
            with self._gate() as db:
                self._registry(db)
            db = self._location.connect(LEASE)
            try:
                db.execute("BEGIN")
                self._location.inspect(db, LEASE)
            finally:
                db.close()
            success = True
        except Exception:
            pass
        if not success:
            raise Denied("profile custody unavailable")

    @contextmanager
    def _gate(self) -> Iterator[sqlite3.Connection]:
        db = self._location.connect(GATE)
        try:
            db.execute("BEGIN IMMEDIATE")
            self._location.inspect(db, GATE)
            yield db
            self._location.check()
            db.execute("COMMIT")
        finally:
            db.close()

    def _registry(self, db: sqlite3.Connection) -> dict[str, tuple[Mapping, bool]]:
        rows = db.execute(
            "SELECT key_id,config,disabled FROM registry ORDER BY key_id"
        ).fetchmany(257)
        require(0 < len(rows) <= 256)
        result: dict[str, tuple[Mapping, bool]] = {}
        fingerprints: set[str] = set()
        sources: set[tuple[object, ...]] = set()
        saves: set[tuple[str, str]] = set()
        for key_id, config, disabled in rows:
            require(type(config) is str and len(config) <= 8192)
            data = openbao.object_value(
                json.loads(
                    config,
                    object_pairs_hook=openbao.pairs,
                    parse_constant=openbao.reject_constant,
                )
            )
            require(type(data.get("path")) is list)
            data["path"] = tuple(cast(list[str], data["path"]))
            m = Mapping(**cast(dict[str, Any], data))
            m.validate()
            require(m.config() == config and m.key_id() == key_id)
            require(type(disabled) is int and disabled in (0, 1))
            source = (m.mount, m.path, m.field_name, m.kv_version)
            require(m.fingerprint not in fingerprints and source not in sources)
            fingerprints.add(m.fingerprint)
            sources.add(source)
            if m.save_key:
                scope = (m.store_id, m.scope())
                require(scope not in saves)
                saves.add(scope)
            result[key_id] = (m, disabled == 1)
        require(manifest_digest(tuple(m for m, _ in result.values())) == self._expected)
        return result

    def _time(self, grant: Grant) -> float:
        remaining = openbao.number(grant.deadline) - openbao.number(self._clock())
        require(remaining > 0)
        return float(remaining)

    def _enabled(self, db: sqlite3.Connection, m: Mapping, grant: Grant) -> None:
        require(self._registry(db).get(m.key_id()) == (m, False))
        self._time(grant)

    def _fetch(self, m: Mapping, grant: Grant) -> bytes:
        with self._gate() as db:
            self._enabled(db, m, grant)
        secret_token = self._token()
        require(
            type(secret_token) is str
            and 0 < len(secret_token) <= 4096
            and all(33 <= ord(c) <= 126 for c in secret_token)
        )
        # Token callbacks can revoke; a new gate snapshot must follow them.
        with self._gate() as db:
            self._enabled(db, m, grant)
        reply = self._transport(
            f"/v1/{m.mount}/data/{'/'.join(m.path)}?version={m.kv_version}",
            secret_token,
            min(self._timeout, self._time(grant)),
        )
        require(
            type(reply) is openbao.Response
            and type(reply.status) is int
            and reply.status == 200
            and type(reply.body) is bytes
            and 0 < len(reply.body) <= openbao.MAX_BODY
        )
        envelope = openbao.object_value(
            json.loads(
                reply.body.decode("utf-8"),
                object_pairs_hook=openbao.pairs,
                parse_constant=openbao.reject_constant,
            )
        )
        data = openbao.object_value(envelope.get("data"))
        metadata = openbao.object_value(data.get("metadata"))
        openbao.alive(metadata)
        require(openbao.version(metadata.get("version")) == m.kv_version)
        value = openbao.object_value(data.get("data")).get(m.field_name)
        require(type(value) is str and len(value) == 44)
        material = base64.b64decode(cast(str, value), validate=True)
        require(
            len(material) == 32 and base64.b64encode(material).decode("ascii") == value
        )
        require(hashlib.sha256(material).hexdigest() == m.fingerprint)
        self._time(grant)
        return material

    @contextmanager
    def acquire(
        self, store_id: str, grant: Grant, version: str | None
    ) -> Iterator[Key]:
        success = cancelled = False
        locked = False
        pending_created = False
        fence: sqlite3.Connection | None = None
        attempt: str | None = None
        material: bytes | None = None
        key: Key | None = None
        try:
            locked = self._lock.acquire(blocking=False)
            require(locked)
            token(store_id, hexadecimal=True)
            require(type(grant) is Grant)
            grant.validate()
            require(
                (grant.action == "save" and version is None)
                or (grant.action == "restore" and type(version) is str)
            )
            self._time(grant)
            fence = self._location.connect(LEASE)
            fence.execute("BEGIN IMMEDIATE")
            self._location.inspect(fence, LEASE)
            # Durable identity comes from the already authenticated full grant,
            # never a caller-supplied lease ID. Persist it before any provider effect.
            attempt = hashlib.sha256(
                encoded([store_id, grant.attempt()]).encode("ascii")
            ).hexdigest()
            with self._gate() as db:
                registry = self._registry(db)
                selected = [
                    m
                    for key_id, (m, disabled) in registry.items()
                    if m.store_id == store_id
                    and m.scope() == grant.scope()
                    and not disabled
                    and ((version is None and m.save_key) or key_id == version)
                ]
                require(len(selected) == 1)
                m = selected[0]
                self._time(grant)
                # Holding the real process fence proves no predecessor is active.
                db.execute(
                    "UPDATE attempts SET state='abandoned' WHERE state IN ('pending','issued')"
                )
                db.execute(
                    "INSERT INTO attempts VALUES (?,?,'pending')", (attempt, m.key_id())
                )
            pending_created = True
            material = self._fetch(m, grant)
            with self._gate() as db:
                self._enabled(db, m, grant)
                require(
                    db.execute(
                        "SELECT key_id,state FROM attempts WHERE attempt=?", (attempt,)
                    ).fetchone()
                    == (m.key_id(), "pending")
                )
                db.execute(
                    "UPDATE attempts SET state='issued' WHERE attempt=?", (attempt,)
                )
            # The preceding commit issues custody. Later disablement applies only
            # to new acquisitions; browser authority/deadline checks stay in Store.
            self._time(grant)
            key = Key(m.key_id(), material)
            yield key
            self._time(grant)
            success = True
        except BaseException as error:
            cancelled = not isinstance(error, Exception)
        finally:
            key = None
            material = None
            try:
                if pending_created and attempt is not None:
                    with self._gate() as db:
                        db.execute(
                            "UPDATE attempts SET state='released' WHERE attempt=? AND state IN ('pending','issued')",
                            (attempt,),
                        )
            except BaseException as error:
                success = False
                cancelled = cancelled or not isinstance(error, Exception)
            finally:
                try:
                    if fence is not None:
                        fence.close()
                except BaseException as error:
                    success = False
                    cancelled = cancelled or not isinstance(error, Exception)
                finally:
                    if locked:
                        self._lock.release()
        if cancelled:
            raise Cancelled("profile custody cancelled")
        if not success:
            raise Denied("profile custody denied")

    def revoke(self, key_id: str) -> str:
        """Trusted admin only. Terminally disable new local leases, not key deletion."""
        success = cancelled = False
        try:
            token(key_id, hexadecimal=True)
            with self._gate() as db:
                require(key_id in self._registry(db))
                db.execute("UPDATE registry SET disabled=1 WHERE key_id=?", (key_id,))
            success = True
        except BaseException as error:
            cancelled = not isinstance(error, Exception)
        if cancelled:
            raise Cancelled("profile custody cancelled")
        if not success:
            raise Denied("profile custody denied")
        return "new-leases-disabled"

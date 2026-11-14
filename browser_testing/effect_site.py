"""Independent synthetic site store; deliberately not idempotent."""

import hashlib
import json
import os
import sqlite3
from dataclasses import asdict
from pathlib import Path

from browser_runtime.effects import Binding, Outcome, Readback


class Site:
    def __init__(self, path: str | Path, fault: str = "none") -> None:
        self.path = path
        self.fault = fault
        with sqlite3.connect(path) as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS events (binding TEXT,digest TEXT,outcome TEXT)"
            )

    def submit(self, binding: Binding, payload: bytes) -> str:
        if self.fault == "crash_before":
            os._exit(17)
        encoded = json.dumps(asdict(binding), sort_keys=True)
        digest = hashlib.sha256(payload).hexdigest()
        with sqlite3.connect(self.path) as db:
            db.execute(
                "INSERT INTO events VALUES (?,?,?)",
                (
                    encoded,
                    digest,
                    "rejected" if self.fault == "reject" else "confirmed",
                ),
            )
        if self.fault == "crash_after":
            os._exit(18)
        if self.fault == "lost":
            raise OSError("synthetic lost response")
        return "transport acknowledgment only"

    def observe(self, binding: Binding, digest: str) -> Readback:
        encoded = json.dumps(asdict(binding), sort_keys=True)
        with sqlite3.connect(self.path) as db:
            rows = db.execute(
                "SELECT outcome FROM events WHERE binding=? AND digest=?",
                (encoded, digest),
            ).fetchall()
        outcome: Outcome = "unknown"
        if len(rows) == 1 and rows[0][0] == "confirmed":
            outcome = "confirmed"
        elif len(rows) == 1 and rows[0][0] == "rejected":
            outcome = "rejected"
        evidence = hashlib.sha256(json.dumps(rows).encode()).hexdigest()
        return Readback(binding, digest, outcome, evidence)

    def effects(self) -> int:
        with sqlite3.connect(self.path) as db:
            return int(
                db.execute(
                    "SELECT COUNT(*) FROM events WHERE outcome='confirmed'"
                ).fetchone()[0]
            )

"""SQLite backed SHA-256 audit chain for demo authorization events."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class AuditLedger:
    def __init__(self, path: str = ":memory:") -> None:
        self._lock = threading.RLock()
        self._db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA busy_timeout=5000")
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS audit_events ("
            "sequence INTEGER PRIMARY KEY, timestamp TEXT NOT NULL, event_type TEXT NOT NULL, "
            "message TEXT NOT NULL, metadata TEXT NOT NULL, previous_hash TEXT NOT NULL, hash TEXT NOT NULL)"
        )

    def append(self, event_type: str, message: str, metadata: dict[str, Any] | None = None) -> dict[str, Any]:
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                last = self._db.execute(
                    "SELECT sequence, hash FROM audit_events ORDER BY sequence DESC LIMIT 1"
                ).fetchone()
                entry = {
                    "sequence": last["sequence"] + 1 if last else 1,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "event_type": event_type,
                    "message": message,
                    "metadata": metadata or {},
                    "previous_hash": last["hash"] if last else "GENESIS",
                }
                entry["hash"] = self._hash(entry)
                self._db.execute(
                    "INSERT INTO audit_events VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        entry["sequence"],
                        entry["timestamp"],
                        entry["event_type"],
                        entry["message"],
                        json.dumps(entry["metadata"], sort_keys=True),
                        entry["previous_hash"],
                        entry["hash"],
                    ),
                )
                self._db.execute("COMMIT")
                return entry
            except Exception:
                self._db.execute("ROLLBACK")
                raise

    def entries(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._db.execute("SELECT * FROM audit_events ORDER BY sequence").fetchall()
            return [{**dict(row), "metadata": json.loads(row["metadata"])} for row in rows]

    def verify(self) -> dict[str, Any]:
        entries = self.entries()
        previous_hash = "GENESIS"
        for index, entry in enumerate(entries, start=1):
            if (
                entry["sequence"] != index
                or entry["previous_hash"] != previous_hash
                or entry["hash"] != self._hash(entry)
            ):
                return {"valid": False, "entries": len(entries), "broken_at": index}
            previous_hash = entry["hash"]
        return {"valid": True, "entries": len(entries), "head": previous_hash}

    def clear(self) -> None:
        with self._lock:
            self._db.execute("DELETE FROM audit_events")

    @staticmethod
    def _hash(entry: dict[str, Any]) -> str:
        payload = {key: value for key, value in entry.items() if key != "hash"}
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(canonical.encode()).hexdigest()


db_path = os.environ.get("TRUSTLAYER_DB", str(Path(__file__).parent / "trustlayer.db"))
LEDGER = AuditLedger(db_path)

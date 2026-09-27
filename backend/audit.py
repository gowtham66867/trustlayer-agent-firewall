"""Hash-chained audit ledger for authorization and execution events."""

from __future__ import annotations

import hashlib
import json
import threading
from datetime import datetime, timezone
from typing import Any


class AuditLedger:
    def __init__(self) -> None:
        self._entries: list[dict[str, Any]] = []
        self._lock = threading.Lock()

    def append(self, event_type: str, message: str, metadata: dict[str, Any] | None = None) -> dict[str, Any]:
        with self._lock:
            previous_hash = self._entries[-1]["hash"] if self._entries else "GENESIS"
            entry = {
                "sequence": len(self._entries) + 1,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event_type": event_type,
                "message": message,
                "metadata": metadata or {},
                "previous_hash": previous_hash,
            }
            entry["hash"] = self._hash(entry)
            self._entries.append(entry)
            return entry.copy()

    def entries(self) -> list[dict[str, Any]]:
        with self._lock:
            return [entry.copy() for entry in self._entries]

    def verify(self) -> dict[str, Any]:
        with self._lock:
            previous_hash = "GENESIS"
            for index, entry in enumerate(self._entries):
                if entry["previous_hash"] != previous_hash or entry["hash"] != self._hash(entry):
                    return {"valid": False, "entries": len(self._entries), "broken_at": index + 1}
                previous_hash = entry["hash"]
            return {
                "valid": True,
                "entries": len(self._entries),
                "head": previous_hash,
            }

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()

    @staticmethod
    def _hash(entry: dict[str, Any]) -> str:
        payload = {key: value for key, value in entry.items() if key != "hash"}
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(canonical.encode()).hexdigest()


LEDGER = AuditLedger()

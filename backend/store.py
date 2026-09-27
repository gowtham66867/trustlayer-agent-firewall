"""Persistent authorization decision state for the local demo."""

from __future__ import annotations

import json
import os
import re
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


def redact(value: Any, key: str = "") -> Any:
    """Remove common credential fields before a request reaches persistence."""
    if re.search(r"secret|password|token|api.?key|credential|private.?key", key, re.I):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {name: redact(item, name) for name, item in value.items()}
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, str):
        value = re.sub(r"(?i)bearer\s+[A-Za-z0-9._~+/-]+", "Bearer [REDACTED]", value)
        value = re.sub(r"(?i)(sk-[A-Za-z0-9_-]{12,})", "[REDACTED]", value)
        return value[:4000]
    return value


class DecisionStore:
    def __init__(self, path: str = ":memory:") -> None:
        self._lock = threading.RLock()
        self._db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA busy_timeout=5000")
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS decisions ("
            "id TEXT PRIMARY KEY, idempotency_key TEXT UNIQUE, created_at TEXT NOT NULL, "
            "expires_at TEXT NOT NULL, request_json TEXT NOT NULL, decision_json TEXT NOT NULL, "
            "state TEXT NOT NULL, artifact_json TEXT, updated_at TEXT NOT NULL)"
        )

    def create(self, request: dict[str, Any], decision: dict[str, Any], ttl_seconds: int) -> dict[str, Any]:
        now = datetime.now(timezone.utc)
        key = request.get("idempotency_key")
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                if (
                    key
                    and self._db.execute(
                        "SELECT id FROM decisions WHERE idempotency_key=?", (key,)
                    ).fetchone()
                ):
                    raise ValueError("Duplicate idempotency key: tool call already evaluated")
                state = {"ALLOW": "allowed", "REVIEW": "pending_review", "BLOCK": "blocked"}[
                    decision["verdict"]
                ]
                self._db.execute(
                    "INSERT INTO decisions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        decision["decision_id"],
                        key,
                        now.isoformat(),
                        (now + timedelta(seconds=ttl_seconds)).isoformat(),
                        json.dumps(redact(request), sort_keys=True),
                        json.dumps(decision, sort_keys=True),
                        state,
                        None,
                        now.isoformat(),
                    ),
                )
                self._db.execute("COMMIT")
            except Exception:
                self._db.execute("ROLLBACK")
                raise
        return self.get(decision["decision_id"])

    def get(self, decision_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._db.execute("SELECT * FROM decisions WHERE id=?", (decision_id,)).fetchone()
            return self._decode(row) if row else None

    def list(self, state: str | None = None) -> list[dict[str, Any]]:
        with self._lock:
            if state:
                rows = self._db.execute(
                    "SELECT * FROM decisions WHERE state=? ORDER BY created_at DESC", (state,)
                )
            else:
                rows = self._db.execute("SELECT * FROM decisions ORDER BY created_at DESC")
            return [self._decode(row) for row in rows.fetchall()]

    def transition(
        self, decision_id: str, from_states: set[str], to_state: str, artifact: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                row = self._db.execute(
                    "SELECT state, expires_at FROM decisions WHERE id=?", (decision_id,)
                ).fetchone()
                if not row:
                    raise KeyError(decision_id)
                if row["state"] not in from_states:
                    raise ValueError(f"Invalid transition from {row['state']} to {to_state}")
                if to_state in {"approved", "executed"} and datetime.fromisoformat(
                    row["expires_at"]
                ) <= datetime.now(timezone.utc):
                    self._db.execute(
                        "UPDATE decisions SET state='expired', updated_at=? WHERE id=?",
                        (datetime.now(timezone.utc).isoformat(), decision_id),
                    )
                    self._db.execute("COMMIT")
                    raise TimeoutError("Authorization decision expired")
                self._db.execute(
                    "UPDATE decisions SET state=?, artifact_json=?, updated_at=? WHERE id=?",
                    (
                        to_state,
                        json.dumps(redact(artifact), sort_keys=True) if artifact is not None else None,
                        datetime.now(timezone.utc).isoformat(),
                        decision_id,
                    ),
                )
                self._db.execute("COMMIT")
            except (KeyError, ValueError):
                self._db.execute("ROLLBACK")
                raise
            except Exception:
                if self._db.in_transaction:
                    self._db.execute("ROLLBACK")
                raise
        return self.get(decision_id)

    def clear(self) -> None:
        with self._lock:
            self._db.execute("DELETE FROM decisions")

    @staticmethod
    def _decode(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "decision_id": row["id"],
            "idempotency_key": row["idempotency_key"],
            "created_at": row["created_at"],
            "expires_at": row["expires_at"],
            "request": json.loads(row["request_json"]),
            "decision": json.loads(row["decision_json"]),
            "state": row["state"],
            "artifact": json.loads(row["artifact_json"]) if row["artifact_json"] else None,
            "updated_at": row["updated_at"],
        }


db_path = os.environ.get("TRUSTLAYER_DB", str(Path(__file__).parent / "trustlayer.db"))
STORE = DecisionStore(db_path)

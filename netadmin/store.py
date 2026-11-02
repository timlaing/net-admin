"""SQLite-backed sessions and audit records."""

from __future__ import annotations

import json
import secrets
import sqlite3
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True, slots=True)
class SessionRecord:
    """Authenticated server-side session."""

    session_id: str
    username: str
    role: str
    expires_at: int


class Store:
    """Small single-instance SQLite persistence layer."""

    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self._initialize()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._connect() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS sessions (
                    session_id TEXT PRIMARY KEY,
                    username TEXT NOT NULL,
                    role TEXT NOT NULL,
                    expires_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS audit (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    occurred_at INTEGER NOT NULL,
                    username TEXT NOT NULL,
                    action TEXT NOT NULL,
                    target TEXT NOT NULL,
                    success INTEGER NOT NULL,
                    details TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS rate_events (
                    bucket TEXT NOT NULL,
                    occurred_at INTEGER NOT NULL
                );
                """
            )

    def create_session(self, username: str, role: str, lifetime_seconds: int) -> str:
        """Create and return an unpredictable session identifier."""
        session_id = secrets.token_urlsafe(32)
        with self._connect() as db:
            db.execute("DELETE FROM sessions WHERE expires_at <= ?", (int(time.time()),))
            db.execute(
                "INSERT INTO sessions VALUES (?, ?, ?, ?)",
                (session_id, username, role, int(time.time()) + lifetime_seconds),
            )
        return session_id

    def get_session(self, session_id: str) -> SessionRecord | None:
        """Return a live session, or remove and reject an expired one."""
        now = int(time.time())
        with self._connect() as db:
            row = db.execute(
                "SELECT session_id, username, role, expires_at FROM sessions WHERE session_id = ?",
                (session_id,),
            ).fetchone()
            if row is None:
                return None
            if int(row["expires_at"]) <= now:
                db.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))
                return None
            return SessionRecord(**dict(row))

    def delete_session(self, session_id: str) -> None:
        """Invalidate a session."""
        with self._connect() as db:
            db.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))

    def delete_user_sessions(self, username: str) -> None:
        """Invalidate every session for one user."""
        with self._connect() as db:
            db.execute("DELETE FROM sessions WHERE username = ?", (username,))

    def audit(
        self,
        username: str,
        action: str,
        target: str,
        success: bool | None,
        details: dict[str, Any] | None = None,
    ) -> None:
        """Append an audit event without storing secrets."""
        with self._connect() as db:
            db.execute(
                "INSERT INTO audit (occurred_at, username, action, target, success, details) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    int(time.time()),
                    username,
                    action,
                    target,
                    -1 if success is None else int(success),
                    json.dumps(details or {}, sort_keys=True),
                ),
            )

    def recent_audit(self, limit: int = 100) -> list[dict[str, Any]]:
        """Return recent audit events."""
        with self._connect() as db:
            rows = db.execute(
                "SELECT occurred_at, username, action, target, success, details "
                "FROM audit ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [
            dict(row) | {"success": None if row["success"] == -1 else row["success"]}
            for row in rows
        ]

    def allow_attempt(self, bucket: str, limit: int, window_seconds: int) -> bool:
        """Consume one attempt when the sliding-window limit permits it."""
        cutoff = int(time.time()) - window_seconds
        with self._connect() as db:
            db.execute("DELETE FROM rate_events WHERE occurred_at < ?", (cutoff,))
            count = db.execute(
                "SELECT COUNT(*) FROM rate_events WHERE bucket = ?", (bucket,)
            ).fetchone()[0]
            if int(count) >= limit:
                return False
            db.execute("INSERT INTO rate_events VALUES (?, ?)", (bucket, int(time.time())))
        return True

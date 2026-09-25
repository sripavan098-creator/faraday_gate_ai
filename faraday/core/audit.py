from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

from pydantic import BaseModel

from faraday.config import faraday_dir
from faraday.core.session import Session

GENESIS_HASH = "0" * 64

FORBIDDEN_METADATA_KEYS = {
    "matched",
    "match",
    "value",
    "secret",
    "password",
    "passwd",
    "token",
    "credential",
    "credentials",
    "private_key",
    "api_key",
    "apikey",
    "raw",
    "content",
    "text",
    "prompt",
}


class AuditError(Exception):
    """Raised when the audit subsystem fails.

    In strict-local mode, audit failure should be treated as a
    security-sensitive failure.
    """


class AuditEvent(BaseModel):
    event_id: str
    session_id: str
    timestamp: str
    event: str
    metadata: Dict[str, Any]
    previous_hash: str
    hash: str


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def canonical_json(payload: Dict[str, Any]) -> str:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )


def compute_event_hash(
    event_id: str,
    session_id: str,
    timestamp: str,
    event: str,
    metadata: Dict[str, Any],
    previous_hash: str,
) -> str:
    """Hash formula: H(current_event_without_hash + previous_hash).

    The hash covers event_id, session_id, timestamp, event name,
    sanitized metadata, and the previous hash.
    """

    payload = {
        "event_id": event_id,
        "session_id": session_id,
        "timestamp": timestamp,
        "event": event,
        "metadata": metadata,
        "previous_hash": previous_hash,
    }

    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def _truncate(value: str) -> str:
    if len(value) <= 500:
        return value

    return value[:497] + "..."


def _sanitize_value(key: str, value: Any) -> Any:
    """Recursively sanitize metadata values.

    Security rule:
        Never store raw secrets, prompts, or sensitive text in audit metadata.
    """

    if isinstance(value, dict):
        sanitized = {}

        for child_key, child_value in value.items():
            if str(child_key).lower() in FORBIDDEN_METADATA_KEYS:
                sanitized[child_key] = "[REDACTED]"
            else:
                sanitized[child_key] = _sanitize_value(child_key, child_value)

        return sanitized

    if isinstance(value, list):
        return [_sanitize_value(key, item) for item in value]

    if isinstance(value, str):
        return _truncate(value)

    return value


def sanitize_metadata(metadata: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Sanitize top-level audit metadata."""

    safe: Dict[str, Any] = {}

    for key, value in (metadata or {}).items():
        if str(key).lower() in FORBIDDEN_METADATA_KEYS:
            safe[key] = "[REDACTED]"
        else:
            safe[key] = _sanitize_value(key, value)

    return safe


class AuditChain:
    """Append-only SHA-256 hash-chained audit trail.

    Storage:
        .faraday/audit/events.jsonl
        .faraday/audit/audit.sqlite3

    JSONL provides portability.
    SQLite provides indexed metadata.
    """

    def __init__(self, root: Optional[Path] = None) -> None:
        self.root = Path(root) if root else faraday_dir() / "audit"
        self.events_path = self.root / "events.jsonl"
        self.db_path = self.root / "audit.sqlite3"

        self.root.mkdir(parents=True, exist_ok=True)
        self._head_cache: Optional[Tuple[int, int, str]] = None
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path)

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS events (
                    event_id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    event TEXT NOT NULL,
                    metadata TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    hash TEXT NOT NULL
                )
                """
            )

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS sessions (
                    id TEXT PRIMARY KEY,
                    started_at TEXT,
                    ended_at TEXT,
                    tool TEXT,
                    mode TEXT,
                    policy_version TEXT,
                    status TEXT,
                    findings_count INTEGER,
                    decisions_count INTEGER,
                    redactions_count INTEGER,
                    output_hash TEXT,
                    audit_head TEXT
                )
                """
            )

            self._migrate_sessions_table(conn)

    def _migrate_sessions_table(self, conn: sqlite3.Connection) -> None:
        """Add newer session columns to pre-existing databases."""

        existing = {
            row[1] for row in conn.execute("PRAGMA table_info(sessions)")
        }

        for column in ("files_scanned", "prompt_tokens_scanned"):
            if column not in existing:
                conn.execute(f"ALTER TABLE sessions ADD COLUMN {column} INTEGER DEFAULT 0")

    def _next_event_id(self) -> str:
        if not self.events_path.exists():
            return "evt_000001"

        count = 0

        with self.events_path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    count += 1

        return f"evt_{count + 1:06d}"

    def head_hash(self) -> str:
        """Return the hash of the latest audit event.

        If no event exists, return GENESIS_HASH.
        """

        if not self.events_path.exists():
            return GENESIS_HASH

        stat = self.events_path.stat()

        if self._head_cache is not None:
            cached_size, cached_mtime, cached_hash = self._head_cache

            if cached_size == stat.st_size and cached_mtime == stat.st_mtime_ns:
                return cached_hash

        last_line: Optional[str] = None

        with self.events_path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    last_line = line.strip()

        if not last_line:
            return GENESIS_HASH

        try:
            event = AuditEvent.model_validate_json(last_line)
        except Exception as exc:
            raise AuditError(f"Corrupt audit tail: {exc}") from exc

        new_stat = self.events_path.stat()
        self._head_cache = (new_stat.st_size, new_stat.st_mtime_ns, event.hash)
        return event.hash

    def append(
        self,
        session_id: str,
        event: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AuditEvent:
        """Append a sanitized, hash-chained audit event."""

        safe_metadata = sanitize_metadata(metadata)
        previous_hash = self.head_hash()
        event_id = self._next_event_id()
        timestamp = utc_timestamp()

        event_hash = compute_event_hash(
            event_id=event_id,
            session_id=session_id,
            timestamp=timestamp,
            event=event,
            metadata=safe_metadata,
            previous_hash=previous_hash,
        )

        audit_event = AuditEvent(
            event_id=event_id,
            session_id=session_id,
            timestamp=timestamp,
            event=event,
            metadata=safe_metadata,
            previous_hash=previous_hash,
            hash=event_hash,
        )

        try:
            with self.events_path.open("a", encoding="utf-8") as handle:
                handle.write(audit_event.model_dump_json() + "\n")

            self._insert_event(audit_event)
        except Exception as exc:
            raise AuditError(f"Failed to write audit event: {exc}") from exc

        stat = self.events_path.stat()
        self._head_cache = (stat.st_size, stat.st_mtime_ns, event_hash)
        return audit_event

    def _insert_event(self, event: AuditEvent) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO events (
                    event_id,
                    session_id,
                    timestamp,
                    event,
                    metadata,
                    previous_hash,
                    hash
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.event_id,
                    event.session_id,
                    event.timestamp,
                    event.event,
                    json.dumps(event.metadata, default=str),
                    event.previous_hash,
                    event.hash,
                ),
            )

    def iter_events(self) -> Iterator[AuditEvent]:
        """Iterate over audit events in append order."""

        if not self.events_path.exists():
            return

        with self.events_path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()

                if not line:
                    continue

                try:
                    yield AuditEvent.model_validate_json(line)
                except Exception as exc:
                    raise AuditError(f"Corrupt audit event: {exc}") from exc

    def verify(self) -> Tuple[bool, str, str]:
        """Verify the full audit chain.

        Returns:
            ok, message, head_hash
        """

        previous_hash = GENESIS_HASH
        count = 0

        try:
            for event in self.iter_events():
                count += 1

                if event.previous_hash != previous_hash:
                    return (
                        False,
                        f"Event {event.event_id} has invalid previous_hash",
                        previous_hash,
                    )

                expected_hash = compute_event_hash(
                    event_id=event.event_id,
                    session_id=event.session_id,
                    timestamp=event.timestamp,
                    event=event.event,
                    metadata=event.metadata,
                    previous_hash=previous_hash,
                )

                if event.hash != expected_hash:
                    return (
                        False,
                        f"Event {event.event_id} has invalid hash",
                        previous_hash,
                    )

                previous_hash = event.hash

        except AuditError as exc:
            return False, str(exc), previous_hash

        return True, f"{count} audit events verified", previous_hash

    def export(self, destination: Optional[Path] = None) -> Path:
        """Export the JSONL audit trail."""

        if not self.events_path.exists():
            raise AuditError("No audit events to export")

        if destination is None:
            reports_dir = self.root.parent / "reports"
            reports_dir.mkdir(parents=True, exist_ok=True)

            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            destination = reports_dir / f"audit-export-{timestamp}.jsonl"

        destination = Path(destination)
        destination.parent.mkdir(parents=True, exist_ok=True)

        destination.write_text(
            self.events_path.read_text(encoding="utf-8"),
            encoding="utf-8",
        )

        return destination

    def save_session(self, session: Session) -> None:
        """Store session metadata in SQLite.

        Important:
            This stores metadata only, not raw sensitive content.
        """

        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO sessions (
                    id,
                    started_at,
                    ended_at,
                    tool,
                    mode,
                    policy_version,
                    status,
                    findings_count,
                    decisions_count,
                    redactions_count,
                    output_hash,
                    audit_head,
                    files_scanned,
                    prompt_tokens_scanned
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session.id,
                    session.started_at.isoformat(),
                    session.ended_at.isoformat() if session.ended_at else None,
                    session.tool,
                    session.mode,
                    session.policy_version,
                    session.status,
                    len(session.findings),
                    len(session.decisions),
                    len(session.redactions),
                    session.output_hash,
                    session.audit_head,
                    session.files_scanned,
                    session.prompt_tokens_scanned,
                ),
            )

    def load_sessions(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Load recent session metadata from SQLite."""

        with self._connect() as conn:
            cursor = conn.execute(
                """
                SELECT
                    id,
                    started_at,
                    ended_at,
                    tool,
                    mode,
                    policy_version,
                    status,
                    findings_count,
                    decisions_count,
                    redactions_count,
                    output_hash,
                    audit_head
                FROM sessions
                ORDER BY started_at DESC
                LIMIT ?
                """,
                (limit,),
            )

            columns = [column[0] for column in cursor.description]
            rows = cursor.fetchall()

            return [dict(zip(columns, row)) for row in rows]

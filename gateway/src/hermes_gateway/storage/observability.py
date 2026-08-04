from __future__ import annotations

import json
import sqlite3
from typing import Any

from ..ids import new_id
from ..security import content_hash, utc_iso


class ObservabilityStoreMixin:
    def append_audit_event(
        self,
        *,
        event_type: str,
        actor_type: str,
        actor_id: str,
        node_id: str,
        request_id: str,
        payload_redacted: dict[str, Any] | None = None,
        agent_id: str | None = None,
        session_id: str | None = None,
        approval_id: str | None = None,
        notification_id: str | None = None,
        voice_session_id: str | None = None,
    ) -> dict[str, Any]:
        audit_event_id = new_id("aud")
        with self.connect() as db:
            # Reading the chain head and appending to it MUST be ONE transaction.
            #
            # This previously called self.latest_audit_hash(), which opens its own
            # connection and runs the SELECT in autocommit (Python's sqlite3 only
            # implicitly BEGINs before DML, never before a SELECT), and then opened
            # a *second* connection here to INSERT. Two concurrent writers therefore
            # read the same head and both appended with that same previous_hash,
            # forking the chain. Production carries 21 such forks among ~11k events.
            # Every individual event's own hash still verified, so this looked like
            # tamper evidence failing when it was only concurrency -- which is worse
            # than useless for a control ADR-0007 sells as tamper detection.
            #
            # BEGIN IMMEDIATE takes the write lock up front, so the head we read is
            # still the head when we insert. It is a file lock, so this holds across
            # processes too, not merely across this process's threads -- which
            # matters because more than one gateway has been pointed at this DB.
            # The explicit BEGIN does not collide with the implicit one from
            # store.connect()'s `with connection:`: once autocommit is off sqlite3
            # issues no BEGIN of its own, and that outer block still commits.
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT hash FROM audit_events ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            previous_hash = row["hash"] if row else None
            # Stamped only once the write lock is held, so created_at cannot run
            # backwards relative to sequence the way the forked pairs do.
            created_at = utc_iso()
            event_hash = content_hash(
                {
                    "audit_event_id": audit_event_id,
                    "event_type": event_type,
                    "actor_type": actor_type,
                    "actor_id": actor_id,
                    "node_id": node_id,
                    "request_id": request_id,
                    "previous_hash": previous_hash,
                    "payload_redacted": payload_redacted or {},
                    "created_at": created_at,
                }
            )
            db.execute(
                """
                INSERT INTO audit_events (
                    audit_event_id, event_type, actor_type, actor_id, node_id, agent_id,
                    session_id, approval_id, notification_id, voice_session_id, request_id,
                    previous_hash, hash, payload_redacted_json, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    audit_event_id,
                    event_type,
                    actor_type,
                    actor_id,
                    node_id,
                    agent_id,
                    session_id,
                    approval_id,
                    notification_id,
                    voice_session_id,
                    request_id,
                    previous_hash,
                    event_hash,
                    json.dumps(payload_redacted or {}),
                    created_at,
                ),
            )
        return self.get_audit_event(audit_event_id)

    def latest_audit_hash(self) -> str | None:
        with self.connect() as db:
            row = db.execute(
                "SELECT hash FROM audit_events ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
        return row["hash"] if row else None

    def get_audit_event(self, audit_event_id: str) -> dict[str, Any]:
        with self.connect() as db:
            row = db.execute(
                "SELECT * FROM audit_events WHERE audit_event_id = ?", (audit_event_id,)
            ).fetchone()
        if row is None:
            raise KeyError(audit_event_id)
        return self._audit_from_row(row)

    def list_audit_events(
        self, event_type: str | None = None, limit: int = 100
    ) -> list[dict[str, Any]]:
        sql = "SELECT * FROM audit_events"
        args: list[Any] = []
        if event_type:
            sql += " WHERE event_type = ?"
            args.append(event_type)
        sql += " ORDER BY sequence DESC LIMIT ?"
        args.append(limit)
        with self.connect() as db:
            rows = db.execute(sql, tuple(args)).fetchall()
        return [self._audit_from_row(row) for row in rows]

    def _audit_from_row(self, row: sqlite3.Row) -> dict[str, Any]:
        audit = dict(row)
        audit.pop("sequence", None)
        audit["payload_redacted"] = json.loads(audit.pop("payload_redacted_json") or "{}")
        return audit

    def create_event(
        self,
        *,
        node_id: str,
        event_type: str,
        payload: dict[str, Any],
        severity: str = "info",
        agent_id: str | None = None,
        session_id: str | None = None,
        conversation_id: str | None = None,
    ) -> dict[str, Any]:
        event_id = new_id("evt")
        occurred_at = utc_iso()
        with self.connect() as db:
            cursor = db.execute(
                """
                INSERT INTO event_envelopes (
                    event_id, node_id, agent_id, session_id, conversation_id, type,
                    severity, occurred_at, payload_json
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    node_id,
                    agent_id,
                    session_id,
                    conversation_id,
                    event_type,
                    severity,
                    occurred_at,
                    json.dumps(payload),
                ),
            )
            sequence = cursor.lastrowid
            event_cursor = f"{node_id}:{sequence:012d}"
            db.execute(
                "UPDATE event_envelopes SET cursor = ? WHERE sequence = ?",
                (event_cursor, sequence),
            )
        return self.get_event_by_id(event_id)

    def get_event_by_id(self, event_id: str) -> dict[str, Any]:
        with self.connect() as db:
            row = db.execute(
                "SELECT * FROM event_envelopes WHERE event_id = ?", (event_id,)
            ).fetchone()
        if row is None:
            raise KeyError(event_id)
        return self._event_from_row(row)

    def list_events_after(self, after: str | None = None, limit: int = 500) -> list[dict[str, Any]]:
        sequence = self._cursor_sequence(after)
        with self.connect() as db:
            rows = db.execute(
                """
                SELECT * FROM event_envelopes
                WHERE sequence > ?
                ORDER BY sequence ASC
                LIMIT ?
                """,
                (sequence, limit),
            ).fetchall()
        return [self._event_from_row(row) for row in rows]

    def event_count(self) -> int:
        with self.connect() as db:
            row = db.execute("SELECT COUNT(*) AS count FROM event_envelopes").fetchone()
        return int(row["count"])

    def _event_from_row(self, row: sqlite3.Row) -> dict[str, Any]:
        event = dict(row)
        event.pop("sequence", None)
        event["payload"] = json.loads(event.pop("payload_json"))
        return event

    def _cursor_sequence(self, cursor: str | None) -> int:
        if not cursor:
            return 0
        try:
            return int(cursor.rsplit(":", 1)[1])
        except (IndexError, ValueError):
            return 0

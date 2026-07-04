from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from .ids import new_id
from .security import content_hash, expires_in, hash_token, now_utc, parse_utc, utc_iso
from .storage.identity import IdentityStoreMixin
from .storage.observability import ObservabilityStoreMixin


def _ensure_column(
    db: sqlite3.Connection,
    table_name: str,
    column_name: str,
    column_definition: str,
) -> None:
    columns = {
        row["name"]
        for row in db.execute(f"PRAGMA table_info({table_name})").fetchall()
    }
    if column_name not in columns:
        db.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_definition}")


class SQLiteStore(IdentityStoreMixin, ObservabilityStoreMixin):
    def __init__(self, database_path: str | Path):
        self.database_path = str(database_path)

    def connect(self) -> sqlite3.Connection:
        if self.database_path != ":memory:":
            Path(self.database_path).parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def initialize(self) -> None:
        with self.connect() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS nodes (
                    node_id TEXT PRIMARY KEY,
                    display_name TEXT NOT NULL,
                    environment TEXT NOT NULL,
                    gateway_base_url TEXT NOT NULL,
                    node_fingerprint TEXT NOT NULL,
                    gateway_version TEXT NOT NULL,
                    hermes_version TEXT,
                    health TEXT NOT NULL,
                    tags_json TEXT NOT NULL,
                    capabilities_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    last_seen_at TEXT
                );

                CREATE TABLE IF NOT EXISTS pairing_sessions (
                    pairing_id TEXT PRIMARY KEY,
                    pairing_token_hash TEXT NOT NULL,
                    challenge TEXT NOT NULL,
                    status TEXT NOT NULL,
                    node_id TEXT NOT NULL,
                    node_fingerprint TEXT NOT NULL,
                    display_name TEXT NOT NULL,
                    requested_permissions_json TEXT NOT NULL,
                    clearance_channel TEXT NOT NULL DEFAULT 'local_terminal',
                    expires_at TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    completed_at TEXT
                );

                CREATE TABLE IF NOT EXISTS devices (
                    device_id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    node_id TEXT NOT NULL,
                    device_name TEXT NOT NULL,
                    platform TEXT NOT NULL,
                    app_instance_id TEXT NOT NULL,
                    app_version TEXT,
                    device_public_key TEXT NOT NULL,
                    device_key_algorithm TEXT NOT NULL DEFAULT 'ed25519',
                    clearance_channel TEXT NOT NULL DEFAULT 'local_terminal',
                    push_token TEXT,
                    status TEXT NOT NULL,
                    permissions_json TEXT NOT NULL,
                    registered_at TEXT NOT NULL,
                    last_seen_at TEXT
                );

                CREATE TABLE IF NOT EXISTS auth_tokens (
                    token_hash TEXT PRIMARY KEY,
                    token_type TEXT NOT NULL,
                    device_id TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    revoked_at TEXT,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(device_id) REFERENCES devices(device_id)
                );

                CREATE TABLE IF NOT EXISTS request_nonces (
                    device_id TEXT NOT NULL,
                    nonce TEXT NOT NULL,
                    timestamp INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY (device_id, nonce),
                    FOREIGN KEY(device_id) REFERENCES devices(device_id)
                );

                CREATE TABLE IF NOT EXISTS agents (
                    agent_id TEXT NOT NULL,
                    node_id TEXT NOT NULL,
                    display_name TEXT NOT NULL,
                    agent_kind TEXT,
                    status TEXT NOT NULL,
                    active_session_id TEXT,
                    current_tool TEXT,
                    current_target TEXT,
                    deployment_trust_context TEXT NOT NULL DEFAULT 'untrusted_host',
                    require_classified_capabilities INTEGER NOT NULL DEFAULT 0,
                    tags_json TEXT NOT NULL,
                    capabilities_json TEXT NOT NULL,
                    last_seen_at TEXT,
                    PRIMARY KEY (node_id, agent_id)
                );

                CREATE TABLE IF NOT EXISTS sessions (
                    session_id TEXT NOT NULL,
                    node_id TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    conversation_id TEXT,
                    status TEXT NOT NULL,
                    title TEXT,
                    summary TEXT,
                    current_plan TEXT,
                    current_tool TEXT,
                    current_target TEXT,
                    started_at TEXT NOT NULL,
                    updated_at TEXT,
                    ended_at TEXT,
                    PRIMARY KEY (node_id, session_id)
                );

                CREATE TABLE IF NOT EXISTS missions (
                    mission_id TEXT PRIMARY KEY,
                    node_id TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    session_id TEXT,
                    state TEXT NOT NULL,
                    title TEXT,
                    summary TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS approval_requests (
                    approval_id TEXT PRIMARY KEY,
                    action_id TEXT NOT NULL,
                    node_id TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    requested_tool TEXT NOT NULL,
                    capability TEXT,
                    risk_level TEXT NOT NULL,
                    risk_category TEXT,
                    risk_family TEXT NOT NULL DEFAULT 'external_effect',
                    params_fingerprint TEXT,
                    short_code TEXT,
                    operator_message TEXT,
                    audit_correlation_id TEXT,
                    tower_id TEXT,
                    contract_version TEXT NOT NULL DEFAULT 'act.clearance.v2',
                    proof_json TEXT NOT NULL DEFAULT '{}',
                    extensions_json TEXT NOT NULL DEFAULT '{}',
                    extensions_digest TEXT,
                    aircraft TEXT,
                    requested_by TEXT,
                    summary TEXT NOT NULL,
                    full_payload_redacted_json TEXT NOT NULL,
                    payload_hash TEXT NOT NULL,
                    resource_scope TEXT,
                    state TEXT NOT NULL,
                    options_json TEXT NOT NULL,
                    decision_scope TEXT,
                    decision_actor_device_id TEXT,
                    decision_metadata_json TEXT NOT NULL DEFAULT '{}',
                    requested_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    decided_at TEXT
                );

                CREATE TABLE IF NOT EXISTS notifications (
                    notification_id TEXT PRIMARY KEY,
                    node_id TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    action_id TEXT,
                    category TEXT NOT NULL,
                    urgency TEXT NOT NULL,
                    title_safe TEXT NOT NULL,
                    body_safe TEXT NOT NULL,
                    composition_mode TEXT,
                    unsafe_input_detected INTEGER NOT NULL DEFAULT 0,
                    dedupe_key TEXT,
                    state TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    last_attempt_at TEXT
                );

                CREATE TABLE IF NOT EXISTS tui_sessions (
                    session_id TEXT PRIMARY KEY,
                    agent_id TEXT NOT NULL,
                    node_id TEXT NOT NULL,
                    user_device_id TEXT NOT NULL,
                    state TEXT NOT NULL,
                    command TEXT NOT NULL,
                    working_directory TEXT NOT NULL,
                    risk_level TEXT NOT NULL,
                    risk_family TEXT NOT NULL DEFAULT 'external_effect',
                    risk_label TEXT NOT NULL DEFAULT 'high-risk terminal',
                    output_retention_enabled INTEGER NOT NULL DEFAULT 0,
                    audit_refs_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    last_activity_at TEXT NOT NULL,
                    closed_at TEXT
                );

                CREATE TABLE IF NOT EXISTS tui_attach_tokens (
                    token_hash TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    device_id TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    used_at TEXT,
                    revoked_at TEXT
                );

                CREATE TABLE IF NOT EXISTS assistance_requests (
                    request_id TEXT PRIMARY KEY,
                    node_id TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    approval_id TEXT,
                    risk_family TEXT NOT NULL DEFAULT 'external_effect',
                    reason TEXT NOT NULL,
                    state TEXT NOT NULL,
                    context_redacted_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS interventions (
                    intervention_id TEXT PRIMARY KEY,
                    node_id TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    device_id TEXT,
                    type TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    instruction TEXT,
                    state TEXT NOT NULL DEFAULT 'pending',
                    resulting_state TEXT,
                    expires_at TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    acknowledged_at TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_interventions_pending
                    ON interventions (session_id, agent_id, state, created_at);

                CREATE TABLE IF NOT EXISTS assistance_sessions (
                    assistance_session_id TEXT PRIMARY KEY,
                    request_id TEXT NOT NULL,
                    node_id TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    state TEXT NOT NULL,
                    created_by_device_id TEXT NOT NULL,
                    return_summary TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    returned_at TEXT,
                    closed_at TEXT
                );

                CREATE TABLE IF NOT EXISTS assistance_messages (
                    message_id TEXT PRIMARY KEY,
                    assistance_session_id TEXT NOT NULL,
                    sender_type TEXT NOT NULL,
                    sender_id TEXT NOT NULL,
                    body TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS browser_assistance_sessions (
                    browser_session_id TEXT PRIMARY KEY,
                    node_id TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    approval_id TEXT,
                    risk_family TEXT NOT NULL DEFAULT 'external_effect',
                    reason TEXT NOT NULL,
                    state TEXT NOT NULL,
                    context_redacted_json TEXT NOT NULL,
                    user_action_notes_json TEXT NOT NULL,
                    return_summary TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    returned_at TEXT,
                    closed_at TEXT
                );

                CREATE TABLE IF NOT EXISTS approval_responses (
                    approval_response_id TEXT PRIMARY KEY,
                    approval_id TEXT NOT NULL,
                    decision_type TEXT NOT NULL,
                    created_by_device_id TEXT NOT NULL,
                    user_message TEXT,
                    alternate_directive TEXT,
                    constraints_json TEXT NOT NULL,
                    policy_proposal_id TEXT,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS approval_policy_proposals (
                    policy_proposal_id TEXT PRIMARY KEY,
                    approval_id TEXT NOT NULL,
                    created_by_device_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    warning TEXT NOT NULL,
                    constraints_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS voice_sessions (
                    voice_session_id TEXT PRIMARY KEY,
                    node_id TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    session_id TEXT,
                    created_by_device_id TEXT NOT NULL,
                    mode TEXT NOT NULL,
                    state TEXT NOT NULL,
                    risk_family TEXT NOT NULL DEFAULT 'external_effect',
                    created_at TEXT NOT NULL,
                    closed_at TEXT
                );

                CREATE TABLE IF NOT EXISTS voice_messages (
                    voice_message_id TEXT PRIMARY KEY,
                    voice_session_id TEXT NOT NULL,
                    sender_type TEXT NOT NULL,
                    body TEXT NOT NULL,
                    input_mode TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS operator_sessions (
                    session_id TEXT PRIMARY KEY,
                    session_type TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    mission_id TEXT,
                    state TEXT NOT NULL,
                    owner_device_id TEXT,
                    capability_requirements_json TEXT NOT NULL,
                    context_json TEXT NOT NULL,
                    return_summary TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS capability_grants (
                    grant_id TEXT PRIMARY KEY,
                    subject_type TEXT NOT NULL,
                    subject_id TEXT NOT NULL,
                    capability TEXT NOT NULL,
                    node_id TEXT NOT NULL,
                    agent_id TEXT,
                    state TEXT NOT NULL,
                    reason TEXT,
                    created_at TEXT NOT NULL,
                    expires_at TEXT
                );

                CREATE TABLE IF NOT EXISTS capability_risk_registry (
                    entry_id TEXT PRIMARY KEY,
                    node_id TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    aircraft TEXT NOT NULL,
                    capability TEXT NOT NULL,
                    risk_family TEXT NOT NULL,
                    status TEXT NOT NULL,
                    version INTEGER NOT NULL,
                    proposed_at TEXT NOT NULL,
                    proposed_by TEXT NOT NULL,
                    approved_by TEXT,
                    approved_at TEXT
                );

                CREATE TABLE IF NOT EXISTS audit_events (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    audit_event_id TEXT NOT NULL UNIQUE,
                    event_type TEXT NOT NULL,
                    actor_type TEXT NOT NULL,
                    actor_id TEXT NOT NULL,
                    node_id TEXT NOT NULL,
                    agent_id TEXT,
                    session_id TEXT,
                    approval_id TEXT,
                    notification_id TEXT,
                    voice_session_id TEXT,
                    request_id TEXT NOT NULL,
                    previous_hash TEXT,
                    hash TEXT NOT NULL,
                    payload_redacted_json TEXT,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS event_envelopes (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL UNIQUE,
                    cursor TEXT,
                    node_id TEXT NOT NULL,
                    agent_id TEXT,
                    session_id TEXT,
                    conversation_id TEXT,
                    type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    occurred_at TEXT NOT NULL,
                    payload_json TEXT NOT NULL
                );
                """
            )
            _ensure_column(db, "notifications", "composition_mode", "TEXT")
            _ensure_column(
                db,
                "notifications",
                "unsafe_input_detected",
                "INTEGER NOT NULL DEFAULT 0",
            )
            _ensure_column(
                db,
                "agents",
                "deployment_trust_context",
                "TEXT NOT NULL DEFAULT 'untrusted_host'",
            )
            _ensure_column(
                db,
                "agents",
                "require_classified_capabilities",
                "INTEGER NOT NULL DEFAULT 0",
            )
            db.execute(
                """
                UPDATE agents
                SET deployment_trust_context = 'untrusted_host'
                WHERE deployment_trust_context IS NULL
                   OR deployment_trust_context = ''
                """
            )
            _ensure_column(
                db,
                "devices",
                "clearance_channel",
                "TEXT NOT NULL DEFAULT 'local_terminal'",
            )
            _ensure_column(
                db,
                "devices",
                "device_key_algorithm",
                "TEXT NOT NULL DEFAULT 'ed25519'",
            )
            _ensure_column(db, "devices", "push_token", "TEXT")
            _ensure_column(
                db,
                "pairing_sessions",
                "clearance_channel",
                "TEXT NOT NULL DEFAULT 'local_terminal'",
            )
            _ensure_column(
                db,
                "approval_requests",
                "risk_family",
                "TEXT NOT NULL DEFAULT 'external_effect'",
            )
            _ensure_column(db, "approval_requests", "params_fingerprint", "TEXT")
            _ensure_column(db, "approval_requests", "capability", "TEXT")
            _ensure_column(db, "approval_requests", "short_code", "TEXT")
            _ensure_column(db, "approval_requests", "operator_message", "TEXT")
            _ensure_column(db, "approval_requests", "audit_correlation_id", "TEXT")
            _ensure_column(db, "approval_requests", "tower_id", "TEXT")
            _ensure_column(
                db,
                "approval_requests",
                "contract_version",
                "TEXT NOT NULL DEFAULT 'act.clearance.v2'",
            )
            _ensure_column(
                db,
                "approval_requests",
                "proof_json",
                "TEXT NOT NULL DEFAULT '{}'",
            )
            _ensure_column(
                db,
                "approval_requests",
                "extensions_json",
                "TEXT NOT NULL DEFAULT '{}'",
            )
            _ensure_column(db, "approval_requests", "extensions_digest", "TEXT")
            _ensure_column(db, "approval_requests", "aircraft", "TEXT")
            _ensure_column(db, "approval_requests", "requested_by", "TEXT")
            self._ensure_column(db, "approval_requests", "decision_scope", "TEXT")
            self._ensure_column(db, "approval_requests", "decision_actor_device_id", "TEXT")
            self._ensure_column(
                db,
                "approval_requests",
                "decision_metadata_json",
                "TEXT NOT NULL DEFAULT '{}'",
            )
            self._ensure_column(db, "approval_requests", "decided_at", "TEXT")
            # BrowserBridge seam (additive): per-surface risk vector + authority
            # provenance. All nullable so existing rows/consumers are unaffected.
            self._ensure_column(db, "approval_requests", "risk_vector_json", "TEXT")
            self._ensure_column(db, "approval_requests", "approved_by", "TEXT")
            self._ensure_column(db, "approval_requests", "human_approved", "TEXT")
            self._ensure_column(
                db,
                "tui_sessions",
                "risk_family",
                "TEXT NOT NULL DEFAULT 'external_effect'",
            )
            self._ensure_column(
                db,
                "tui_sessions",
                "risk_label",
                "TEXT NOT NULL DEFAULT 'high-risk terminal'",
            )
            self._ensure_column(
                db,
                "tui_sessions",
                "output_retention_enabled",
                "INTEGER NOT NULL DEFAULT 0",
            )
            self._ensure_column(
                db,
                "assistance_requests",
                "risk_family",
                "TEXT NOT NULL DEFAULT 'external_effect'",
            )
            self._ensure_column(
                db,
                "browser_assistance_sessions",
                "risk_family",
                "TEXT NOT NULL DEFAULT 'external_effect'",
            )
            self._ensure_column(
                db,
                "voice_sessions",
                "risk_family",
                "TEXT NOT NULL DEFAULT 'external_effect'",
            )

    def _ensure_column(
        self, db: sqlite3.Connection, table_name: str, column_name: str, definition: str
    ) -> None:
        columns = {
            row["name"] for row in db.execute(f"PRAGMA table_info({table_name})").fetchall()
        }
        if column_name not in columns:
            db.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {definition}")

    def upsert_node(self, node: dict[str, Any]) -> dict[str, Any]:
        created_at = node.get("created_at") or utc_iso()
        last_seen_at = node.get("last_seen_at") or created_at
        capabilities = node.get("capabilities") or [
            {"name": "events_websocket", "status": "available"},
            {"name": "pairing", "status": "available"},
            {"name": "mobile_notify", "status": "available"},
            {"name": "approvals", "status": "available"},
        ]
        with self.connect() as db:
            db.execute(
                """
                INSERT INTO nodes (
                    node_id, display_name, environment, gateway_base_url, node_fingerprint,
                    gateway_version, hermes_version, health, tags_json, capabilities_json,
                    created_at, last_seen_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(node_id) DO UPDATE SET
                    display_name=excluded.display_name,
                    environment=excluded.environment,
                    gateway_base_url=excluded.gateway_base_url,
                    node_fingerprint=excluded.node_fingerprint,
                    gateway_version=excluded.gateway_version,
                    hermes_version=excluded.hermes_version,
                    health=excluded.health,
                    tags_json=excluded.tags_json,
                    capabilities_json=excluded.capabilities_json,
                    last_seen_at=excluded.last_seen_at
                """,
                (
                    node["node_id"],
                    node["display_name"],
                    node["environment"],
                    node["gateway_base_url"],
                    node["node_fingerprint"],
                    node["gateway_version"],
                    node.get("hermes_version"),
                    node.get("health", "online"),
                    json.dumps(node.get("tags", [])),
                    json.dumps(capabilities),
                    created_at,
                    last_seen_at,
                ),
            )
        return self.get_node(node["node_id"])

    def get_node(self, node_id: str) -> dict[str, Any]:
        with self.connect() as db:
            row = db.execute("SELECT * FROM nodes WHERE node_id = ?", (node_id,)).fetchone()
        if row is None:
            raise KeyError(node_id)
        node = dict(row)
        node["tags"] = json.loads(node.pop("tags_json"))
        node["capabilities"] = json.loads(node.pop("capabilities_json"))
        node["agents"] = self.list_agents(node_id=node_id)
        return node

    def list_nodes(self) -> list[dict[str, Any]]:
        with self.connect() as db:
            rows = db.execute("SELECT node_id FROM nodes ORDER BY display_name").fetchall()
        return [self.get_node(row["node_id"]) for row in rows]

    def upsert_agent(self, agent: dict[str, Any]) -> dict[str, Any]:
        if "deployment_trust_context" not in agent:
            try:
                existing = self.get_agent(agent["node_id"], agent["agent_id"])
                agent["deployment_trust_context"] = existing.get(
                    "deployment_trust_context",
                    "untrusted_host",
                )
            except KeyError:
                agent["deployment_trust_context"] = "untrusted_host"
        if "require_classified_capabilities" not in agent:
            try:
                existing = self.get_agent(agent["node_id"], agent["agent_id"])
                agent["require_classified_capabilities"] = existing.get(
                    "require_classified_capabilities",
                    False,
                )
            except KeyError:
                agent["require_classified_capabilities"] = False
        with self.connect() as db:
            db.execute(
                """
                INSERT INTO agents (
                    agent_id, node_id, display_name, agent_kind, status, active_session_id,
                    current_tool, current_target, deployment_trust_context,
                    require_classified_capabilities, tags_json, capabilities_json, last_seen_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(node_id, agent_id) DO UPDATE SET
                    display_name=excluded.display_name,
                    agent_kind=excluded.agent_kind,
                    status=excluded.status,
                    active_session_id=excluded.active_session_id,
                    current_tool=excluded.current_tool,
                    current_target=excluded.current_target,
                    deployment_trust_context=excluded.deployment_trust_context,
                    require_classified_capabilities=excluded.require_classified_capabilities,
                    tags_json=excluded.tags_json,
                    capabilities_json=excluded.capabilities_json,
                    last_seen_at=excluded.last_seen_at
                """,
                (
                    agent["agent_id"],
                    agent["node_id"],
                    agent["display_name"],
                    agent.get("agent_kind"),
                    agent.get("status", "idle"),
                    agent.get("active_session_id"),
                    agent.get("current_tool"),
                    agent.get("current_target"),
                    agent.get("deployment_trust_context", "untrusted_host"),
                    1 if agent.get("require_classified_capabilities") else 0,
                    json.dumps(agent.get("tags", [])),
                    json.dumps(agent.get("capabilities", [])),
                    agent.get("last_seen_at") or utc_iso(),
                ),
            )
        return self.get_agent(agent["node_id"], agent["agent_id"])

    def get_agent(self, node_id: str, agent_id: str) -> dict[str, Any]:
        with self.connect() as db:
            row = db.execute(
                "SELECT * FROM agents WHERE node_id = ? AND agent_id = ?", (node_id, agent_id)
            ).fetchone()
        if row is None:
            raise KeyError(agent_id)
        agent = dict(row)
        agent["require_classified_capabilities"] = bool(
            agent.get("require_classified_capabilities")
        )
        agent["tags"] = json.loads(agent.pop("tags_json"))
        agent["capabilities"] = json.loads(agent.pop("capabilities_json"))
        return agent

    def update_agent_trust_context(
        self,
        *,
        node_id: str,
        agent_id: str,
        deployment_trust_context: str,
    ) -> dict[str, Any]:
        with self.connect() as db:
            cursor = db.execute(
                """
                UPDATE agents
                SET deployment_trust_context = ?
                WHERE node_id = ? AND agent_id = ?
                """,
                (deployment_trust_context, node_id, agent_id),
            )
        if cursor.rowcount == 0:
            raise KeyError(agent_id)
        return self.get_agent(node_id, agent_id)

    def list_agents(self, node_id: str | None = None) -> list[dict[str, Any]]:
        sql = "SELECT * FROM agents"
        args: tuple[Any, ...] = ()
        if node_id:
            sql += " WHERE node_id = ?"
            args = (node_id,)
        sql += " ORDER BY display_name"
        with self.connect() as db:
            rows = db.execute(sql, args).fetchall()
        agents = []
        for row in rows:
            agent = dict(row)
            agent["require_classified_capabilities"] = bool(
                agent.get("require_classified_capabilities")
            )
            agent["tags"] = json.loads(agent.pop("tags_json"))
            agent["capabilities"] = json.loads(agent.pop("capabilities_json"))
            agents.append(agent)
        return agents

    def upsert_session(self, session: dict[str, Any]) -> dict[str, Any]:
        now = utc_iso()
        with self.connect() as db:
            db.execute(
                """
                INSERT INTO sessions (
                    session_id, node_id, agent_id, conversation_id, status, title, summary,
                    current_plan, current_tool, current_target, started_at, updated_at, ended_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(node_id, session_id) DO UPDATE SET
                    agent_id=excluded.agent_id,
                    conversation_id=excluded.conversation_id,
                    status=excluded.status,
                    title=excluded.title,
                    summary=excluded.summary,
                    current_plan=excluded.current_plan,
                    current_tool=excluded.current_tool,
                    current_target=excluded.current_target,
                    updated_at=excluded.updated_at,
                    ended_at=excluded.ended_at
                """,
                (
                    session["session_id"],
                    session["node_id"],
                    session["agent_id"],
                    session.get("conversation_id"),
                    session.get("status", "active"),
                    session.get("title"),
                    session.get("summary"),
                    session.get("current_plan"),
                    session.get("current_tool"),
                    session.get("current_target"),
                    session.get("started_at") or now,
                    session.get("updated_at") or now,
                    session.get("ended_at"),
                ),
            )
        return self.get_session(session["node_id"], session["session_id"])

    def get_session(self, node_id: str, session_id: str) -> dict[str, Any]:
        with self.connect() as db:
            row = db.execute(
                "SELECT * FROM sessions WHERE node_id = ? AND session_id = ?",
                (node_id, session_id),
            ).fetchone()
        if row is None:
            raise KeyError(session_id)
        return dict(row)

    def list_sessions(
        self, node_id: str | None = None, agent_id: str | None = None
    ) -> list[dict[str, Any]]:
        where = []
        args: list[Any] = []
        if node_id:
            where.append("node_id = ?")
            args.append(node_id)
        if agent_id:
            where.append("agent_id = ?")
            args.append(agent_id)
        sql = "SELECT * FROM sessions"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY updated_at DESC"
        with self.connect() as db:
            rows = db.execute(sql, tuple(args)).fetchall()
        return [dict(row) for row in rows]

    def upsert_mission(self, mission: dict[str, Any]) -> dict[str, Any]:
        now = utc_iso()
        created_at = mission.get("created_at") or now
        updated_at = mission.get("updated_at") or now
        with self.connect() as db:
            db.execute(
                """
                INSERT INTO missions (
                    mission_id, node_id, agent_id, session_id, state, title, summary,
                    created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(mission_id) DO UPDATE SET
                    node_id=excluded.node_id,
                    agent_id=excluded.agent_id,
                    session_id=excluded.session_id,
                    state=excluded.state,
                    title=excluded.title,
                    summary=excluded.summary,
                    updated_at=excluded.updated_at
                """,
                (
                    mission["mission_id"],
                    mission["node_id"],
                    mission["agent_id"],
                    mission.get("session_id"),
                    mission.get("state", "running"),
                    mission.get("title"),
                    mission.get("summary"),
                    created_at,
                    updated_at,
                ),
            )
        return self.get_mission(mission["mission_id"])

    def get_mission(self, mission_id: str) -> dict[str, Any]:
        with self.connect() as db:
            row = db.execute(
                "SELECT * FROM missions WHERE mission_id = ?",
                (mission_id,),
            ).fetchone()
        if row is None:
            raise KeyError(mission_id)
        return dict(row)

    def list_missions(
        self, node_id: str | None = None, agent_id: str | None = None
    ) -> list[dict[str, Any]]:
        sql = "SELECT * FROM missions"
        args: list[Any] = []
        where = []
        if node_id:
            where.append("node_id = ?")
            args.append(node_id)
        if agent_id:
            where.append("agent_id = ?")
            args.append(agent_id)
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY updated_at DESC"
        with self.connect() as db:
            rows = db.execute(sql, tuple(args)).fetchall()
        return [dict(row) for row in rows]

    def create_approval(self, approval: dict[str, Any]) -> dict[str, Any]:
        payload = approval.get("full_payload_redacted", {})
        with self.connect() as db:
            db.execute(
                """
                INSERT INTO approval_requests (
                    approval_id, action_id, node_id, agent_id, session_id, requested_tool,
                    capability,
                    risk_level, risk_category, risk_family, params_fingerprint, short_code,
                    operator_message, audit_correlation_id, tower_id, contract_version,
                    proof_json, extensions_json, extensions_digest, aircraft, requested_by, summary,
                    full_payload_redacted_json, payload_hash, resource_scope, state,
                    options_json, requested_at, expires_at,
                    risk_vector_json
                )
                VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                )
                """,
                (
                    approval["approval_id"],
                    approval["action_id"],
                    approval["node_id"],
                    approval["agent_id"],
                    approval["session_id"],
                    approval["requested_tool"],
                    approval.get("capability"),
                    approval["risk_level"],
                    approval.get("risk_category"),
                    approval.get("risk_family", "external_effect"),
                    approval.get("params_fingerprint") or content_hash(payload),
                    approval.get("short_code"),
                    approval.get("operator_message"),
                    approval.get("audit_correlation_id"),
                    approval.get("tower_id"),
                    approval.get("contract_version", "act.clearance.v2"),
                    json.dumps(approval.get("proof") or {}),
                    json.dumps(approval.get("extensions") or {}),
                    approval.get("extensions_digest"),
                    approval.get("aircraft"),
                    approval.get("requested_by"),
                    approval["summary"],
                    json.dumps(payload),
                    approval.get("payload_hash") or content_hash(payload),
                    approval.get("resource_scope"),
                    approval.get("state", "pending"),
                    json.dumps(approval.get("options", [])),
                    approval.get("requested_at") or utc_iso(),
                    approval["expires_at"],
                    json.dumps(approval["risk_vector"])
                    if approval.get("risk_vector")
                    else None,
                ),
            )
        return self.get_approval(approval["approval_id"])

    def create_capability_risk_entry(self, entry: dict[str, Any]) -> dict[str, Any]:
        proposed_at = entry.get("proposed_at") or utc_iso()
        version = entry.get("version") or self.next_capability_risk_version(
            node_id=entry["node_id"],
            agent_id=entry["agent_id"],
            capability=entry["capability"],
        )
        with self.connect() as db:
            db.execute(
                """
                INSERT INTO capability_risk_registry (
                    entry_id, node_id, agent_id, aircraft, capability, risk_family,
                    status, version, proposed_at, proposed_by, approved_by, approved_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    entry["entry_id"],
                    entry["node_id"],
                    entry["agent_id"],
                    entry["aircraft"],
                    entry["capability"],
                    entry["risk_family"],
                    entry.get("status", "pending"),
                    version,
                    proposed_at,
                    entry["proposed_by"],
                    entry.get("approved_by"),
                    entry.get("approved_at"),
                ),
            )
        return self.get_capability_risk_entry(entry["entry_id"])

    def next_capability_risk_version(
        self,
        *,
        node_id: str,
        agent_id: str,
        capability: str,
    ) -> int:
        with self.connect() as db:
            row = db.execute(
                """
                SELECT MAX(version) AS max_version
                FROM capability_risk_registry
                WHERE node_id = ? AND agent_id = ? AND capability = ?
                """,
                (node_id, agent_id, capability),
            ).fetchone()
        return int(row["max_version"] or 0) + 1

    def get_capability_risk_entry(self, entry_id: str) -> dict[str, Any]:
        with self.connect() as db:
            row = db.execute(
                "SELECT * FROM capability_risk_registry WHERE entry_id = ?",
                (entry_id,),
            ).fetchone()
        if row is None:
            raise KeyError(entry_id)
        return dict(row)

    def list_capability_risk_entries(
        self,
        *,
        node_id: str | None = None,
        agent_id: str | None = None,
        status: str | None = None,
    ) -> list[dict[str, Any]]:
        where = []
        args: list[Any] = []
        if node_id:
            where.append("node_id = ?")
            args.append(node_id)
        if agent_id:
            where.append("agent_id = ?")
            args.append(agent_id)
        if status:
            where.append("status = ?")
            args.append(status)
        sql = "SELECT * FROM capability_risk_registry"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY proposed_at DESC"
        with self.connect() as db:
            rows = db.execute(sql, tuple(args)).fetchall()
        return [dict(row) for row in rows]

    def get_approved_capability_risk(
        self,
        *,
        node_id: str,
        agent_id: str,
        capability: str,
    ) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute(
                """
                SELECT *
                FROM capability_risk_registry
                WHERE node_id = ?
                  AND agent_id = ?
                  AND capability = ?
                  AND status = 'approved'
                ORDER BY version DESC, approved_at DESC
                LIMIT 1
                """,
                (node_id, agent_id, capability),
            ).fetchone()
        return dict(row) if row else None

    def approve_capability_risk_entry(
        self,
        *,
        entry_id: str,
        approved_by: str,
    ) -> dict[str, Any]:
        approved_at = utc_iso()
        with self.connect() as db:
            cursor = db.execute(
                """
                UPDATE capability_risk_registry
                SET status = 'approved', approved_by = ?, approved_at = ?
                WHERE entry_id = ? AND status = 'pending'
                """,
                (approved_by, approved_at, entry_id),
            )
        if cursor.rowcount == 0:
            raise KeyError(entry_id)
        return self.get_capability_risk_entry(entry_id)

    def reject_capability_risk_entry(self, entry_id: str) -> dict[str, Any]:
        entry = self.get_capability_risk_entry(entry_id)
        if entry["status"] != "pending":
            raise KeyError(entry_id)
        with self.connect() as db:
            db.execute(
                "DELETE FROM capability_risk_registry WHERE entry_id = ?",
                (entry_id,),
            )
        return entry

    def get_approval(self, approval_id: str) -> dict[str, Any]:
        with self.connect() as db:
            row = db.execute(
                "SELECT * FROM approval_requests WHERE approval_id = ?", (approval_id,)
            ).fetchone()
        if row is None:
            raise KeyError(approval_id)
        return self._approval_from_row(row)

    def list_approvals(self, state: str | None = None) -> list[dict[str, Any]]:
        sql = "SELECT * FROM approval_requests"
        args: tuple[Any, ...] = ()
        if state:
            sql += " WHERE state = ?"
            args = (state,)
        sql += " ORDER BY requested_at DESC"
        with self.connect() as db:
            rows = db.execute(sql, args).fetchall()
        return [self._approval_from_row(row) for row in rows]

    def resolve_approval(
        self,
        approval_id: str,
        state: str,
        *,
        decision_scope: str | None = None,
        decision_actor_device_id: str | None = None,
        decision_metadata: dict[str, Any] | None = None,
        approved_by: str | None = None,
        human_approved: bool = False,
    ) -> None:
        decided_at = utc_iso()
        with self.connect() as db:
            db.execute(
                """
                UPDATE approval_requests
                SET state = ?,
                    decision_scope = ?,
                    decision_actor_device_id = ?,
                    decision_metadata_json = ?,
                    decided_at = ?,
                    approved_by = ?,
                    human_approved = ?
                WHERE approval_id = ?
                """,
                (
                    state,
                    decision_scope,
                    decision_actor_device_id,
                    json.dumps(decision_metadata or {}),
                    decided_at,
                    approved_by,
                    "1" if human_approved else "0",
                    approval_id,
                ),
            )

    def update_approval_decision_metadata(
        self,
        approval_id: str,
        metadata: dict[str, Any],
    ) -> dict[str, Any]:
        approval = self.get_approval(approval_id)
        merged = (approval.get("decision_metadata") or {}) | metadata
        with self.connect() as db:
            db.execute(
                "UPDATE approval_requests SET decision_metadata_json = ? WHERE approval_id = ?",
                (json.dumps(merged), approval_id),
            )
        return self.get_approval(approval_id)

    def _approval_from_row(self, row: sqlite3.Row) -> dict[str, Any]:
        approval = dict(row)
        approval["full_payload_redacted"] = json.loads(
            approval.pop("full_payload_redacted_json")
        )
        approval["options"] = json.loads(approval.pop("options_json"))
        approval["decision_metadata"] = json.loads(
            approval.pop("decision_metadata_json", "{}") or "{}"
        )
        approval["proof"] = json.loads(approval.pop("proof_json", "{}") or "{}") or None
        approval["extensions"] = json.loads(approval.pop("extensions_json", "{}") or "{}")
        approval["contract_version"] = approval.get("contract_version") or "act.clearance.v2"
        # BrowserBridge seam (additive) deserialization.
        risk_vector_json = approval.pop("risk_vector_json", None)
        approval["risk_vector"] = (
            json.loads(risk_vector_json) if risk_vector_json else None
        )
        approval["human_approved"] = approval.get("human_approved") == "1"
        approval.setdefault("approved_by", None)
        approval.pop("decision_actor_device_id", None)
        approval.pop("payload_hash", None)
        approval.pop("requested_at", None)
        return approval

    def reserve_approval(self, approval_id: str) -> dict[str, Any]:
        """Two-phase consume, phase 1 (BrowserBridge seam). Atomically move an
        ``approved`` clearance to ``reserved`` so only one consumer can hold it.
        Raises KeyError if missing, ValueError if not reservable."""
        with self.connect() as db:
            cursor = db.execute(
                """
                UPDATE approval_requests SET state = 'reserved'
                WHERE approval_id = ? AND state = 'approved'
                """,
                (approval_id,),
            )
            if cursor.rowcount == 0:
                current = db.execute(
                    "SELECT state FROM approval_requests WHERE approval_id = ?",
                    (approval_id,),
                ).fetchone()
                if current is None:
                    raise KeyError(approval_id)
                raise ValueError(f"approval not reservable from state {current[0]!r}")
        return self.get_approval(approval_id)

    def commit_approval(self, approval_id: str) -> dict[str, Any]:
        """Two-phase consume, phase 2 (BrowserBridge seam). Commit only succeeds
        from ``reserved``, preserving one-time consumption."""
        with self.connect() as db:
            cursor = db.execute(
                """
                UPDATE approval_requests SET state = 'committed'
                WHERE approval_id = ? AND state = 'reserved'
                """,
                (approval_id,),
            )
            if cursor.rowcount == 0:
                current = db.execute(
                    "SELECT state FROM approval_requests WHERE approval_id = ?",
                    (approval_id,),
                ).fetchone()
                if current is None:
                    raise KeyError(approval_id)
                raise ValueError(f"approval not committable from state {current[0]!r}")
        return self.get_approval(approval_id)

    def release_approval(self, approval_id: str) -> dict[str, Any]:
        """Two-phase consume, symmetric inverse of ``commit`` (BrowserBridge
        seam). Release only succeeds from ``reserved`` -> ``cancelled``,
        preserving one-time consumption: a released clearance can never
        afterward be committed or re-reserved (both guard on the prior state),
        and ``committed`` clearances are left untouched (release -> ValueError)."""
        with self.connect() as db:
            cursor = db.execute(
                """
                UPDATE approval_requests SET state = 'cancelled'
                WHERE approval_id = ? AND state = 'reserved'
                """,
                (approval_id,),
            )
            if cursor.rowcount == 0:
                current = db.execute(
                    "SELECT state FROM approval_requests WHERE approval_id = ?",
                    (approval_id,),
                ).fetchone()
                if current is None:
                    raise KeyError(approval_id)
                raise ValueError(f"approval not releasable from state {current[0]!r}")
        return self.get_approval(approval_id)

    def bulk_invalidate_approvals(
        self, *, session_id: str, reason: str = "panic"
    ) -> list[str]:
        """Panic dominance (BrowserBridge seam). Atomically invalidate every
        pending AND approved-but-unconsumed (approved/reserved) clearance for a
        session. Committed clearances are already consumed and are left intact.
        Returns the invalidated approval ids."""
        decided_at = utc_iso()
        with self.connect() as db:
            rows = db.execute(
                """
                SELECT approval_id FROM approval_requests
                WHERE session_id = ? AND state IN ('pending', 'approved', 'reserved')
                """,
                (session_id,),
            ).fetchall()
            ids = [row[0] for row in rows]
            db.execute(
                """
                UPDATE approval_requests
                SET state = 'cancelled',
                    decided_at = COALESCE(decided_at, ?),
                    decision_metadata_json = ?
                WHERE session_id = ? AND state IN ('pending', 'approved', 'reserved')
                """,
                (decided_at, json.dumps({"reason": reason}), session_id),
            )
        return ids

    def create_notification(self, notification: dict[str, Any]) -> dict[str, Any]:
        notification_id = notification.get("notification_id") or new_id("ntf")
        created_at = notification.get("created_at") or utc_iso()
        with self.connect() as db:
            db.execute(
                """
                INSERT INTO notifications (
                    notification_id, node_id, agent_id, session_id, action_id, category,
                    urgency, title_safe, body_safe, composition_mode,
                    unsafe_input_detected, dedupe_key, state, created_at, last_attempt_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    notification_id,
                    notification["node_id"],
                    notification["agent_id"],
                    notification["session_id"],
                    notification.get("action_id"),
                    notification["category"],
                    notification["urgency"],
                    notification["title_safe"],
                    notification["body_safe"],
                    notification.get("composition_mode"),
                    1 if notification.get("unsafe_input_detected") else 0,
                    notification.get("dedupe_key"),
                    notification.get("state", "queued"),
                    created_at,
                    notification.get("last_attempt_at"),
                ),
            )
        return self.get_notification(notification_id)

    def get_notification(self, notification_id: str) -> dict[str, Any]:
        with self.connect() as db:
            row = db.execute(
                "SELECT * FROM notifications WHERE notification_id = ?", (notification_id,)
            ).fetchone()
        if row is None:
            raise KeyError(notification_id)
        return self._notification_from_row(row)

    def list_notifications(self, category: str | None = None) -> list[dict[str, Any]]:
        sql = "SELECT * FROM notifications"
        args: tuple[Any, ...] = ()
        if category:
            sql += " WHERE category = ?"
            args = (category,)
        sql += " ORDER BY created_at DESC"
        with self.connect() as db:
            rows = db.execute(sql, args).fetchall()
        return [self._notification_from_row(row) for row in rows]

    def _notification_from_row(self, row: sqlite3.Row) -> dict[str, Any]:
        notification = dict(row)
        notification["unsafe_input_detected"] = bool(
            notification.get("unsafe_input_detected")
        )
        return notification

    def create_tui_session(self, session: dict[str, Any]) -> dict[str, Any]:
        now = utc_iso()
        with self.connect() as db:
            db.execute(
                """
                INSERT INTO tui_sessions (
                    session_id, agent_id, node_id, user_device_id, state, command,
                    working_directory, risk_level, risk_family, risk_label,
                    output_retention_enabled,
                    audit_refs_json, created_at, last_activity_at, closed_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session["session_id"],
                    session["agent_id"],
                    session["node_id"],
                    session["user_device_id"],
                    session.get("state", "requested"),
                    session["command"],
                    session["working_directory"],
                    session["risk_level"],
                    session.get("risk_family", "external_effect"),
                    session.get("risk_label", "high-risk terminal"),
                    1 if session.get("output_retention_enabled", False) else 0,
                    json.dumps(session.get("audit_refs", [])),
                    session.get("created_at") or now,
                    session.get("last_activity_at") or now,
                    session.get("closed_at"),
                ),
            )
        return self.get_tui_session(session["session_id"])

    def get_tui_session(self, session_id: str) -> dict[str, Any]:
        with self.connect() as db:
            row = db.execute(
                "SELECT * FROM tui_sessions WHERE session_id = ?",
                (session_id,),
            ).fetchone()
        if row is None:
            raise KeyError(session_id)
        return self._tui_session_from_row(row)

    def list_tui_sessions(
        self,
        *,
        user_device_id: str | None = None,
        state: str | None = None,
    ) -> list[dict[str, Any]]:
        where = []
        args: list[Any] = []
        if user_device_id:
            where.append("user_device_id = ?")
            args.append(user_device_id)
        if state:
            where.append("state = ?")
            args.append(state)
        sql = "SELECT * FROM tui_sessions"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY last_activity_at DESC"
        with self.connect() as db:
            rows = db.execute(sql, tuple(args)).fetchall()
        return [self._tui_session_from_row(row) for row in rows]

    def update_tui_session_state(
        self,
        session_id: str,
        state: str,
        *,
        closed_at: str | None = None,
    ) -> dict[str, Any]:
        now = utc_iso()
        closed_value = closed_at
        if closed_value is None and state in {"closed", "failed"}:
            closed_value = now
        with self.connect() as db:
            db.execute(
                """
                UPDATE tui_sessions
                SET state = ?,
                    last_activity_at = ?,
                    closed_at = COALESCE(?, closed_at)
                WHERE session_id = ?
                """,
                (state, now, closed_value, session_id),
            )
        return self.get_tui_session(session_id)

    def touch_tui_session(self, session_id: str) -> dict[str, Any]:
        with self.connect() as db:
            db.execute(
                "UPDATE tui_sessions SET last_activity_at = ? WHERE session_id = ?",
                (utc_iso(), session_id),
            )
        return self.get_tui_session(session_id)

    def add_tui_audit_ref(self, session_id: str, audit_event_id: str) -> dict[str, Any]:
        session = self.get_tui_session(session_id)
        refs = [*session["audit_refs"], audit_event_id]
        with self.connect() as db:
            db.execute(
                "UPDATE tui_sessions SET audit_refs_json = ? WHERE session_id = ?",
                (json.dumps(refs), session_id),
            )
        return self.get_tui_session(session_id)

    def count_open_tui_sessions(self) -> int:
        with self.connect() as db:
            row = db.execute(
                """
                SELECT COUNT(*) AS count
                FROM tui_sessions
                WHERE state IN ('requested', 'active', 'detached')
                """
            ).fetchone()
        return int(row["count"])

    def _tui_session_from_row(self, row: sqlite3.Row) -> dict[str, Any]:
        session = dict(row)
        session["audit_refs"] = json.loads(session.pop("audit_refs_json"))
        session["output_retention_enabled"] = bool(session["output_retention_enabled"])
        return session

    def create_tui_attach_token(
        self,
        *,
        token: str,
        session_id: str,
        device_id: str,
        ttl_seconds: int,
    ) -> dict[str, Any]:
        expires_at = utc_iso(expires_in(ttl_seconds))
        with self.connect() as db:
            db.execute(
                """
                INSERT INTO tui_attach_tokens (
                    token_hash, session_id, device_id, expires_at, created_at
                )
                VALUES (?, ?, ?, ?, ?)
                """,
                (hash_token(token), session_id, device_id, expires_at, utc_iso()),
            )
        return {"attach_token": token, "expires_at": expires_at}

    def verify_tui_attach_token(self, token: str) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute(
                """
                SELECT * FROM tui_attach_tokens
                WHERE token_hash = ? AND revoked_at IS NULL
                """,
                (hash_token(token),),
            ).fetchone()
            if row is None:
                return None
            token_row = dict(row)
            if parse_utc(token_row["expires_at"]) <= now_utc():
                return None
            db.execute(
                "UPDATE tui_attach_tokens SET used_at = ? WHERE token_hash = ?",
                (utc_iso(), token_row["token_hash"]),
            )
        return token_row

    def create_assistance_request(self, request: dict[str, Any]) -> dict[str, Any]:
        request_id = request.get("request_id") or new_id("tua_req")
        now = utc_iso()
        with self.connect() as db:
            db.execute(
                """
                INSERT INTO assistance_requests (
                    request_id, node_id, agent_id, session_id, approval_id, risk_family, reason,
                    state, context_redacted_json, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    request_id,
                    request["node_id"],
                    request["agent_id"],
                    request["session_id"],
                    request.get("approval_id"),
                    request.get("risk_family") or "external_effect",
                    request["reason"],
                    request.get("state", "requested"),
                    json.dumps(request.get("context_redacted", {})),
                    request.get("created_at") or now,
                    request.get("updated_at") or now,
                ),
            )
        return self.get_assistance_request(request_id)

    # --- interventions (operator pause/steer/stop, drained by the plugin) ----

    def enqueue_intervention(self, record: dict[str, Any]) -> dict[str, Any]:
        intervention_id = record.get("intervention_id") or new_id("intv")
        now = utc_iso()
        with self.connect() as db:
            db.execute(
                """
                INSERT INTO interventions (
                    intervention_id, node_id, agent_id, session_id, device_id, type,
                    reason, instruction, state, resulting_state, expires_at,
                    created_at, updated_at, acknowledged_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    intervention_id,
                    record["node_id"],
                    record["agent_id"],
                    record["session_id"],
                    record.get("device_id"),
                    record["type"],
                    record["reason"],
                    record.get("instruction"),
                    record.get("state", "pending"),
                    None,
                    record["expires_at"],
                    record.get("created_at") or now,
                    now,
                    None,
                ),
            )
        return self.get_intervention(intervention_id)

    def get_intervention(self, intervention_id: str) -> dict[str, Any]:
        with self.connect() as db:
            row = db.execute(
                "SELECT * FROM interventions WHERE intervention_id = ?",
                (intervention_id,),
            ).fetchone()
        if row is None:
            raise KeyError(intervention_id)
        return self._intervention_from_row(row)

    def list_pending_interventions(
        self, session_id: str, agent_id: str | None = None
    ) -> list[dict[str, Any]]:
        clauses = ["session_id = ?", "state = 'pending'"]
        args: list[Any] = [session_id]
        if agent_id:
            clauses.append("agent_id = ?")
            args.append(agent_id)
        sql = (
            "SELECT * FROM interventions WHERE "
            + " AND ".join(clauses)
            + " ORDER BY created_at ASC"
        )
        with self.connect() as db:
            rows = db.execute(sql, tuple(args)).fetchall()
        now = now_utc()
        # Skip expired pending rows so a stale command is never applied.
        return [
            item
            for row in rows
            if parse_utc((item := self._intervention_from_row(row))["expires_at"]) > now
        ]

    def ack_intervention(
        self, intervention_id: str, ack_result: str = "accepted"
    ) -> dict[str, Any]:
        now = utc_iso()
        new_state = "rejected" if ack_result == "rejected" else "acknowledged"
        with self.connect() as db:
            db.execute(
                """
                UPDATE interventions
                SET state = ?,
                    resulting_state = ?,
                    acknowledged_at = COALESCE(acknowledged_at, ?),
                    updated_at = ?
                WHERE intervention_id = ? AND state = 'pending'
                """,
                (new_state, ack_result, now, now, intervention_id),
            )
        return self.get_intervention(intervention_id)

    def _intervention_from_row(self, row: sqlite3.Row) -> dict[str, Any]:
        return dict(row)

    def get_assistance_request(self, request_id: str) -> dict[str, Any]:
        with self.connect() as db:
            row = db.execute(
                "SELECT * FROM assistance_requests WHERE request_id = ?",
                (request_id,),
            ).fetchone()
        if row is None:
            raise KeyError(request_id)
        request = dict(row)
        request["context_redacted"] = json.loads(request.pop("context_redacted_json"))
        return request

    def list_assistance_requests(self, state: str | None = None) -> list[dict[str, Any]]:
        sql = "SELECT * FROM assistance_requests"
        args: tuple[Any, ...] = ()
        if state:
            sql += " WHERE state = ?"
            args = (state,)
        sql += " ORDER BY updated_at DESC"
        with self.connect() as db:
            rows = db.execute(sql, args).fetchall()
        return [self._assistance_request_from_row(row) for row in rows]

    def create_assistance_session(self, session: dict[str, Any]) -> dict[str, Any]:
        session_id = session.get("assistance_session_id") or new_id("tua")
        now = utc_iso()
        with self.connect() as db:
            db.execute(
                """
                INSERT INTO assistance_sessions (
                    assistance_session_id, request_id, node_id, agent_id, session_id,
                    state, created_by_device_id, return_summary, created_at, updated_at,
                    returned_at, closed_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session_id,
                    session["request_id"],
                    session["node_id"],
                    session["agent_id"],
                    session["session_id"],
                    session.get("state", "active"),
                    session["created_by_device_id"],
                    session.get("return_summary"),
                    session.get("created_at") or now,
                    session.get("updated_at") or now,
                    session.get("returned_at"),
                    session.get("closed_at"),
                ),
            )
            db.execute(
                "UPDATE assistance_requests SET state = ?, updated_at = ? WHERE request_id = ?",
                ("active", now, session["request_id"]),
            )
        return self.get_assistance_session(session_id)

    def get_assistance_session(self, session_id: str) -> dict[str, Any]:
        with self.connect() as db:
            row = db.execute(
                "SELECT * FROM assistance_sessions WHERE assistance_session_id = ?",
                (session_id,),
            ).fetchone()
        if row is None:
            raise KeyError(session_id)
        session = dict(row)
        session["messages"] = self.list_assistance_messages(session_id)
        return session

    def list_assistance_sessions(
        self,
        *,
        request_id: str | None = None,
        state: str | None = None,
    ) -> list[dict[str, Any]]:
        sql = "SELECT * FROM assistance_sessions"
        args: list[Any] = []
        where = []
        if request_id:
            where.append("request_id = ?")
            args.append(request_id)
        if state:
            where.append("state = ?")
            args.append(state)
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY updated_at DESC"
        with self.connect() as db:
            rows = db.execute(sql, tuple(args)).fetchall()
        sessions = []
        for row in rows:
            session = dict(row)
            session["messages"] = self.list_assistance_messages(
                session["assistance_session_id"]
            )
            sessions.append(session)
        return sessions

    def update_assistance_session_state(
        self,
        session_id: str,
        state: str,
        *,
        return_summary: str | None = None,
    ) -> dict[str, Any]:
        now = utc_iso()
        returned_at = now if state == "returned_to_agent" else None
        closed_at = now if state in {"closed", "cancelled"} else None
        with self.connect() as db:
            db.execute(
                """
                UPDATE assistance_sessions
                SET state = ?,
                    return_summary = COALESCE(?, return_summary),
                    updated_at = ?,
                    returned_at = COALESCE(?, returned_at),
                    closed_at = COALESCE(?, closed_at)
                WHERE assistance_session_id = ?
                """,
                (state, return_summary, now, returned_at, closed_at, session_id),
            )
        return self.get_assistance_session(session_id)

    def create_assistance_message(self, message: dict[str, Any]) -> dict[str, Any]:
        message_id = message.get("message_id") or new_id("tua_msg")
        with self.connect() as db:
            db.execute(
                """
                INSERT INTO assistance_messages (
                    message_id, assistance_session_id, sender_type, sender_id, body, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    message_id,
                    message["assistance_session_id"],
                    message["sender_type"],
                    message["sender_id"],
                    message["body"],
                    message.get("created_at") or utc_iso(),
                ),
            )
        return self.get_assistance_message(message_id)

    def get_assistance_message(self, message_id: str) -> dict[str, Any]:
        with self.connect() as db:
            row = db.execute(
                "SELECT * FROM assistance_messages WHERE message_id = ?",
                (message_id,),
            ).fetchone()
        if row is None:
            raise KeyError(message_id)
        return dict(row)

    def list_assistance_messages(self, session_id: str) -> list[dict[str, Any]]:
        with self.connect() as db:
            rows = db.execute(
                """
                SELECT * FROM assistance_messages
                WHERE assistance_session_id = ?
                ORDER BY created_at ASC
                """,
                (session_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def create_browser_assistance_session(self, session: dict[str, Any]) -> dict[str, Any]:
        session_id = session.get("browser_session_id") or new_id("bas")
        now = utc_iso()
        with self.connect() as db:
            db.execute(
                """
                INSERT INTO browser_assistance_sessions (
                    browser_session_id, node_id, agent_id, session_id, approval_id,
                    risk_family, reason, state, context_redacted_json, user_action_notes_json,
                    return_summary, created_at, updated_at, returned_at, closed_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session_id,
                    session["node_id"],
                    session["agent_id"],
                    session["session_id"],
                    session.get("approval_id"),
                    session.get("risk_family") or "external_effect",
                    session["reason"],
                    session.get("state", "requested"),
                    json.dumps(session.get("context_redacted", {})),
                    json.dumps(session.get("user_action_notes", [])),
                    session.get("return_summary"),
                    session.get("created_at") or now,
                    session.get("updated_at") or now,
                    session.get("returned_at"),
                    session.get("closed_at"),
                ),
            )
        return self.get_browser_assistance_session(session_id)

    def get_browser_assistance_session(self, session_id: str) -> dict[str, Any]:
        with self.connect() as db:
            row = db.execute(
                "SELECT * FROM browser_assistance_sessions WHERE browser_session_id = ?",
                (session_id,),
            ).fetchone()
        if row is None:
            raise KeyError(session_id)
        return self._browser_assistance_session_from_row(row)

    def list_browser_assistance_sessions(
        self, state: str | None = None
    ) -> list[dict[str, Any]]:
        sql = "SELECT * FROM browser_assistance_sessions"
        args: tuple[Any, ...] = ()
        if state:
            sql += " WHERE state = ?"
            args = (state,)
        sql += " ORDER BY updated_at DESC"
        with self.connect() as db:
            rows = db.execute(sql, args).fetchall()
        return [self._browser_assistance_session_from_row(row) for row in rows]

    def add_browser_assistance_note(self, session_id: str, note: str) -> dict[str, Any]:
        session = self.get_browser_assistance_session(session_id)
        notes = [*session["user_action_notes"], note]
        with self.connect() as db:
            db.execute(
                """
                UPDATE browser_assistance_sessions
                SET user_action_notes_json = ?, updated_at = ?, state = ?
                WHERE browser_session_id = ?
                """,
                (json.dumps(notes), utc_iso(), "user_controlling", session_id),
            )
        return self.get_browser_assistance_session(session_id)

    def update_browser_assistance_state(
        self,
        session_id: str,
        state: str,
        *,
        return_summary: str | None = None,
    ) -> dict[str, Any]:
        now = utc_iso()
        returned_at = now if state == "returned_to_agent" else None
        closed_at = now if state in {"closed", "failed"} else None
        with self.connect() as db:
            db.execute(
                """
                UPDATE browser_assistance_sessions
                SET state = ?,
                    return_summary = COALESCE(?, return_summary),
                    updated_at = ?,
                    returned_at = COALESCE(?, returned_at),
                    closed_at = COALESCE(?, closed_at)
                WHERE browser_session_id = ?
                """,
                (state, return_summary, now, returned_at, closed_at, session_id),
            )
        return self.get_browser_assistance_session(session_id)

    def create_approval_policy_proposal(self, proposal: dict[str, Any]) -> dict[str, Any]:
        proposal_id = proposal.get("policy_proposal_id") or new_id("polp")
        with self.connect() as db:
            db.execute(
                """
                INSERT INTO approval_policy_proposals (
                    policy_proposal_id, approval_id, created_by_device_id, status,
                    warning, constraints_json, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    proposal_id,
                    proposal["approval_id"],
                    proposal["created_by_device_id"],
                    proposal.get("status", "proposed"),
                    proposal["warning"],
                    json.dumps(proposal.get("constraints", [])),
                    proposal.get("created_at") or utc_iso(),
                ),
            )
        return self.get_approval_policy_proposal(proposal_id)

    def get_approval_policy_proposal(self, proposal_id: str) -> dict[str, Any]:
        with self.connect() as db:
            row = db.execute(
                "SELECT * FROM approval_policy_proposals WHERE policy_proposal_id = ?",
                (proposal_id,),
            ).fetchone()
        if row is None:
            raise KeyError(proposal_id)
        proposal = dict(row)
        proposal["constraints"] = json.loads(proposal.pop("constraints_json"))
        return proposal

    def create_approval_response(self, response: dict[str, Any]) -> dict[str, Any]:
        response_id = response.get("approval_response_id") or new_id("appr_resp")
        with self.connect() as db:
            db.execute(
                """
                INSERT INTO approval_responses (
                    approval_response_id, approval_id, decision_type,
                    created_by_device_id, user_message, alternate_directive,
                    constraints_json, policy_proposal_id, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    response_id,
                    response["approval_id"],
                    response["decision_type"],
                    response["created_by_device_id"],
                    response.get("user_message"),
                    response.get("alternate_directive"),
                    json.dumps(response.get("constraints", [])),
                    response.get("policy_proposal_id"),
                    response.get("created_at") or utc_iso(),
                ),
            )
        return self.get_approval_response(response_id)

    def get_approval_response(self, response_id: str) -> dict[str, Any]:
        with self.connect() as db:
            row = db.execute(
                "SELECT * FROM approval_responses WHERE approval_response_id = ?",
                (response_id,),
            ).fetchone()
        if row is None:
            raise KeyError(response_id)
        response = dict(row)
        response["constraints"] = json.loads(response.pop("constraints_json"))
        return response

    def list_approval_responses(self, approval_id: str) -> list[dict[str, Any]]:
        with self.connect() as db:
            rows = db.execute(
                "SELECT * FROM approval_responses WHERE approval_id = ? ORDER BY created_at DESC",
                (approval_id,),
            ).fetchall()
        responses = []
        for row in rows:
            response = dict(row)
            response["constraints"] = json.loads(response.pop("constraints_json"))
            responses.append(response)
        return responses

    def create_voice_session(self, session: dict[str, Any]) -> dict[str, Any]:
        session_id = session.get("voice_session_id") or new_id("voice")
        with self.connect() as db:
            db.execute(
                """
                INSERT INTO voice_sessions (
                    voice_session_id, node_id, agent_id, session_id, created_by_device_id,
                    mode, state, risk_family, created_at, closed_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session_id,
                    session["node_id"],
                    session["agent_id"],
                    session.get("session_id"),
                    session["created_by_device_id"],
                    session["mode"],
                    session.get("state", "active"),
                    session.get("risk_family") or "external_effect",
                    session.get("created_at") or utc_iso(),
                    session.get("closed_at"),
                ),
            )
        return self.get_voice_session(session_id)

    def get_voice_session(self, session_id: str) -> dict[str, Any]:
        with self.connect() as db:
            row = db.execute(
                "SELECT * FROM voice_sessions WHERE voice_session_id = ?",
                (session_id,),
            ).fetchone()
        if row is None:
            raise KeyError(session_id)
        session = dict(row)
        session["messages"] = self.list_voice_messages(session_id)
        return session

    def update_voice_session_state(self, session_id: str, state: str) -> dict[str, Any]:
        closed_at = utc_iso() if state == "closed" else None
        with self.connect() as db:
            db.execute(
                """
                UPDATE voice_sessions
                SET state = ?, closed_at = COALESCE(?, closed_at)
                WHERE voice_session_id = ?
                """,
                (state, closed_at, session_id),
            )
        return self.get_voice_session(session_id)

    def create_voice_message(self, message: dict[str, Any]) -> dict[str, Any]:
        message_id = message.get("voice_message_id") or new_id("voice_msg")
        with self.connect() as db:
            db.execute(
                """
                INSERT INTO voice_messages (
                    voice_message_id, voice_session_id, sender_type, body,
                    input_mode, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    message_id,
                    message["voice_session_id"],
                    message.get("sender_type", "user"),
                    message["body"],
                    message["input_mode"],
                    message.get("created_at") or utc_iso(),
                ),
            )
        return self.get_voice_message(message_id)

    def get_voice_message(self, message_id: str) -> dict[str, Any]:
        with self.connect() as db:
            row = db.execute(
                "SELECT * FROM voice_messages WHERE voice_message_id = ?",
                (message_id,),
            ).fetchone()
        if row is None:
            raise KeyError(message_id)
        return dict(row)

    def list_voice_messages(self, session_id: str) -> list[dict[str, Any]]:
        with self.connect() as db:
            rows = db.execute(
                """
                SELECT * FROM voice_messages
                WHERE voice_session_id = ?
                ORDER BY created_at ASC
                """,
                (session_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def create_operator_session(self, session: dict[str, Any]) -> dict[str, Any]:
        now = utc_iso()
        created_at = session.get("created_at") or now
        updated_at = session.get("updated_at") or now
        with self.connect() as db:
            db.execute(
                """
                INSERT INTO operator_sessions (
                    session_id, session_type, agent_id, mission_id, state, owner_device_id,
                    capability_requirements_json, context_json, return_summary,
                    created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(session_id) DO UPDATE SET
                    session_type=excluded.session_type,
                    agent_id=excluded.agent_id,
                    mission_id=excluded.mission_id,
                    state=excluded.state,
                    owner_device_id=COALESCE(excluded.owner_device_id, owner_device_id),
                    capability_requirements_json=excluded.capability_requirements_json,
                    context_json=excluded.context_json,
                    return_summary=COALESCE(excluded.return_summary, return_summary),
                    updated_at=excluded.updated_at
                """,
                (
                    session["session_id"],
                    session["session_type"],
                    session["agent_id"],
                    session.get("mission_id"),
                    session.get("state", "requested"),
                    session.get("owner_device_id"),
                    json.dumps(session.get("capability_requirements", [])),
                    json.dumps(session.get("context", {})),
                    session.get("return_summary"),
                    created_at,
                    updated_at,
                ),
            )
        return self.get_operator_session(session["session_id"])

    def get_operator_session(self, session_id: str) -> dict[str, Any]:
        with self.connect() as db:
            row = db.execute(
                "SELECT * FROM operator_sessions WHERE session_id = ?",
                (session_id,),
            ).fetchone()
        if row is None:
            raise KeyError(session_id)
        return self._operator_session_from_row(row)

    def list_operator_sessions(
        self,
        *,
        session_type: str | None = None,
        state: str | None = None,
        agent_id: str | None = None,
    ) -> list[dict[str, Any]]:
        sql = "SELECT * FROM operator_sessions"
        args: list[Any] = []
        where = []
        if session_type:
            where.append("session_type = ?")
            args.append(session_type)
        if state:
            where.append("state = ?")
            args.append(state)
        if agent_id:
            where.append("agent_id = ?")
            args.append(agent_id)
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY updated_at DESC"
        with self.connect() as db:
            rows = db.execute(sql, tuple(args)).fetchall()
        return [self._operator_session_from_row(row) for row in rows]

    def update_operator_session_state(
        self,
        session_id: str,
        state: str,
        *,
        owner_device_id: str | None = None,
        return_summary: str | None = None,
    ) -> dict[str, Any]:
        with self.connect() as db:
            db.execute(
                """
                UPDATE operator_sessions
                SET state = ?,
                    owner_device_id = COALESCE(?, owner_device_id),
                    return_summary = COALESCE(?, return_summary),
                    updated_at = ?
                WHERE session_id = ?
                """,
                (state, owner_device_id, return_summary, utc_iso(), session_id),
            )
        return self.get_operator_session(session_id)

    def create_capability_grant(self, grant: dict[str, Any]) -> dict[str, Any]:
        grant_id = grant.get("grant_id") or new_id("cap")
        with self.connect() as db:
            db.execute(
                """
                INSERT INTO capability_grants (
                    grant_id, subject_type, subject_id, capability, node_id, agent_id,
                    state, reason, created_at, expires_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    grant_id,
                    grant["subject_type"],
                    grant["subject_id"],
                    grant["capability"],
                    grant["node_id"],
                    grant.get("agent_id"),
                    grant.get("state", "granted"),
                    grant.get("reason"),
                    grant.get("created_at") or utc_iso(),
                    grant.get("expires_at"),
                ),
            )
        return self.get_capability_grant(grant_id)

    def get_capability_grant(self, grant_id: str) -> dict[str, Any]:
        with self.connect() as db:
            row = db.execute(
                "SELECT * FROM capability_grants WHERE grant_id = ?",
                (grant_id,),
            ).fetchone()
        if row is None:
            raise KeyError(grant_id)
        return dict(row)

    def list_capability_grants(
        self,
        *,
        subject_type: str | None = None,
        subject_id: str | None = None,
        capability: str | None = None,
        state: str | None = None,
    ) -> list[dict[str, Any]]:
        sql = "SELECT * FROM capability_grants"
        args: list[Any] = []
        where = []
        if subject_type:
            where.append("subject_type = ?")
            args.append(subject_type)
        if subject_id:
            where.append("subject_id = ?")
            args.append(subject_id)
        if capability:
            where.append("capability = ?")
            args.append(capability)
        if state:
            where.append("state = ?")
            args.append(state)
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY created_at DESC"
        with self.connect() as db:
            rows = db.execute(sql, tuple(args)).fetchall()
        return [dict(row) for row in rows]

    def has_active_capability_grant(
        self,
        *,
        subject_type: str,
        subject_id: str,
        capability: str,
        node_id: str,
        agent_id: str | None = None,
    ) -> bool:
        now = now_utc()
        for grant in self.list_capability_grants(
            subject_type=subject_type,
            subject_id=subject_id,
            capability=capability,
            state="granted",
        ):
            if grant["node_id"] != node_id:
                continue
            if grant.get("agent_id") and agent_id and grant["agent_id"] != agent_id:
                continue
            expires_at = grant.get("expires_at")
            if expires_at and parse_utc(expires_at) <= now:
                continue
            return True
        return False

    def _assistance_request_from_row(self, row: sqlite3.Row) -> dict[str, Any]:
        request = dict(row)
        request["context_redacted"] = json.loads(request.pop("context_redacted_json"))
        return request

    def _browser_assistance_session_from_row(self, row: sqlite3.Row) -> dict[str, Any]:
        session = dict(row)
        session["context_redacted"] = json.loads(session.pop("context_redacted_json"))
        session["user_action_notes"] = json.loads(session.pop("user_action_notes_json"))
        return session

    def _operator_session_from_row(self, row: sqlite3.Row) -> dict[str, Any]:
        session = dict(row)
        session["capability_requirements"] = json.loads(
            session.pop("capability_requirements_json")
        )
        session["context"] = json.loads(session.pop("context_json"))
        return session

    def seed_mock_data(self, *, node_id: str) -> None:
        if self.list_agents(node_id=node_id):
            return
        agent_id = "agent_mock"
        session_id = "sess_mock"
        self.upsert_agent(
            {
                "agent_id": agent_id,
                "node_id": node_id,
                "display_name": "Mock Hermes Agent",
                "agent_kind": "primary",
                "status": "idle",
                "capabilities": [
                    {"name": "chat", "status": "available"},
                    {"name": "approvals", "status": "available"},
                ],
            }
        )
        self.upsert_session(
            {
                "session_id": session_id,
                "node_id": node_id,
                "agent_id": agent_id,
                "status": "active",
                "title": "Mock control-plane session",
                "summary": "Seed session for gateway smoke tests.",
                "current_plan": "Waiting for mobile control-plane events.",
            }
        )
        if self.event_count() == 0:
            for event_type, payload in self.mock_events(agent_id=agent_id, session_id=session_id):
                self.create_event(
                    node_id=node_id,
                    agent_id=agent_id,
                    session_id=session_id,
                    event_type=event_type,
                    payload=payload,
                )

    def mock_events(
        self, *, agent_id: str, session_id: str
    ) -> Iterable[tuple[str, dict[str, Any]]]:
        return (
            ("agent.status", {"agent_id": agent_id, "status": "idle"}),
            ("agent.activity", {"session_id": session_id, "summary": "Mock activity event"}),
            ("approval.requested", {"approval_id": "approval_mock", "risk_level": "medium"}),
            ("approval.resolved", {"approval_id": "approval_mock", "state": "denied"}),
            ("notification.created", {"notification_id": "notification_mock"}),
            ("system.health", {"status": "healthy"}),
        )

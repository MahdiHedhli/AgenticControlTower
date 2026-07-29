"""Store-layer contract for standing approval grants (WS2).

Covers the match rules, the mandatory hard expiry, and — because the production
database is live — that the migration is purely additive on an existing file.
"""

from __future__ import annotations

import sqlite3
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

from hermes_gateway.security import now_utc, utc_iso
from hermes_gateway.store import SQLiteStore


def iso_in(seconds: int) -> str:
    return (now_utc() + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")


@pytest.fixture()
def store(tmp_path: Path) -> SQLiteStore:
    store = SQLiteStore(str(tmp_path / "gateway.sqlite3"))
    store.initialize()
    return store


def make_grant(store: SQLiteStore, **overrides: Any) -> dict[str, Any]:
    grant: dict[str, Any] = {
        "node_id": "node_test",
        "agent_id": "agent_a",
        "session_id": "sess_a",
        "requested_tool": "git_status",
        "params_fingerprint": "fp_one",
        "risk_family": "external_effect",
        "scope": "session",
        "source_approval_id": "appr_source",
        "expires_at": iso_in(3600),
    }
    grant.update(overrides)
    return store.create_approval_grant(grant)


def lookup(store: SQLiteStore, **overrides: Any) -> dict[str, Any] | None:
    query: dict[str, Any] = {
        "node_id": "node_test",
        "agent_id": "agent_a",
        "session_id": "sess_a",
        "requested_tool": "git_status",
        "params_fingerprint": "fp_one",
        "risk_family": "external_effect",
    }
    query.update(overrides)
    return store.find_matching_grant(**query)


def test_grant_requires_a_hard_expiry(store: SQLiteStore) -> None:
    with pytest.raises(ValueError, match="hard expires_at"):
        store.create_approval_grant(
            {
                "node_id": "node_test",
                "agent_id": "agent_a",
                "requested_tool": "git_status",
                "scope": "permanent",
                "source_approval_id": "appr_source",
                "expires_at": None,
            }
        )


def test_grant_rejects_the_once_scope(store: SQLiteStore) -> None:
    with pytest.raises(ValueError, match="unsupported grant scope"):
        make_grant(store, scope="once")


def test_session_grant_matches_identical_request(store: SQLiteStore) -> None:
    grant = make_grant(store, scope="session")
    assert (lookup(store) or {}).get("grant_id") == grant["grant_id"]


def test_session_grant_requires_fingerprint_match(store: SQLiteStore) -> None:
    make_grant(store, scope="session")
    assert lookup(store, params_fingerprint="fp_other") is None


def test_session_grant_requires_same_session(store: SQLiteStore) -> None:
    make_grant(store, scope="session")
    assert lookup(store, session_id="sess_other") is None


def test_agent_grant_ignores_fingerprint_and_session(store: SQLiteStore) -> None:
    grant = make_grant(store, scope="agent", session_id=None, params_fingerprint=None)
    match = lookup(store, params_fingerprint="fp_other", session_id="sess_other")
    assert (match or {}).get("grant_id") == grant["grant_id"]


def test_agent_grant_does_not_cross_agents(store: SQLiteStore) -> None:
    make_grant(store, scope="agent", session_id=None, params_fingerprint=None)
    assert lookup(store, agent_id="agent_b") is None


def test_permanent_grant_ignores_agent_session_and_fingerprint(store: SQLiteStore) -> None:
    grant = make_grant(
        store, scope="permanent", session_id=None, params_fingerprint=None
    )
    match = lookup(
        store,
        agent_id="agent_b",
        session_id="sess_other",
        params_fingerprint="fp_other",
    )
    assert (match or {}).get("grant_id") == grant["grant_id"]


def test_permanent_grant_does_not_cross_tools(store: SQLiteStore) -> None:
    make_grant(store, scope="permanent", session_id=None, params_fingerprint=None)
    assert lookup(store, requested_tool="rm_rf") is None


def test_permanent_grant_does_not_cross_nodes(store: SQLiteStore) -> None:
    make_grant(store, scope="permanent", session_id=None, params_fingerprint=None)
    assert lookup(store, node_id="node_other") is None


def test_expired_grant_never_matches(store: SQLiteStore) -> None:
    make_grant(store, scope="agent", expires_at=iso_in(-1))
    assert lookup(store) is None


def test_revoked_grant_never_matches(store: SQLiteStore) -> None:
    grant = make_grant(store, scope="agent")
    assert lookup(store) is not None
    store.revoke_approval_grant(grant["grant_id"], revoked_by="dev_test")
    assert lookup(store) is None


def test_revoking_twice_is_rejected(store: SQLiteStore) -> None:
    grant = make_grant(store, scope="agent")
    store.revoke_approval_grant(grant["grant_id"], revoked_by="dev_test")
    with pytest.raises(ValueError, match="not active"):
        store.revoke_approval_grant(grant["grant_id"], revoked_by="dev_test")


def test_risk_family_must_match_exactly(store: SQLiteStore) -> None:
    """A tool reclassified upward must re-prompt, not ride the old grant."""
    make_grant(store, scope="agent", risk_family="routine")
    assert lookup(store, risk_family="external_effect") is None
    assert lookup(store, risk_family="routine") is not None


def test_narrowest_scope_wins(store: SQLiteStore) -> None:
    make_grant(store, scope="permanent", session_id=None, params_fingerprint=None)
    make_grant(store, scope="agent", session_id=None, params_fingerprint=None)
    session_grant = make_grant(store, scope="session")

    assert (lookup(store) or {})["grant_id"] == session_grant["grant_id"]


def test_list_can_exclude_expired(store: SQLiteStore) -> None:
    live = make_grant(store, scope="agent")
    make_grant(store, scope="agent", expires_at=iso_in(-5))

    assert len(store.list_approval_grants()) == 2
    live_only = store.list_approval_grants(include_expired=False)
    assert [row["grant_id"] for row in live_only] == [live["grant_id"]]


def test_migration_is_additive_on_an_existing_database(tmp_path: Path) -> None:
    """The production gateway database is live. Re-initializing must add
    columns to a pre-existing approval_grants table without touching rows."""
    database_path = str(tmp_path / "legacy.sqlite3")
    with sqlite3.connect(database_path) as db:
        db.execute(
            """
            CREATE TABLE approval_grants (
                grant_id TEXT PRIMARY KEY,
                node_id TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                session_id TEXT,
                requested_tool TEXT NOT NULL,
                scope TEXT NOT NULL,
                state TEXT NOT NULL,
                source_approval_id TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            )
            """
        )
        db.execute(
            "INSERT INTO approval_grants VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "grant_legacy",
                "node_test",
                "agent_a",
                "sess_a",
                "git_status",
                "agent",
                "active",
                "appr_legacy",
                utc_iso(),
                iso_in(3600),
            ),
        )

    store = SQLiteStore(database_path)
    store.initialize()

    surviving = store.get_approval_grant("grant_legacy")
    assert surviving["requested_tool"] == "git_status"
    assert surviving["state"] == "active"
    # Columns added by the additive migration, defaulted for the legacy row.
    assert surviving["risk_family"] == "external_effect"
    assert surviving["params_fingerprint"] is None
    assert surviving["revoked_at"] is None

    # And the legacy row still participates in lookups.
    match = store.find_matching_grant(
        node_id="node_test",
        agent_id="agent_a",
        session_id="sess_whatever",
        requested_tool="git_status",
        params_fingerprint="fp_whatever",
        risk_family="external_effect",
    )
    assert (match or {}).get("grant_id") == "grant_legacy"


def test_reinitialize_preserves_existing_grants(store: SQLiteStore) -> None:
    grant = make_grant(store, scope="agent")
    store.initialize()
    assert store.get_approval_grant(grant["grant_id"])["state"] == "active"

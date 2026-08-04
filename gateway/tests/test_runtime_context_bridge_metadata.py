"""The bridge-metadata half of the runtime-context contract.

Every heartbeat from the installed act-clearance plugin was rejected 422 since
01:49: the plugin posts ``bridge_plugin_name`` / ``bridge_plugin_version`` as
top-level fields, ``RuntimeContextRequest`` is a ``StrictModel``
(``extra="forbid"``), and FastAPI rejects the body before the route runs. The
plugin's ``_post_context`` fails open and swallows the 4xx, so the app's
Fleet/Agents/Missions simply showed hours-old state as current.

Root cause worth remembering: the plugin half of that feature was captured into
git (f983eef) while the gateway-side schema change stayed in an uncommitted
worktree. A partial capture, not a plugin bug.

What is pinned here: the metadata is accepted (via the namespaced ``extensions``
escape hatch, not two one-off fields), strictness is NOT relaxed for anything
else, and a rejected body is loud in the log instead of silent.
"""

from __future__ import annotations

import logging
from collections.abc import Generator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from hermes_gateway.app import create_app
from hermes_gateway.config import Settings
from hermes_gateway.schemas import RuntimeContextRequest
from hermes_gateway.store import SQLiteStore


@pytest.fixture()
def client(tmp_path: Path) -> Generator[TestClient]:
    settings = Settings(
        node_id="node_bridge",
        node_display_name="Bridge Test Tower",
        node_fingerprint="bridge-test-fingerprint",
        gateway_base_url="http://127.0.0.1:8990/v1",
        database_path=str(tmp_path / "gateway.sqlite3"),
    )
    # Loopback client host: /v1/runtime/* is a Hermes-local endpoint.
    with TestClient(create_app(settings), client=("127.0.0.1", 50000)) as test_client:
        yield test_client


def _heartbeat_body() -> dict:
    """The exact shape the installed plugin posts (act-clearance 0.1.4)."""
    return {
        "agent_id": "agent_hermes",
        "display_name": "Hermes",
        "bridge_plugin_name": "act-clearance",
        "bridge_plugin_version": "0.1.4",
        "agent_status": "running",
        "session_id": "sess_1",
        "mission_state": "running",
        "mission_title": "Hermes session",
    }


def test_bridge_heartbeat_is_accepted(client: TestClient) -> None:
    """The live 422. Was: whole body rejected before the route ran."""
    response = client.post("/v1/runtime/context", json=_heartbeat_body())
    assert response.status_code == 200, response.text
    assert response.json()["agent"]["agent_id"] == "agent_hermes"


def test_flat_bridge_keys_land_in_the_extensions_namespace() -> None:
    payload = RuntimeContextRequest.model_validate(_heartbeat_body())
    assert payload.extensions == {
        "bridge": {"plugin_name": "act-clearance", "plugin_version": "0.1.4"}
    }


def test_an_unknown_bridge_field_needs_no_gateway_release() -> None:
    """The point of a namespace rather than two named fields."""
    payload = RuntimeContextRequest.model_validate(
        {"agent_id": "a", "bridge_plugin_build": "2026-07-31"}
    )
    assert payload.extensions["bridge"] == {"plugin_build": "2026-07-31"}


def test_nested_extensions_are_accepted_directly() -> None:
    """The forward shape, matching CreateApprovalRequest.extensions."""
    payload = RuntimeContextRequest.model_validate(
        {"agent_id": "a", "extensions": {"bridge": {"plugin_name": "act-clearance"}}}
    )
    assert payload.extensions == {"bridge": {"plugin_name": "act-clearance"}}


def test_explicit_extensions_win_over_folded_flat_keys() -> None:
    payload = RuntimeContextRequest.model_validate(
        {
            "agent_id": "a",
            "bridge_plugin_name": "legacy",
            "extensions": {"bridge": {"plugin_name": "explicit"}},
        }
    )
    assert payload.extensions["bridge"]["plugin_name"] == "explicit"


def test_strictness_is_not_relaxed(client: TestClient) -> None:
    """Only the bridge namespace is absorbed. A typo is still a 422."""
    body = _heartbeat_body() | {"agnet_status": "running"}
    response = client.post("/v1/runtime/context", json=body)
    assert response.status_code == 422
    assert "agnet_status" in response.text

    # And the bare prefix is not a wildcard for the model's own fields.
    with pytest.raises(ValueError):
        RuntimeContextRequest.model_validate({"agent_id": "a", "bridge_": "x"})


def test_bridge_metadata_is_persisted_to_the_audit_trail(
    client: TestClient, tmp_path: Path
) -> None:
    """Deliberate destination: the audit log, not the agents row.

    It answers "which plugin build is talking to me", which is a diagnostic, not
    agent state — and putting it on the agents row would mean a schema migration
    on a live database for a diagnostic.
    """
    assert client.post("/v1/runtime/context", json=_heartbeat_body()).status_code == 200

    store = SQLiteStore(str(tmp_path / "gateway.sqlite3"))
    with store.connect() as db:
        rows = [
            dict(row)
            for row in db.execute(
                "SELECT payload_redacted_json FROM audit_events "
                "WHERE event_type = 'runtime_context_registered'"
            )
        ]
    assert rows, "no runtime_context_registered audit event"
    assert "act-clearance" in rows[-1]["payload_redacted_json"]
    assert "0.1.4" in rows[-1]["payload_redacted_json"]


def test_a_rejected_body_is_logged_at_warning_with_the_field_names(
    client: TestClient, caplog: pytest.LogCaptureFixture
) -> None:
    """The bridge swallows 4xx, so the gateway has to be the one that says so."""
    with caplog.at_level(logging.WARNING, logger="hermes_gateway"):
        response = client.post(
            "/v1/runtime/context",
            json={"agent_id": "a", "totally_unexpected": 1},
        )
    assert response.status_code == 422
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert warnings, "a rejected context post left no trace in the log"
    message = warnings[-1].getMessage()
    assert "/v1/runtime/context" in message
    assert "totally_unexpected" in message


def test_the_warning_log_carries_field_names_not_values(
    client: TestClient, caplog: pytest.LogCaptureFixture
) -> None:
    """ADR-0005: request payload content must not reach the log."""
    with caplog.at_level(logging.WARNING, logger="hermes_gateway"):
        client.post(
            "/v1/runtime/context",
            json={"agent_id": "a", "secret_field": "s3cret-value"},
        )
    message = caplog.records[-1].getMessage()
    assert "secret_field" in message
    assert "s3cret-value" not in message

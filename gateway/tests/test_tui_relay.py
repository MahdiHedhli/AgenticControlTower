"""TUI mirror relay: the plugin feeds the agent's terminal output (hermes-local)
to a node-owned, read-only TUI session any paired tui-capable device can watch.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from conftest import pair_device, signed_request


def test_relay_creates_attachable_shared_session(client: TestClient) -> None:
    relay = client.post(
        "/v1/runtime/tui/relay",
        json={
            "session_id": "agentsess_1",
            "agent_id": "agent_mock",
            "chunk": "$ echo hi\nhi\n",
        },
    )
    assert relay.status_code == 200, relay.text
    assert relay.json()["session_id"] == "agentsess_1"

    # Any paired tui-capable device can attach to the relay session, even though
    # it did not create it (node-owned, shared).
    paired = pair_device(client, requested_permissions=["read_state", "tui"])
    token = signed_request(
        client,
        "POST",
        "/v1/tui/sessions/agentsess_1/attach-token",
        private_key=paired["private_key"],
        device_id=paired["device"]["device_id"],
    )
    assert token.status_code == 200, token.text

    # Re-feed is idempotent (same session).
    again = client.post(
        "/v1/runtime/tui/relay",
        json={"session_id": "agentsess_1", "agent_id": "agent_mock", "chunk": "more\n"},
    )
    assert again.status_code == 200


def test_relay_attach_requires_tui_capability(client: TestClient) -> None:
    client.post(
        "/v1/runtime/tui/relay",
        json={"session_id": "agentsess_2", "agent_id": "agent_mock", "chunk": "x\n"},
    )
    # A device without the tui capability cannot attach.
    paired = pair_device(client, requested_permissions=["read_state", "approve"])
    token = signed_request(
        client,
        "POST",
        "/v1/tui/sessions/agentsess_2/attach-token",
        private_key=paired["private_key"],
        device_id=paired["device"]["device_id"],
    )
    assert token.status_code == 403


def test_list_tui_sessions_accepts_access_token(client: TestClient) -> None:
    """Viewing the terminal mirror is a read: a bare access token (no device
    signature, hence no biometric prompt) must be accepted, returning the same
    payload as the signed-device path."""
    paired = pair_device(client, requested_permissions=["read_state", "tui"])
    access_token = paired["tokens"]["access_token"]

    token_auth = client.get(
        "/v1/tui/sessions",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert token_auth.status_code == 200, token_auth.text
    assert "sessions" in token_auth.json()

    # Same result as the signed-device path (relay-listing behavior unchanged).
    signed = signed_request(
        client,
        "GET",
        "/v1/tui/sessions",
        private_key=paired["private_key"],
        device_id=paired["device"]["device_id"],
    )
    assert signed.status_code == 200, signed.text
    assert token_auth.json() == signed.json()


def test_get_tui_session_accepts_access_token(client: TestClient) -> None:
    """Reading a single relay (mirror) session also works with token auth."""
    client.post(
        "/v1/runtime/tui/relay",
        json={"session_id": "agentsess_3", "agent_id": "agent_mock", "chunk": "y\n"},
    )
    paired = pair_device(client, requested_permissions=["read_state", "tui"])
    access_token = paired["tokens"]["access_token"]

    read = client.get(
        "/v1/tui/sessions/agentsess_3",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert read.status_code == 200, read.text
    assert read.json()["session_id"] == "agentsess_3"


def test_list_tui_sessions_rejects_unauthenticated(client: TestClient) -> None:
    """Fail-closed: no signature and no token -> rejected."""
    response = client.get("/v1/tui/sessions")
    assert response.status_code in (401, 403)

    bad_token = client.get(
        "/v1/tui/sessions",
        headers={"Authorization": "Bearer not-a-real-token"},
    )
    assert bad_token.status_code in (401, 403)


def test_get_tui_session_rejects_unauthenticated(client: TestClient) -> None:
    client.post(
        "/v1/runtime/tui/relay",
        json={"session_id": "agentsess_4", "agent_id": "agent_mock", "chunk": "z\n"},
    )
    response = client.get("/v1/tui/sessions/agentsess_4")
    assert response.status_code in (401, 403)

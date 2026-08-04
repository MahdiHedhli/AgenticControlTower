from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from conftest import pair_device, signed_request


def test_websocket_receives_mock_events(client: TestClient) -> None:
    paired = pair_device(client)
    token = paired["tokens"]["access_token"]

    with client.websocket_connect(f"/v1/events/stream?access_token={token}") as websocket:
        events = [websocket.receive_json() for _ in range(6)]

    event_types = {event["type"] for event in events}
    assert {
        "agent.status",
        "agent.activity",
        "approval.requested",
        "approval.resolved",
        "notification.created",
        "system.health",
    }.issubset(event_types)


def test_websocket_disconnect_reconnect_uses_cursor(client: TestClient) -> None:
    paired = pair_device(client)
    token = paired["tokens"]["access_token"]

    with client.websocket_connect(f"/v1/events/stream?access_token={token}") as websocket:
        first = websocket.receive_json()
        cursor = first["cursor"]

    with client.websocket_connect(
        f"/v1/events/stream?access_token={token}&after={cursor}"
    ) as websocket:
        resumed = websocket.receive_json()

    assert resumed["cursor"] != cursor
    assert resumed["type"] in {
        "agent.activity",
        "approval.requested",
        "approval.resolved",
        "notification.created",
        "system.health",
    }


def test_expired_access_token_is_refused_while_signed_http_still_works(
    client: TestClient,
) -> None:
    """The asymmetry that stranded a paired iPhone on "Live stream connecting".

    The event stream is the only consumer of the 15 minute access token; signed
    HTTP authenticates with the device key and never expires. So an app that
    never refreshes keeps getting 200 on every REST call while the upgrade is
    refused forever. Fail closed here, and let the client notice the status.
    """
    paired = pair_device(client)
    store = client.app.state.store
    device_id = paired["device"]["device_id"]

    expired = "expired-access-token"
    store.create_auth_token(
        token=expired,
        token_type="access",
        device_id=device_id,
        ttl_seconds=-1,
    )

    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect(f"/v1/events/stream?access_token={expired}"):
            pass

    still_authorized = signed_request(
        client,
        "GET",
        "/v1/agents",
        private_key=paired["private_key"],
        device_id=device_id,
    )
    assert still_authorized.status_code == 200


def test_refreshed_access_token_reconnects_the_stream(client: TestClient) -> None:
    """The recovery path the app relies on after a refused upgrade."""
    paired = pair_device(client)
    device_id = paired["device"]["device_id"]

    stale = "stale-access-token"
    client.app.state.store.create_auth_token(
        token=stale,
        token_type="access",
        device_id=device_id,
        ttl_seconds=-1,
    )
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect(f"/v1/events/stream?access_token={stale}"):
            pass

    refreshed = signed_request(
        client,
        "POST",
        "/v1/auth/token/refresh",
        private_key=paired["private_key"],
        device_id=device_id,
        json_body={"refresh_token": paired["tokens"]["refresh_token"]},
    )
    assert refreshed.status_code == 200

    token = refreshed.json()["access_token"]
    with client.websocket_connect(f"/v1/events/stream?access_token={token}") as websocket:
        assert websocket.receive_json()["cursor"]


def test_revoked_device_cannot_open_the_stream(client: TestClient) -> None:
    paired = pair_device(client)
    token = paired["tokens"]["access_token"]
    client.app.state.store.revoke_device(paired["device"]["device_id"])

    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect(f"/v1/events/stream?access_token={token}"):
            pass


def test_missing_access_token_is_refused(client: TestClient) -> None:
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/v1/events/stream"):
            pass

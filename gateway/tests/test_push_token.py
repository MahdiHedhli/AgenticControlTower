"""Device-signed APNs push-token registration for an already-paired device."""

from __future__ import annotations

from fastapi.testclient import TestClient

from conftest import pair_device, signed_request


def test_push_token_register_and_clear(client: TestClient) -> None:
    paired = pair_device(client)

    registered = signed_request(
        client,
        "POST",
        "/v1/devices/me/push-token",
        private_key=paired["private_key"],
        device_id=paired["device"]["device_id"],
        json_body={"push_token": "apns-device-token-abc123"},
    )
    assert registered.status_code == 200, registered.text
    assert registered.json()["push_registered"] is True

    cleared = signed_request(
        client,
        "POST",
        "/v1/devices/me/push-token",
        private_key=paired["private_key"],
        device_id=paired["device"]["device_id"],
        json_body={"push_token": None},
    )
    assert cleared.status_code == 200
    assert cleared.json()["push_registered"] is False

from __future__ import annotations

import json
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from conftest import pair_device, signature_headers, signed_request


def test_valid_signed_request_accepted(client: TestClient) -> None:
    paired = pair_device(client)

    response = signed_request(
        client,
        "GET",
        "/v1/devices",
        private_key=paired["private_key"],
        device_id=paired["device"]["device_id"],
    )

    assert response.status_code == 200
    assert response.json()["devices"]


def test_missing_signature_rejected(client: TestClient) -> None:
    response = client.get("/v1/devices")

    assert response.status_code == 401
    assert response.json()["detail"] == "missing device signature"


def test_invalid_signature_rejected(client: TestClient) -> None:
    paired = pair_device(client)
    wrong_key = Ed25519PrivateKey.generate()

    response = signed_request(
        client,
        "GET",
        "/v1/devices",
        private_key=wrong_key,
        device_id=paired["device"]["device_id"],
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "invalid device signature"


def test_timestamp_outside_window_rejected(client: TestClient) -> None:
    paired = pair_device(client)

    response = signed_request(
        client,
        "GET",
        "/v1/devices",
        private_key=paired["private_key"],
        device_id=paired["device"]["device_id"],
        timestamp=int(time.time()) - 1000,
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "expired request timestamp"


def test_nonce_replay_rejected(client: TestClient) -> None:
    paired = pair_device(client)
    nonce = "replay-nonce"
    timestamp = int(time.time())
    headers = signature_headers(
        private_key=paired["private_key"],
        device_id=paired["device"]["device_id"],
        method="GET",
        path="/v1/devices",
        timestamp=timestamp,
        nonce=nonce,
    )

    first = client.get("/v1/devices", headers=headers)
    second = client.get("/v1/devices", headers=headers)

    assert first.status_code == 200
    assert second.status_code == 409
    detail = second.json()["detail"]
    # A replay is retryable with a fresh nonce; an approval conflict is not.
    # Both are 409, so the client can only tell them apart by this code.
    assert detail["error"] == "request_replayed"


def test_body_tampering_rejected(client: TestClient) -> None:
    paired = pair_device(client)
    approval = create_approval(client)
    original = json.dumps(
        {
            "decision_id": "decision-1",
            "decision": "approve",
            "scope": "once",
            "signed_payload": {"approval_id": approval["approval_id"]},
            "signature": "inner-signature-placeholder",
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    tampered = json.dumps(
        {
            "decision_id": "decision-1",
            "decision": "deny",
            "scope": "once",
            "signed_payload": {"approval_id": approval["approval_id"]},
            "signature": "inner-signature-placeholder",
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")

    response = signed_request(
        client,
        "POST",
        f"/v1/approvals/{approval['approval_id']}/decisions",
        private_key=paired["private_key"],
        device_id=paired["device"]["device_id"],
        send_body=tampered,
        sign_body=original,
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "invalid device signature"


def test_path_and_method_tampering_rejected(client: TestClient) -> None:
    paired = pair_device(client)

    response = signed_request(
        client,
        "GET",
        "/v1/notifications",
        private_key=paired["private_key"],
        device_id=paired["device"]["device_id"],
        sign_method="POST",
        sign_path="/v1/devices",
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "invalid device signature"


def test_revoked_device_rejected(client: TestClient) -> None:
    paired = pair_device(client)
    device_id = paired["device"]["device_id"]
    revoke = signed_request(
        client,
        "DELETE",
        f"/v1/devices/{device_id}",
        private_key=paired["private_key"],
        device_id=device_id,
    )
    assert revoke.status_code == 204

    response = signed_request(
        client,
        "GET",
        "/v1/devices",
        private_key=paired["private_key"],
        device_id=device_id,
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "device is not active"


def test_unknown_device_rejected(client: TestClient) -> None:
    private_key = Ed25519PrivateKey.generate()

    response = signed_request(
        client,
        "GET",
        "/v1/devices",
        private_key=private_key,
        device_id="dev_unknown",
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "unknown device"


def create_approval(client: TestClient) -> dict:
    response = client.post(
        "/v1/approvals",
        json={
            "action_id": "act_signing",
            "agent_id": "agent_mock",
            "session_id": "sess_mock",
            "requested_tool": "shell",
            "risk_level": "high",
            "risk_family": "destructive",
            "summary": "Run a command",
            "full_payload_redacted": {"command": "redacted"},
            "resource_scope": "repo",
            "expires_at": "2099-01-01T00:00:00Z",
        },
    )
    assert response.status_code == 201
    return response.json()

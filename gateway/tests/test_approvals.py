from __future__ import annotations

from fastapi.testclient import TestClient

from conftest import pair_device, signed_request


def test_create_and_list_pending_approval(client: TestClient) -> None:
    paired = pair_device(client)
    approval = create_approval(client, action_id="act_create")

    response = signed_request(
        client,
        "GET",
        "/v1/approvals?state=pending",
        private_key=paired["private_key"],
        device_id=paired["device"]["device_id"],
    )

    assert response.status_code == 200
    approvals = response.json()["approvals"]
    assert any(item["approval_id"] == approval["approval_id"] for item in approvals)


def test_approve_once_creates_audit_and_event(client: TestClient) -> None:
    paired = pair_device(client)
    approval = create_approval(client, action_id="act_approve")

    response = signed_request(
        client,
        "POST",
        f"/v1/approvals/{approval['approval_id']}/approve_once",
        private_key=paired["private_key"],
        device_id=paired["device"]["device_id"],
    )

    assert response.status_code == 200
    assert response.json()["state"] == "approved"
    assert response.json()["applied_scope"] == "once"
    assert audit_exists(client, paired, "approval_decision")
    assert approval_event_exists(client, paired, approval["approval_id"], "approved")


def test_deny_approval(client: TestClient) -> None:
    paired = pair_device(client)
    approval = create_approval(client, action_id="act_deny")

    response = signed_request(
        client,
        "POST",
        f"/v1/approvals/{approval['approval_id']}/deny",
        private_key=paired["private_key"],
        device_id=paired["device"]["device_id"],
    )

    assert response.status_code == 200
    assert response.json()["state"] == "denied"


def test_scoped_approval_decision_records_session_scope(client: TestClient) -> None:
    """The decision RECORDS session scope. It does not APPLY it.

    ``create_approval`` here declares ``risk_family="destructive"``, which is
    above the standing-grant exclusion floor, so ``mint_grant_for_decision``
    refuses and ``approval_grants`` stays empty. ``applied_scope`` used to echo
    ``session`` back anyway — the phone said "approved for this session" for an
    authority that was never granted (0 grant rows against 131 approvals in
    production). The refusal policy is unchanged; only the reporting is honest.
    """
    paired = pair_device(client)
    approval = create_approval(client, action_id="act_session_scope")

    response = signed_request(
        client,
        "POST",
        f"/v1/approvals/{approval['approval_id']}/decisions",
        private_key=paired["private_key"],
        device_id=paired["device"]["device_id"],
        json_body=decision_body(
            approval_id=approval["approval_id"],
            decision="approve",
            scope="session",
            params_fingerprint=approval["params_fingerprint"],
        ),
    )

    assert response.status_code == 200
    body = response.json()
    assert body["state"] == "approved"
    assert body["requested_scope"] == "session"
    assert body["applied_scope"] == "once"
    assert body["grant_minted"] is False
    assert body["grant_refused_reason"] == "risk_family_excluded"

    detail = signed_request(
        client,
        "GET",
        f"/v1/approvals/{approval['approval_id']}",
        private_key=paired["private_key"],
        device_id=paired["device"]["device_id"],
    )
    assert detail.status_code == 200
    assert detail.json()["decision_scope"] == "session"
    assert approval_event_exists(client, paired, approval["approval_id"], "approved")


def test_scoped_approval_decision_records_agent_scope(client: TestClient) -> None:
    paired = pair_device(client)
    approval = create_approval(client, action_id="act_agent_scope")

    response = signed_request(
        client,
        "POST",
        f"/v1/approvals/{approval['approval_id']}/decisions",
        private_key=paired["private_key"],
        device_id=paired["device"]["device_id"],
        json_body=decision_body(
            approval_id=approval["approval_id"],
            decision="approve",
            scope="agent",
            params_fingerprint=approval["params_fingerprint"],
        ),
    )

    assert response.status_code == 200
    body = response.json()
    assert body["state"] == "approved"
    # Same story as the session-scope case: recorded, refused, reported honestly.
    assert body["requested_scope"] == "agent"
    assert body["applied_scope"] == "once"
    assert body["grant_minted"] is False
    assert body["grant_refused_reason"] == "risk_family_excluded"


def test_params_fingerprint_is_returned_and_bound_to_decision(client: TestClient) -> None:
    paired = pair_device(client)
    approval = create_approval(client, action_id="act_params_bound")

    response = signed_request(
        client,
        "POST",
        f"/v1/approvals/{approval['approval_id']}/decisions",
        private_key=paired["private_key"],
        device_id=paired["device"]["device_id"],
        json_body=decision_body(
            approval_id=approval["approval_id"],
            decision="approve",
            scope="once",
            params_fingerprint="substituted-params",
        ),
    )

    assert approval["params_fingerprint"]
    assert response.status_code == 400
    assert response.json()["detail"] == "params fingerprint mismatch"
    assert client.app.state.store.get_approval(approval["approval_id"])["state"] == "pending"


def test_expire_approval(client: TestClient) -> None:
    paired = pair_device(client)
    approval = create_approval(client, action_id="act_expire")

    response = signed_request(
        client,
        "POST",
        f"/v1/approvals/{approval['approval_id']}/expire",
        private_key=paired["private_key"],
        device_id=paired["device"]["device_id"],
    )

    assert response.status_code == 200
    assert response.json()["state"] == "expired"


def test_cancel_approval(client: TestClient) -> None:
    paired = pair_device(client)
    approval = create_approval(client, action_id="act_cancel")

    response = signed_request(
        client,
        "POST",
        f"/v1/approvals/{approval['approval_id']}/cancel",
        private_key=paired["private_key"],
        device_id=paired["device"]["device_id"],
    )

    assert response.status_code == 200
    assert response.json()["state"] == "cancelled"


def test_invalid_transition_rejected(client: TestClient) -> None:
    paired = pair_device(client)
    approval = create_approval(client, action_id="act_transition")
    first = signed_request(
        client,
        "POST",
        f"/v1/approvals/{approval['approval_id']}/approve_once",
        private_key=paired["private_key"],
        device_id=paired["device"]["device_id"],
    )
    assert first.status_code == 200

    second = signed_request(
        client,
        "POST",
        f"/v1/approvals/{approval['approval_id']}/deny",
        private_key=paired["private_key"],
        device_id=paired["device"]["device_id"],
    )

    assert second.status_code == 409
    assert second.json()["detail"] == "approval is not pending"


def test_expired_approval_cannot_be_approved(client: TestClient) -> None:
    paired = pair_device(client)
    approval = create_approval(
        client,
        action_id="act_expired",
        expires_at="2000-01-01T00:00:00Z",
    )

    response = signed_request(
        client,
        "POST",
        f"/v1/approvals/{approval['approval_id']}/approve_once",
        private_key=paired["private_key"],
        device_id=paired["device"]["device_id"],
    )

    assert response.status_code == 409
    assert response.json()["detail"] == "approval expired"
    assert approval_event_exists(client, paired, approval["approval_id"], "expired")


def test_invalid_approval_id_rejected(client: TestClient) -> None:
    paired = pair_device(client)

    response = signed_request(
        client,
        "POST",
        "/v1/approvals/appr_missing/approve_once",
        private_key=paired["private_key"],
        device_id=paired["device"]["device_id"],
    )

    assert response.status_code == 404


def create_approval(
    client: TestClient,
    *,
    action_id: str,
    expires_at: str = "2099-01-01T00:00:00Z",
) -> dict:
    response = client.post(
        "/v1/approvals",
        json={
            "action_id": action_id,
            "agent_id": "agent_mock",
            "session_id": "sess_mock",
            "requested_tool": "shell",
            "risk_level": "high",
            "risk_family": "destructive",
            "summary": "Run a command",
            "full_payload_redacted": {"command": "redacted"},
            "resource_scope": "repo",
            "expires_at": expires_at,
        },
    )
    assert response.status_code == 201
    return response.json()


def decision_body(
    *,
    approval_id: str,
    decision: str,
    scope: str,
    params_fingerprint: str,
) -> dict:
    decision_id = f"dec_{approval_id}_{scope}"
    return {
        "decision_id": decision_id,
        "decision": decision,
        "scope": scope,
        "signed_payload": {
            "approval_id": approval_id,
            "decision": decision,
            "scope": scope,
            "decision_id": decision_id,
            "params_fingerprint": params_fingerprint,
        },
        "signature": "hmcp-device-request-signature",
    }


def audit_exists(client: TestClient, paired: dict, event_type: str) -> bool:
    response = signed_request(
        client,
        "GET",
        f"/v1/audit/events?event_type={event_type}",
        private_key=paired["private_key"],
        device_id=paired["device"]["device_id"],
    )
    assert response.status_code == 200
    return bool(response.json()["audit_events"])


def approval_event_exists(client: TestClient, paired: dict, approval_id: str, state: str) -> bool:
    response = signed_request(
        client,
        "GET",
        "/v1/events",
        private_key=paired["private_key"],
        device_id=paired["device"]["device_id"],
    )
    assert response.status_code == 200
    return any(
        event["type"] == "approval.resolved"
        and event["payload"].get("approval_id") == approval_id
        and event["payload"].get("state") == state
        for event in response.json()["events"]
    )

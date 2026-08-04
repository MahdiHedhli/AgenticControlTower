"""The decision response must describe what happened, not what was asked for.

``ApprovalDecisionResponse.applied_scope`` echoed the requested scope
unconditionally, including when ``mint_grant_for_decision`` had just refused to
mint anything. So tapping "approve for this session" on a request whose risk
family can never carry standing authority returned ``applied_scope: "session"``
and the phone reported the session approved — while ``approval_grants`` stayed
empty: 0 rows lifetime against 131 approvals on the production gateway.

The refusal policy itself is NOT touched here; which requests may carry standing
authority is an operator decision. Only the reporting of it changes.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from conftest import pair_device, signed_request

#: A family a standing grant MAY satisfy. Everything in
#: MOBILE_MANDATORY_RISK_FAMILIES requires a human on a mobile-signed channel.
GRANTABLE_RISK_FAMILY = "routine"


def _create_approval(
    client: TestClient,
    *,
    action_id: str,
    risk_family: str = GRANTABLE_RISK_FAMILY,
    requested_tool: str = "git_status",
) -> dict:
    response = client.post(
        "/v1/approvals",
        json={
            "action_id": action_id,
            "agent_id": "agent_mock",
            "session_id": "sess_mock",
            "requested_tool": requested_tool,
            "risk_level": "medium",
            "risk_family": risk_family,
            "summary": "Run a command",
            "full_payload_redacted": {"command": "redacted"},
            "resource_scope": "repo",
            "expires_at": "2099-01-01T00:00:00Z",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def _decide(client: TestClient, paired: dict, approval: dict, *, scope: str) -> dict:
    decision_id = f"dec_{approval['approval_id']}_{scope}"
    response = signed_request(
        client,
        "POST",
        f"/v1/approvals/{approval['approval_id']}/decisions",
        private_key=paired["private_key"],
        device_id=paired["device"]["device_id"],
        json_body={
            "decision_id": decision_id,
            "decision": "approve",
            "scope": scope,
            "signed_payload": {
                "approval_id": approval["approval_id"],
                "decision": "approve",
                "scope": scope,
                "decision_id": decision_id,
                "params_fingerprint": approval["params_fingerprint"],
            },
            "signature": "hmcp-device-request-signature",
        },
    )
    assert response.status_code == 200, response.text
    return response.json()


def test_a_minted_grant_reports_the_scope_it_actually_applied(
    client: TestClient,
) -> None:
    """The honest positive: a grant really exists, so `session` is the truth."""
    paired = pair_device(client)
    approval = _create_approval(client, action_id="act_grantable")

    body = _decide(client, paired, approval, scope="session")

    assert body["applied_scope"] == "session"
    assert body["requested_scope"] == "session"
    assert body["grant_minted"] is True
    assert body["grant_refused_reason"] is None

    grants = signed_request(
        client,
        "GET",
        "/v1/approval-grants",
        private_key=paired["private_key"],
        device_id=paired["device"]["device_id"],
    ).json()
    assert [g["scope"] for g in grants["approval_grants"]] == ["session"]


def test_a_refused_grant_reports_once_and_says_why(client: TestClient) -> None:
    """The defect. Was: `applied_scope: "session"` with zero grant rows."""
    paired = pair_device(client)
    approval = _create_approval(
        client, action_id="act_excluded", risk_family="destructive"
    )

    body = _decide(client, paired, approval, scope="session")

    assert body["applied_scope"] == "once"
    assert body["requested_scope"] == "session"
    assert body["grant_minted"] is False
    assert body["grant_refused_reason"] == "risk_family_excluded"

    grants = signed_request(
        client,
        "GET",
        "/v1/approval-grants",
        private_key=paired["private_key"],
        device_id=paired["device"]["device_id"],
    ).json()
    assert grants["approval_grants"] == []


def test_asking_for_once_is_not_a_refusal(client: TestClient) -> None:
    """No standing authority was requested, so there is nothing to explain."""
    paired = pair_device(client)
    approval = _create_approval(client, action_id="act_once")

    body = _decide(client, paired, approval, scope="once")

    assert body["applied_scope"] == "once"
    assert body["grant_minted"] is False
    assert body["grant_refused_reason"] is None


def test_deny_and_expire_report_exactly_what_they_reported_before(
    client: TestClient,
) -> None:
    """Only an approval can apply a scope; the other transitions are unchanged."""
    paired = pair_device(client)

    denied = signed_request(
        client,
        "POST",
        f"/v1/approvals/{_create_approval(client, action_id='act_deny')['approval_id']}/deny",
        private_key=paired["private_key"],
        device_id=paired["device"]["device_id"],
    ).json()
    assert denied["state"] == "denied"
    assert denied["applied_scope"] == "once"
    assert denied["grant_minted"] is False

    expired = signed_request(
        client,
        "POST",
        f"/v1/approvals/{_create_approval(client, action_id='act_exp')['approval_id']}/expire",
        private_key=paired["private_key"],
        device_id=paired["device"]["device_id"],
    ).json()
    assert expired["state"] == "expired"
    assert expired["applied_scope"] is None
    assert expired["grant_minted"] is False

"""Standing approval grants — "allow for this session" / "allow forever".

Reproduce-first gate (WS1): approving with ``scope`` other than ``once`` records
``approval_requests.decision_scope`` but nothing consumes it, so a byte-identical
second request still comes back ``pending``. These tests fail on that behaviour
and pass once the grant is minted at decision time and consumed at
request-creation time.
"""

from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient

from conftest import pair_device, signed_request

# The gate scenarios deliberately use a risk family OUTSIDE the never-auto-satisfy
# set (destructive / credential_or_secret / safety_critical / irreversible), which
# is exercised separately by the fail-closed negatives.
GRANTABLE_RISK_FAMILY = "external_effect"


def create_approval(
    client: TestClient,
    *,
    action_id: str,
    agent_id: str = "agent_mock",
    session_id: str = "sess_mock",
    requested_tool: str = "shell",
    risk_family: str = GRANTABLE_RISK_FAMILY,
    risk_level: str = "medium",
    payload_redacted: dict[str, Any] | None = None,
    risk_vector: dict[str, Any] | None = None,
    expires_at: str = "2099-01-01T00:00:00Z",
) -> dict:
    body: dict[str, Any] = {
        "action_id": action_id,
        "agent_id": agent_id,
        "session_id": session_id,
        "requested_tool": requested_tool,
        "risk_level": risk_level,
        "risk_family": risk_family,
        "summary": "Run a command",
        "full_payload_redacted": payload_redacted
        if payload_redacted is not None
        else {"command": "redacted"},
        "resource_scope": "repo",
        "expires_at": expires_at,
    }
    if risk_vector is not None:
        body["risk_vector"] = risk_vector
    response = client.post("/v1/approvals", json=body)
    assert response.status_code == 201, response.text
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


def decide(
    client: TestClient,
    paired: dict,
    approval: dict,
    *,
    scope: str,
    decision: str = "approve",
) -> dict:
    response = signed_request(
        client,
        "POST",
        f"/v1/approvals/{approval['approval_id']}/decisions",
        private_key=paired["private_key"],
        device_id=paired["device"]["device_id"],
        json_body=decision_body(
            approval_id=approval["approval_id"],
            decision=decision,
            scope=scope,
            params_fingerprint=approval["params_fingerprint"],
        ),
    )
    assert response.status_code == 200, response.text
    return response.json()


def test_session_scope_grant_auto_approves_identical_request(client: TestClient) -> None:
    """"Approve for this session" must clear a byte-identical repeat."""
    paired = pair_device(client)
    first = create_approval(client, action_id="act_session_1", requested_tool="git_status")
    decide(client, paired, first, scope="session")

    second = create_approval(client, action_id="act_session_2", requested_tool="git_status")

    assert second["params_fingerprint"] == first["params_fingerprint"]
    assert second["state"] == "approved"
    assert second["decision_scope"] == "session"


def test_agent_scope_grant_auto_approves_differing_params(client: TestClient) -> None:
    """"Approve for this agent" covers repeated, differing invocations."""
    paired = pair_device(client)
    first = create_approval(
        client,
        action_id="act_agent_1",
        requested_tool="git_log",
        payload_redacted={"command": "git log -1"},
    )
    decide(client, paired, first, scope="agent")

    second = create_approval(
        client,
        action_id="act_agent_2",
        requested_tool="git_log",
        session_id="sess_other",
        payload_redacted={"command": "git log -5"},
    )

    assert second["params_fingerprint"] != first["params_fingerprint"]
    assert second["state"] == "approved"
    assert second["decision_scope"] == "agent"


def test_permanent_scope_grant_auto_approves_across_agents(client: TestClient) -> None:
    """"Allow forever" is node+tool wide — a different agent still clears."""
    paired = pair_device(client)
    first = create_approval(
        client,
        action_id="act_perm_1",
        requested_tool="ls_repo",
        payload_redacted={"command": "ls"},
    )
    decide(client, paired, first, scope="permanent")

    second = create_approval(
        client,
        action_id="act_perm_2",
        requested_tool="ls_repo",
        agent_id="agent_other",
        session_id="sess_other",
        payload_redacted={"command": "ls -la"},
    )

    assert second["state"] == "approved"
    assert second["decision_scope"] == "permanent"


def test_once_scope_does_not_create_a_standing_grant(client: TestClient) -> None:
    """The default scope must keep prompting — no silent standing authority."""
    paired = pair_device(client)
    first = create_approval(client, action_id="act_once_1", requested_tool="rm_tmp")
    decide(client, paired, first, scope="once")

    second = create_approval(client, action_id="act_once_2", requested_tool="rm_tmp")

    assert second["state"] == "pending"


def test_auto_satisfied_approval_is_recorded_not_skipped(client: TestClient) -> None:
    """Every attempted action must still leave an approval record and an audit
    trail — auto-satisfying may never mean "no record"."""
    paired = pair_device(client)
    first = create_approval(client, action_id="act_audit_1", requested_tool="cat_file")
    decide(client, paired, first, scope="session")

    second = create_approval(client, action_id="act_audit_2", requested_tool="cat_file")
    assert second["state"] == "approved"

    detail = signed_request(
        client,
        "GET",
        f"/v1/approvals/{second['approval_id']}",
        private_key=paired["private_key"],
        device_id=paired["device"]["device_id"],
    )
    assert detail.status_code == 200
    record = detail.json()
    assert record["state"] == "approved"
    assert record["approved_by"] == "standing_grant"
    assert record["human_approved"] is False

    events = signed_request(
        client,
        "GET",
        "/v1/audit/events?event_type=approval_auto_satisfied",
        private_key=paired["private_key"],
        device_id=paired["device"]["device_id"],
    )
    assert events.status_code == 200
    audit = events.json()["audit_events"]
    assert audit, "auto-satisfied approvals must emit an approval_auto_satisfied audit event"
    assert audit[0]["payload_redacted"].get("grant_id")

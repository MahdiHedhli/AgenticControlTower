from __future__ import annotations

from fastapi.testclient import TestClient

from conftest import pair_device, signed_request


def test_runtime_context_registers_agent_mission_and_state(client: TestClient) -> None:
    paired = pair_device(client)

    context = _register_runtime_context(client)

    assert context["agent"]["status"] == "running"
    assert context["mission"]["state"] == "running"
    missions = _signed_json(client, paired, "GET", "/v1/missions")
    assert missions["missions"][0]["mission_id"] == "mission_runtime"
    mission_detail = _signed_json(client, paired, "GET", "/v1/missions/mission_runtime")
    assert mission_detail["state"] == "running"
    events = _signed_json(client, paired, "GET", "/v1/events")
    assert _has_event(events, "mission.state")
    assert _has_event(events, "agent.status")


def test_runtime_approval_round_trip_delivers_signed_mobile_decision(
    client: TestClient,
) -> None:
    paired = _pair_operator_device(client)
    _register_runtime_context(client)
    approval = _runtime_approval(client, action_id="act_runtime_approval")

    decided = _signed_json(
        client,
        paired,
        "POST",
        f"/v1/approvals/{approval['approval_id']}/responses",
        json_body={
            "decision_type": "approve_session",
            "params_fingerprint": approval["params_fingerprint"],
        },
    )
    assert decided["decision_type"] == "approve_session"

    result = client.get(f"/v1/runtime/approvals/{approval['approval_id']}/result")
    assert result.status_code == 200
    body = result.json()
    assert body["state"] == "approved"
    # `selected_scope` is read from the stored `decision_scope`, and this is the
    # surface the AGENT reads. The fixture's risk family is `destructive`, which
    # can never carry standing authority, so no grant was minted — this used to
    # tell the agent it had session-wide authority that did not exist anywhere
    # in `approval_grants`. What the operator's tap actually bought is one
    # approval, and that is what the agent is now told.
    assert body["selected_scope"] == "once"
    assert body["responses"][0]["decision_type"] == "approve_session"


def test_runtime_modified_approval_result_includes_constraints(
    client: TestClient,
) -> None:
    paired = _pair_operator_device(client)
    _register_runtime_context(client)
    approval = _runtime_approval(client, action_id="act_runtime_modified")

    modified = _signed_json(
        client,
        paired,
        "POST",
        f"/v1/approvals/{approval['approval_id']}/responses",
        json_body={
            "decision_type": "modified",
            "alternate_directive": "Use the dry-run command only.",
            "constraints": [
                {
                    "constraint_type": "mode",
                    "value_redacted": {"value": "dry_run"},
                }
            ],
        },
    )
    assert modified["constraints"][0]["constraint_type"] == "mode"

    result = client.get(f"/v1/runtime/approvals/{approval['approval_id']}/result")
    assert result.status_code == 200
    body = result.json()
    assert body["state"] == "pending"
    assert body["responses"][0]["decision_type"] == "modified"
    assert body["responses"][0]["constraints"][0]["value_redacted"]["value"] == "dry_run"


def test_runtime_can_cancel_pending_approval(client: TestClient) -> None:
    _register_runtime_context(client)
    approval = _runtime_approval(client, action_id="act_runtime_cancel")

    cancelled = client.post(f"/v1/runtime/approvals/{approval['approval_id']}/cancel")

    assert cancelled.status_code == 200
    assert cancelled.json()["state"] == "cancelled"


def test_runtime_tua_handoff_returns_messages_and_summary(client: TestClient) -> None:
    paired = _pair_operator_device(client)
    _register_runtime_context(client)

    request = client.post(
        "/v1/runtime/tua/requests",
        json={
            "agent_id": "agent_runtime",
            "session_id": "sess_runtime",
            "reason": "Need user guidance.",
            "risk_family": "read_only",
            "context_redacted": {"mission_id": "mission_runtime"},
        },
    )
    assert request.status_code == 201
    tua_request = request.json()

    session = _signed_json(
        client,
        paired,
        "POST",
        f"/v1/tua/requests/{tua_request['request_id']}/sessions",
        json_body={"initial_message": "I am reviewing this now."},
    )
    _signed_json(
        client,
        paired,
        "POST",
        f"/v1/tua/sessions/{session['assistance_session_id']}/messages",
        json_body={"body": "Use the non-destructive path."},
    )
    _signed_json(
        client,
        paired,
        "POST",
        f"/v1/tua/sessions/{session['assistance_session_id']}/return-control",
        json_body={"summary": "Returned with non-destructive guidance."},
    )

    result = client.get(f"/v1/runtime/tua/requests/{tua_request['request_id']}/result")
    assert result.status_code == 200
    body = result.json()
    assert body["latest_session"]["state"] == "returned_to_agent"
    assert body["return_summary"] == "Returned with non-destructive guidance."
    assert len(body["latest_session"]["messages"]) == 2


def test_runtime_browser_assistance_handoff_returns_summary(
    client: TestClient,
) -> None:
    paired = _pair_operator_device(client)
    _register_runtime_context(client)

    response = client.post(
        "/v1/runtime/browser-assistance/sessions",
        json={
            "agent_id": "agent_runtime",
            "session_id": "sess_runtime",
            "reason": "Browser submit needs review.",
            "risk_family": "read_only",
            "context_redacted": {
                "mission_id": "mission_runtime",
                "url": "https://example.invalid/review",
            },
        },
    )
    assert response.status_code == 201
    session = response.json()

    _signed_json(
        client,
        paired,
        "POST",
        f"/v1/browser-assistance/sessions/{session['browser_session_id']}/event",
        json_body={"note": "Reviewed the redacted browser context."},
    )
    _signed_json(
        client,
        paired,
        "POST",
        f"/v1/browser-assistance/sessions/{session['browser_session_id']}/return-control",
        json_body={"summary": "Browser context reviewed; continue."},
    )

    result = client.get(
        f"/v1/runtime/browser-assistance/sessions/{session['browser_session_id']}/result"
    )
    assert result.status_code == 200
    assert result.json()["session"]["state"] == "returned_to_agent"
    assert result.json()["return_summary"] == "Browser context reviewed; continue."


def test_runtime_voice_handoff_receives_text_backed_message(
    client: TestClient,
) -> None:
    paired = _pair_operator_device(client)
    _register_runtime_context(client)

    response = client.post(
        "/v1/runtime/voice/sessions",
        json={
            "agent_id": "agent_runtime",
            "session_id": "sess_runtime",
            "mode": "text_fallback",
            "risk_family": "read_only",
            "context_redacted": {"mission_id": "mission_runtime"},
        },
    )
    assert response.status_code == 201
    session = response.json()

    _signed_json(
        client,
        paired,
        "POST",
        f"/v1/voice/sessions/{session['voice_session_id']}/messages",
        json_body={"body": "Proceed after approval.", "input_mode": "text_fallback"},
    )
    _signed_json(
        client,
        paired,
        "POST",
        f"/v1/voice/sessions/{session['voice_session_id']}/close",
    )

    result = client.get(f"/v1/runtime/voice/sessions/{session['voice_session_id']}/result")
    assert result.status_code == 200
    body = result.json()
    assert body["session"]["state"] == "closed"
    assert body["messages"][0]["body"] == "Proceed after approval."


def test_runtime_operator_session_projection_and_capability_denial_audit(
    client: TestClient,
) -> None:
    paired = _pair_operator_device(client)
    _register_runtime_context(client)
    browser = client.post(
        "/v1/runtime/browser-assistance/sessions",
        json={
            "agent_id": "agent_runtime",
            "session_id": "sess_runtime",
            "reason": "Browser review.",
            "context_redacted": {"mission_id": "mission_runtime"},
        },
    )
    assert browser.status_code == 201

    operator_sessions = _signed_json(client, paired, "GET", "/v1/operator-sessions")
    assert any(
        item["session_type"] == "browser_assistance"
        for item in operator_sessions["operator_sessions"]
    )

    denied_context = client.post(
        "/v1/runtime/context",
        json={
            "agent_id": "agent_no_tua",
            "display_name": "No TUA Agent",
            "session_id": "sess_no_tua",
            "capabilities": [],
        },
    )
    assert denied_context.status_code == 200
    denied = client.post(
        "/v1/runtime/tua/requests",
        json={
            "agent_id": "agent_no_tua",
            "session_id": "sess_no_tua",
            "reason": "Should be denied.",
        },
    )
    assert denied.status_code == 403

    audit = _signed_json(
        client,
        paired,
        "GET",
        "/v1/audit/events?event_type=capability_check_denied",
    )
    assert audit["audit_events"][0]["payload_redacted"]["capability"] == "tua"


def _pair_operator_device(client: TestClient) -> dict:
    return pair_device(
        client,
        requested_permissions=[
            "read_state",
            "approve",
            "intervene",
            "browser_assist",
            "voice",
        ],
    )


def _register_runtime_context(client: TestClient) -> dict:
    response = client.post(
        "/v1/runtime/context",
        json={
            "agent_id": "agent_runtime",
            "display_name": "Runtime Agent",
            "agent_status": "running",
            "mission_id": "mission_runtime",
            "mission_state": "running",
            "session_id": "sess_runtime",
            "mission_title": "Runtime integration smoke",
            "mission_summary": "Exercise runtime-to-mobile round trips.",
            "current_tool": "shell",
            "capabilities": [
                {"name": "tua", "status": "available"},
                {"name": "browser_assist", "status": "available"},
                {"name": "voice", "status": "available"},
            ],
        },
    )
    assert response.status_code == 200
    return response.json()


def _runtime_approval(client: TestClient, *, action_id: str) -> dict:
    response = client.post(
        "/v1/runtime/approvals",
        json={
            "requested_tool": "shell",
            "risk_level": "high",
            "risk_family": "destructive",
            "summary": "Run a runtime-created redacted command.",
            "payload_redacted": {"command": "redacted"},
            "agent_id": "agent_runtime",
            "session_id": "sess_runtime",
            "expires_in_seconds": 300,
            "suggested_scopes": ["once", "session", "agent"],
            "action_id": action_id,
        },
    )
    assert response.status_code == 201
    return response.json()


def _signed_json(
    client: TestClient,
    paired: dict,
    method: str,
    path: str,
    *,
    json_body: dict | None = None,
) -> dict:
    response = signed_request(
        client,
        method,
        path,
        private_key=paired["private_key"],
        device_id=paired["device"]["device_id"],
        json_body=json_body,
    )
    assert response.status_code < 400, response.text
    return response.json() if response.content else {}


def _has_event(events_response: dict, event_type: str) -> bool:
    return any(event["type"] == event_type for event in events_response["events"])

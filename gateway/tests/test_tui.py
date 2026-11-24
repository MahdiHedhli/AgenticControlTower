from __future__ import annotations

import shutil
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from conftest import pair_device, signed_request
from hermes_gateway.app import create_app
from hermes_gateway.clearance_contract import build_params_fingerprint
from hermes_gateway.config import Settings
from hermes_gateway.security import expires_in


@pytest.fixture()
def tui_client(tmp_path: Path) -> TestClient:
    command = _cat_command()
    settings = Settings(
        node_id="node_tui",
        node_display_name="TUI Hermes",
        node_fingerprint="tui-fingerprint",
        gateway_base_url="http://127.0.0.1:8787/v1",
        database_path=str(tmp_path / "gateway.sqlite3"),
        pairing_ttl_seconds=60,
        tui_enable_local_pty=True,
        tui_allowed_commands=(command,),
        tui_default_command=command,
        tui_allowed_working_directory=str(tmp_path),
        tui_command_risk_family={command: "read_only"},
        tui_max_sessions=3,
    )
    with TestClient(create_app(settings), client=("127.0.0.1", 50000)) as test_client:
        yield test_client


@pytest.fixture()
def high_risk_tui_client(tmp_path: Path) -> TestClient:
    command = _cat_command()
    settings = Settings(
        node_id="node_tui_high",
        node_display_name="TUI Hermes",
        node_fingerprint="tui-high-fingerprint",
        gateway_base_url="http://127.0.0.1:8787/v1",
        database_path=str(tmp_path / "gateway.sqlite3"),
        pairing_ttl_seconds=60,
        tui_enable_local_pty=True,
        tui_allowed_commands=(command,),
        tui_default_command=command,
        tui_allowed_working_directory=str(tmp_path),
        tui_max_sessions=3,
    )
    with TestClient(create_app(settings), client=("127.0.0.1", 50000)) as test_client:
        yield test_client


def test_tui_disabled_by_default(client: TestClient) -> None:
    paired = pair_device(client, requested_permissions=["read_state", "tui"])

    response = signed_request(
        client,
        "POST",
        "/v1/tui/sessions",
        private_key=paired["private_key"],
        device_id=paired["device"]["device_id"],
        json_body={"agent_id": "agent_mock"},
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "local TUI PTY is disabled"


def test_tui_signed_request_required(client: TestClient) -> None:
    response = client.post("/v1/tui/sessions", json={"agent_id": "agent_mock"})

    assert response.status_code == 401
    assert response.json()["detail"] == "missing device signature"


def test_tui_revoked_device_rejected(tui_client: TestClient) -> None:
    _grant_tui_capability(tui_client)
    paired = _pair_tui_device(tui_client)
    device_id = paired["device"]["device_id"]
    revoke = signed_request(
        tui_client,
        "DELETE",
        f"/v1/devices/{device_id}",
        private_key=paired["private_key"],
        device_id=device_id,
    )
    assert revoke.status_code == 204

    response = _signed_create_tui(tui_client, paired)

    assert response.status_code == 403
    assert response.json()["detail"] == "device is not active"


def test_tui_session_creation_when_enabled(tui_client: TestClient) -> None:
    _grant_tui_capability(tui_client)
    paired = _pair_tui_device(tui_client)

    response = _signed_create_tui(tui_client, paired)

    assert response.status_code == 201
    session = response.json()
    assert session["state"] == "active"
    assert session["user_device_id"] == paired["device"]["device_id"]
    assert session["risk_label"] == "operator terminal - high risk"
    assert session["output_retention_enabled"] is False
    _signed_close_tui(tui_client, paired, session["session_id"])


def test_high_risk_tui_start_without_bound_clearance_rejected(
    high_risk_tui_client: TestClient,
) -> None:
    _grant_tui_capability(high_risk_tui_client)
    paired = _pair_tui_device(high_risk_tui_client)

    response = _signed_create_tui(high_risk_tui_client, paired)

    assert response.status_code == 403
    assert response.json()["detail"] == "missing_clearance"


def test_tui_client_risk_level_cannot_downgrade_unmapped_command(
    high_risk_tui_client: TestClient,
) -> None:
    _grant_tui_capability(high_risk_tui_client)
    paired = _pair_tui_device(high_risk_tui_client)

    response = _signed_create_tui(high_risk_tui_client, paired, risk_level="low")

    assert response.status_code == 403
    assert response.json()["detail"] == "missing_clearance"


def test_high_risk_tui_start_rejects_denied_expired_mismatched_and_local_clearance(
    high_risk_tui_client: TestClient,
) -> None:
    _grant_tui_capability(high_risk_tui_client)
    paired = _pair_tui_operator_device(high_risk_tui_client)
    command = _cat_command()
    workdir = high_risk_tui_client.app.state.settings.tui_allowed_working_directory

    cases = [
        _seed_tui_clearance(
            high_risk_tui_client,
            command=command,
            working_directory=workdir,
            state="denied",
        ),
        _seed_tui_clearance(
            high_risk_tui_client,
            command=command,
            working_directory=workdir,
            expires_at="2000-01-01T00:00:00Z",
        ),
        _seed_tui_clearance(
            high_risk_tui_client,
            command=command,
            working_directory=workdir,
            payload_working_directory="/tmp/mismatch",
        ),
        _seed_tui_clearance(
            high_risk_tui_client,
            command=command,
            working_directory=workdir,
            channel="local_terminal",
            eligible_channels=["mobile_signed"],
        ),
    ]

    for approval in cases:
        response = _signed_create_tui(
            high_risk_tui_client,
            paired,
            approval_id=approval["approval_id"],
            session_context_id="tui",
        )
        assert response.status_code == 403


def test_high_risk_tui_start_accepts_mobile_clearance_and_consumes_it(
    tmp_path: Path,
) -> None:
    settings = Settings(
        node_id="node_tui_shell_bound",
        node_display_name="TUI Hermes",
        node_fingerprint="tui-shell-bound-fingerprint",
        gateway_base_url="http://127.0.0.1:8787/v1",
        database_path=str(tmp_path / "gateway.sqlite3"),
        pairing_ttl_seconds=60,
        tui_enable_local_pty=True,
        tui_allowed_commands=("/bin/sh",),
        tui_default_command="/bin/sh",
        tui_allowed_working_directory=str(tmp_path),
        tui_allow_shell_commands=True,
    )
    with TestClient(create_app(settings), client=("127.0.0.1", 50000)) as client:
        _grant_tui_capability(client)
        paired = _pair_tui_operator_device(client)
        approval = _create_and_approve_tui_clearance(
            client,
            paired,
            command="/bin/sh",
            working_directory=settings.tui_allowed_working_directory,
        )

        response = _signed_create_tui(
            client,
            paired,
            command="/bin/sh",
            approval_id=approval["approval_id"],
            session_context_id="tui",
        )

        assert response.status_code == 201
        session = response.json()
        assert session["risk_family"] == "external_effect"
        consumed = client.app.state.store.get_approval(approval["approval_id"])
        assert consumed["decision_metadata"]["tui_consumed_by"] == session["session_id"]

        second = _signed_create_tui(
            client,
            paired,
            command="/bin/sh",
            approval_id=approval["approval_id"],
            session_context_id="tui",
        )
        assert second.status_code == 403
        assert second.json()["detail"] == "not_consumed"
        _signed_close_tui(client, paired, session["session_id"])


def test_shell_allowlist_requires_explicit_opt_in(tmp_path: Path) -> None:
    settings = Settings(
        node_id="node_tui_shell",
        node_display_name="TUI Hermes",
        node_fingerprint="tui-shell-fingerprint",
        gateway_base_url="http://127.0.0.1:8787/v1",
        database_path=str(tmp_path / "gateway.sqlite3"),
        pairing_ttl_seconds=60,
        tui_enable_local_pty=True,
        tui_allowed_commands=("/bin/sh",),
        tui_default_command="/bin/sh",
        tui_allowed_working_directory=str(tmp_path),
    )
    with TestClient(create_app(settings), client=("127.0.0.1", 50000)) as client:
        _grant_tui_capability(client)
        paired = _pair_tui_device(client)

        response = _signed_create_tui(client, paired, command="/bin/sh")

        assert response.status_code == 403
        assert response.json()["detail"] == "TUI shell commands require explicit opt-in"


def test_shell_allowlist_with_opt_in_still_requires_high_risk_clearance(tmp_path: Path) -> None:
    settings = Settings(
        node_id="node_tui_shell_opt",
        node_display_name="TUI Hermes",
        node_fingerprint="tui-shell-opt-fingerprint",
        gateway_base_url="http://127.0.0.1:8787/v1",
        database_path=str(tmp_path / "gateway.sqlite3"),
        pairing_ttl_seconds=60,
        tui_enable_local_pty=True,
        tui_allowed_commands=("/bin/sh",),
        tui_default_command="/bin/sh",
        tui_allowed_working_directory=str(tmp_path),
        tui_allow_shell_commands=True,
    )
    with TestClient(create_app(settings), client=("127.0.0.1", 50000)) as client:
        _grant_tui_capability(client)
        paired = _pair_tui_device(client)

        response = _signed_create_tui(client, paired, command="/bin/sh")

        assert response.status_code == 403
        assert response.json()["detail"] == "missing_clearance"


def test_tui_command_not_allowlisted_rejected(tui_client: TestClient) -> None:
    _grant_tui_capability(tui_client)
    paired = _pair_tui_device(tui_client)

    response = _signed_create_tui(tui_client, paired, command="/bin/sh")

    assert response.status_code == 403
    assert response.json()["detail"] == "TUI command is not allowlisted"


def test_tui_working_directory_outside_allowed_root_rejected(
    tui_client: TestClient,
) -> None:
    _grant_tui_capability(tui_client)
    paired = _pair_tui_device(tui_client)

    response = _signed_create_tui(tui_client, paired, working_directory="/")

    assert response.status_code == 403
    assert response.json()["detail"] == "TUI working directory is outside the allowed root"


def test_tui_detach_creates_audit_event(tui_client: TestClient) -> None:
    _grant_tui_capability(tui_client)
    paired = _pair_tui_device(tui_client)
    session = _signed_create_tui(tui_client, paired).json()

    response = signed_request(
        tui_client,
        "POST",
        f"/v1/tui/sessions/{session['session_id']}/detach",
        private_key=paired["private_key"],
        device_id=paired["device"]["device_id"],
    )

    assert response.status_code == 200
    assert response.json()["session"]["state"] == "detached"
    audit = _signed_audit_events(tui_client, paired, "tui_session_detached")
    assert audit["audit_events"]
    _signed_close_tui(tui_client, paired, session["session_id"])


def test_tui_close_creates_audit_event(tui_client: TestClient) -> None:
    _grant_tui_capability(tui_client)
    paired = _pair_tui_device(tui_client)
    session = _signed_create_tui(tui_client, paired).json()

    response = _signed_close_tui(tui_client, paired, session["session_id"])

    assert response.status_code == 200
    assert response.json()["session"]["state"] == "closed"
    audit = _signed_audit_events(tui_client, paired, "tui_session_closed")
    assert audit["audit_events"]


def test_tui_websocket_rejects_invalid_session(tui_client: TestClient) -> None:
    _grant_tui_capability(tui_client)
    paired = _pair_tui_device(tui_client)
    session = _signed_create_tui(tui_client, paired).json()
    attach_token = _signed_create_attach_token(
        tui_client,
        paired,
        session["session_id"],
    )["attach_token"]

    with pytest.raises(WebSocketDisconnect):
        with tui_client.websocket_connect(
            f"/v1/tui/sessions/tui_missing/stream?attach_token={attach_token}"
        ):
            pass
    _signed_close_tui(tui_client, paired, session["session_id"])


def test_tui_websocket_basic_pty_output_smoke(tui_client: TestClient) -> None:
    _grant_tui_capability(tui_client)
    paired = _pair_tui_device(tui_client)
    session = _signed_create_tui(tui_client, paired).json()
    attach_token = _signed_create_attach_token(
        tui_client,
        paired,
        session["session_id"],
    )["attach_token"]

    with tui_client.websocket_connect(
        f"/v1/tui/sessions/{session['session_id']}/stream?attach_token={attach_token}"
    ) as websocket:
        assert websocket.receive_json()["type"] == "state"
        assert websocket.receive_json()["type"] == "audit_notice"
        websocket.send_json({"type": "input", "data": "hmcp_tui_smoke\n"})

        output = ""
        for _ in range(20):
            message = websocket.receive_json()
            if message["type"] == "output":
                output += message["data"]
            if "hmcp_tui_smoke" in output:
                break

        websocket.send_json({"type": "close"})

    assert "hmcp_tui_smoke" in output


def test_tui_device_without_grant_rejected(tui_client: TestClient) -> None:
    _grant_tui_capability(tui_client)
    paired = pair_device(tui_client)

    response = _signed_create_tui(tui_client, paired)

    assert response.status_code == 403
    assert response.json()["detail"] == "device lacks tui permission"


def test_tui_agent_without_capability_rejected(tui_client: TestClient) -> None:
    paired = _pair_tui_device(tui_client)

    response = _signed_create_tui(tui_client, paired)

    assert response.status_code == 403
    assert response.json()["detail"] == "TUI capability unavailable"


def test_tui_expired_attach_token_rejected(tmp_path: Path) -> None:
    command = _cat_command()
    settings = Settings(
        node_id="node_tui_expired",
        node_display_name="TUI Hermes",
        node_fingerprint="tui-expired-fingerprint",
        gateway_base_url="http://127.0.0.1:8787/v1",
        database_path=str(tmp_path / "gateway.sqlite3"),
        pairing_ttl_seconds=60,
        tui_enable_local_pty=True,
        tui_allowed_commands=(command,),
        tui_default_command=command,
        tui_allowed_working_directory=str(tmp_path),
        tui_command_risk_family={command: "read_only"},
        tui_attach_token_ttl_seconds=-1,
    )
    with TestClient(create_app(settings), client=("127.0.0.1", 50000)) as client:
        _grant_tui_capability(client)
        paired = _pair_tui_device(client)
        session = _signed_create_tui(client, paired).json()
        attach_token = _signed_create_attach_token(
            client,
            paired,
            session["session_id"],
        )["attach_token"]

        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect(
                f"/v1/tui/sessions/{session['session_id']}/stream"
                f"?attach_token={attach_token}"
            ):
                pass
        _signed_close_tui(client, paired, session["session_id"])


def test_tui_wrong_device_attach_token_rejected(tui_client: TestClient) -> None:
    _grant_tui_capability(tui_client)
    first = _pair_tui_device(tui_client)
    second = _pair_tui_device(tui_client)
    first_session = _signed_create_tui(tui_client, first).json()
    second_session = _signed_create_tui(tui_client, second).json()
    attach_token = _signed_create_attach_token(
        tui_client,
        first,
        first_session["session_id"],
    )["attach_token"]

    with pytest.raises(WebSocketDisconnect):
        with tui_client.websocket_connect(
            f"/v1/tui/sessions/{second_session['session_id']}/stream"
            f"?attach_token={attach_token}"
        ):
            pass

    _signed_close_tui(tui_client, first, first_session["session_id"])
    _signed_close_tui(tui_client, second, second_session["session_id"])


def test_tui_attach_token_cannot_be_replayed(tui_client: TestClient) -> None:
    _grant_tui_capability(tui_client)
    paired = _pair_tui_device(tui_client)
    session = _signed_create_tui(tui_client, paired).json()
    stream = f"/v1/tui/sessions/{session['session_id']}/stream"
    attach_token = _signed_create_attach_token(
        tui_client,
        paired,
        session["session_id"],
    )["attach_token"]

    # First attach is admitted; leaving the block detaches without closing.
    with tui_client.websocket_connect(f"{stream}?attach_token={attach_token}") as ws:
        assert ws.receive_json()["type"] == "state"

    # The same token again is refused.
    with pytest.raises(WebSocketDisconnect):
        with tui_client.websocket_connect(f"{stream}?attach_token={attach_token}"):
            pass

    # ...and it is the token that was refused, not the session: a fresh token
    # for the same still-running session attaches.
    fresh_token = _signed_create_attach_token(
        tui_client,
        paired,
        session["session_id"],
    )["attach_token"]
    with tui_client.websocket_connect(f"{stream}?attach_token={fresh_token}") as ws:
        assert ws.receive_json()["type"] == "state"
        ws.send_json({"type": "close"})


def test_tui_paste_metadata_audited(tui_client: TestClient) -> None:
    _grant_tui_capability(tui_client)
    paired = _pair_tui_device(tui_client)
    session = _signed_create_tui(tui_client, paired).json()
    attach_token = _signed_create_attach_token(
        tui_client,
        paired,
        session["session_id"],
    )["attach_token"]

    with tui_client.websocket_connect(
        f"/v1/tui/sessions/{session['session_id']}/stream?attach_token={attach_token}"
    ) as websocket:
        assert websocket.receive_json()["type"] == "state"
        assert websocket.receive_json()["type"] == "audit_notice"
        websocket.send_json({"type": "paste", "data": "one\ntwo\n"})
        websocket.send_json({"type": "ping"})
        for _ in range(20):
            if websocket.receive_json()["type"] == "pong":
                break
        else:
            pytest.fail("TUI stream did not acknowledge paste follow-up ping")
        websocket.send_json({"type": "close"})

    audit = _signed_audit_events(tui_client, paired, "tui_paste_sent")
    assert audit["audit_events"]
    payload = audit["audit_events"][0]["payload_redacted"]
    assert payload["contents_logged"] is False
    assert "multiline_paste" in payload["risk_warnings"]


def _signed_create_tui(
    client: TestClient,
    paired: dict,
    *,
    command: str | None = None,
    working_directory: str | None = None,
    risk_level: str | None = None,
    approval_id: str | None = None,
    session_context_id: str | None = None,
) -> object:
    body = {
        "agent_id": "agent_mock",
        "command": command,
        "working_directory": working_directory,
    }
    if risk_level is not None:
        body["risk_level"] = risk_level
    if approval_id is not None:
        body["approval_id"] = approval_id
    if session_context_id is not None:
        body["session_context_id"] = session_context_id
    return signed_request(
        client,
        "POST",
        "/v1/tui/sessions",
        private_key=paired["private_key"],
        device_id=paired["device"]["device_id"],
        json_body=body,
    )


def _signed_create_attach_token(
    client: TestClient,
    paired: dict,
    session_id: str,
) -> dict:
    response = signed_request(
        client,
        "POST",
        f"/v1/tui/sessions/{session_id}/attach-token",
        private_key=paired["private_key"],
        device_id=paired["device"]["device_id"],
    )
    assert response.status_code == 200
    return response.json()


def _signed_close_tui(client: TestClient, paired: dict, session_id: str) -> object:
    return signed_request(
        client,
        "POST",
        f"/v1/tui/sessions/{session_id}/close",
        private_key=paired["private_key"],
        device_id=paired["device"]["device_id"],
    )


def _signed_audit_events(client: TestClient, paired: dict, event_type: str) -> dict:
    response = signed_request(
        client,
        "GET",
        f"/v1/audit/events?event_type={event_type}",
        private_key=paired["private_key"],
        device_id=paired["device"]["device_id"],
    )
    assert response.status_code == 200
    return response.json()


def _cat_command() -> str:
    command = shutil.which("cat")
    if command is None:
        pytest.skip("cat command is unavailable for PTY smoke tests")
    return command


def _pair_tui_device(client: TestClient) -> dict:
    return pair_device(client, requested_permissions=["read_state", "tui"])


def _pair_tui_operator_device(client: TestClient) -> dict:
    return pair_device(client, requested_permissions=["read_state", "tui", "approve"])


def _grant_tui_capability(client: TestClient) -> None:
    store = client.app.state.store
    settings = client.app.state.settings
    agent = store.get_agent(settings.node_id, "agent_mock")
    capabilities = [
        *agent.get("capabilities", []),
        {"name": "tui", "status": "available"},
    ]
    store.upsert_agent({**agent, "capabilities": capabilities})


def _create_and_approve_tui_clearance(
    client: TestClient,
    paired: dict,
    *,
    command: str,
    working_directory: str,
) -> dict:
    approval = _seed_tui_clearance(
        client,
        command=command,
        working_directory=working_directory,
        state="pending",
        decision_metadata={},
    )
    response = signed_request(
        client,
        "POST",
        f"/v1/approvals/{approval['approval_id']}/approve_once",
        private_key=paired["private_key"],
        device_id=paired["device"]["device_id"],
    )
    assert response.status_code == 200, response.text
    return client.app.state.store.get_approval(approval["approval_id"])


def _seed_tui_clearance(
    client: TestClient,
    *,
    command: str,
    working_directory: str,
    payload_working_directory: str | None = None,
    state: str = "approved",
    channel: str = "mobile_signed",
    eligible_channels: list[str] | None = None,
    expires_at: str | None = None,
    decision_metadata: dict | None = None,
) -> dict:
    payload = {
        "command": command,
        "working_directory": payload_working_directory
        or str(Path(working_directory).expanduser().resolve()),
    }
    metadata = decision_metadata
    if metadata is None:
        metadata = {
            "channel": channel,
            "risk_family": "external_effect",
            "eligibility_result": "allowed",
            "eligible_channels": eligible_channels or ["mobile_signed"],
        }
    approval = {
        "approval_id": f"appr_tui_{len(client.app.state.store.list_approvals())}",
        "action_id": "act_tui_start",
        "node_id": client.app.state.settings.node_id,
        "agent_id": "agent_mock",
        "session_id": "tui",
        "requested_tool": "tui.start",
        "risk_level": "high",
        "risk_category": "terminal",
        "risk_family": "external_effect",
        "params_fingerprint": build_params_fingerprint(
            payload_redacted=payload,
            extensions={},
        ),
        "summary": "Start a TUI command",
        "full_payload_redacted": payload,
        "resource_scope": working_directory,
        "state": state,
        "options": ["approve_once", "deny"],
        "expires_at": expires_at or expires_in(300).isoformat().replace("+00:00", "Z"),
    }
    created = client.app.state.store.create_approval(approval)
    if state != "pending":
        client.app.state.store.resolve_approval(
            created["approval_id"],
            state,
            decision_scope="once" if state == "approved" else None,
            decision_metadata=metadata,
        )
        return client.app.state.store.get_approval(created["approval_id"])
    return created

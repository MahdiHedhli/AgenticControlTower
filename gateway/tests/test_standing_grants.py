"""Standing approval grants — "allow for this session" / "allow forever".

Reproduce-first gate (WS1): approving with ``scope`` other than ``once`` records
``approval_requests.decision_scope`` but nothing consumes it, so a byte-identical
second request still comes back ``pending``. These tests fail on that behaviour
and pass once the grant is minted at decision time and consumed at
request-creation time.
"""

from __future__ import annotations

from collections.abc import Generator
from dataclasses import replace
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from conftest import pair_device, signed_request
from hermes_gateway import clearance_policy
from hermes_gateway.app import create_app
from hermes_gateway.clearance_contract import (
    ClearanceProofMaterial,
    build_params_fingerprint,
    extensions_digest,
    tower_public_key_b64,
    verify_clearance_proof,
)
from hermes_gateway.clearance_policy import (
    LOW_RISK_FAMILIES,
    MOBILE_MANDATORY_RISK_FAMILIES,
    required_channels_for_request,
)
from hermes_gateway.config import Settings
from hermes_gateway.grants import (
    GRANT_UNGRANTABLE_RISK_FAMILIES,
    standing_grant_block_reason,
)

# The gate scenarios deliberately use a risk family a standing grant MAY satisfy.
# That is only the low-risk tier: every family in MOBILE_MANDATORY_RISK_FAMILIES
# (external_effect / destructive / credential_or_secret / safety_critical /
# irreversible) requires a human on a mobile-signed channel and can never be
# auto-satisfied — exercised separately by the fail-closed negatives.
GRANTABLE_RISK_FAMILY = "routine"


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


def audit_events(client: TestClient, paired: dict, event_type: str) -> list[dict]:
    response = signed_request(
        client,
        "GET",
        f"/v1/audit/events?event_type={event_type}",
        private_key=paired["private_key"],
        device_id=paired["device"]["device_id"],
    )
    assert response.status_code == 200, response.text
    return response.json()["audit_events"]


# --------------------------------------------------------------------------
# WS3 — write side: a scoped decision mints an auditable, hard-expiring grant
# --------------------------------------------------------------------------


def test_scoped_decision_emits_capability_grant_created(client: TestClient) -> None:
    paired = pair_device(client)
    approval = create_approval(client, action_id="act_mint", requested_tool="git_diff")
    decide(client, paired, approval, scope="session")

    events = audit_events(client, paired, "capability_grant_created")
    assert len(events) == 1
    payload = events[0]["payload_redacted"]
    assert payload["scope"] == "session"
    assert payload["requested_tool"] == "git_diff"
    assert payload["source_approval_id"] == approval["approval_id"]
    assert payload["params_fingerprint"] == approval["params_fingerprint"]
    assert payload["expires_at"], "every grant must carry a hard expiry"
    assert payload["ttl_seconds"] == 4 * 60 * 60


def test_agent_and_permanent_grants_carry_their_own_expiry(client: TestClient) -> None:
    paired = pair_device(client)
    decide(
        client,
        paired,
        create_approval(client, action_id="act_ttl_agent", requested_tool="tool_a"),
        scope="agent",
    )
    decide(
        client,
        paired,
        create_approval(client, action_id="act_ttl_perm", requested_tool="tool_b"),
        scope="permanent",
    )

    ttls = {
        event["payload_redacted"]["scope"]: event["payload_redacted"]["ttl_seconds"]
        for event in audit_events(client, paired, "capability_grant_created")
    }
    assert ttls == {"agent": 24 * 60 * 60, "permanent": 30 * 24 * 60 * 60}
    # "permanent" is a renewable standing order, never an unbounded one.
    for event in audit_events(client, paired, "capability_grant_created"):
        assert event["payload_redacted"]["expires_at"]


def test_once_scope_mints_no_grant(client: TestClient) -> None:
    paired = pair_device(client)
    approval = create_approval(client, action_id="act_no_mint", requested_tool="git_diff")
    decide(client, paired, approval, scope="once")

    assert audit_events(client, paired, "capability_grant_created") == []
    assert audit_events(client, paired, "capability_grant_refused") == []


def test_destructive_risk_family_refuses_to_mint_a_grant(client: TestClient) -> None:
    """Never-auto-satisfy families do not even get a dead grant row."""
    paired = pair_device(client)
    approval = create_approval(
        client,
        action_id="act_destructive",
        requested_tool="rm_rf",
        risk_family="destructive",
        risk_level="high",
    )
    decide(client, paired, approval, scope="permanent")

    assert audit_events(client, paired, "capability_grant_created") == []
    refusals = audit_events(client, paired, "capability_grant_refused")
    assert len(refusals) == 1
    assert refusals[0]["payload_redacted"]["reason"] == "risk_family_excluded"


def test_channel_mandating_risk_vector_refuses_to_mint_a_grant(
    client: TestClient,
) -> None:
    """A class that mandates a mobile-signed decision must always prompt."""
    paired = pair_device(client)
    approval = create_approval(
        client,
        action_id="act_channel",
        requested_tool="submit_form",
        risk_vector={"submit_risk_class": "critical"},
    )
    decide(client, paired, approval, scope="agent")

    assert audit_events(client, paired, "capability_grant_created") == []
    refusals = audit_events(client, paired, "capability_grant_refused")
    assert len(refusals) == 1
    assert refusals[0]["payload_redacted"]["reason"] == "channel_requirement"


def test_denied_decision_never_mints_a_grant(client: TestClient) -> None:
    paired = pair_device(client)
    approval = create_approval(client, action_id="act_denied", requested_tool="git_diff")
    decide(client, paired, approval, scope="session", decision="deny")

    assert audit_events(client, paired, "capability_grant_created") == []


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


# --------------------------------------------------------------------------
# WS4 — read side: the actual fix, plus every fail-closed negative
# --------------------------------------------------------------------------


def custom_client(tmp_path: Path, **overrides: Any) -> Generator[TestClient]:
    settings = Settings(
        node_id="node_test",
        node_display_name="Test Hermes",
        node_fingerprint="test-fingerprint",
        gateway_base_url="http://127.0.0.1:8787/v1",
        database_path=str(tmp_path / "gateway.sqlite3"),
        pairing_ttl_seconds=60,
        **overrides,
    )
    with TestClient(create_app(settings), client=("127.0.0.1", 50000)) as test_client:
        yield test_client


def rewind_grant_expiry(client: TestClient, grant_id: str) -> None:
    """Simulate the hard expiry lapsing, without sleeping through a TTL."""
    store = client.app.state.store
    with store.connect() as db:
        db.execute(
            "UPDATE approval_grants SET expires_at = ? WHERE grant_id = ?",
            ("2000-01-01T00:00:00Z", grant_id),
        )


def only_grant_id(client: TestClient, paired: dict) -> str:
    events = audit_events(client, paired, "capability_grant_created")
    assert len(events) == 1, events
    return str(events[0]["payload_redacted"]["grant_id"])


def test_auto_satisfied_approval_carries_a_verifiable_clearance_proof(
    client: TestClient,
) -> None:
    """The whole point of the clearance contract is that a consumer can verify
    the tower actually cleared this exact request. An auto-satisfied approval is
    a cleared request, so it must carry a canonical params_fingerprint and an
    Ed25519 proof that verifies against the tower key — otherwise standing
    grants would mint clearances that aircraft strict verification rejects."""
    paired = pair_device(client)
    payload = {"command": "git diff --stat"}
    first = create_approval(
        client,
        action_id="act_proof_1",
        requested_tool="git_diff",
        payload_redacted=payload,
    )
    decide(client, paired, first, scope="session")

    second = create_approval(
        client,
        action_id="act_proof_2",
        requested_tool="git_diff",
        payload_redacted=payload,
    )
    assert second["state"] == "approved"
    assert second["approved_by"] == "standing_grant"

    # The fingerprint must be the canonical one a client can recompute itself,
    # not a state-dependent or backfilled value.
    canonical = build_params_fingerprint(payload_redacted=payload, extensions={})
    assert second["params_fingerprint"] == canonical

    stored = client.app.state.store.get_approval(second["approval_id"])
    material = ClearanceProofMaterial(
        approval_id=second["approval_id"],
        params_fingerprint=canonical,
        short_code=stored["short_code"],
        risk_family=stored["risk_family"],
        expires_at=stored["expires_at"],
        tower_id=stored["tower_id"],
        contract_version=stored["contract_version"],
        extensions_digest=extensions_digest({}),
    )
    assert verify_clearance_proof(
        public_key_b64=tower_public_key_b64(client.app.state.settings),
        material=material,
        proof=stored["proof"] or {},
    )
    # And the proof is bound: it must not verify for a different fingerprint.
    assert not verify_clearance_proof(
        public_key_b64=tower_public_key_b64(client.app.state.settings),
        material=replace(material, params_fingerprint="0" * 64),
        proof=stored["proof"] or {},
    )


def test_runtime_creation_path_consumes_the_same_grant(client: TestClient) -> None:
    """The fix has to live at BOTH request-creation call sites. A grant minted
    from a /v1/approvals decision must also clear a /v1/runtime/approvals
    request — a read side wired into one path only is not wired in."""
    paired = pair_device(client)
    first = create_approval(
        client,
        action_id="act_runtime_1",
        agent_id="agent_runtime",
        requested_tool="git_fetch",
    )
    decide(client, paired, first, scope="agent")

    response = client.post(
        "/v1/runtime/approvals",
        json={
            "requested_tool": "git_fetch",
            "risk_level": "medium",
            "risk_family": GRANTABLE_RISK_FAMILY,
            "summary": "Fetch again",
            "payload_redacted": {"command": "git fetch --all"},
            "agent_id": "agent_runtime",
            "session_id": "sess_runtime_other",
            "expires_in_seconds": 300,
        },
    )
    assert response.status_code == 201, response.text
    runtime_approval = response.json()
    assert runtime_approval["state"] == "approved"
    assert runtime_approval["decision_scope"] == "agent"
    assert runtime_approval["approved_by"] == "standing_grant"
    assert runtime_approval["human_approved"] is False

    # An auto-satisfied request never waits on a human, so the agent must not be
    # parked in a state no decision will ever leave.
    agent = client.app.state.store.get_agent("node_test", "agent_runtime")
    assert agent["status"] == "running"


def test_session_scope_fingerprint_mismatch_does_not_auto_satisfy(
    client: TestClient,
) -> None:
    """Strict by operator decision: "approve for this session" authorizes THAT
    command, not any command that session happens to run next."""
    paired = pair_device(client)
    first = create_approval(
        client,
        action_id="act_fp_1",
        requested_tool="shell",
        payload_redacted={"command": "git status"},
    )
    decide(client, paired, first, scope="session")

    second = create_approval(
        client,
        action_id="act_fp_2",
        requested_tool="shell",
        payload_redacted={"command": "rm -rf build"},
    )
    assert second["params_fingerprint"] != first["params_fingerprint"]
    assert second["state"] == "pending"
    assert audit_events(client, paired, "approval_auto_satisfied") == []


def test_expired_grant_no_longer_auto_satisfies(client: TestClient) -> None:
    """Hard expiry is mandatory precisely so a forgotten grant stops working."""
    paired = pair_device(client)
    first = create_approval(client, action_id="act_exp_1", requested_tool="git_pull")
    decide(client, paired, first, scope="agent")

    second = create_approval(client, action_id="act_exp_2", requested_tool="git_pull")
    assert second["state"] == "approved", "sanity: the grant works before it lapses"

    rewind_grant_expiry(client, only_grant_id(client, paired))

    third = create_approval(client, action_id="act_exp_3", requested_tool="git_pull")
    assert third["state"] == "pending"


def test_revoked_grant_no_longer_auto_satisfies(client: TestClient) -> None:
    paired = pair_device(client)
    first = create_approval(client, action_id="act_rev_1", requested_tool="git_push")
    decide(client, paired, first, scope="agent")

    second = create_approval(client, action_id="act_rev_2", requested_tool="git_push")
    assert second["state"] == "approved", "sanity: the grant works before revocation"

    client.app.state.store.revoke_approval_grant(
        only_grant_id(client, paired), revoked_by="dev_test"
    )

    third = create_approval(client, action_id="act_rev_3", requested_tool="git_push")
    assert third["state"] == "pending"


def test_excluded_risk_family_is_refused_at_read_time_too(client: TestClient) -> None:
    """The read side re-applies the gate rather than trusting the row. A
    destructive-family grant — however it got into the table (a row predating a
    policy change, a hand-edited database) — must never clear a request."""
    paired = pair_device(client)
    store = client.app.state.store
    store.create_approval_grant(
        {
            "node_id": "node_test",
            "agent_id": "agent_mock",
            "requested_tool": "rm_rf",
            "risk_family": "destructive",
            "scope": "permanent",
            "source_approval_id": "appr_planted",
            "expires_at": "2099-01-01T00:00:00Z",
        }
    )

    approval = create_approval(
        client,
        action_id="act_excluded",
        requested_tool="rm_rf",
        risk_family="destructive",
        risk_level="high",
    )
    assert approval["state"] == "pending"
    assert audit_events(client, paired, "approval_auto_satisfied") == []
    refusals = audit_events(client, paired, "approval_auto_satisfy_refused")
    assert len(refusals) == 1
    assert refusals[0]["payload_redacted"]["reason"] == "risk_family_excluded"


def test_channel_mandating_request_is_refused_at_read_time_too(
    client: TestClient,
) -> None:
    """A live grant does not survive a request that mandates a mobile-signed
    decision: a standing grant is not that channel."""
    paired = pair_device(client)
    first = create_approval(
        client,
        action_id="act_chan_1",
        requested_tool="submit_form",
        payload_redacted={"form": "one"},
    )
    decide(client, paired, first, scope="agent")

    second = create_approval(
        client,
        action_id="act_chan_2",
        requested_tool="submit_form",
        payload_redacted={"form": "two"},
        risk_vector={"submit_risk_class": "critical"},
    )
    assert second["state"] == "pending"
    assert audit_events(client, paired, "approval_auto_satisfied") == []
    refusals = audit_events(client, paired, "approval_auto_satisfy_refused")
    assert len(refusals) == 1
    assert refusals[0]["payload_redacted"]["reason"] == "channel_requirement"


def test_kill_switch_disables_minting_and_consuming(tmp_path: Path) -> None:
    """ACT_STANDING_GRANTS_ENABLED=0 must make the gateway prompt every time."""
    for client in custom_client(tmp_path, standing_grants_enabled=False):
        paired = pair_device(client)
        first = create_approval(client, action_id="act_off_1", requested_tool="git_status")
        decide(client, paired, first, scope="session")

        assert audit_events(client, paired, "capability_grant_created") == []
        refusals = audit_events(client, paired, "capability_grant_refused")
        assert len(refusals) == 1
        assert refusals[0]["payload_redacted"]["reason"] == "standing_grants_disabled"

        second = create_approval(client, action_id="act_off_2", requested_tool="git_status")
        assert second["state"] == "pending"


def test_auto_satisfied_request_is_audited_after_being_requested(
    client: TestClient,
) -> None:
    """Ordering matters for the trail: the attempt is recorded first, then the
    clearance. Both events must name the same approval."""
    paired = pair_device(client)
    first = create_approval(client, action_id="act_order_1", requested_tool="ls_repo")
    decide(client, paired, first, scope="session")
    second = create_approval(client, action_id="act_order_2", requested_tool="ls_repo")

    requested = [
        event
        for event in audit_events(client, paired, "approval_requested")
        if event["approval_id"] == second["approval_id"]
    ]
    satisfied = [
        event
        for event in audit_events(client, paired, "approval_auto_satisfied")
        if event["approval_id"] == second["approval_id"]
    ]
    assert len(requested) == 1
    assert len(satisfied) == 1
    assert requested[0]["created_at"] <= satisfied[0]["created_at"]
    assert satisfied[0]["payload_redacted"]["human_approved"] is False
    assert satisfied[0]["actor_type"] == "gateway"
    assert satisfied[0]["actor_id"] == "standing_grant"


# --------------------------------------------------------------------------
# WS5 — listing and revocation over HTTP
# --------------------------------------------------------------------------


def list_grants(client: TestClient, paired: dict, query: str = "") -> list[dict]:
    response = signed_request(
        client,
        "GET",
        f"/v1/approval-grants{query}",
        private_key=paired["private_key"],
        device_id=paired["device"]["device_id"],
    )
    assert response.status_code == 200, response.text
    return response.json()["approval_grants"]


def revoke_grant(client: TestClient, paired: dict, grant_id: str) -> Any:
    return signed_request(
        client,
        "POST",
        f"/v1/approval-grants/{grant_id}/revoke",
        private_key=paired["private_key"],
        device_id=paired["device"]["device_id"],
        json_body={},
    )


def test_listing_shows_the_live_grant_with_scope_expiry_and_source(
    client: TestClient,
) -> None:
    paired = pair_device(client)
    approval = create_approval(client, action_id="act_list_1", requested_tool="git_diff")
    decide(client, paired, approval, scope="agent")

    grants = list_grants(client, paired)
    assert len(grants) == 1
    grant = grants[0]
    assert grant["scope"] == "agent"
    assert grant["state"] == "active"
    assert grant["requested_tool"] == "git_diff"
    assert grant["risk_family"] == GRANTABLE_RISK_FAMILY
    assert grant["source_approval_id"] == approval["approval_id"]
    assert grant["expires_at"], "a listed grant must show its hard expiry"
    assert grant["granted_by_device_id"] == paired["device"]["device_id"]


def test_listing_requires_a_signed_device(client: TestClient) -> None:
    """Same posture as the neighbouring approval routes — never anonymous."""
    assert client.get("/v1/approval-grants").status_code == 401


def test_listing_requires_the_approvals_capability(client: TestClient) -> None:
    read_only = pair_device(client, requested_permissions=["read_state"])
    response = signed_request(
        client,
        "GET",
        "/v1/approval-grants",
        private_key=read_only["private_key"],
        device_id=read_only["device"]["device_id"],
    )
    assert response.status_code == 403


def test_revocation_requires_the_approvals_capability(client: TestClient) -> None:
    paired = pair_device(client)
    decide(
        client,
        paired,
        create_approval(client, action_id="act_perm_guard", requested_tool="git_diff"),
        scope="agent",
    )
    grant_id = list_grants(client, paired)[0]["grant_id"]

    read_only = pair_device(client, requested_permissions=["read_state"])
    assert revoke_grant(client, read_only, grant_id).status_code == 403
    # ...and the grant is untouched.
    assert list_grants(client, paired)[0]["state"] == "active"


def test_revocation_takes_effect_immediately(client: TestClient) -> None:
    """The point of revocation: the very next request prompts again."""
    paired = pair_device(client)
    first = create_approval(client, action_id="act_revoke_1", requested_tool="git_clean")
    decide(client, paired, first, scope="agent")

    second = create_approval(client, action_id="act_revoke_2", requested_tool="git_clean")
    assert second["state"] == "approved", "sanity: the grant clears before revocation"

    grant_id = list_grants(client, paired)[0]["grant_id"]
    response = revoke_grant(client, paired, grant_id)
    assert response.status_code == 200, response.text
    revoked = response.json()
    assert revoked["state"] == "revoked"
    assert revoked["revoked_at"]
    assert revoked["revoked_by"] == paired["device"]["device_id"]

    third = create_approval(client, action_id="act_revoke_3", requested_tool="git_clean")
    assert third["state"] == "pending"


def test_revoked_grant_leaves_the_live_listing_but_stays_in_history(
    client: TestClient,
) -> None:
    paired = pair_device(client)
    decide(
        client,
        paired,
        create_approval(client, action_id="act_hist", requested_tool="git_gc"),
        scope="permanent",
    )
    grant_id = list_grants(client, paired)[0]["grant_id"]
    assert revoke_grant(client, paired, grant_id).status_code == 200

    assert list_grants(client, paired) == []
    history = list_grants(client, paired, "?include_inactive=true")
    assert [item["grant_id"] for item in history] == [grant_id]
    assert history[0]["state"] == "revoked"


def test_revocation_is_audited(client: TestClient) -> None:
    paired = pair_device(client)
    approval = create_approval(client, action_id="act_rev_audit", requested_tool="git_gc")
    decide(client, paired, approval, scope="agent")
    grant_id = list_grants(client, paired)[0]["grant_id"]
    assert revoke_grant(client, paired, grant_id).status_code == 200

    events = audit_events(client, paired, "capability_grant_revoked")
    assert len(events) == 1
    payload = events[0]["payload_redacted"]
    assert payload["grant_id"] == grant_id
    assert payload["scope"] == "agent"
    assert payload["source_approval_id"] == approval["approval_id"]
    assert events[0]["actor_id"] == paired["device"]["device_id"]


def test_revoking_twice_conflicts_and_unknown_grant_is_404(client: TestClient) -> None:
    paired = pair_device(client)
    decide(
        client,
        paired,
        create_approval(client, action_id="act_rev_twice", requested_tool="git_gc"),
        scope="agent",
    )
    grant_id = list_grants(client, paired)[0]["grant_id"]

    assert revoke_grant(client, paired, grant_id).status_code == 200
    assert revoke_grant(client, paired, grant_id).status_code == 409
    assert revoke_grant(client, paired, "grant_does_not_exist").status_code == 404


def test_listing_can_filter_by_agent(client: TestClient) -> None:
    paired = pair_device(client)
    decide(
        client,
        paired,
        create_approval(
            client, action_id="act_f_a", agent_id="agent_a", requested_tool="git_gc"
        ),
        scope="agent",
    )
    decide(
        client,
        paired,
        create_approval(
            client, action_id="act_f_b", agent_id="agent_b", requested_tool="git_gc"
        ),
        scope="agent",
    )

    assert len(list_grants(client, paired)) == 2
    only_b = list_grants(client, paired, "?agent_id=agent_b")
    assert [item["agent_id"] for item in only_b] == ["agent_b"]


def test_expired_grant_is_absent_from_the_live_listing(client: TestClient) -> None:
    paired = pair_device(client)
    decide(
        client,
        paired,
        create_approval(client, action_id="act_exp_list", requested_tool="git_gc"),
        scope="agent",
    )
    grant_id = list_grants(client, paired)[0]["grant_id"]
    rewind_grant_expiry(client, grant_id)

    assert list_grants(client, paired) == []
    assert [item["grant_id"] for item in list_grants(client, paired, "?include_inactive=true")] == [
        grant_id
    ]


def test_auto_satisfied_clearance_can_be_reserved_and_committed(
    client: TestClient,
) -> None:
    """A cleared request has to be usable by the consumer that asked for it.
    The two-phase consume seam (reserve -> commit) must accept an
    auto-satisfied clearance exactly like a human-approved one — otherwise the
    grant would clear requests nothing could execute."""
    paired = pair_device(client)
    first = create_approval(client, action_id="act_2pc_1", requested_tool="git_show")
    decide(client, paired, first, scope="session")

    second = create_approval(client, action_id="act_2pc_2", requested_tool="git_show")
    assert second["state"] == "approved"

    reserved = client.post(f"/v1/runtime/approvals/{second['approval_id']}/reserve")
    assert reserved.status_code == 200, reserved.text
    assert reserved.json()["state"] == "reserved"

    committed = client.post(f"/v1/runtime/approvals/{second['approval_id']}/commit")
    assert committed.status_code == 200, committed.text
    assert committed.json()["state"] == "committed"
    # One-time consumption still holds.
    assert client.post(f"/v1/runtime/approvals/{second['approval_id']}/reserve").status_code == 409


# --------------------------------------------------------------------------
# WS6 — the fail-closed gate must enforce the WHOLE channel policy, not the
# risk_vector half of it.
#
# Regression: standing_grant_block_reason consulted only
# required_channels_for_risk_vector, so ``external_effect`` — which ranks BELOW
# the destructive exclusion floor yet is in MOBILE_MANDATORY_RISK_FAMILIES —
# slipped through both halves and came back approved / approved_by=standing_grant
# / human_approved=False, bypassing a policy that says a human on a mobile-signed
# channel must decide it.
# --------------------------------------------------------------------------


def plant_grant(
    client: TestClient,
    *,
    scope: str,
    risk_family: str,
    requested_tool: str,
    agent_id: str | None = "agent_mock",
    session_id: str | None = None,
    params_fingerprint: str | None = None,
) -> dict:
    """Insert a live grant straight into the store.

    Deliberately bypasses the write side: the mint gate now refuses these, so a
    row like this can only arrive by predating a policy change or by a
    hand-edited database — exactly the case the read side must survive.
    """
    return client.app.state.store.create_approval_grant(
        {
            "node_id": "node_test",
            "agent_id": agent_id or "agent_mock",
            "session_id": session_id,
            "requested_tool": requested_tool,
            "params_fingerprint": params_fingerprint,
            "risk_family": risk_family,
            "scope": scope,
            "state": "active",
            "source_approval_id": "appr_planted",
            "expires_at": "2099-01-01T00:00:00Z",
        }
    )


def test_external_effect_is_never_auto_satisfied_by_a_live_agent_grant(
    client: TestClient,
) -> None:
    """The reviewer's probe. A live agent-scope grant matching an
    ``external_effect`` request must NOT clear it: the request stays pending, no
    auto-satisfaction is recorded, and the refusal is audited."""
    paired = pair_device(client)
    plant_grant(
        client,
        scope="agent",
        risk_family="external_effect",
        requested_tool="send_email",
    )

    approval = create_approval(
        client,
        action_id="act_ext_agent",
        requested_tool="send_email",
        risk_family="external_effect",
        risk_level="high",
    )

    assert approval["state"] == "pending"
    assert approval.get("approved_by") != "standing_grant"
    assert not approval.get("human_approved")
    assert audit_events(client, paired, "approval_auto_satisfied") == []
    refusals = audit_events(client, paired, "approval_auto_satisfy_refused")
    assert len(refusals) == 1
    assert refusals[0]["payload_redacted"]["reason"] == "channel_requirement"
    assert refusals[0]["payload_redacted"]["risk_family"] == "external_effect"


def test_external_effect_is_never_auto_satisfied_by_a_live_permanent_grant(
    client: TestClient,
) -> None:
    """Same for the broadest scope — ``permanent`` keys on node + tool only, so
    it is the widest hole an unenforced half of the policy would open."""
    paired = pair_device(client)
    plant_grant(
        client,
        scope="permanent",
        risk_family="external_effect",
        requested_tool="post_webhook",
    )

    approval = create_approval(
        client,
        action_id="act_ext_perm",
        agent_id="agent_other",
        requested_tool="post_webhook",
        risk_family="external_effect",
        risk_level="high",
    )

    assert approval["state"] == "pending"
    assert audit_events(client, paired, "approval_auto_satisfied") == []
    refusals = audit_events(client, paired, "approval_auto_satisfy_refused")
    assert len(refusals) == 1
    assert refusals[0]["payload_redacted"]["reason"] == "channel_requirement"


def test_external_effect_decision_refuses_to_mint_a_grant(client: TestClient) -> None:
    """Write side of the same gate: "allow forever" on an ``external_effect``
    action must not persist standing authority in the first place."""
    paired = pair_device(client)
    approval = create_approval(
        client,
        action_id="act_ext_mint",
        requested_tool="send_email",
        risk_family="external_effect",
        risk_level="high",
    )
    decide(client, paired, approval, scope="permanent")

    assert audit_events(client, paired, "capability_grant_created") == []
    refusals = audit_events(client, paired, "capability_grant_refused")
    assert len(refusals) == 1
    assert refusals[0]["payload_redacted"]["reason"] == "channel_requirement"


def test_every_mobile_mandatory_family_blocks_a_standing_grant() -> None:
    """No family that requires a human on a mobile-signed channel may be
    auto-satisfiable, and an unrecognised family still blocks."""
    settings = Settings(
        node_id="node_test",
        node_display_name="Test",
        node_fingerprint="fp",
        gateway_base_url="http://127.0.0.1:8787/v1",
        database_path=":memory:",
    )
    for family in MOBILE_MANDATORY_RISK_FAMILIES:
        reason = standing_grant_block_reason(
            settings=settings, risk_family=family, risk_vector=None
        )
        assert reason is not None, family
        assert required_channels_for_request(risk_family=family) == ("mobile_signed",)
    assert MOBILE_MANDATORY_RISK_FAMILIES <= set(GRANT_UNGRANTABLE_RISK_FAMILIES)
    assert (
        standing_grant_block_reason(
            settings=settings, risk_family="not_a_family", risk_vector=None
        )
        is not None
    )
    # The low tier stays grantable, otherwise the feature is dead rather than safe.
    for family in LOW_RISK_FAMILIES:
        assert (
            standing_grant_block_reason(
                settings=settings, risk_family=family, risk_vector=None
            )
            is None
        ), family


def test_gate_tracks_the_mobile_mandatory_set_without_editing_grants(
    monkeypatch: Any,
) -> None:
    """Derived, not enumerated: adding a family to MOBILE_MANDATORY_RISK_FAMILIES
    must block auto-satisfy with no edit to grants.py. ``routine`` is grantable
    today; moved into the mobile-mandatory set it must stop being grantable."""
    settings = Settings(
        node_id="node_test",
        node_display_name="Test",
        node_fingerprint="fp",
        gateway_base_url="http://127.0.0.1:8787/v1",
        database_path=":memory:",
    )
    assert (
        standing_grant_block_reason(
            settings=settings, risk_family="routine", risk_vector=None
        )
        is None
    )
    monkeypatch.setattr(
        clearance_policy,
        "MOBILE_MANDATORY_RISK_FAMILIES",
        clearance_policy.MOBILE_MANDATORY_RISK_FAMILIES | {"routine"},
    )
    assert (
        standing_grant_block_reason(
            settings=settings, risk_family="routine", risk_vector=None
        )
        == "channel_requirement"
    )

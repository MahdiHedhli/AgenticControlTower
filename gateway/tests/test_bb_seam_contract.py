"""Per-change tests for the BrowserBridge seam clearance-contract extension.

Proves the additive contract from
``docs/implementation/browserbridge-seam-contract-handoff.md``: authority
provenance round-trip, per-surface risk-vector round-trip, two-phase
reserve->commit, panic dominance, and risk-class -> channel policy.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from conftest import pair_device, signed_request
from hermes_gateway.clearance_policy import (
    authority_from_channel,
    channel_satisfies,
    required_channels_for_risk_vector,
)


def _future(seconds: int = 3600) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).isoformat()


def _create(client: TestClient, *, action_id: str, risk_vector: dict | None = None) -> dict:
    payload = {
        "action_id": action_id,
        "agent_id": "agent_mock",
        "session_id": "sess_mock",
        "requested_tool": "shell",
        "risk_level": "high",
        # The tower requires an explicit risk-family declaration (422 without
        # one); "external_effect" matches what risk_level=high derives to.
        "risk_family": "external_effect",
        "summary": "Run a command",
        "full_payload_redacted": {"command": "redacted"},
        "expires_at": _future(),
    }
    if risk_vector is not None:
        payload["risk_vector"] = risk_vector
    response = client.post("/v1/approvals", json=payload)
    assert response.status_code == 201, response.text
    return response.json()


def _approve(client: TestClient, paired: dict, approval_id: str):
    return signed_request(
        client,
        "POST",
        f"/v1/approvals/{approval_id}/approve_once",
        private_key=paired["private_key"],
        device_id=paired["device"]["device_id"],
    )


def _get(client: TestClient, paired: dict, approval_id: str) -> dict:
    response = signed_request(
        client,
        "GET",
        f"/v1/approvals/{approval_id}",
        private_key=paired["private_key"],
        device_id=paired["device"]["device_id"],
    )
    assert response.status_code == 200, response.text
    return response.json()


def _audit_events(client: TestClient, paired: dict, event_type: str) -> list[dict]:
    response = signed_request(
        client,
        "GET",
        f"/v1/audit/events?event_type={event_type}",
        private_key=paired["private_key"],
        device_id=paired["device"]["device_id"],
    )
    assert response.status_code == 200, response.text
    return response.json()["audit_events"]


# --- Change 1: authority provenance -----------------------------------------

def test_provenance_defaults_then_round_trips(client: TestClient) -> None:
    paired = pair_device(client)
    approval = _create(client, action_id="prov_1")
    assert approval["approved_by"] is None
    assert approval["human_approved"] is False

    assert _approve(client, paired, approval["approval_id"]).status_code == 200
    fetched = _get(client, paired, approval["approval_id"])
    assert fetched["approved_by"] in {"human_mobile", "human_local", "test_operator"}
    # A real mobile (Secure-Enclave) paired device is a human channel.
    assert fetched["approved_by"] == "human_mobile"
    assert fetched["human_approved"] is True


# --- Change 2: per-surface risk vector --------------------------------------

def test_risk_vector_round_trips(client: TestClient) -> None:
    vector = {
        "field_class": "sensitive",
        "submit_risk_class": "high",
        "click_risk_class": "low",
    }
    approval = _create(client, action_id="rv_1", risk_vector=vector)
    assert approval["risk_vector"] == vector
    # Scalar risk_level is untouched.
    assert approval["risk_level"] == "high"


def test_risk_vector_absent_is_none(client: TestClient) -> None:
    approval = _create(client, action_id="rv_2")
    assert approval["risk_vector"] is None


# --- Change 3: two-phase reserve->commit ------------------------------------

def test_reserve_then_commit(client: TestClient) -> None:
    paired = pair_device(client)
    approval = _create(client, action_id="rc_1")
    assert _approve(client, paired, approval["approval_id"]).status_code == 200
    aid = approval["approval_id"]

    reserved = client.post(f"/v1/runtime/approvals/{aid}/reserve")
    assert reserved.status_code == 200, reserved.text
    assert reserved.json()["state"] == "reserved"

    committed = client.post(f"/v1/runtime/approvals/{aid}/commit")
    assert committed.status_code == 200, committed.text
    assert committed.json()["state"] == "committed"


def test_double_reserve_is_rejected(client: TestClient) -> None:
    paired = pair_device(client)
    approval = _create(client, action_id="rc_2")
    assert _approve(client, paired, approval["approval_id"]).status_code == 200
    aid = approval["approval_id"]

    assert client.post(f"/v1/runtime/approvals/{aid}/reserve").status_code == 200
    # Second reserve must fail — one-time consumption preserved.
    assert client.post(f"/v1/runtime/approvals/{aid}/reserve").status_code == 409


def test_commit_requires_reserved(client: TestClient) -> None:
    paired = pair_device(client)
    approval = _create(client, action_id="rc_3")
    assert _approve(client, paired, approval["approval_id"]).status_code == 200
    aid = approval["approval_id"]
    # Commit straight from approved (not reserved) must fail.
    assert client.post(f"/v1/runtime/approvals/{aid}/commit").status_code == 409


def test_reserve_requires_approved(client: TestClient) -> None:
    approval = _create(client, action_id="rc_4")  # still pending
    aid = approval["approval_id"]
    assert client.post(f"/v1/runtime/approvals/{aid}/reserve").status_code == 409


# --- Change 3b: single-clearance release (symmetric inverse of commit) -------

def test_reserve_then_release(client: TestClient) -> None:
    paired = pair_device(client)
    approval = _create(client, action_id="rl_1")
    assert _approve(client, paired, approval["approval_id"]).status_code == 200
    aid = approval["approval_id"]

    reserved = client.post(f"/v1/runtime/approvals/{aid}/reserve")
    assert reserved.status_code == 200, reserved.text
    assert reserved.json()["state"] == "reserved"

    released = client.post(f"/v1/runtime/approvals/{aid}/release")
    assert released.status_code == 200, released.text
    assert released.json()["state"] == "cancelled"

    # The release must be audited (approval_released) — fail-closed evidence,
    # not just a silent state flip.
    events = _audit_events(client, paired, "approval_released")
    assert any(
        e["approval_id"] == aid
        and e.get("payload_redacted", {}).get("state") == "cancelled"
        for e in events
    ), "expected an approval_released audit event for the released clearance"


def test_commit_after_release_is_rejected(client: TestClient) -> None:
    paired = pair_device(client)
    approval = _create(client, action_id="rl_2")
    assert _approve(client, paired, approval["approval_id"]).status_code == 200
    aid = approval["approval_id"]

    assert client.post(f"/v1/runtime/approvals/{aid}/reserve").status_code == 200
    assert client.post(f"/v1/runtime/approvals/{aid}/release").status_code == 200
    # Released (cancelled) clearance can never afterward be committed — replay
    # denial / one-time consumption preserved.
    assert client.post(f"/v1/runtime/approvals/{aid}/commit").status_code == 409
    assert _get(client, paired, aid)["state"] == "cancelled"


def test_release_leaves_committed_intact(client: TestClient) -> None:
    paired = pair_device(client)
    approval = _create(client, action_id="rl_3")
    assert _approve(client, paired, approval["approval_id"]).status_code == 200
    aid = approval["approval_id"]

    assert client.post(f"/v1/runtime/approvals/{aid}/reserve").status_code == 200
    assert client.post(f"/v1/runtime/approvals/{aid}/commit").status_code == 200
    # Release on a committed clearance is rejected and leaves state committed.
    assert client.post(f"/v1/runtime/approvals/{aid}/release").status_code == 409
    assert _get(client, paired, aid)["state"] == "committed"


def test_release_missing_is_404(client: TestClient) -> None:
    assert client.post("/v1/runtime/approvals/apr_does_not_exist/release").status_code == 404


def test_release_requires_reserved(client: TestClient) -> None:
    # Pending (never-reserved) clearance: release must conflict, not no-op.
    approval = _create(client, action_id="rl_4")  # still pending
    aid = approval["approval_id"]
    assert client.post(f"/v1/runtime/approvals/{aid}/release").status_code == 409


# --- Change 4: panic dominance ----------------------------------------------

def _emergency_stop(client: TestClient, paired: dict) -> None:
    response = signed_request(
        client,
        "POST",
        "/v1/sessions/sess_mock/interventions",
        private_key=paired["private_key"],
        device_id=paired["device"]["device_id"],
        json_body={
            "intervention_id": "int_panic",
            "type": "emergency_stop",
            "reason": "panic",
            "signed_payload": {"type": "emergency_stop"},
            "signature": "sig_test",
        },
    )
    assert response.status_code == 200
    assert response.json()["resulting_state"] == "approvals_invalidated"


def test_panic_invalidates_approved_but_unconsumed(client: TestClient) -> None:
    paired = pair_device(client)
    approval = _create(client, action_id="panic_1")
    assert _approve(client, paired, approval["approval_id"]).status_code == 200
    # Approved-but-unconsumed (not reserved/committed).
    assert _get(client, paired, approval["approval_id"])["state"] == "approved"

    _emergency_stop(client, paired)

    assert _get(client, paired, approval["approval_id"])["state"] == "cancelled"


def test_panic_invalidates_pending(client: TestClient) -> None:
    paired = pair_device(client)
    approval = _create(client, action_id="panic_2")  # pending
    _emergency_stop(client, paired)
    assert _get(client, paired, approval["approval_id"])["state"] == "cancelled"


def test_panic_leaves_committed_intact(client: TestClient) -> None:
    paired = pair_device(client)
    approval = _create(client, action_id="panic_3")
    aid = approval["approval_id"]
    assert _approve(client, paired, aid).status_code == 200
    assert client.post(f"/v1/runtime/approvals/{aid}/reserve").status_code == 200
    assert client.post(f"/v1/runtime/approvals/{aid}/commit").status_code == 200
    _emergency_stop(client, paired)
    # Committed = already consumed; panic does not touch it.
    assert _get(client, paired, aid)["state"] == "committed"


# --- Change 5: risk-class -> channel policy ---------------------------------

def test_channel_policy_function() -> None:
    assert required_channels_for_risk_vector(None) is None
    assert required_channels_for_risk_vector({"submit_risk_class": "low"}) is None
    assert required_channels_for_risk_vector(
        {"submit_risk_class": "high"}
    ) == ("mobile_signed",)
    assert required_channels_for_risk_vector(
        {"click_risk_class": "critical"}
    ) == ("mobile_signed",)
    assert channel_satisfies("mobile_signed", ("mobile_signed",)) is True
    assert channel_satisfies("local_terminal", ("mobile_signed",)) is False
    assert channel_satisfies("local_terminal", None) is True


def test_authority_from_channel() -> None:
    assert authority_from_channel("mobile_signed") == "human_mobile"
    assert authority_from_channel("local_terminal") == "human_local"
    assert authority_from_channel(None) == "test_operator"
    assert authority_from_channel("unknown") == "test_operator"


def test_high_risk_vector_approval_via_mobile_succeeds(client: TestClient) -> None:
    # The mandated channel (mobile_signed) is satisfied by the paired device.
    paired = pair_device(client)
    approval = _create(
        client, action_id="cp_1", risk_vector={"submit_risk_class": "high"}
    )
    assert _approve(client, paired, approval["approval_id"]).status_code == 200

"""WS9 — device revocation must cascade to the standing grants it minted.

Reproduce-first gate: the live decision path 403s a non-active device
(``signing.py``: ``device["status"] != "active"`` -> ``device is not active``)
*before* channel evaluation, but ``grant_channel_authority_block_reason``
resolved the granting device with a bare ``store.get_device`` and asked only the
channel question. So after ``DELETE /v1/devices/<id>`` the revoked device's
standing grants kept auto-approving to full TTL. These tests fail on that
behaviour and pass once:

* the read side requires the same liveness the live path requires (only
  ``status == 'active'`` confers authority; missing/unknown status fails
  closed) with the dedicated refusal reason ``grant_device_revoked``; and
* ``DELETE /v1/devices/<id>`` cascade-revokes the device's active grants,
  auditing one ``capability_grant_revoked`` per grant.

The read-side gate is the load-bearing control (it also covers rows reached
without the route — a hand-flipped status, a status value invented later); the
cascade-write is honesty for ``GET /v1/approval-grants`` plus defense in depth.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from conftest import pair_device, signed_request
from test_standing_grants import (
    audit_events,
    create_approval,
    decide,
    list_grants,
)


def delete_device(client: TestClient, operator: dict, device_id: str) -> None:
    response = signed_request(
        client,
        "DELETE",
        f"/v1/devices/{device_id}",
        private_key=operator["private_key"],
        device_id=operator["device"]["device_id"],
    )
    assert response.status_code == 204, response.text


def grant_from(client: TestClient, granting: dict, *, action_id: str, tool: str) -> None:
    approval = create_approval(client, action_id=action_id, requested_tool=tool)
    decide(client, granting, approval, scope="agent")


# --------------------------------------------------------------------------
# (a) The reproduce-first failing test: the real route, end to end.
# --------------------------------------------------------------------------


def test_deleted_device_grants_stop_auto_satisfying(client: TestClient) -> None:
    """DELETE /v1/devices/<id> must withdraw the device's standing authority:
    the very next matching request prompts instead of auto-approving."""
    granting = pair_device(client)
    operator = pair_device(client)
    grant_from(client, granting, action_id="act_cascade_1", tool="git_status")

    second = create_approval(client, action_id="act_cascade_2", requested_tool="git_status")
    assert second["state"] == "approved", "sanity: the grant works before revocation"

    delete_device(client, operator, granting["device"]["device_id"])

    third = create_approval(client, action_id="act_cascade_3", requested_tool="git_status")
    assert third["state"] == "pending", (
        "BYPASS: the operator unpaired the granting device, yet its standing "
        f"grant still auto-approved: {third['state']} / {third.get('approved_by')}"
    )
    assert third.get("approved_by") != "standing_grant"
    assert not third.get("human_approved")


# --------------------------------------------------------------------------
# (b) The precise refusal reason is audited. The read-side gate is exercised in
# isolation via store.revoke_device — the exact pre-fix reachable state (status
# flipped, grants rows untouched) and the state a future status value or a
# hand-edited row would recreate. This is also the test that proves the gate
# load-bearing: with the cascade-write in place, only THIS path still has an
# active grant row for a non-active device.
# --------------------------------------------------------------------------


def test_read_side_gate_refuses_a_revoked_device_grant_with_the_precise_reason(
    client: TestClient,
) -> None:
    granting = pair_device(client)
    auditor = pair_device(client)
    grant_from(client, granting, action_id="act_gate_1", tool="git_diff")

    # Flip the status only — no cascade — leaving the grant row active.
    assert client.app.state.store.revoke_device(granting["device"]["device_id"])
    assert list_grants(client, auditor)[0]["state"] == "active", (
        "precondition: the grant row must still be active so the read-side "
        "gate, not the cascade, is what refuses"
    )

    approval = create_approval(client, action_id="act_gate_2", requested_tool="git_diff")
    assert approval["state"] == "pending"
    assert approval.get("approved_by") != "standing_grant"

    assert audit_events(client, auditor, "approval_auto_satisfied") == []
    refusals = audit_events(client, auditor, "approval_auto_satisfy_refused")
    assert len(refusals) == 1
    assert refusals[0]["payload_redacted"]["reason"] == "grant_device_revoked"
    assert refusals[0]["payload_redacted"]["requested_tool"] == "git_diff"


def test_unknown_device_status_fails_closed(client: TestClient) -> None:
    """Only ``status == 'active'`` confers authority — a status value this code
    has never heard of (or a NULL) must refuse, exactly like the live path's
    ``device["status"] != "active"``."""
    granting = pair_device(client)
    auditor = pair_device(client)
    grant_from(client, granting, action_id="act_status_1", tool="git_log")

    store = client.app.state.store
    with store.connect() as db:
        db.execute(
            "UPDATE devices SET status = 'suspended' WHERE device_id = ?",
            (granting["device"]["device_id"],),
        )

    approval = create_approval(client, action_id="act_status_2", requested_tool="git_log")
    assert approval["state"] == "pending"
    refusals = audit_events(client, auditor, "approval_auto_satisfy_refused")
    assert len(refusals) == 1
    assert refusals[0]["payload_redacted"]["reason"] == "grant_device_revoked"


# --------------------------------------------------------------------------
# (c) Feature alive: authority is withdrawn per device, not per node.
# --------------------------------------------------------------------------


def test_grant_from_a_still_active_device_survives_an_unrelated_deletion(
    client: TestClient,
) -> None:
    granting = pair_device(client)
    unrelated = pair_device(client)
    operator = pair_device(client)
    grant_from(client, granting, action_id="act_alive_cascade_1", tool="git_fetch")

    delete_device(client, operator, unrelated["device"]["device_id"])

    second = create_approval(
        client, action_id="act_alive_cascade_2", requested_tool="git_fetch"
    )
    assert second["state"] == "approved"
    assert second["approved_by"] == "standing_grant"
    # ...and the surviving device's grant row was not touched by the cascade.
    grants = list_grants(client, operator)
    assert [g["state"] for g in grants] == ["active"]
    assert grants[0]["granted_by_device_id"] == granting["device"]["device_id"]


# --------------------------------------------------------------------------
# (d) Cascade-write: the listing tells the truth and the withdrawal is audited
# per grant, naming the device deletion as the revoker.
# --------------------------------------------------------------------------


def test_device_deletion_cascade_revokes_and_audits_each_grant(
    client: TestClient,
) -> None:
    granting = pair_device(client)
    operator = pair_device(client)
    grant_from(client, granting, action_id="act_list_cascade_1", tool="git_show")
    grant_from(client, granting, action_id="act_list_cascade_2", tool="git_blame")
    device_id = granting["device"]["device_id"]

    delete_device(client, operator, device_id)

    assert list_grants(client, operator) == [], "no live grants may survive the deletion"
    history = list_grants(client, operator, "?include_inactive=true")
    assert len(history) == 2
    for grant in history:
        assert grant["state"] == "revoked"
        assert grant["revoked_at"]
        assert grant["revoked_by"] == f"device_revoked:{device_id}"

    events = audit_events(client, operator, "capability_grant_revoked")
    assert len(events) == 2
    assert {e["payload_redacted"]["grant_id"] for e in events} == {
        g["grant_id"] for g in history
    }
    for event in events:
        assert event["payload_redacted"]["revoked_by"] == f"device_revoked:{device_id}"
        assert event["actor_id"] == operator["device"]["device_id"]


def test_cascade_only_touches_the_deleted_devices_active_grants(
    client: TestClient,
) -> None:
    """Proportionate: an already-revoked grant is not re-revoked (no duplicate
    audit), and another device's grants are untouched."""
    granting = pair_device(client)
    other = pair_device(client)
    operator = pair_device(client)
    grant_from(client, granting, action_id="act_scope_cascade_1", tool="git_show")
    # A grant by another device on the same node.
    approval = create_approval(
        client, action_id="act_scope_cascade_2", requested_tool="ls_repo"
    )
    decide(client, other, approval, scope="agent")

    # Revoke the granting device's grant by hand first.
    grant_id = next(
        g["grant_id"]
        for g in list_grants(client, operator)
        if g["granted_by_device_id"] == granting["device"]["device_id"]
    )
    assert (
        signed_request(
            client,
            "POST",
            f"/v1/approval-grants/{grant_id}/revoke",
            private_key=operator["private_key"],
            device_id=operator["device"]["device_id"],
            json_body={},
        ).status_code
        == 200
    )

    delete_device(client, operator, granting["device"]["device_id"])

    history = list_grants(client, operator, "?include_inactive=true")
    by_id = {g["grant_id"]: g for g in history}
    # The hand-revoked grant keeps its original revoker — the cascade did not
    # stamp over it.
    assert by_id[grant_id]["revoked_by"] == operator["device"]["device_id"]
    # The other device's grant is still live.
    live = list_grants(client, operator)
    assert [g["granted_by_device_id"] for g in live] == [other["device"]["device_id"]]
    # Exactly one capability_grant_revoked from the hand revoke; none from the
    # cascade (it had nothing active left to revoke).
    events = audit_events(client, operator, "capability_grant_revoked")
    assert len(events) == 1


# --------------------------------------------------------------------------
# KNOWN GAP 2 closure: channel resolution now mirrors the live path
# (``device.get("clearance_channel", "local_terminal")``) instead of falling
# back to ``platform``. A row with an emptied clearance_channel and a mobile
# platform must refuse, exactly as the live path 403s it.
# --------------------------------------------------------------------------


def test_emptied_clearance_channel_no_longer_resolves_via_platform(
    client: TestClient,
) -> None:
    granting = pair_device(client)  # platform "ios", clearance_channel "mobile_signed"
    auditor = pair_device(client)
    grant_from(client, granting, action_id="act_chanfix_1", tool="git_grep")

    store = client.app.state.store
    with store.connect() as db:
        db.execute(
            "UPDATE devices SET clearance_channel = '' WHERE device_id = ?",
            (granting["device"]["device_id"],),
        )

    approval = create_approval(client, action_id="act_chanfix_2", requested_tool="git_grep")
    assert approval["state"] == "pending", (
        "BYPASS: the live path rejects '' as a decision channel, but the grants "
        "path resolved mobile_signed from the platform and auto-approved"
    )
    refusals = audit_events(client, auditor, "approval_auto_satisfy_refused")
    assert len(refusals) == 1
    assert refusals[0]["payload_redacted"]["reason"] == "grant_channel_authority_unresolved"

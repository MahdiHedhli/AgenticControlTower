"""Every surface must report the scope that was APPLIED.

5bd7379 made the decision RESPONSE honest and stopped there. The phone does not
re-read that response — it re-reads the approval, and it listens to events. So
for a `destructive` request approved with `scope=session` (a family that can
never carry standing authority, hence zero grants) the four surfaces disagreed:

    POST .../decisions            applied_scope   "once"     <- honest
    GET  /v1/approvals/{id}       decision_scope  "session"  <- the lie
    approval.resolved event       scope           "session"  <- the lie
    audit approval_decision       scope           "session"  <- the lie
    GET /v1/runtime/approvals/    selected_scope  "session"  <- the lie, to the
        {id}/result                                             AGENT

ROOT CAUSE, and where it is fixed: the store PERSISTED the requested scope.
`decision_scope` is the column all four readers derive from, so one honest
write fixes all of them and cannot drift back out of step the way three patched
readers could.

The requested scope is not lost: it moves to `requested_scope`, on the row and
in both records.
"""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from conftest import pair_device, signed_request

#: (risk_family, requested scope) -> what the gateway can actually apply.
#: `read_only` is below the standing-grant exclusion floor and its channel map
#: admits a mobile_signed decision, so a grant really is minted there — which is
#: what makes this a test of honesty rather than of always saying "once".
GRANTABLE_FAMILY = "read_only"
REFUSED_FAMILY = "destructive"


def _create(client: TestClient, *, action_id: str, risk_family: str) -> dict:
    response = client.post(
        "/v1/approvals",
        json={
            "action_id": action_id,
            "agent_id": "agent_mock",
            "session_id": "sess_mock",
            "requested_tool": "shell",
            "risk_level": "high",
            "risk_family": risk_family,
            "summary": "Run a command",
            "full_payload_redacted": {"command": "redacted"},
            "resource_scope": "repo",
            "expires_at": "2099-01-01T00:00:00Z",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def _decide(client: TestClient, paired: dict, approval: dict, scope: str) -> dict:
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


def _surfaces(client: TestClient, paired: dict, approval_id: str) -> dict[str, Any]:
    pk, did = paired["private_key"], paired["device"]["device_id"]

    detail = signed_request(
        client, "GET", f"/v1/approvals/{approval_id}", private_key=pk, device_id=did
    ).json()

    events = signed_request(client, "GET", "/v1/events", private_key=pk, device_id=did).json()
    resolved = next(
        event["payload"]
        for event in events["events"]
        if event["type"] == "approval.resolved"
        and event["payload"].get("approval_id") == approval_id
    )

    audit = signed_request(
        client,
        "GET",
        "/v1/audit/events?event_type=approval_decision",
        private_key=pk,
        device_id=did,
    ).json()
    record = next(
        row["payload_redacted"]
        for row in audit["audit_events"]
        if row.get("approval_id") == approval_id
    )

    runtime = client.get(f"/v1/runtime/approvals/{approval_id}/result").json()

    return {
        "approval.decision_scope": detail["decision_scope"],
        "event.scope": resolved["scope"],
        "audit.scope": record["scope"],
        "runtime.selected_scope": runtime["selected_scope"],
        "_detail": detail,
        "_event": resolved,
        "_audit": record,
    }


def _grant_count(client: TestClient, paired: dict) -> int:
    body = signed_request(
        client,
        "GET",
        "/v1/approval-grants",
        private_key=paired["private_key"],
        device_id=paired["device"]["device_id"],
    ).json()
    return len(body.get("grants", body.get("approval_grants", [])))


@pytest.mark.parametrize("scope", ["session", "agent", "permanent"])
def test_a_refused_scope_reads_back_as_once_everywhere(
    client: TestClient, scope: str
) -> None:
    """The measured defect: response said `once`, every other surface `session`."""
    paired = pair_device(client)
    approval = _create(client, action_id=f"act_refused_{scope}", risk_family=REFUSED_FAMILY)

    decision = _decide(client, paired, approval, scope)
    assert decision["applied_scope"] == "once"
    assert decision["grant_minted"] is False
    assert decision["grant_refused_reason"] == "risk_family_excluded"
    assert _grant_count(client, paired) == 0, "nothing was granted, so nothing may claim it was"

    surfaces = _surfaces(client, paired, approval["approval_id"])
    reported = {
        key: value for key, value in surfaces.items() if not key.startswith("_")
    }
    assert set(reported.values()) == {"once"}, reported


def test_a_granted_scope_reads_back_as_that_scope_everywhere(client: TestClient) -> None:
    """Honesty, not pessimism: when a grant IS minted, every surface says so."""
    paired = pair_device(client)
    approval = _create(client, action_id="act_granted", risk_family=GRANTABLE_FAMILY)

    decision = _decide(client, paired, approval, "session")
    assert decision["applied_scope"] == "session"
    assert decision["grant_minted"] is True
    assert decision["grant_refused_reason"] is None
    assert _grant_count(client, paired) == 1

    surfaces = _surfaces(client, paired, approval["approval_id"])
    reported = {
        key: value for key, value in surfaces.items() if not key.startswith("_")
    }
    assert set(reported.values()) == {"session"}, reported


def test_the_requested_scope_is_retained_not_discarded(client: TestClient) -> None:
    """Making the row honest must not cost the audit trail what was asked for."""
    paired = pair_device(client)
    approval = _create(client, action_id="act_retained", risk_family=REFUSED_FAMILY)

    _decide(client, paired, approval, "session")
    surfaces = _surfaces(client, paired, approval["approval_id"])

    assert surfaces["_detail"]["requested_scope"] == "session"
    assert surfaces["_detail"]["decision_scope"] == "once"

    # Both records name which is which, rather than leaving it to be inferred
    # from a nullable grant_id.
    for record in (surfaces["_event"], surfaces["_audit"]):
        assert record["requested_scope"] == "session"
        assert record["applied_scope"] == "once"
        assert record["scope"] == "once", "the legacy key must not stay the lie"
    assert surfaces["_audit"]["grant_refused_reason"] == "risk_family_excluded"


def test_approve_once_is_unchanged(client: TestClient) -> None:
    """The overwhelmingly common path must be byte-identical to before."""
    paired = pair_device(client)
    approval = _create(client, action_id="act_plain_once", risk_family=REFUSED_FAMILY)

    response = signed_request(
        client,
        "POST",
        f"/v1/approvals/{approval['approval_id']}/approve_once",
        private_key=paired["private_key"],
        device_id=paired["device"]["device_id"],
    )
    assert response.status_code == 200
    assert response.json()["applied_scope"] == "once"
    assert response.json()["grant_refused_reason"] is None

    surfaces = _surfaces(client, paired, approval["approval_id"])
    assert surfaces["approval.decision_scope"] == "once"
    assert surfaces["_detail"]["requested_scope"] == "once"


def test_a_denial_records_what_it_always_recorded(client: TestClient) -> None:
    """Only an approval can APPLY a scope; deny/expire/cancel are untouched.

    Pinned so a later reading of "make it honest" does not quietly change what a
    refusal records — that is a separate decision, not this fix.
    """
    paired = pair_device(client)
    approval = _create(client, action_id="act_denied", risk_family=REFUSED_FAMILY)

    response = signed_request(
        client,
        "POST",
        f"/v1/approvals/{approval['approval_id']}/deny",
        private_key=paired["private_key"],
        device_id=paired["device"]["device_id"],
    )
    assert response.status_code == 200
    assert response.json()["state"] == "denied"
    assert response.json()["applied_scope"] == "once"

    detail = signed_request(
        client,
        "GET",
        f"/v1/approvals/{approval['approval_id']}",
        private_key=paired["private_key"],
        device_id=paired["device"]["device_id"],
    ).json()
    assert detail["decision_scope"] == "once"


def test_auto_satisfaction_records_the_grant_scope_it_really_used(
    client: TestClient,
) -> None:
    """A standing grant clearing a later request applies a REAL scope.

    Nobody requested one, so `requested_scope` stays null — the row says "this
    was not asked for, it was granted earlier", which is exactly right.
    """
    paired = pair_device(client)
    first = _create(client, action_id="act_auto_1", risk_family=GRANTABLE_FAMILY)
    _decide(client, paired, first, "session")

    second = _create(client, action_id="act_auto_2", risk_family=GRANTABLE_FAMILY)
    assert second["state"] == "approved"
    assert second["decision_scope"] == "session"
    assert second["requested_scope"] is None

"""
Characterization tests for ACT's current clearance-contract behavior.

These tests lock down the current state of:
- ApprovalRequest JSON shape (no provenance/risk-vector fields)
- RiskLevel as scalar only
- Single-phase resolve transition
- Intervention returns not_executed_placeholder
- Current channel policy (single decision endpoint behavior)

Purpose: Ensure 5 additive changes prove backward-compatibility without breaking
these fundamental contracts.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient

from conftest import pair_device, signed_request


class TestApprovalRequestShape:
    """Verify ApprovalRequest JSON shape has no provenance or risk-vector fields."""

    def test_approval_request_has_required_scalar_fields(self, client: TestClient) -> None:
        """ApprovalRequest must have: approval_id, action_id, node_id, agent_id, session_id, requested_tool, risk_level (scalar), summary, full_payload_redacted, state, expires_at, options."""
        approval = create_approval(client, action_id="act_shape_1")

        # Verify it's a scalar risk_level, not an object with provenance
        assert isinstance(approval["risk_level"], str)
        assert approval["risk_level"] in ["low", "medium", "high", "critical"]

        # Verify required top-level fields exist
        required_fields = {
            "approval_id",
            "action_id",
            "node_id",
            "agent_id",
            "session_id",
            "requested_tool",
            "risk_level",
            "summary",
            "full_payload_redacted",
            "state",
            "expires_at",
            "options",
        }
        assert required_fields.issubset(set(approval.keys()))

    def test_approval_request_includes_seam_contract_fields(
        self, client: TestClient
    ) -> None:
        """Contract evolution — BrowserBridge seam landed (was: this test pinned
        the ABSENCE of risk_vector/provenance). ApprovalRequest now carries the
        additive risk_vector + authority-provenance fields; they are present and
        default-safe (None/None/False) on a fresh pending approval, so existing
        consumers that ignore unknown fields are unaffected."""
        approval = create_approval(client, action_id="act_shape_2")

        assert "risk_vector" in approval and approval["risk_vector"] is None
        assert "approved_by" in approval and approval["approved_by"] is None
        assert "human_approved" in approval and approval["human_approved"] is False

    def test_approval_request_excludes_multi_phase_fields(
        self, client: TestClient
    ) -> None:
        """Approval JSON must NOT contain multi-phase fields like phases or phase_id."""
        approval = create_approval(client, action_id="act_shape_3")

        forbidden_fields = {"phases", "phase_id", "current_phase", "phase_state"}
        assert not forbidden_fields.intersection(set(approval.keys()))

    def test_approval_optional_fields_present(self, client: TestClient) -> None:
        """Approval may have optional fields: risk_category, resource_scope, decision_scope, decided_at, decision_metadata."""
        approval = create_approval(
            client,
            action_id="act_shape_4",
            risk_category="system_integrity",
            resource_scope="root_level",
        )

        # Optional fields may be None or present
        optional_fields = {
            "risk_category",
            "resource_scope",
            "decision_scope",
            "decided_at",
            "decision_metadata",
        }
        found_optional = optional_fields.intersection(set(approval.keys()))
        assert len(found_optional) > 0  # At least some present

    def test_approval_full_payload_redacted_is_dict(self, client: TestClient) -> None:
        """full_payload_redacted must be a dict, not nested provenance object."""
        approval = create_approval(client, action_id="act_shape_5")

        assert isinstance(approval["full_payload_redacted"], dict)
        assert "command" in approval["full_payload_redacted"]


class TestRiskLevelScalarOnly:
    """Verify risk_level is a scalar (string literal), not an object or array."""

    def test_risk_level_is_string_literal_low(self, client: TestClient) -> None:
        response = client.post(
            "/v1/approvals",
            json={
                "action_id": "act_risk_low",
                "agent_id": "agent_mock",
                "session_id": "sess_mock",
                "requested_tool": "read_file",
                "risk_level": "low",
                "risk_family": "read_only",
                "summary": "Read a config file",
                "full_payload_redacted": {"file": "redacted"},
                "expires_at": future_time(3600),
            },
        )
        assert response.status_code == 201
        approval = response.json()
        assert approval["risk_level"] == "low"
        assert isinstance(approval["risk_level"], str)

    def test_risk_level_is_string_literal_medium(self, client: TestClient) -> None:
        approval = create_approval(client, action_id="act_risk_medium", risk_level="medium")
        assert approval["risk_level"] == "medium"
        assert isinstance(approval["risk_level"], str)

    def test_risk_level_is_string_literal_high(self, client: TestClient) -> None:
        approval = create_approval(client, action_id="act_risk_high", risk_level="high")
        assert approval["risk_level"] == "high"
        assert isinstance(approval["risk_level"], str)

    def test_risk_level_is_string_literal_critical(self, client: TestClient) -> None:
        approval = create_approval(
            client, action_id="act_risk_critical", risk_level="critical"
        )
        assert approval["risk_level"] == "critical"
        assert isinstance(approval["risk_level"], str)

    def test_risk_level_not_an_object(self, client: TestClient) -> None:
        """risk_level must not be an object with nested fields."""
        approval = create_approval(client, action_id="act_risk_not_obj")
        # If it were an object, this assertion would fail
        assert not isinstance(approval["risk_level"], dict)
        assert not isinstance(approval["risk_level"], list)


class TestSinglePhaseResolve:
    """Verify approval resolution is single-phase: pending -> {approved|denied|expired|cancelled}."""

    def test_approval_initial_state_pending(self, client: TestClient) -> None:
        """New approval starts in pending state."""
        approval = create_approval(client, action_id="act_phase_init")
        assert approval["state"] == "pending"

    def test_resolve_approval_single_transition_approve_once(
        self, client: TestClient
    ) -> None:
        """Approval resolves in single step: pending -> approved."""
        paired = pair_device(client)
        approval = create_approval(client, action_id="act_phase_single_approve")

        response = signed_request(
            client,
            "POST",
            f"/v1/approvals/{approval['approval_id']}/approve_once",
            private_key=paired["private_key"],
            device_id=paired["device"]["device_id"],
        )

        assert response.status_code == 200
        result = response.json()
        assert result["state"] == "approved"
        assert result["applied_scope"] == "once"

        # Verify no intermediate phases were recorded
        detail = signed_request(
            client,
            "GET",
            f"/v1/approvals/{approval['approval_id']}",
            private_key=paired["private_key"],
            device_id=paired["device"]["device_id"],
        )
        assert detail.status_code == 200
        detail_json = detail.json()
        assert detail_json["state"] == "approved"
        # No "current_phase" or "phases" field
        assert "current_phase" not in detail_json
        assert "phases" not in detail_json

    def test_resolve_approval_single_transition_deny(self, client: TestClient) -> None:
        """Approval resolves in single step: pending -> denied."""
        paired = pair_device(client)
        approval = create_approval(client, action_id="act_phase_single_deny")

        response = signed_request(
            client,
            "POST",
            f"/v1/approvals/{approval['approval_id']}/deny",
            private_key=paired["private_key"],
            device_id=paired["device"]["device_id"],
        )

        assert response.status_code == 200
        result = response.json()
        assert result["state"] == "denied"

    def test_resolve_approval_single_transition_expire(self, client: TestClient) -> None:
        """Approval resolves in single step: pending -> expired."""
        paired = pair_device(client)
        approval = create_approval(client, action_id="act_phase_single_expire")

        response = signed_request(
            client,
            "POST",
            f"/v1/approvals/{approval['approval_id']}/expire",
            private_key=paired["private_key"],
            device_id=paired["device"]["device_id"],
        )

        assert response.status_code == 200
        result = response.json()
        assert result["state"] == "expired"

    def test_resolve_approval_single_transition_cancel(self, client: TestClient) -> None:
        """Approval resolves in single step: pending -> cancelled."""
        paired = pair_device(client)
        approval = create_approval(client, action_id="act_phase_single_cancel")

        response = signed_request(
            client,
            "POST",
            f"/v1/approvals/{approval['approval_id']}/cancel",
            private_key=paired["private_key"],
            device_id=paired["device"]["device_id"],
        )

        assert response.status_code == 200
        result = response.json()
        assert result["state"] == "cancelled"

    def test_no_valid_transition_from_approved(self, client: TestClient) -> None:
        """Once resolved, approval cannot transition to another state."""
        paired = pair_device(client)
        approval = create_approval(client, action_id="act_phase_no_retrans")

        # Transition to approved
        first = signed_request(
            client,
            "POST",
            f"/v1/approvals/{approval['approval_id']}/approve_once",
            private_key=paired["private_key"],
            device_id=paired["device"]["device_id"],
        )
        assert first.status_code == 200
        assert first.json()["state"] == "approved"

        # Attempt second transition should fail
        second = signed_request(
            client,
            "POST",
            f"/v1/approvals/{approval['approval_id']}/deny",
            private_key=paired["private_key"],
            device_id=paired["device"]["device_id"],
        )
        assert second.status_code == 409
        assert "not pending" in second.json()["detail"]


class TestInterventionPlaceholder:
    """Contract evolution — panic dominance landed (was: this class pinned the
    intervention stub returning 'not_executed_placeholder'). Non-emergency
    interventions are now durably 'queued' (drained by hermes-local at the
    agent's next tool boundary — mobile-beta intervention queue); emergency
    interventions are 'approvals_invalidated' (they bulk-invalidate
    clearances — see TestPanicDominance for the invalidation proof)."""

    def test_intervention_non_emergency_is_queued(
        self, client: TestClient
    ) -> None:
        """A non-emergency intervention (pause) is durably queued."""
        paired = pair_device(client)

        response = signed_request(
            client,
            "POST",
            "/v1/sessions/sess_mock/interventions",
            private_key=paired["private_key"],
            device_id=paired["device"]["device_id"],
            json_body={
                "intervention_id": "int_test_1",
                "type": "pause",
                "reason": "test pause",
                "signed_payload": {"type": "pause", "reason": "test"},
                "signature": "sig_test",
            },
        )

        assert response.status_code == 200
        result = response.json()
        assert result["intervention_id"] == "int_test_1"
        assert result["resulting_state"] == "queued"

    def test_intervention_types_have_expected_resulting_state(
        self, client: TestClient
    ) -> None:
        """Emergency types invalidate approvals; the rest are durably queued."""
        paired = pair_device(client)
        emergency = {
            "cancel_task",
            "kill_task",
            "kill_agent",
            "quarantine_agent",
            "emergency_stop",
        }
        intervention_types = [
            "pause",
            "resume",
            "inject_instruction",
            *sorted(emergency),
        ]

        for intervention_type in intervention_types:
            response = signed_request(
                client,
                "POST",
                "/v1/sessions/sess_mock/interventions",
                private_key=paired["private_key"],
                device_id=paired["device"]["device_id"],
                json_body={
                    "intervention_id": f"int_test_{intervention_type}",
                    "type": intervention_type,
                    "reason": f"test {intervention_type}",
                    "signed_payload": {"type": intervention_type},
                    "signature": "sig_test",
                },
            )

            assert response.status_code == 200
            result = response.json()
            expected = (
                "approvals_invalidated"
                if intervention_type in emergency
                else "queued"
            )
            assert result["resulting_state"] == expected


class TestCurrentChannelPolicy:
    """Verify current approval decision channel behavior (single-endpoint policy)."""

    def test_approve_once_endpoint_creates_approved_state_with_once_scope(
        self, client: TestClient
    ) -> None:
        """POST /v1/approvals/{id}/approve_once creates approved state with scope=once."""
        paired = pair_device(client)
        approval = create_approval(client, action_id="act_channel_once")

        response = signed_request(
            client,
            "POST",
            f"/v1/approvals/{approval['approval_id']}/approve_once",
            private_key=paired["private_key"],
            device_id=paired["device"]["device_id"],
        )

        assert response.status_code == 200
        result = response.json()
        assert result["state"] == "approved"
        assert result["applied_scope"] == "once"

    def test_decisions_endpoint_records_arbitrary_scope(self, client: TestClient) -> None:
        """POST /v1/approvals/{id}/decisions records requested scope."""
        paired = pair_device(client)
        approval = create_approval(client, action_id="act_channel_decisions")

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
        result = response.json()
        assert result["state"] == "approved"
        assert result["applied_scope"] == "session"

    def test_deny_endpoint_creates_denied_state(self, client: TestClient) -> None:
        """POST /v1/approvals/{id}/deny creates denied state."""
        paired = pair_device(client)
        approval = create_approval(client, action_id="act_channel_deny")

        response = signed_request(
            client,
            "POST",
            f"/v1/approvals/{approval['approval_id']}/deny",
            private_key=paired["private_key"],
            device_id=paired["device"]["device_id"],
        )

        assert response.status_code == 200
        result = response.json()
        assert result["state"] == "denied"
        # Deny always has scope "once" in current policy
        assert result["applied_scope"] == "once"

    def test_option_list_defaults_to_approve_once_and_deny(
        self, client: TestClient
    ) -> None:
        """If no options specified, defaults to ['approve_once', 'deny']."""
        response = client.post(
            "/v1/approvals",
            json={
                "action_id": "act_channel_options",
                "agent_id": "agent_mock",
                "session_id": "sess_mock",
                "requested_tool": "shell",
                "risk_level": "high",
                "risk_family": "external_effect",
                "summary": "Run a command",
                "full_payload_redacted": {"command": "redacted"},
                "expires_at": future_time(3600),
                # No options specified
            },
        )
        assert response.status_code == 201
        approval = response.json()
        assert approval["options"] == ["approve_once", "deny"]

    def test_hermes_approval_status_endpoint_current_contract(
        self, client: TestClient
    ) -> None:
        """Hermes tool endpoint returns ApprovalStatusResponse with current contract fields."""
        approval = create_approval(client, action_id="act_hermes_status")

        # Call hermes tool endpoint
        response = client.post(
            "/v1/hermes/tools/approval_status",
            json={"approval_id": approval["approval_id"]},
        )

        assert response.status_code == 200
        status_response = response.json()
        # Should have these fields:
        assert "approval_id" in status_response
        assert "state" in status_response
        assert status_response["approval_id"] == approval["approval_id"]
        assert status_response["state"] == "pending"
        # selected_scope should be None for pending
        assert status_response.get("selected_scope") is None
        # decided_at should be None for pending
        assert status_response.get("decided_at") is None


class TestApprovalOptionsField:
    """Verify options field behavior (list of approval action strings)."""

    def test_options_is_list_of_strings(self, client: TestClient) -> None:
        """options field must be a list of strings."""
        approval = create_approval(client, action_id="act_options_list")

        assert isinstance(approval["options"], list)
        assert all(isinstance(opt, str) for opt in approval["options"])

    def test_options_are_valid_decision_types(self, client: TestClient) -> None:
        """options must be valid decision types like 'approve_once', 'deny', etc."""
        valid_decision_types = {
            "approve_once",
            "approve_session",
            "approve_agent",
            "deny",
            "modified",
            "needs_info",
            "propose_policy",
        }
        approval = create_approval(client, action_id="act_options_valid")

        assert all(opt in valid_decision_types for opt in approval["options"])


class TestDecisionMetadataField:
    """Verify decision_metadata field behavior."""

    def test_decision_metadata_empty_dict_before_resolution(
        self, client: TestClient
    ) -> None:
        """Before resolution, decision_metadata should be empty dict or None."""
        approval = create_approval(client, action_id="act_meta_empty")

        metadata = approval.get("decision_metadata")
        assert metadata is None or metadata == {}

    def test_decision_metadata_after_approval(self, client: TestClient) -> None:
        """After approval, decision_metadata records decision info."""
        paired = pair_device(client)
        approval = create_approval(client, action_id="act_meta_approved")

        # Approve the request
        signed_request(
            client,
            "POST",
            f"/v1/approvals/{approval['approval_id']}/approve_once",
            private_key=paired["private_key"],
            device_id=paired["device"]["device_id"],
        )

        # Get approval details
        detail = signed_request(
            client,
            "GET",
            f"/v1/approvals/{approval['approval_id']}",
            private_key=paired["private_key"],
            device_id=paired["device"]["device_id"],
        )
        assert detail.status_code == 200
        approved = detail.json()

        # decision_metadata should be a dict (may be empty per current contract)
        assert isinstance(approved.get("decision_metadata", {}), dict)


class TestApprovalAuditAndEvents:
    """Verify approval operations create audit events and events."""

    def test_approval_creation_recorded_in_store(self, client: TestClient) -> None:
        """Approval creation must be persisted in store."""
        approval = create_approval(client, action_id="act_audit_create")

        # Retrieve the approval
        paired = pair_device(client)
        response = signed_request(
            client,
            "GET",
            f"/v1/approvals/{approval['approval_id']}",
            private_key=paired["private_key"],
            device_id=paired["device"]["device_id"],
        )

        assert response.status_code == 200
        fetched = response.json()
        assert fetched["approval_id"] == approval["approval_id"]

    def test_approval_decision_creates_audit_event(self, client: TestClient) -> None:
        """Approval decisions create audit_event with event_type='approval_decision'."""
        paired = pair_device(client)
        approval = create_approval(client, action_id="act_audit_decision")

        # Make a decision
        signed_request(
            client,
            "POST",
            f"/v1/approvals/{approval['approval_id']}/approve_once",
            private_key=paired["private_key"],
            device_id=paired["device"]["device_id"],
        )

        # Check audit events
        response = signed_request(
            client,
            "GET",
            "/v1/audit/events?event_type=approval_decision",
            private_key=paired["private_key"],
            device_id=paired["device"]["device_id"],
        )

        assert response.status_code == 200
        audit_events = response.json()["audit_events"]
        assert len(audit_events) > 0


# Helper functions


def create_approval(
    client: TestClient,
    *,
    action_id: str,
    risk_level: str = "high",
    risk_category: str | None = None,
    resource_scope: str | None = None,
    expires_at: str | None = None,
) -> dict:
    """Create an approval request."""
    payload = {
        "action_id": action_id,
        "agent_id": "agent_mock",
        "session_id": "sess_mock",
        "requested_tool": "shell",
        "risk_level": risk_level,
        # The tower requires an explicit risk-family declaration (422 without
        # one); "external_effect" is the conservative (mobile-mandatory) family.
        "risk_family": "external_effect",
        "summary": "Run a command",
        "full_payload_redacted": {"command": "redacted"},
        "expires_at": expires_at or future_time(3600),
    }
    if risk_category is not None:
        payload["risk_category"] = risk_category
    if resource_scope is not None:
        payload["resource_scope"] = resource_scope

    response = client.post("/v1/approvals", json=payload)
    assert response.status_code == 201
    return response.json()


def decision_body(
    *,
    approval_id: str,
    decision: str,
    scope: str,
    params_fingerprint: str | None = None,
) -> dict:
    """Create approval decision request body.

    The /decisions endpoint requires the signed payload to bind the approval's
    ``params_fingerprint`` (clearance-binding verification; 400 on mismatch)."""
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


def future_time(seconds: int = 3600) -> str:
    """Generate a future ISO timestamp."""
    future = datetime.utcnow() + timedelta(seconds=seconds)
    return future.strftime("%Y-%m-%dT%H:%M:%SZ")

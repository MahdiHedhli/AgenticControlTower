from __future__ import annotations

from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from conftest import b64url, pair_device, signed_request
from hermes_gateway.app import create_app
from hermes_gateway.config import Settings


def test_low_risk_action_clears_from_local_terminal_when_enabled(tmp_path: Path) -> None:
    with _policy_client(tmp_path, local_enabled=True) as client:
        _set_agent_trust(client, "trusted_host")
        approval = _create_approval(client, risk_family="read_only", risk_level="low")

        response = _local_decision(client, approval["approval_id"], decision="approve")

        assert response.status_code == 200
        assert response.json()["state"] == "approved"
        detail = client.app.state.store.get_approval(approval["approval_id"])
        assert detail["decision_metadata"]["channel"] == "local_terminal"
        assert detail["decision_metadata"]["risk_family"] == "read_only"


def test_low_risk_action_clears_from_mobile(tmp_path: Path) -> None:
    with _policy_client(tmp_path, local_enabled=True) as client:
        paired = pair_device(client)
        approval = _create_approval(client, risk_family="routine", risk_level="low")

        response = signed_request(
            client,
            "POST",
            f"/v1/approvals/{approval['approval_id']}/approve_once",
            private_key=paired["private_key"],
            device_id=paired["device"]["device_id"],
        )

        assert response.status_code == 200
        detail = client.app.state.store.get_approval(approval["approval_id"])
        assert detail["decision_metadata"]["channel"] == "mobile_signed"


def test_high_risk_action_rejects_local_terminal_in_both_mode(tmp_path: Path) -> None:
    with _policy_client(tmp_path, local_enabled=True) as client:
        _set_agent_trust(client, "trusted_host")
        approval = _create_approval(
            client,
            risk_family="external_effect",
            risk_level="high",
        )

        response = _local_decision(client, approval["approval_id"], decision="approve")

        assert response.status_code == 403
        assert response.json()["detail"] == "channel_not_eligible_for_risk_family"
        assert client.app.state.store.get_approval(approval["approval_id"])["state"] == "pending"
        assert _audit_payloads(client, "clearance_channel_rejected")[0]["risk_family"] == (
            "external_effect"
        )


def test_high_risk_action_clears_from_mobile_in_both_mode(tmp_path: Path) -> None:
    with _policy_client(tmp_path, local_enabled=True) as client:
        paired = pair_device(client)
        approval = _create_approval(
            client,
            risk_family="credential_or_secret",
            risk_level="critical",
        )

        response = signed_request(
            client,
            "POST",
            f"/v1/approvals/{approval['approval_id']}/approve_once",
            private_key=paired["private_key"],
            device_id=paired["device"]["device_id"],
        )

        assert response.status_code == 200
        detail = client.app.state.store.get_approval(approval["approval_id"])
        assert detail["decision_metadata"]["channel"] == "mobile_signed"
        assert detail["decision_metadata"]["risk_family"] == "credential_or_secret"


def test_untrusted_host_rejects_all_local_terminal_clearances(tmp_path: Path) -> None:
    with _policy_client(tmp_path, local_enabled=True) as client:
        _set_agent_trust(client, "untrusted_host")
        approval = _create_approval(client, risk_family="read_only", risk_level="low")

        response = _local_decision(client, approval["approval_id"], decision="approve")

        assert response.status_code == 403
        assert response.json()["detail"] == "local_terminal_disabled_for_trust_context"
        payload = _audit_payloads(client, "clearance_channel_rejected")[0]
        assert payload["deployment_trust_context"] == "untrusted_host"


def test_mobile_still_clears_for_untrusted_host(tmp_path: Path) -> None:
    with _policy_client(tmp_path, local_enabled=True) as client:
        paired = pair_device(client)
        _set_agent_trust(client, "untrusted_host")
        approval = _create_approval(client, risk_family="destructive", risk_level="high")

        response = signed_request(
            client,
            "POST",
            f"/v1/approvals/{approval['approval_id']}/approve_once",
            private_key=paired["private_key"],
            device_id=paired["device"]["device_id"],
        )

        assert response.status_code == 200
        detail = client.app.state.store.get_approval(approval["approval_id"])
        assert detail["decision_metadata"]["deployment_trust_context"] == "untrusted_host"


def test_rejected_channel_is_audited_without_marking_approved(tmp_path: Path) -> None:
    with _policy_client(tmp_path, local_enabled=True) as client:
        _set_agent_trust(client, "trusted_host")
        approval = _create_approval(client, risk_family="irreversible", risk_level="critical")

        response = _local_decision(client, approval["approval_id"], decision="approve")

        assert response.status_code == 403
        assert client.app.state.store.get_approval(approval["approval_id"])["state"] == "pending"
        payload = _audit_payloads(client, "clearance_channel_rejected")[0]
        assert payload["channel"] == "local_terminal"
        assert payload["eligibility_result"] == "rejected"


def test_every_issued_clearance_records_channel_and_risk_family(tmp_path: Path) -> None:
    with _policy_client(tmp_path, local_enabled=True) as client:
        _set_agent_trust(client, "trusted_host")
        approval = _create_approval(client, risk_family="routine", risk_level="low")

        response = _local_decision(client, approval["approval_id"], decision="deny")

        assert response.status_code == 200
        payload = _audit_payloads(client, "approval_decision")[0]
        assert payload["channel"] == "local_terminal"
        assert payload["risk_family"] == "routine"


def test_both_mode_cannot_start_without_risk_tier_map(tmp_path: Path) -> None:
    settings = _settings(
        tmp_path,
        clearance_enabled_channels=("mobile_signed", "local_terminal"),
        clearance_local_terminal_enabled=True,
        clearance_risk_channel_map={},
    )

    with pytest.raises(ValueError, match="requires risk-tier map"):
        create_app(settings)


def test_aircraft_cannot_override_channel_rules(tmp_path: Path) -> None:
    with _policy_client(tmp_path, local_enabled=True) as client:
        response = client.post(
            "/v1/approvals",
            json=_approval_payload(risk_family="destructive", risk_level="high")
            | {"channel_eligibility": {"destructive": ["local_terminal"]}},
        )

        assert response.status_code == 422


def test_deployment_trust_context_is_tower_configured_not_request_supplied(
    tmp_path: Path,
) -> None:
    with _policy_client(tmp_path, local_enabled=True) as client:
        _set_agent_trust(client, "untrusted_host")
        response = client.post(
            "/v1/approvals",
            json=_approval_payload(risk_family="read_only", risk_level="low")
            | {"deployment_trust_context": "trusted_host"},
        )

        assert response.status_code == 422


def test_request_policy_override_attempt_is_rejected(tmp_path: Path) -> None:
    with _policy_client(tmp_path, local_enabled=True) as client:
        response = client.post(
            "/v1/approvals",
            json=_approval_payload(risk_family="read_only", risk_level="low")
            | {
                "deployment_trust_context": "adversarial_host",
                "channel_eligibility": {"read_only": ["local_terminal"]},
            },
        )

        assert response.status_code == 422


def test_request_without_risk_family_rejected(tmp_path: Path) -> None:
    with _policy_client(tmp_path, local_enabled=True) as client:
        payload = _approval_payload(risk_family="read_only", risk_level="low")
        payload.pop("risk_family")

        response = client.post("/v1/approvals", json=payload)

        assert response.status_code == 422


def test_local_terminal_requires_registered_signed_principal(tmp_path: Path) -> None:
    with _policy_client(tmp_path, local_enabled=True) as client:
        approval = _create_approval(client, risk_family="read_only", risk_level="low")
        unknown_key = Ed25519PrivateKey.generate()

        response = signed_request(
            client,
            "POST",
            f"/v1/local-terminal/approvals/{approval['approval_id']}/decisions",
            private_key=unknown_key,
            device_id="dev_unregistered_terminal",
            json_body={"decision": "approve", "scope": "once"},
        )

        assert response.status_code == 401
        assert response.json()["detail"] == "unknown device"


def test_operator_setter_changes_aircraft_trust_context_and_audits(
    tmp_path: Path,
) -> None:
    with _policy_client(tmp_path, local_enabled=True) as client:
        _set_agent_trust(client, "untrusted_host")
        operator = pair_device(client, requested_permissions=["read_state", "manage_devices"])

        response = signed_request(
            client,
            "PATCH",
            "/v1/agents/agent_policy/deployment-trust-context?node_id=node_policy",
            private_key=operator["private_key"],
            device_id=operator["device"]["device_id"],
            json_body={"deployment_trust_context": "trusted_host"},
        )

        assert response.status_code == 200
        assert response.json()["deployment_trust_context"] == "trusted_host"
        payload = _audit_payloads(client, "agent_trust_context_updated")[0]
        assert payload == {"old": "untrusted_host", "new": "trusted_host"}


def test_aircraft_and_loopback_caller_cannot_set_trust_context(tmp_path: Path) -> None:
    with _policy_client(tmp_path, local_enabled=True) as client:
        _set_agent_trust(client, "untrusted_host")
        no_permission = pair_device(client, requested_permissions=["read_state", "approve"])

        unsigned = client.patch(
            "/v1/agents/agent_policy/deployment-trust-context?node_id=node_policy",
            json={"deployment_trust_context": "trusted_host"},
        )
        signed_without_permission = signed_request(
            client,
            "PATCH",
            "/v1/agents/agent_policy/deployment-trust-context?node_id=node_policy",
            private_key=no_permission["private_key"],
            device_id=no_permission["device"]["device_id"],
            json_body={"deployment_trust_context": "trusted_host"},
        )

        assert unsigned.status_code == 401
        assert signed_without_permission.status_code == 403
        assert client.app.state.store.get_agent("node_policy", "agent_policy")[
            "deployment_trust_context"
        ] == "untrusted_host"


def test_config_cannot_downgrade_a_mobile_mandatory_family(tmp_path: Path) -> None:
    """The channel policy has one canonical answer for both of its inputs.

    ``MOBILE_MANDATORY_RISK_FAMILIES`` is that canonical policy: configuration may
    tighten it but must never relax it. An operator-supplied risk-channel map that
    hands ``external_effect`` to the local terminal is therefore still refused —
    the decision path consults ``required_channels_for_request`` (the same entry
    point the standing-grant gate uses), not just the configurable tier map.
    """
    downgraded = dict(Settings.default_clearance_risk_channel_map)
    downgraded["external_effect"] = ("mobile_signed", "local_terminal")
    settings = _settings(
        tmp_path,
        clearance_enabled_channels=("mobile_signed", "local_terminal"),
        clearance_local_terminal_enabled=True,
        clearance_risk_channel_map=downgraded,
    )
    with TestClient(create_app(settings), client=("127.0.0.1", 50000)) as client:
        _set_agent_trust(client, "trusted_host")
        approval = _create_approval(
            client, risk_family="external_effect", risk_level="high"
        )

        response = _local_decision(client, approval["approval_id"], decision="approve")

        assert response.status_code == 403
        stored = client.app.state.store.get_approval(approval["approval_id"])
        assert stored["state"] == "pending"
        rejections = _audit_payloads(client, "approval_channel_rejected")
        assert rejections and rejections[0]["required_channels"] == ["mobile_signed"]


def _policy_client(tmp_path: Path, *, local_enabled: bool) -> TestClient:
    return TestClient(
        create_app(
            _settings(
                tmp_path,
                clearance_enabled_channels=("mobile_signed", "local_terminal")
                if local_enabled
                else ("mobile_signed",),
                clearance_local_terminal_enabled=local_enabled,
            )
        ),
        client=("127.0.0.1", 50000),
    )


def _settings(tmp_path: Path, **overrides: object) -> Settings:
    values: dict[str, object] = {
        "node_id": "node_policy",
        "node_display_name": "Policy Test Tower",
        "node_fingerprint": "policy-test-fingerprint",
        "gateway_base_url": "http://127.0.0.1:8787/v1",
        "database_path": str(tmp_path / "gateway.sqlite3"),
        "pairing_ttl_seconds": 60,
        "clearance_risk_channel_map": dict(Settings.default_clearance_risk_channel_map),
    }
    values.update(overrides)
    return Settings(**values)


def _create_approval(
    client: TestClient,
    *,
    risk_family: str,
    risk_level: str,
) -> dict:
    response = client.post(
        "/v1/approvals",
        json=_approval_payload(
            risk_family=risk_family,
            risk_level=risk_level,
        ),
    )
    assert response.status_code == 201
    return response.json()


def _approval_payload(
    *,
    risk_family: str,
    risk_level: str,
) -> dict:
    return {
        "action_id": f"act_{risk_family}",
        "agent_id": "agent_policy",
        "session_id": "work_policy",
        "requested_tool": "generic_operation",
        "risk_level": risk_level,
        "risk_family": risk_family,
        "summary": "Generic clearance request.",
        "full_payload_redacted": {"operation": "redacted"},
        "expires_at": "2099-01-01T00:00:00Z",
    }


def _local_decision(client: TestClient, approval_id: str, *, decision: str) -> object:
    terminal = _terminal_principal(client)
    return signed_request(
        client,
        "POST",
        f"/v1/local-terminal/approvals/{approval_id}/decisions",
        private_key=terminal["private_key"],
        device_id=terminal["device"]["device_id"],
        json_body={
            "decision": decision,
            "scope": "once",
        },
    )


def _terminal_principal(client: TestClient) -> dict:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    device = client.app.state.store.create_device(
        node_id="node_policy",
        device_name="Terminal",
        platform="local_terminal",
        app_instance_id=f"terminal-{id(private_key)}",
        app_version="0.1.0",
        device_public_key=b64url(public_key),
        permissions=["read_state", "approve"],
        clearance_channel="local_terminal",
    )
    return {"device": device, "private_key": private_key}


def _set_agent_trust(client: TestClient, trust_context: str) -> None:
    client.app.state.store.upsert_agent(
        {
            "node_id": "node_policy",
            "agent_id": "agent_policy",
            "display_name": "Policy Test Agent",
            "status": "idle",
            "deployment_trust_context": trust_context,
        }
    )


def _audit_payloads(client: TestClient, event_type: str) -> list[dict]:
    return [
        event["payload_redacted"]
        for event in client.app.state.store.list_audit_events(event_type=event_type)
    ]

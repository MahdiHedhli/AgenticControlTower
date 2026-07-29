from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from fastapi import HTTPException, status

from .config import Settings
from .ids import new_id
from .notification_composer import compose_notification
from .schemas import MobileNotifyRequest
from .store import SQLiteStore

UNKNOWN_CAPABILITY_RISK_FAMILY = "external_effect"


@dataclass(frozen=True)
class CapabilityRiskResolution:
    capability: str | None
    aircraft: str
    requested_risk_family: str
    resolved_risk_family: str
    source: str
    registry_entry_id: str | None = None


def aircraft_principal(*, node_id: str, agent_id: str) -> str:
    return f"{node_id}:{agent_id}"


def capability_from_request(
    *,
    capability: str | None,
    extensions: dict[str, dict[str, Any]] | None,
) -> tuple[str | None, bool]:
    if capability:
        return capability, False
    agentickvm = (extensions or {}).get("agentickvm") or {}
    extension_capability = agentickvm.get("capability")
    if isinstance(extension_capability, str) and extension_capability:
        return extension_capability, True
    return None, False


def resolve_capability_risk(
    *,
    store: SQLiteStore,
    settings: Settings,
    node_id: str,
    agent_id: str,
    session_id: str,
    capability: str | None,
    requested_risk_family: str,
    request_id: str,
    actor_type: str,
    actor_id: str,
) -> CapabilityRiskResolution:
    aircraft = aircraft_principal(node_id=node_id, agent_id=agent_id)
    if capability is None:
        return CapabilityRiskResolution(
            capability=None,
            aircraft=aircraft,
            requested_risk_family=requested_risk_family,
            resolved_risk_family=requested_risk_family,
            source="legacy_no_capability",
        )

    approved = store.get_approved_capability_risk(
        node_id=node_id,
        agent_id=agent_id,
        capability=capability,
    )
    if approved:
        pinned = approved["risk_family"]
        if requested_risk_family != pinned:
            severity = (
                "security"
                if _risk_rank(requested_risk_family) < _risk_rank(pinned)
                else "drift"
            )
            _alert_capability_registry(
                store=store,
                settings=settings,
                node_id=node_id,
                agent_id=agent_id,
                session_id=session_id,
                request_id=request_id,
                actor_type=actor_type,
                actor_id=actor_id,
                event_type="capability_risk_mismatch",
                capability=capability,
                requested_risk_family=requested_risk_family,
                resolved_risk_family=pinned,
                severity=severity,
            )
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                "capability_risk_mismatch",
            )
        return CapabilityRiskResolution(
            capability=capability,
            aircraft=aircraft,
            requested_risk_family=requested_risk_family,
            resolved_risk_family=pinned,
            source="approved_pin",
            registry_entry_id=approved["entry_id"],
        )

    require_classified = False
    try:
        require_classified = bool(
            store.get_agent(node_id, agent_id).get("require_classified_capabilities")
        )
    except KeyError:
        pass
    _alert_capability_registry(
        store=store,
        settings=settings,
        node_id=node_id,
        agent_id=agent_id,
        session_id=session_id,
        request_id=request_id,
        actor_type=actor_type,
        actor_id=actor_id,
        event_type="capability_unclassified",
        capability=capability,
        requested_risk_family=requested_risk_family,
        resolved_risk_family=UNKNOWN_CAPABILITY_RISK_FAMILY,
        severity="classify",
    )
    if require_classified:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "capability_unclassified",
        )
    return CapabilityRiskResolution(
        capability=capability,
        aircraft=aircraft,
        requested_risk_family=requested_risk_family,
        resolved_risk_family=UNKNOWN_CAPABILITY_RISK_FAMILY,
        source="unclassified_fail_closed",
    )


def create_capability_alert_notification(
    *,
    store: SQLiteStore,
    settings: Settings,
    node_id: str,
    agent_id: str,
    session_id: str,
    request_id: str,
    event_type: str,
    capability: str,
    requested_risk_family: str,
    resolved_risk_family: str,
    severity: str,
) -> None:
    _alert_capability_registry(
        store=store,
        settings=settings,
        node_id=node_id,
        agent_id=agent_id,
        session_id=session_id,
        request_id=request_id,
        actor_type="gateway",
        actor_id="gateway",
        event_type=event_type,
        capability=capability,
        requested_risk_family=requested_risk_family,
        resolved_risk_family=resolved_risk_family,
        severity=severity,
    )


def _alert_capability_registry(
    *,
    store: SQLiteStore,
    settings: Settings,
    node_id: str,
    agent_id: str,
    session_id: str,
    request_id: str,
    actor_type: str,
    actor_id: str,
    event_type: str,
    capability: str,
    requested_risk_family: str,
    resolved_risk_family: str,
    severity: str,
) -> None:
    composed = compose_notification(
        MobileNotifyRequest(
            title="Capability registry alert",
            body="Capability registry requires operator review.",
            urgency="high" if severity == "security" else "normal",
            category="security_alert",
            agent_id=agent_id,
            session_id=session_id,
            backend_display_name=settings.node_display_name,
            subject_display_name=agent_id,
            risk_family=resolved_risk_family,
            operation_label=capability,
        )
    )
    notification = store.create_notification(
        {
            "notification_id": new_id("ntf"),
            "node_id": node_id,
            "agent_id": agent_id,
            "session_id": session_id,
            "category": "security_alert",
            "urgency": "high" if severity == "security" else "normal",
            "title_safe": composed.title,
            "body_safe": composed.body,
            "composition_mode": composed.mode,
            "unsafe_input_detected": composed.unsafe_input_detected,
            "state": "queued",
        }
    )
    payload = {
        "capability": composed.safe_fields["operation_label"],
        "capability_supplied": bool(capability),
        "requested_risk_family": requested_risk_family,
        "resolved_risk_family": resolved_risk_family,
        "severity": severity,
        "notification_id": notification["notification_id"],
        "composition_mode": composed.mode,
        "unsafe_reasons": composed.unsafe_reasons,
    }
    store.append_audit_event(
        event_type=event_type,
        actor_type=actor_type,
        actor_id=actor_id,
        node_id=node_id,
        agent_id=agent_id,
        session_id=session_id,
        notification_id=notification["notification_id"],
        request_id=request_id,
        payload_redacted=payload,
    )
    store.create_event(
        node_id=node_id,
        agent_id=agent_id,
        session_id=session_id,
        event_type=event_type,
        payload=payload,
    )


# Canonical risk ladder. Public so other policy modules (standing grants) can
# derive their thresholds from it instead of hardcoding a parallel list that
# would silently drift when a family is added.
RISK_FAMILY_RANKS: dict[str, int] = {
    "observe": 0,
    "read_only": 1,
    "routine": 2,
    "external_effect": 3,
    "destructive": 4,
    "credential_or_secret": 5,
    "safety_critical": 6,
    "irreversible": 7,
}


def _risk_rank(risk_family: str) -> int:
    return RISK_FAMILY_RANKS.get(risk_family, 3)

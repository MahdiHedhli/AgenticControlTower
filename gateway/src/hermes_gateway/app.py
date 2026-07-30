from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect, status
from fastapi.middleware.cors import CORSMiddleware

from .capabilities import require_device_capability, require_runtime_capability
from .capability_registry import (
    aircraft_principal,
    capability_from_request,
    create_capability_alert_notification,
    resolve_capability_risk,
)
from .clearance_contract import (
    build_clearance_contract_fields,
    build_params_fingerprint,
    sanitize_operator_message,
)
from .clearance_policy import (
    LOW_RISK_FAMILIES,
    ClearanceChannelPolicy,
    authority_from_channel,
    channel_for_device,
    channel_satisfies,
    decision_metadata,
    enforce_clearance_channel,
    evaluate_clearance_channel,
    required_channels_for_request,
    risk_family_from_request,
)
from .config import Settings
from .grants import (
    mint_grant_for_decision,
    record_auto_satisfaction,
    record_auto_satisfy_refusal,
    standing_grant_for_request,
)
from .handoff import _require_bound_clearance
from .handoff import engage_handoff as _engage_handoff
from .ids import new_id
from .local_binding import HermesLocalCaller, verify_hermes_local_request
from .notification_composer import compose_notification
from .routers.identity import register_identity_routes
from .routers.observability import register_observability_routes
from .runtime_adapter import (
    HermesRuntimeAdapter,
    RuntimeAdapter,
    RuntimeClearanceRequest,
    RuntimeHandoffRequest,
    RuntimeNotice,
    RuntimeWorkState,
)
from .schemas import (
    Agent,
    ApprovalDecisionRequest,
    ApprovalDecisionResponse,
    ApprovalGrant,
    ApprovalPolicyProposal,
    ApprovalRequest,
    ApprovalResponse,
    ApprovalStatusRequest,
    ApprovalStatusResponse,
    AssistanceMessage,
    AssistanceRequest,
    AssistanceSession,
    BrowserAssistanceEventRequest,
    BrowserAssistanceSession,
    CapabilityRiskDecisionRequest,
    CapabilityRiskProposalRequest,
    CapabilityRiskRegistryEntry,
    CreateApprovalRequest,
    CreateApprovalResponseRequest,
    CreateAssistanceMessageRequest,
    CreateAssistanceRequest,
    CreateAssistanceSessionRequest,
    CreateBrowserAssistanceSessionRequest,
    CreateTuiSessionRequest,
    CreateVoiceMessageRequest,
    CreateVoiceSessionRequest,
    GatewayHealth,
    HermesApprovalRequestedRequest,
    InterventionRequest,
    InterventionResponse,
    Inventory,
    LocalTerminalApprovalDecisionRequest,
    Mission,
    MobileNotifyRequest,
    Node,
    NodeRegistration,
    Notification,
    PushTokenUpdateRequest,
    ReturnControlRequest,
    RuntimeApprovalResult,
    RuntimeBrowserAssistanceResult,
    RuntimeContextRequest,
    RuntimeContextResponse,
    RuntimeCreateVoiceSessionRequest,
    RuntimeInterventionAck,
    RuntimeTuaResult,
    RuntimeTuiRelayRequest,
    RuntimeVoiceResult,
    TuiAttachTokenResponse,
    TuiSession,
    TuiSessionControlResponse,
    UpdateAgentTrustContextRequest,
    VoiceMessage,
    VoiceSession,
)
from .security import expires_in, has_secret_text, new_token, now_utc, parse_utc
from .signing import VerifiedDevice, verify_signed_request
from .store import DEFAULT_NODE_CAPABILITIES, SQLiteStore
from .tui import (
    LocalPtyManager,
    tui_command_risk_family,
    validate_tui_frame,
    validate_tui_request,
)

DEFAULT_PERMISSIONS = ["read_state", "chat", "approve", "intervene"]

def create_app(settings: Settings | None = None) -> FastAPI:
    resolved_settings = settings or Settings.from_env()
    ClearanceChannelPolicy.from_settings(resolved_settings)
    store = SQLiteStore(resolved_settings.database_path)
    store.initialize()
    _ensure_local_node(store, resolved_settings)
    if resolved_settings.seed_mock_data:
        store.seed_mock_data(node_id=resolved_settings.node_id)
    tui_manager = LocalPtyManager(store=store, settings=resolved_settings)
    runtime_adapter: RuntimeAdapter = HermesRuntimeAdapter(
        store=store,
        settings=resolved_settings,
    )
    from .push import ApnsPushDispatcher

    push_dispatcher = ApnsPushDispatcher(resolved_settings)

    def _dispatch_clearance_push(approval: dict) -> None:
        """Best-effort APNs hint to the operator's phone for a new clearance.
        Hint only — no secrets / no raw aircraft text (ADR-0005)."""
        if not push_dispatcher.configured:
            return
        if approval.get("state") != "pending":
            # Nothing to decide: a standing grant already cleared this request.
            # "Clearance required" would be false, and the grant creation is
            # what the operator was asked about.
            return
        try:
            node_id = approval.get("node_id") or resolved_settings.node_id
            tokens = store.push_targets(node_id)
            if not tokens:
                return
            short_code = approval.get("short_code") or ""
            risk_family = approval.get("risk_family") or "clearance"
            push_dispatcher.dispatch_clearance(
                tokens,
                title="Clearance required",
                body=f"An agent needs your approval · {risk_family} · {short_code}",
                approval_id=approval.get("approval_id") or approval.get("request_id") or "",
                short_code=short_code,
            )
        except Exception:  # never let push break the approval flow
            pass

    def _create_approval_request_and_notify(**kwargs):
        result = _create_approval_request(**kwargs)
        try:
            _dispatch_clearance_push(result.model_dump())
        except Exception:
            pass
        return result

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        try:
            yield
        finally:
            await tui_manager.close_all()

    app = FastAPI(
        title="Agentic Control Tower Gateway",
        version=resolved_settings.gateway_version,
        description="Self-hosted control tower gateway for agentic backends.",
        lifespan=lifespan,
    )
    app.state.settings = resolved_settings
    app.state.store = store
    app.state.tui_manager = tui_manager
    app.state.runtime_adapter = runtime_adapter
    if resolved_settings.cors_allowed_origin_regex:
        app.add_middleware(
            CORSMiddleware,
            allow_origin_regex=resolved_settings.cors_allowed_origin_regex,
            allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
            allow_headers=["*"],
        )

    async def require_signed_device(request: Request) -> VerifiedDevice:
        return await verify_signed_request(request, store=store, settings=resolved_settings)

    def require_hermes_local_request(request: Request) -> HermesLocalCaller:
        return verify_hermes_local_request(
            request,
            store=store,
            settings=resolved_settings,
        )

    signed_device_dependency = Depends(require_signed_device)
    hermes_local_dependency = Depends(require_hermes_local_request)

    @app.get("/v1/health", response_model=GatewayHealth)
    def health() -> GatewayHealth:
        return GatewayHealth(
            node_id=resolved_settings.node_id,
            status="healthy",
            gateway_version=resolved_settings.gateway_version,
            hermes_version=resolved_settings.hermes_version,
            checked_at=now_utc(),
            services={
                "database": "healthy",
                "pairing": "healthy",
                "event_stream": "healthy",
                "push_dispatch": "healthy"
                if resolved_settings.push_configured
                else "unavailable",
                "tui_pty": "healthy"
                if resolved_settings.tui_enable_local_pty
                else "unavailable",
            },
        )

    @app.post("/v1/nodes/register", response_model=Node, status_code=status.HTTP_201_CREATED)
    def register_node(
        payload: NodeRegistration,
        request: Request,
        _caller: HermesLocalCaller = hermes_local_dependency,
    ) -> Node:
        node_id = payload.node_id or resolved_settings.node_id
        node = store.upsert_node(
            {
                "node_id": node_id,
                "display_name": payload.display_name,
                "environment": payload.environment,
                "gateway_base_url": payload.gateway_base_url,
                "node_fingerprint": payload.node_fingerprint,
                "gateway_version": payload.gateway_version,
                "hermes_version": payload.hermes_version,
                "health": "online",
                "tags": payload.tags,
            }
        )
        store.append_audit_event(
            event_type="node_registered",
            actor_type="gateway",
            actor_id="gateway",
            node_id=node_id,
            request_id=_request_id(request),
            payload_redacted={"display_name": payload.display_name},
        )
        store.create_event(
            node_id=node_id,
            event_type="system.health",
            payload={"status": "healthy", "reason": "node_registered"},
        )
        return Node.model_validate(node)

    @app.get("/v1/inventory", response_model=Inventory)
    def inventory(_device: VerifiedDevice = signed_device_dependency) -> Inventory:
        return Inventory(nodes=[Node.model_validate(node) for node in store.list_nodes()])

    @app.get("/v1/nodes/{node_id}", response_model=Node)
    def get_node(
        node_id: str,
        _device: VerifiedDevice = signed_device_dependency,
    ) -> Node:
        try:
            return Node.model_validate(store.get_node(node_id))
        except KeyError as exc:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "node not found") from exc

    @app.get("/v1/agents")
    def list_agents(
        node_id: str | None = None,
        _device: VerifiedDevice = signed_device_dependency,
    ) -> dict[str, list[Agent]]:
        return {"agents": [Agent.model_validate(agent) for agent in store.list_agents(node_id)]}

    @app.get("/v1/agents/{agent_id}", response_model=Agent)
    def get_agent(
        agent_id: str,
        node_id: str,
        _device: VerifiedDevice = signed_device_dependency,
    ) -> Agent:
        try:
            return Agent.model_validate(store.get_agent(node_id, agent_id))
        except KeyError as exc:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "agent not found") from exc

    @app.patch(
        "/v1/agents/{agent_id}/deployment-trust-context",
        response_model=Agent,
    )
    def update_agent_deployment_trust_context(
        agent_id: str,
        node_id: str,
        payload: UpdateAgentTrustContextRequest,
        request: Request,
        device: VerifiedDevice = signed_device_dependency,
    ) -> Agent:
        _require_permission(device, "manage_devices")
        try:
            existing = store.get_agent(node_id, agent_id)
            updated = store.update_agent_trust_context(
                node_id=node_id,
                agent_id=agent_id,
                deployment_trust_context=payload.deployment_trust_context,
            )
        except KeyError as exc:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "agent not found") from exc
        store.append_audit_event(
            event_type="agent_trust_context_updated",
            actor_type="device",
            actor_id=device.device_id,
            node_id=node_id,
            agent_id=agent_id,
            request_id=_request_id(request),
            payload_redacted={
                "old": existing.get("deployment_trust_context"),
                "new": payload.deployment_trust_context,
            },
        )
        store.create_event(
            node_id=node_id,
            agent_id=agent_id,
            event_type="agent.trust_context.updated",
            payload={
                "agent_id": agent_id,
                "deployment_trust_context": payload.deployment_trust_context,
            },
        )
        return Agent.model_validate(updated)

    @app.post(
        "/v1/capability-registry/proposals",
        status_code=status.HTTP_201_CREATED,
    )
    def propose_capability_risks(
        payload: CapabilityRiskProposalRequest,
        request: Request,
        _caller: HermesLocalCaller = hermes_local_dependency,
    ) -> dict[str, list[CapabilityRiskRegistryEntry]]:
        node_id = payload.node_id or resolved_settings.node_id
        aircraft = aircraft_principal(node_id=node_id, agent_id=payload.agent_id)
        entries = []
        for proposed in payload.entries:
            entry = store.create_capability_risk_entry(
                {
                    "entry_id": new_id("caprisk"),
                    "node_id": node_id,
                    "agent_id": payload.agent_id,
                    "aircraft": aircraft,
                    "capability": proposed.capability,
                    "risk_family": proposed.risk_family,
                    "status": "pending",
                    "proposed_by": aircraft,
                }
            )
            entries.append(entry)
            store.append_audit_event(
                event_type="capability_risk_proposed",
                actor_type="runtime",
                actor_id=aircraft,
                node_id=node_id,
                agent_id=payload.agent_id,
                request_id=_request_id(request),
                payload_redacted={
                    "capability": proposed.capability,
                    "risk_family": proposed.risk_family,
                    "status": "pending",
                    "version": entry["version"],
                },
            )
        return {
            "entries": [
                CapabilityRiskRegistryEntry.model_validate(entry) for entry in entries
            ]
        }

    @app.get("/v1/capability-registry")
    def list_capability_registry(
        node_id: str | None = None,
        agent_id: str | None = None,
        status_filter: str | None = None,
        device: VerifiedDevice = signed_device_dependency,
    ) -> dict[str, list[CapabilityRiskRegistryEntry]]:
        _require_permission(device, "manage_capabilities")
        return {
            "entries": [
                CapabilityRiskRegistryEntry.model_validate(entry)
                for entry in store.list_capability_risk_entries(
                    node_id=node_id,
                    agent_id=agent_id,
                    status=status_filter,
                )
            ]
        }

    @app.post(
        "/v1/capability-registry/{entry_id}/decision",
        response_model=CapabilityRiskRegistryEntry,
    )
    def decide_capability_risk(
        entry_id: str,
        payload: CapabilityRiskDecisionRequest,
        request: Request,
        device: VerifiedDevice = signed_device_dependency,
    ) -> CapabilityRiskRegistryEntry:
        _require_permission(device, "manage_capabilities")
        try:
            existing = store.get_capability_risk_entry(entry_id)
            if payload.decision == "approve":
                is_downgrade = _is_downgrade(store, existing)
                entry = store.approve_capability_risk_entry(
                    entry_id=entry_id,
                    approved_by=device.device_id,
                )
                event_type = "capability_risk_approved"
                audit_payload = {
                    "capability": entry["capability"],
                    "risk_family": entry["risk_family"],
                    "status": "approved",
                    "version": entry["version"],
                }
                if is_downgrade:
                    create_capability_alert_notification(
                        store=store,
                        settings=resolved_settings,
                        node_id=entry["node_id"],
                        agent_id=entry["agent_id"],
                        session_id="capability_registry",
                        request_id=_request_id(request),
                        event_type="capability_risk_downgrade_approved",
                        capability=entry["capability"],
                        requested_risk_family=entry["risk_family"],
                        resolved_risk_family=entry["risk_family"],
                        severity="drift",
                    )
            else:
                entry = store.reject_capability_risk_entry(entry_id)
                event_type = "capability_risk_rejected"
                audit_payload = {
                    "capability": entry["capability"],
                    "risk_family": entry["risk_family"],
                    "status": "rejected",
                    "version": entry["version"],
                }
        except KeyError as exc:
            raise HTTPException(
                status.HTTP_404_NOT_FOUND,
                "capability registry entry not found",
            ) from exc
        store.append_audit_event(
            event_type=event_type,
            actor_type="device",
            actor_id=device.device_id,
            node_id=entry["node_id"],
            agent_id=entry["agent_id"],
            request_id=_request_id(request),
            payload_redacted=audit_payload,
        )
        return CapabilityRiskRegistryEntry.model_validate(entry)

    @app.get("/v1/sessions")
    def list_sessions(
        node_id: str | None = None,
        agent_id: str | None = None,
        _device: VerifiedDevice = signed_device_dependency,
    ) -> dict[str, list[dict[str, Any]]]:
        return {"sessions": store.list_sessions(node_id=node_id, agent_id=agent_id)}

    @app.get("/v1/sessions/{session_id}")
    def get_session(
        session_id: str,
        node_id: str,
        _device: VerifiedDevice = signed_device_dependency,
    ) -> dict[str, Any]:
        try:
            return store.get_session(node_id, session_id)
        except KeyError as exc:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "session not found") from exc

    @app.get("/v1/sessions/{session_id}/activity")
    def get_session_activity(
        session_id: str,
        node_id: str,
        _device: VerifiedDevice = signed_device_dependency,
    ) -> dict[str, Any]:
        try:
            session = store.get_session(node_id, session_id)
        except KeyError as exc:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "session not found") from exc
        events = [
            event
            for event in store.list_events_after(limit=25)
            if event.get("node_id") == node_id and event.get("session_id") == session_id
        ]
        return {
            "session": session,
            "recent_events": events,
            "terminal_tail": None,
            "browser_state": None,
        }

    @app.get("/v1/missions")
    def list_missions(
        node_id: str | None = None,
        agent_id: str | None = None,
        _device: VerifiedDevice = signed_device_dependency,
    ) -> dict[str, list[Mission]]:
        return {
            "missions": [
                Mission.model_validate(mission)
                for mission in store.list_missions(node_id=node_id, agent_id=agent_id)
            ]
        }

    @app.get("/v1/missions/{mission_id}", response_model=Mission)
    def get_mission(
        mission_id: str,
        _device: VerifiedDevice = signed_device_dependency,
    ) -> Mission:
        try:
            return Mission.model_validate(store.get_mission(mission_id))
        except KeyError as exc:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "mission not found") from exc

    @app.post("/v1/runtime/context", response_model=RuntimeContextResponse)
    def runtime_register_context(
        payload: RuntimeContextRequest,
        request: Request,
        _caller: HermesLocalCaller = hermes_local_dependency,
    ) -> RuntimeContextResponse:
        return runtime_adapter.record_work_state(
            RuntimeWorkState(
                actor_ref=payload.agent_id,
                display_name=payload.display_name,
                state=payload.agent_status,
                unit_ref=payload.mission_id,
                unit_state=payload.mission_state,
                work_ref=payload.session_id,
                unit_title=payload.mission_title,
                unit_summary=payload.mission_summary,
                operation=payload.current_tool,
                target=payload.current_target,
                node_ref=payload.node_id,
                capabilities=[capability.model_dump() for capability in payload.capabilities],
            ),
            request_id=_request_id(request),
        )

    @app.post(
        "/v1/runtime/notifications",
        response_model=Notification,
        status_code=status.HTTP_202_ACCEPTED,
    )
    def runtime_notification(
        payload: MobileNotifyRequest,
        request: Request,
        _caller: HermesLocalCaller = hermes_local_dependency,
    ) -> Notification:
        require_runtime_capability(
            store=store,
            settings=resolved_settings,
            capability="notifications",
            request_id=_request_id(request),
            actor_id=payload.agent_id,
            agent_id=payload.agent_id,
        )
        result = runtime_adapter.publish_notice(
            RuntimeNotice(
                title=payload.title,
                body=payload.body,
                urgency=payload.urgency,
                category=payload.category,
                actor_ref=payload.agent_id,
                work_ref=payload.session_id,
                action_ref=payload.action_id,
                deep_link=payload.deep_link,
            ),
            request_id=_request_id(request),
        )
        return result.raw

    @app.post(
        "/v1/runtime/approvals",
        response_model=ApprovalRequest,
        status_code=status.HTTP_201_CREATED,
    )
    def runtime_approval_requested(
        payload: HermesApprovalRequestedRequest,
        request: Request,
        _caller: HermesLocalCaller = hermes_local_dependency,
    ) -> ApprovalRequest:
        require_runtime_capability(
            store=store,
            settings=resolved_settings,
            capability="approvals",
            request_id=_request_id(request),
            actor_id=payload.agent_id,
            node_id=payload.node_id,
            agent_id=payload.agent_id,
        )
        result = runtime_adapter.request_clearance(
            RuntimeClearanceRequest(
                operation=payload.requested_tool,
                risk_level=payload.risk_level,
                summary=payload.summary,
                payload_redacted=payload.payload_redacted,
                actor_ref=payload.agent_id,
                work_ref=payload.session_id,
                expires_in_seconds=payload.expires_in_seconds,
                scopes=payload.suggested_scopes,
                action_ref=payload.action_id,
                node_ref=payload.node_id,
                risk_category=payload.risk_category,
                risk_family=payload.risk_family,
                capability=payload.capability,
                operator_message=payload.operator_message,
                audit_correlation_id=payload.audit_correlation_id,
                short_code=payload.short_code,
                params_fingerprint=payload.params_fingerprint,
                extensions=payload.extensions,
                aircraft=payload.aircraft,
                requested_by=payload.requested_by,
                resource_scope=payload.resource_scope,
            ),
            request_id=_request_id(request),
        )
        return result.raw

    @app.get("/v1/runtime/approvals/{approval_id}/result", response_model=RuntimeApprovalResult)
    def runtime_approval_result(
        approval_id: str,
        _caller: HermesLocalCaller = hermes_local_dependency,
    ) -> RuntimeApprovalResult:
        return runtime_adapter.check_clearance(approval_id).result

    @app.post("/v1/runtime/approvals/{approval_id}/cancel", response_model=RuntimeApprovalResult)
    def runtime_cancel_approval(
        approval_id: str,
        request: Request,
        _caller: HermesLocalCaller = hermes_local_dependency,
    ) -> RuntimeApprovalResult:
        return runtime_adapter.cancel_clearance(
            approval_id,
            request_id=_request_id(request),
            actor_ref="runtime",
        ).result

    @app.post(
        "/v1/runtime/approvals/{approval_id}/reserve",
        response_model=ApprovalRequest,
    )
    def runtime_reserve_approval(
        approval_id: str,
        request: Request,
        _caller: HermesLocalCaller = hermes_local_dependency,
    ) -> ApprovalRequest:
        # Change 3 — two-phase consume, phase 1. Reserve an approved clearance at
        # validation; only one consumer can hold it (atomic state guard).
        try:
            approval = store.reserve_approval(approval_id)
        except KeyError as exc:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "approval not found") from exc
        except ValueError as exc:
            raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
        store.append_audit_event(
            event_type="approval_reserved",
            actor_type="runtime",
            actor_id="runtime",
            node_id=approval["node_id"],
            agent_id=approval["agent_id"],
            session_id=approval["session_id"],
            approval_id=approval_id,
            request_id=_request_id(request),
            payload_redacted={"state": "reserved"},
        )
        return ApprovalRequest.model_validate(approval)

    @app.post(
        "/v1/runtime/approvals/{approval_id}/commit",
        response_model=ApprovalRequest,
    )
    def runtime_commit_approval(
        approval_id: str,
        request: Request,
        _caller: HermesLocalCaller = hermes_local_dependency,
    ) -> ApprovalRequest:
        # Change 3 — two-phase consume, phase 2. Commit only from reserved,
        # preserving one-time consumption.
        try:
            approval = store.commit_approval(approval_id)
        except KeyError as exc:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "approval not found") from exc
        except ValueError as exc:
            raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
        store.append_audit_event(
            event_type="approval_committed",
            actor_type="runtime",
            actor_id="runtime",
            node_id=approval["node_id"],
            agent_id=approval["agent_id"],
            session_id=approval["session_id"],
            approval_id=approval_id,
            request_id=_request_id(request),
            payload_redacted={"state": "committed"},
        )
        return ApprovalRequest.model_validate(approval)

    @app.post(
        "/v1/runtime/approvals/{approval_id}/release",
        response_model=ApprovalRequest,
    )
    def runtime_release_approval(
        approval_id: str,
        request: Request,
        _caller: HermesLocalCaller = hermes_local_dependency,
    ) -> ApprovalRequest:
        # Change 3 — two-phase consume, symmetric inverse of commit. Release a
        # reserved clearance back to cancelled (only from reserved), so a
        # reserved-but-not-executed clearance never dangles. Fail-closed: 404 if
        # missing, 409 if not reserved; one-time consumption preserved.
        try:
            approval = store.release_approval(approval_id)
        except KeyError as exc:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "approval not found") from exc
        except ValueError as exc:
            raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
        store.append_audit_event(
            event_type="approval_released",
            actor_type="runtime",
            actor_id="runtime",
            node_id=approval["node_id"],
            agent_id=approval["agent_id"],
            session_id=approval["session_id"],
            approval_id=approval_id,
            request_id=_request_id(request),
            payload_redacted={"state": "cancelled"},
        )
        return ApprovalRequest.model_validate(approval)

    @app.post(
        "/v1/runtime/tua/requests",
        response_model=AssistanceRequest,
        status_code=status.HTTP_201_CREATED,
    )
    def runtime_tua_request(
        payload: CreateAssistanceRequest,
        request: Request,
        _caller: HermesLocalCaller = hermes_local_dependency,
    ) -> AssistanceRequest:
        result = runtime_adapter.request_handoff(
            RuntimeHandoffRequest(
                handoff_kind="operator_guidance",
                actor_ref=payload.agent_id,
                work_ref=payload.session_id,
                reason=payload.reason,
                node_ref=payload.node_id,
                clearance_ref=payload.approval_id,
                risk_family=payload.risk_family,
                context_redacted=payload.context_redacted,
            ),
            request_id=_request_id(request),
            actor_ref=payload.agent_id,
        )
        return AssistanceRequest.model_validate(result.raw)

    @app.get("/v1/runtime/tua/requests/{request_id}/result", response_model=RuntimeTuaResult)
    def runtime_tua_result(
        request_id: str,
        _caller: HermesLocalCaller = hermes_local_dependency,
    ) -> RuntimeTuaResult:
        return runtime_adapter.check_handoff("operator_guidance", request_id).raw

    @app.get("/v1/runtime/interventions/pending")
    def runtime_pending_interventions(
        session_id: str,
        agent_id: str | None = None,
        _caller: HermesLocalCaller = hermes_local_dependency,
    ) -> dict[str, Any]:
        # Drained by the in-process plugin to apply operator commands at the
        # agent's tool boundary. Loopback-only.
        return {
            "interventions": store.list_pending_interventions(session_id, agent_id)
        }

    @app.post("/v1/runtime/interventions/{intervention_id}/ack")
    def runtime_ack_intervention(
        intervention_id: str,
        payload: RuntimeInterventionAck,
        request: Request,
        _caller: HermesLocalCaller = hermes_local_dependency,
    ) -> dict[str, Any]:
        try:
            updated = store.ack_intervention(intervention_id, payload.ack_result)
        except KeyError as exc:
            raise HTTPException(
                status.HTTP_404_NOT_FOUND, "intervention not found"
            ) from exc
        store.append_audit_event(
            event_type="intervention_acknowledged",
            actor_type="runtime",
            actor_id="hermes-local",
            node_id=resolved_settings.node_id,
            session_id=updated["session_id"],
            request_id=_request_id(request),
            payload_redacted={
                "intervention_id": intervention_id,
                "ack_result": payload.ack_result,
            },
        )
        return {"intervention_id": intervention_id, "state": updated["state"]}

    @app.post("/v1/runtime/tui/relay")
    async def runtime_tui_relay(
        payload: RuntimeTuiRelayRequest,
        _caller: HermesLocalCaller = hermes_local_dependency,
    ) -> dict[str, Any]:
        # Mirror an agent's terminal output to a node-owned, read-only TUI session
        # that any paired tui-capable device can watch. Loopback-only; idempotent.
        node_id = payload.node_id or resolved_settings.node_id
        session_id = payload.session_id
        try:
            store.get_tui_session(session_id)
        except KeyError:
            store.create_tui_session(
                {
                    "session_id": session_id,
                    "agent_id": payload.agent_id,
                    "node_id": node_id,
                    "user_device_id": _RELAY_TUI_OWNER,
                    "state": "active",
                    "command": "<agent terminal mirror>",
                    "working_directory": ".",
                    "risk_level": "high",
                    "risk_family": "external_effect",
                    "risk_label": "agent terminal mirror",
                    "output_retention_enabled": False,
                    "audit_refs": [],
                }
            )
        await tui_manager.create_relay_runtime(session_id=session_id)
        if payload.chunk:
            await tui_manager.feed_output(session_id, payload.chunk)
        return {"session_id": session_id, "state": "active"}

    @app.post(
        "/v1/runtime/browser-assistance/sessions",
        response_model=BrowserAssistanceSession,
        status_code=status.HTTP_201_CREATED,
    )
    def runtime_browser_assistance_session(
        payload: CreateBrowserAssistanceSessionRequest,
        request: Request,
        _caller: HermesLocalCaller = hermes_local_dependency,
    ) -> BrowserAssistanceSession:
        return runtime_adapter.request_handoff(
            RuntimeHandoffRequest(
                handoff_kind="browser_review",
                actor_ref=payload.agent_id,
                work_ref=payload.session_id,
                reason=payload.reason,
                node_ref=payload.node_id,
                clearance_ref=payload.approval_id,
                risk_family=payload.risk_family,
                context_redacted=payload.context_redacted,
            ),
            request_id=_request_id(request),
            actor_ref=payload.agent_id,
        ).raw

    @app.get(
        "/v1/runtime/browser-assistance/sessions/{session_id}/result",
        response_model=RuntimeBrowserAssistanceResult,
    )
    def runtime_browser_assistance_result(
        session_id: str,
        _caller: HermesLocalCaller = hermes_local_dependency,
    ) -> RuntimeBrowserAssistanceResult:
        return runtime_adapter.check_handoff("browser_review", session_id).raw

    @app.post(
        "/v1/runtime/voice/sessions",
        response_model=VoiceSession,
        status_code=status.HTTP_201_CREATED,
    )
    def runtime_voice_session(
        payload: RuntimeCreateVoiceSessionRequest,
        request: Request,
        _caller: HermesLocalCaller = hermes_local_dependency,
    ) -> VoiceSession:
        return runtime_adapter.request_handoff(
            RuntimeHandoffRequest(
                handoff_kind="voice_prompt",
                actor_ref=payload.agent_id,
                work_ref=payload.session_id,
                reason="Runtime requested a voice prompt.",
                node_ref=payload.node_id,
                risk_family=payload.risk_family,
                context_redacted=payload.context_redacted,
                mode=payload.mode,
            ),
            request_id=_request_id(request),
            actor_ref=payload.agent_id,
        ).raw

    @app.get("/v1/runtime/voice/sessions/{session_id}/result", response_model=RuntimeVoiceResult)
    def runtime_voice_result(
        session_id: str,
        _caller: HermesLocalCaller = hermes_local_dependency,
    ) -> RuntimeVoiceResult:
        return runtime_adapter.check_handoff("voice_prompt", session_id).raw

    register_identity_routes(
        app=app,
        store=store,
        settings=resolved_settings,
        signed_device_dependency=signed_device_dependency,
        default_permissions=DEFAULT_PERMISSIONS,
        request_id=_request_id,
        expire_pairing_if_needed=_expire_pairing_if_needed,
    )

    @app.post("/v1/approvals", response_model=ApprovalRequest, status_code=status.HTTP_201_CREATED)
    def create_approval(
        payload: CreateApprovalRequest,
        request: Request,
        _caller: HermesLocalCaller = hermes_local_dependency,
    ) -> ApprovalRequest:
        return _create_approval_request_and_notify(
            store=store,
            settings=resolved_settings,
            request=request,
            payload=payload,
            caller=_caller,
        )

    @app.post(
        "/v1/hermes/tools/approval_requested",
        response_model=ApprovalRequest,
        status_code=status.HTTP_201_CREATED,
    )
    def hermes_approval_requested(
        payload: HermesApprovalRequestedRequest,
        request: Request,
        _caller: HermesLocalCaller = hermes_local_dependency,
    ) -> ApprovalRequest:
        # Canonical clearance path: delegate to the runtime adapter (same as
        # /v1/runtime/approvals) so ALL act.clearance.v2 contract fields —
        # params_fingerprint, short_code, operator_message,
        # audit_correlation_id, extensions — flow through and the proof is
        # signed over the canonical fingerprint (payload_redacted + extensions).
        require_runtime_capability(
            store=store,
            settings=resolved_settings,
            capability="approvals",
            request_id=_request_id(request),
            actor_id=payload.agent_id,
            node_id=payload.node_id,
            agent_id=payload.agent_id,
        )
        result = runtime_adapter.request_clearance(
            RuntimeClearanceRequest(
                operation=payload.requested_tool,
                risk_level=payload.risk_level,
                summary=payload.summary,
                payload_redacted=payload.payload_redacted,
                actor_ref=payload.agent_id,
                work_ref=payload.session_id,
                expires_in_seconds=payload.expires_in_seconds,
                scopes=payload.suggested_scopes,
                action_ref=payload.action_id,
                node_ref=payload.node_id,
                risk_category=payload.risk_category,
                risk_family=payload.risk_family,
                capability=payload.capability,
                operator_message=payload.operator_message,
                audit_correlation_id=payload.audit_correlation_id,
                short_code=payload.short_code,
                params_fingerprint=payload.params_fingerprint,
                extensions=payload.extensions,
                aircraft=payload.aircraft,
                requested_by=payload.requested_by,
                resource_scope=payload.resource_scope,
            ),
            request_id=_request_id(request),
        )
        approval: ApprovalRequest = result.raw
        # Preserve this route's APNs hint behavior (best-effort, never blocks).
        try:
            _dispatch_clearance_push(approval.model_dump())
        except Exception:
            pass
        return approval

    @app.post("/v1/hermes/tools/approval_status", response_model=ApprovalStatusResponse)
    def hermes_approval_status(
        payload: ApprovalStatusRequest,
        _caller: HermesLocalCaller = hermes_local_dependency,
    ) -> ApprovalStatusResponse:
        _expire_pending_approvals(store)
        try:
            approval = store.get_approval(payload.approval_id)
        except KeyError as exc:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "approval not found") from exc
        return ApprovalStatusResponse(
            approval_id=approval["approval_id"],
            state=approval["state"],
            selected_scope=approval["decision_scope"] if approval["state"] == "approved" else None,
            decided_at=approval["decided_at"],
            decision_metadata=approval["decision_metadata"],
            capability=approval.get("capability"),
            risk_family=approval["risk_family"],
            expires_at=approval["expires_at"],
            params_fingerprint=approval["params_fingerprint"],
            short_code=approval.get("short_code"),
            operator_message=approval.get("operator_message"),
            audit_correlation_id=approval.get("audit_correlation_id"),
            reason=(approval["decision_metadata"] or {}).get("reason"),
            tower_id=approval.get("tower_id"),
            contract_version=approval.get("contract_version") or "act.clearance.v2",
            proof=approval.get("proof"),
            extensions=approval.get("extensions") or {},
        )

    @app.get("/v1/approvals")
    def list_approvals(
        state: str | None = None,
        _device: VerifiedDevice = signed_device_dependency,
    ) -> dict[str, list[ApprovalRequest]]:
        _expire_pending_approvals(store)
        return {
            "approvals": [
                ApprovalRequest.model_validate(approval)
                for approval in store.list_approvals(state=state)
            ]
        }

    @app.get("/v1/approvals/{approval_id}", response_model=ApprovalRequest)
    def get_approval(
        approval_id: str,
        _device: VerifiedDevice = signed_device_dependency,
    ) -> ApprovalRequest:
        _expire_pending_approvals(store)
        try:
            return ApprovalRequest.model_validate(store.get_approval(approval_id))
        except KeyError as exc:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "approval not found") from exc

    @app.post("/v1/approvals/{approval_id}/decisions", response_model=ApprovalDecisionResponse)
    def decide_approval(
        approval_id: str,
        payload: ApprovalDecisionRequest,
        request: Request,
        device: VerifiedDevice = signed_device_dependency,
    ) -> ApprovalDecisionResponse:
        _require_approval_capability(
            store=store,
            settings=resolved_settings,
            request=request,
            device=device,
            approval_id=approval_id,
        )
        if payload.signed_payload.get("params_fingerprint") != store.get_approval(
            approval_id
        ).get("params_fingerprint"):
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "params fingerprint mismatch")
        state = "approved" if payload.decision == "approve" else "denied"
        return _transition_approval(
            store=store,
            settings=resolved_settings,
            approval_id=approval_id,
            target_state=state,
            request_id=_request_id(request),
            principal=device,
            decision=payload.decision,
            scope=payload.scope,
        )

    @app.post("/v1/approvals/{approval_id}/approve_once", response_model=ApprovalDecisionResponse)
    def approve_once(
        approval_id: str,
        request: Request,
        device: VerifiedDevice = signed_device_dependency,
    ) -> ApprovalDecisionResponse:
        _require_approval_capability(
            store=store,
            settings=resolved_settings,
            request=request,
            device=device,
            approval_id=approval_id,
        )
        return _transition_approval(
            store=store,
            settings=resolved_settings,
            approval_id=approval_id,
            target_state="approved",
            request_id=_request_id(request),
            principal=device,
            decision="approve",
            scope="once",
        )

    @app.post("/v1/approvals/{approval_id}/deny", response_model=ApprovalDecisionResponse)
    def deny_approval(
        approval_id: str,
        request: Request,
        device: VerifiedDevice = signed_device_dependency,
    ) -> ApprovalDecisionResponse:
        _require_approval_capability(
            store=store,
            settings=resolved_settings,
            request=request,
            device=device,
            approval_id=approval_id,
        )
        return _transition_approval(
            store=store,
            settings=resolved_settings,
            approval_id=approval_id,
            target_state="denied",
            request_id=_request_id(request),
            principal=device,
            decision="deny",
            scope="once",
        )

    @app.post("/v1/approvals/{approval_id}/expire", response_model=ApprovalDecisionResponse)
    def expire_approval(
        approval_id: str,
        request: Request,
        device: VerifiedDevice = signed_device_dependency,
    ) -> ApprovalDecisionResponse:
        _require_approval_capability(
            store=store,
            settings=resolved_settings,
            request=request,
            device=device,
            approval_id=approval_id,
        )
        return _transition_approval(
            store=store,
            settings=resolved_settings,
            approval_id=approval_id,
            target_state="expired",
            request_id=_request_id(request),
            principal=device,
            decision=None,
            scope=None,
        )

    @app.post("/v1/approvals/{approval_id}/cancel", response_model=ApprovalDecisionResponse)
    def cancel_approval(
        approval_id: str,
        request: Request,
        device: VerifiedDevice = signed_device_dependency,
    ) -> ApprovalDecisionResponse:
        _require_approval_capability(
            store=store,
            settings=resolved_settings,
            request=request,
            device=device,
            approval_id=approval_id,
        )
        return _transition_approval(
            store=store,
            settings=resolved_settings,
            approval_id=approval_id,
            target_state="cancelled",
            request_id=_request_id(request),
            principal=device,
            decision=None,
            scope=None,
        )

    # Standing approval grants. Same auth posture as deciding an approval —
    # a signed device plus the "approvals" capability gate — because a standing
    # grant IS approval authority. Deliberately not stricter than granting:
    # revocation is the safety valve, and a valve the granting device cannot
    # reach is not a valve.
    @app.get("/v1/approval-grants")
    def list_approval_grants(
        request: Request,
        node_id: str | None = None,
        agent_id: str | None = None,
        include_inactive: bool = False,
        device: VerifiedDevice = signed_device_dependency,
    ) -> dict[str, list[ApprovalGrant]]:
        require_device_capability(
            store=store,
            settings=resolved_settings,
            device=device,
            capability="approvals",
            request_id=_request_id(request),
            node_id=node_id or resolved_settings.node_id,
            agent_id=agent_id,
        )
        # Default is the live set — what is actually clearing requests right
        # now. Lapsed and revoked rows are history, available on request.
        grants = store.list_approval_grants(
            node_id=node_id,
            agent_id=agent_id,
            state=None if include_inactive else "active",
            include_expired=include_inactive,
        )
        return {
            "approval_grants": [ApprovalGrant.model_validate(grant) for grant in grants]
        }

    @app.post("/v1/approval-grants/{grant_id}/revoke", response_model=ApprovalGrant)
    def revoke_approval_grant(
        grant_id: str,
        request: Request,
        device: VerifiedDevice = signed_device_dependency,
    ) -> ApprovalGrant:
        try:
            grant = store.get_approval_grant(grant_id)
        except KeyError as exc:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "grant not found") from exc
        require_device_capability(
            store=store,
            settings=resolved_settings,
            device=device,
            capability="approvals",
            request_id=_request_id(request),
            node_id=grant["node_id"],
            agent_id=grant["agent_id"],
        )
        try:
            revoked = store.revoke_approval_grant(grant_id, revoked_by=device.device_id)
        except ValueError as exc:
            raise HTTPException(
                status.HTTP_409_CONFLICT, "grant is not active"
            ) from exc
        # Withdrawing authority is as auditable as granting it.
        store.append_audit_event(
            event_type="capability_grant_revoked",
            actor_type="device",
            actor_id=device.device_id,
            node_id=revoked["node_id"],
            agent_id=revoked["agent_id"],
            session_id=revoked.get("session_id"),
            approval_id=revoked["source_approval_id"],
            request_id=_request_id(request),
            payload_redacted={
                "grant_id": revoked["grant_id"],
                "scope": revoked["scope"],
                "requested_tool": revoked["requested_tool"],
                "risk_family": revoked["risk_family"],
                "source_approval_id": revoked["source_approval_id"],
                "revoked_at": revoked["revoked_at"],
            },
        )
        store.create_event(
            node_id=revoked["node_id"],
            agent_id=revoked["agent_id"],
            session_id=revoked.get("session_id"),
            event_type="capability_grant.revoked",
            payload={
                "grant_id": revoked["grant_id"],
                "scope": revoked["scope"],
                "requested_tool": revoked["requested_tool"],
            },
        )
        return ApprovalGrant.model_validate(revoked)

    @app.post(
        "/v1/local-terminal/approvals/{approval_id}/decisions",
        response_model=ApprovalDecisionResponse,
    )
    def local_terminal_decide_approval(
        approval_id: str,
        payload: LocalTerminalApprovalDecisionRequest,
        request: Request,
        device: VerifiedDevice = signed_device_dependency,
        _caller: HermesLocalCaller = hermes_local_dependency,
    ) -> ApprovalDecisionResponse:
        if device.clearance_channel != "local_terminal":
            approval = _get_approval_or_404(store, approval_id)
            _audit_channel_auth_failure(
                store=store,
                request_id=_request_id(request),
                approval=approval,
                actor_id=device.device_id,
                channel=device.clearance_channel,
                reason="principal_not_local_terminal",
            )
            raise HTTPException(status.HTTP_403_FORBIDDEN, "principal is not local terminal")
        target_state = "approved" if payload.decision == "approve" else "denied"
        return _transition_approval(
            store=store,
            settings=resolved_settings,
            approval_id=approval_id,
            target_state=target_state,
            request_id=_request_id(request),
            principal=device,
            decision=payload.decision,
            scope=payload.scope,
        )

    register_observability_routes(
        app=app,
        store=store,
        settings=resolved_settings,
        signed_device_dependency=signed_device_dependency,
        hermes_local_dependency=hermes_local_dependency,
        create_mobile_notification=_create_mobile_notification,
        request_id=_request_id,
        websocket_token=_websocket_token,
    )

    @app.post("/v1/sessions/{session_id}/interventions", response_model=InterventionResponse)
    def session_intervention(
        session_id: str,
        payload: InterventionRequest,
        request: Request,
        device: VerifiedDevice = signed_device_dependency,
    ) -> InterventionResponse:
        # Durably enqueue the operator command; the in-process plugin drains it
        # (hermes-local) and applies it at the agent's next tool boundary.
        node_id = resolved_settings.node_id
        signed = payload.signed_payload or {}
        agent_id = signed.get("agent_id")
        if not agent_id:
            try:
                agent_id = store.get_session(node_id, session_id).get("agent_id")
            except KeyError:
                agent_id = None
        agent_id = agent_id or "unknown"
        require_device_capability(
            store=store,
            settings=resolved_settings,
            device=device,
            capability="intervene",
            request_id=_request_id(request),
            node_id=node_id,
            agent_id=agent_id,
        )
        intervention_id = payload.intervention_id or new_id("intv")
        store.enqueue_intervention(
            {
                "intervention_id": intervention_id,
                "node_id": node_id,
                "agent_id": agent_id,
                "session_id": session_id,
                "device_id": device.device_id,
                "type": payload.type,
                "reason": payload.reason,
                "instruction": payload.instruction,
                "state": "pending",
                "expires_at": expires_in(300).isoformat(),
            }
        )
        # Panic dominance (BrowserBridge seam). Emergency interventions
        # BULK-INVALIDATE every pending AND approved-but-unconsumed
        # (approved/reserved) clearance for the session; committed clearances
        # are already consumed and left intact. Non-emergency interventions
        # are durably queued only.
        emergency_types = {
            "emergency_stop",
            "kill_task",
            "kill_agent",
            "quarantine_agent",
            "cancel_task",
        }
        invalidated: list[str] = []
        if payload.type in emergency_types:
            invalidated = store.bulk_invalidate_approvals(
                session_id=session_id, reason=f"intervention:{payload.type}"
            )
            resulting_state = "approvals_invalidated"
        else:
            resulting_state = "queued"
        store.append_audit_event(
            event_type="intervention_requested",
            actor_type="device",
            actor_id=device.device_id,
            node_id=node_id,
            session_id=session_id,
            request_id=_request_id(request),
            payload_redacted={
                "intervention_id": intervention_id,
                "type": payload.type,
                "reason": payload.reason,
                "invalidated_count": len(invalidated),
            },
        )
        return InterventionResponse(
            intervention_id=intervention_id,
            resulting_state=resulting_state,
        )

    @app.post("/v1/devices/me/push-token")
    def update_my_push_token(
        payload: PushTokenUpdateRequest,
        request: Request,
        device: VerifiedDevice = signed_device_dependency,
    ) -> dict[str, Any]:
        # The app uploads its APNs device token after registering with APNs.
        # The token itself is never logged (only whether one is present).
        store.set_device_push_token(device.device_id, payload.push_token)
        store.append_audit_event(
            event_type="device_push_token_updated",
            actor_type="device",
            actor_id=device.device_id,
            node_id=resolved_settings.node_id,
            request_id=_request_id(request),
            payload_redacted={"has_token": bool(payload.push_token)},
        )
        return {
            "device_id": device.device_id,
            "push_registered": bool(payload.push_token),
        }

    @app.post(
        "/v1/tui/sessions",
        response_model=TuiSession,
        status_code=status.HTTP_201_CREATED,
    )
    async def create_tui_session(
        payload: CreateTuiSessionRequest,
        request: Request,
        device: VerifiedDevice = signed_device_dependency,
    ) -> TuiSession:
        node_id = payload.node_id or resolved_settings.node_id
        require_device_capability(
            store=store,
            settings=resolved_settings,
            device=device,
            capability="tui",
            request_id=_request_id(request),
            node_id=node_id,
            agent_id=payload.agent_id,
        )
        await tui_manager.cleanup_idle_sessions()
        if store.count_open_tui_sessions() >= resolved_settings.tui_max_sessions:
            raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "TUI session limit reached")

        command, working_directory = validate_tui_request(
            settings=resolved_settings,
            command=payload.command,
            working_directory=payload.working_directory,
        )
        risk_family = tui_command_risk_family(resolved_settings, command)
        params_fingerprint = build_params_fingerprint(
            payload_redacted={
                "command": command,
                "working_directory": working_directory,
            },
            extensions={},
        )
        clearance, clearance_metadata = _require_tui_start_clearance(
            store=store,
            node_id=node_id,
            agent_id=payload.agent_id,
            work_ref=payload.session_context_id or "tui",
            risk_family=risk_family,
            clearance_ref=payload.approval_id,
            params_fingerprint=params_fingerprint,
            request_id=_request_id(request),
            device=device,
        )
        session_id = new_id("tui")
        _require_tui_capability(store, node_id=node_id, agent_id=payload.agent_id)
        session = store.create_tui_session(
            {
                "session_id": session_id,
                "agent_id": payload.agent_id,
                "node_id": node_id,
                "user_device_id": device.device_id,
                "state": "requested",
                "command": command,
                "working_directory": working_directory,
                "risk_level": payload.risk_level,
                "risk_family": risk_family,
                "risk_label": _tui_risk_label(payload.risk_level),
                "output_retention_enabled": resolved_settings.tui_output_retention_enabled,
            }
        )
        try:
            await tui_manager.create_runtime(
                session_id=session_id,
                command=command,
                working_directory=working_directory,
            )
            session = store.update_tui_session_state(session_id, "active")
        except HTTPException:
            store.update_tui_session_state(session_id, "failed")
            raise
        except Exception as exc:
            store.update_tui_session_state(session_id, "failed")
            raise HTTPException(
                status.HTTP_500_INTERNAL_SERVER_ERROR,
                "TUI session failed to start",
            ) from exc
        if clearance is not None:
            store.update_approval_decision_metadata(
                clearance["approval_id"],
                {
                    "tui_consumed_by": session_id,
                    "tui_consumed_at": now_utc().isoformat().replace("+00:00", "Z"),
                },
            )

        audit = store.append_audit_event(
            event_type="tui_session_created",
            actor_type="device",
            actor_id=device.device_id,
            node_id=node_id,
            agent_id=payload.agent_id,
            session_id=session_id,
            request_id=_request_id(request),
            payload_redacted={
                "command": command,
                "working_directory": working_directory,
                "risk_level": payload.risk_level,
                "risk_family": risk_family,
                "clearance_ref": payload.approval_id,
                "channel": clearance_metadata.get("channel"),
                "decision": "started",
                "eligibility_result": clearance_metadata.get("eligibility_result"),
                "hermes_session_id": payload.session_context_id,
            },
        )
        session = store.add_tui_audit_ref(session_id, audit["audit_event_id"])
        store.create_operator_session(
            {
                "session_id": session_id,
                "session_type": "tui",
                "agent_id": payload.agent_id,
                "state": session["state"],
                "owner_device_id": device.device_id,
                "capability_requirements": ["tui"],
                "context": {
                    "hermes_session_id": payload.session_context_id,
                    "command": command,
                    "working_directory": working_directory,
                    "risk_level": payload.risk_level,
                    "risk_family": risk_family,
                    "approval_id": payload.approval_id,
                },
            }
        )
        store.create_event(
            node_id=node_id,
            agent_id=payload.agent_id,
            session_id=session_id,
            event_type="tui.session.state",
            payload={"session_id": session_id, "state": session["state"]},
        )
        return TuiSession.model_validate(session)

    @app.post(
        "/v1/tui/sessions/{session_id}/attach-token",
        response_model=TuiAttachTokenResponse,
    )
    def create_tui_attach_token(
        session_id: str,
        request: Request,
        device: VerifiedDevice = signed_device_dependency,
    ) -> TuiAttachTokenResponse:
        require_device_capability(
            store=store,
            settings=resolved_settings,
            device=device,
            capability="tui",
            request_id=_request_id(request),
        )
        session = _owned_tui_session(store, session_id, device)
        if session["state"] in {"closed", "failed"}:
            raise HTTPException(status.HTTP_409_CONFLICT, "TUI session is not attachable")
        token = new_token()
        attach = store.create_tui_attach_token(
            token=token,
            session_id=session_id,
            device_id=device.device_id,
            ttl_seconds=resolved_settings.tui_attach_token_ttl_seconds,
        )
        store.append_audit_event(
            event_type="tui_attach_token_created",
            actor_type="device",
            actor_id=device.device_id,
            node_id=session["node_id"],
            agent_id=session["agent_id"],
            session_id=session_id,
            request_id=_request_id(request),
            payload_redacted={"expires_at": attach["expires_at"]},
        )
        return TuiAttachTokenResponse.model_validate(attach)

    @app.get("/v1/tui/sessions")
    async def list_tui_sessions(
        state: str | None = None,
        device: VerifiedDevice = signed_device_dependency,
    ) -> dict[str, list[TuiSession]]:
        await tui_manager.cleanup_idle_sessions()
        return {
            "sessions": [
                TuiSession.model_validate(session)
                for session in store.list_tui_sessions(
                    user_device_id=device.device_id,
                    state=state,
                )
            ]
        }

    @app.get("/v1/tui/sessions/{session_id}", response_model=TuiSession)
    async def get_tui_session(
        session_id: str,
        device: VerifiedDevice = signed_device_dependency,
    ) -> TuiSession:
        await tui_manager.cleanup_idle_sessions()
        session = _owned_tui_session(store, session_id, device)
        return TuiSession.model_validate(session)

    @app.post("/v1/tui/sessions/{session_id}/detach", response_model=TuiSessionControlResponse)
    async def detach_tui_session(
        session_id: str,
        request: Request,
        device: VerifiedDevice = signed_device_dependency,
    ) -> TuiSessionControlResponse:
        session = _owned_tui_session(store, session_id, device)
        if session["state"] in {"closed", "failed"}:
            raise HTTPException(status.HTTP_409_CONFLICT, "TUI session is not attachable")
        await tui_manager.detach(session_id)
        session = _record_tui_state_change(
            store=store,
            session_id=session_id,
            event_type="tui_session_detached",
            request_id=_request_id(request),
            actor_device_id=device.device_id,
        )
        return TuiSessionControlResponse(session=TuiSession.model_validate(session))

    @app.post("/v1/tui/sessions/{session_id}/close", response_model=TuiSessionControlResponse)
    async def close_tui_session(
        session_id: str,
        request: Request,
        device: VerifiedDevice = signed_device_dependency,
    ) -> TuiSessionControlResponse:
        session = _owned_tui_session(store, session_id, device)
        if session["state"] == "closed":
            return TuiSessionControlResponse(session=TuiSession.model_validate(session))
        await tui_manager.close(session_id)
        session = _record_tui_state_change(
            store=store,
            session_id=session_id,
            event_type="tui_session_closed",
            request_id=_request_id(request),
            actor_device_id=device.device_id,
        )
        return TuiSessionControlResponse(session=TuiSession.model_validate(session))

    @app.post(
        "/v1/tua/requests",
        response_model=AssistanceRequest,
        status_code=status.HTTP_201_CREATED,
    )
    def create_tua_request(
        payload: CreateAssistanceRequest,
        request: Request,
        _caller: HermesLocalCaller = hermes_local_dependency,
    ) -> AssistanceRequest:
        node_id = payload.node_id or resolved_settings.node_id
        assistance_request = store.create_assistance_request(
            {
                "node_id": node_id,
                "agent_id": payload.agent_id,
                "session_id": payload.session_id,
                "approval_id": payload.approval_id,
                "risk_family": payload.risk_family,
                "reason": payload.reason,
                "state": "requested",
                "context_redacted": payload.context_redacted,
            }
        )
        store.append_audit_event(
            event_type="tua_request_created",
            actor_type="hermes",
            actor_id=payload.agent_id,
            node_id=node_id,
            agent_id=payload.agent_id,
            session_id=payload.session_id,
            request_id=_request_id(request),
            payload_redacted={"request_id": assistance_request["request_id"]},
        )
        store.create_event(
            node_id=node_id,
            agent_id=payload.agent_id,
            session_id=payload.session_id,
            event_type="tua.requested",
            payload={"request_id": assistance_request["request_id"]},
        )
        return AssistanceRequest.model_validate(assistance_request)

    @app.get("/v1/tua/requests")
    def list_tua_requests(
        state: str | None = None,
        _device: VerifiedDevice = signed_device_dependency,
    ) -> dict[str, list[AssistanceRequest]]:
        return {
            "requests": [
                AssistanceRequest.model_validate(item)
                for item in store.list_assistance_requests(state=state)
            ]
        }

    @app.get("/v1/tua/requests/{request_id}", response_model=AssistanceRequest)
    def get_tua_request(
        request_id: str,
        _device: VerifiedDevice = signed_device_dependency,
    ) -> AssistanceRequest:
        try:
            return AssistanceRequest.model_validate(store.get_assistance_request(request_id))
        except KeyError as exc:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "TUA request not found") from exc

    @app.post(
        "/v1/tua/requests/{request_id}/sessions",
        response_model=AssistanceSession,
        status_code=status.HTTP_201_CREATED,
    )
    def create_tua_session(
        request_id: str,
        payload: CreateAssistanceSessionRequest,
        request: Request,
        device: VerifiedDevice = signed_device_dependency,
    ) -> AssistanceSession:
        try:
            assistance_request = store.get_assistance_request(request_id)
        except KeyError as exc:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "TUA request not found") from exc
        require_device_capability(
            store=store,
            settings=resolved_settings,
            device=device,
            capability="tua",
            request_id=_request_id(request),
            node_id=assistance_request["node_id"],
            agent_id=assistance_request["agent_id"],
        )
        session = _engage_handoff(
            store=store,
            settings=resolved_settings,
            handoff_kind="operator_guidance",
            handoff_ref=request_id,
            node_id=assistance_request["node_id"],
            agent_id=assistance_request["agent_id"],
            work_ref=assistance_request["session_id"],
            risk_family=assistance_request["risk_family"],
            clearance_ref=assistance_request.get("approval_id"),
            request_id=_request_id(request),
            actor_type="device",
            actor_id=device.device_id,
            engage=lambda: store.create_assistance_session(
                {
                    "request_id": request_id,
                    "node_id": assistance_request["node_id"],
                    "agent_id": assistance_request["agent_id"],
                    "session_id": assistance_request["session_id"],
                    "state": "active",
                    "created_by_device_id": device.device_id,
                }
            ),
        )
        if payload.initial_message:
            store.create_assistance_message(
                {
                    "assistance_session_id": session["assistance_session_id"],
                    "sender_type": "user",
                    "sender_id": device.device_id,
                    "body": payload.initial_message,
                }
            )
            session = store.get_assistance_session(session["assistance_session_id"])
        store.append_audit_event(
            event_type="tua_session_created",
            actor_type="device",
            actor_id=device.device_id,
            node_id=session["node_id"],
            agent_id=session["agent_id"],
            session_id=session["session_id"],
            request_id=_request_id(request),
            payload_redacted={"assistance_session_id": session["assistance_session_id"]},
        )
        store.create_operator_session(
            {
                "session_id": session["assistance_session_id"],
                "session_type": "tua",
                "agent_id": session["agent_id"],
                "mission_id": _mission_id_from_context(
                    assistance_request.get("context_redacted", {})
                ),
                "state": session["state"],
                "owner_device_id": device.device_id,
                "capability_requirements": ["tua"],
                "context": assistance_request.get("context_redacted", {}),
            }
        )
        store.create_event(
            node_id=session["node_id"],
            agent_id=session["agent_id"],
            session_id=session["session_id"],
            event_type="tua.session.created",
            payload={"assistance_session_id": session["assistance_session_id"]},
        )
        return AssistanceSession.model_validate(session)

    @app.get("/v1/tua/sessions/{session_id}", response_model=AssistanceSession)
    def get_tua_session(
        session_id: str,
        _device: VerifiedDevice = signed_device_dependency,
    ) -> AssistanceSession:
        try:
            return AssistanceSession.model_validate(store.get_assistance_session(session_id))
        except KeyError as exc:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "TUA session not found") from exc

    @app.post(
        "/v1/tua/sessions/{session_id}/messages",
        response_model=AssistanceMessage,
        status_code=status.HTTP_201_CREATED,
    )
    def create_tua_message(
        session_id: str,
        payload: CreateAssistanceMessageRequest,
        request: Request,
        device: VerifiedDevice = signed_device_dependency,
    ) -> AssistanceMessage:
        session = _get_assistance_session_or_404(store, session_id)
        require_device_capability(
            store=store,
            settings=resolved_settings,
            device=device,
            capability="tua",
            request_id=_request_id(request),
            node_id=session["node_id"],
            agent_id=session["agent_id"],
        )
        message = store.create_assistance_message(
            {
                "assistance_session_id": session_id,
                "sender_type": "user",
                "sender_id": device.device_id,
                "body": payload.body,
            }
        )
        store.append_audit_event(
            event_type="tua_message_created",
            actor_type="device",
            actor_id=device.device_id,
            node_id=session["node_id"],
            agent_id=session["agent_id"],
            session_id=session["session_id"],
            request_id=_request_id(request),
            payload_redacted={
                "message_id": message["message_id"],
                "body_length": len(payload.body),
            },
        )
        store.create_event(
            node_id=session["node_id"],
            agent_id=session["agent_id"],
            session_id=session["session_id"],
            event_type="tua.message.created",
            payload={"assistance_session_id": session_id, "message_id": message["message_id"]},
        )
        return AssistanceMessage.model_validate(message)

    @app.post("/v1/tua/sessions/{session_id}/return-control", response_model=AssistanceSession)
    def return_tua_control(
        session_id: str,
        payload: ReturnControlRequest,
        request: Request,
        device: VerifiedDevice = signed_device_dependency,
    ) -> AssistanceSession:
        session = _get_assistance_session_or_404(store, session_id)
        require_device_capability(
            store=store,
            settings=resolved_settings,
            device=device,
            capability="tua",
            request_id=_request_id(request),
            node_id=session["node_id"],
            agent_id=session["agent_id"],
        )
        updated = store.update_assistance_session_state(
            session_id,
            "returned_to_agent",
            return_summary=payload.summary,
        )
        store.append_audit_event(
            event_type="tua_returned_to_agent",
            actor_type="device",
            actor_id=device.device_id,
            node_id=session["node_id"],
            agent_id=session["agent_id"],
            session_id=session["session_id"],
            request_id=_request_id(request),
            payload_redacted={"summary_length": len(payload.summary)},
        )
        store.create_event(
            node_id=session["node_id"],
            agent_id=session["agent_id"],
            session_id=session["session_id"],
            event_type="tua.returned_to_agent",
            payload={"assistance_session_id": session_id},
        )
        _update_operator_session_if_exists(
            store,
            session_id,
            "returned_to_agent",
            owner_device_id=device.device_id,
            return_summary=payload.summary,
        )
        return AssistanceSession.model_validate(updated)

    @app.post("/v1/tua/sessions/{session_id}/close", response_model=AssistanceSession)
    def close_tua_session(
        session_id: str,
        request: Request,
        device: VerifiedDevice = signed_device_dependency,
    ) -> AssistanceSession:
        session = _get_assistance_session_or_404(store, session_id)
        require_device_capability(
            store=store,
            settings=resolved_settings,
            device=device,
            capability="tua",
            request_id=_request_id(request),
            node_id=session["node_id"],
            agent_id=session["agent_id"],
        )
        updated = store.update_assistance_session_state(session_id, "closed")
        store.append_audit_event(
            event_type="tua_session_closed",
            actor_type="device",
            actor_id=device.device_id,
            node_id=session["node_id"],
            agent_id=session["agent_id"],
            session_id=session["session_id"],
            request_id=_request_id(request),
            payload_redacted={},
        )
        store.create_event(
            node_id=session["node_id"],
            agent_id=session["agent_id"],
            session_id=session["session_id"],
            event_type="tua.closed",
            payload={"assistance_session_id": session_id},
        )
        _update_operator_session_if_exists(
            store,
            session_id,
            "closed",
            owner_device_id=device.device_id,
        )
        return AssistanceSession.model_validate(updated)

    @app.post(
        "/v1/browser-assistance/sessions",
        response_model=BrowserAssistanceSession,
        status_code=status.HTTP_201_CREATED,
    )
    def create_browser_assistance_session(
        payload: CreateBrowserAssistanceSessionRequest,
        request: Request,
        _caller: HermesLocalCaller = hermes_local_dependency,
    ) -> BrowserAssistanceSession:
        node_id = payload.node_id or resolved_settings.node_id
        session = store.create_browser_assistance_session(
            {
                "node_id": node_id,
                "agent_id": payload.agent_id,
                "session_id": payload.session_id,
                "approval_id": payload.approval_id,
                "risk_family": payload.risk_family,
                "reason": payload.reason,
                "state": "requested",
                "context_redacted": payload.context_redacted,
            }
        )
        store.append_audit_event(
            event_type="browser_assistance_requested",
            actor_type="hermes",
            actor_id=payload.agent_id,
            node_id=node_id,
            agent_id=payload.agent_id,
            session_id=payload.session_id,
            request_id=_request_id(request),
            payload_redacted={"browser_session_id": session["browser_session_id"]},
        )
        store.create_operator_session(
            {
                "session_id": session["browser_session_id"],
                "session_type": "browser_assistance",
                "agent_id": session["agent_id"],
                "mission_id": _mission_id_from_context(payload.context_redacted),
                "state": session["state"],
                "capability_requirements": ["browser_assistance"],
                "context": payload.context_redacted,
            }
        )
        store.create_event(
            node_id=node_id,
            agent_id=payload.agent_id,
            session_id=payload.session_id,
            event_type="browser_assistance.requested",
            payload={"browser_session_id": session["browser_session_id"]},
        )
        return BrowserAssistanceSession.model_validate(session)

    @app.get("/v1/browser-assistance/sessions")
    def list_browser_assistance_sessions(
        state: str | None = None,
        _device: VerifiedDevice = signed_device_dependency,
    ) -> dict[str, list[BrowserAssistanceSession]]:
        return {
            "sessions": [
                BrowserAssistanceSession.model_validate(item)
                for item in store.list_browser_assistance_sessions(state=state)
            ]
        }

    @app.get(
        "/v1/browser-assistance/sessions/{session_id}",
        response_model=BrowserAssistanceSession,
    )
    def get_browser_assistance_session(
        session_id: str,
        _device: VerifiedDevice = signed_device_dependency,
    ) -> BrowserAssistanceSession:
        try:
            return BrowserAssistanceSession.model_validate(
                store.get_browser_assistance_session(session_id)
            )
        except KeyError as exc:
            raise HTTPException(
                status.HTTP_404_NOT_FOUND, "browser assistance session not found"
            ) from exc

    @app.post(
        "/v1/browser-assistance/sessions/{session_id}/event",
        response_model=BrowserAssistanceSession,
    )
    def add_browser_assistance_event(
        session_id: str,
        payload: BrowserAssistanceEventRequest,
        request: Request,
        device: VerifiedDevice = signed_device_dependency,
    ) -> BrowserAssistanceSession:
        session = _get_browser_session_or_404(store, session_id)
        require_device_capability(
            store=store,
            settings=resolved_settings,
            device=device,
            capability="browser_assistance",
            request_id=_request_id(request),
            node_id=session["node_id"],
            agent_id=session["agent_id"],
        )
        updated = _engage_handoff(
            store=store,
            settings=resolved_settings,
            handoff_kind="browser_review",
            handoff_ref=session_id,
            node_id=session["node_id"],
            agent_id=session["agent_id"],
            work_ref=session["session_id"],
            risk_family=session["risk_family"],
            clearance_ref=session.get("approval_id"),
            request_id=_request_id(request),
            actor_type="device",
            actor_id=device.device_id,
            engage=lambda: store.add_browser_assistance_note(session_id, payload.note),
        )
        store.append_audit_event(
            event_type="browser_assistance_event_recorded",
            actor_type="device",
            actor_id=device.device_id,
            node_id=session["node_id"],
            agent_id=session["agent_id"],
            session_id=session["session_id"],
            request_id=_request_id(request),
            payload_redacted={"note_length": len(payload.note)},
        )
        store.create_event(
            node_id=session["node_id"],
            agent_id=session["agent_id"],
            session_id=session["session_id"],
            event_type="browser_assistance.event",
            payload={"browser_session_id": session_id},
        )
        _update_operator_session_if_exists(
            store,
            session_id,
            "user_controlling",
            owner_device_id=device.device_id,
        )
        return BrowserAssistanceSession.model_validate(updated)

    @app.post(
        "/v1/browser-assistance/sessions/{session_id}/return-control",
        response_model=BrowserAssistanceSession,
    )
    def return_browser_assistance_control(
        session_id: str,
        payload: ReturnControlRequest,
        request: Request,
        device: VerifiedDevice = signed_device_dependency,
    ) -> BrowserAssistanceSession:
        session = _get_browser_session_or_404(store, session_id)
        require_device_capability(
            store=store,
            settings=resolved_settings,
            device=device,
            capability="browser_assistance",
            request_id=_request_id(request),
            node_id=session["node_id"],
            agent_id=session["agent_id"],
        )
        updated = store.update_browser_assistance_state(
            session_id,
            "returned_to_agent",
            return_summary=payload.summary,
        )
        store.append_audit_event(
            event_type="browser_assistance_returned_to_agent",
            actor_type="device",
            actor_id=device.device_id,
            node_id=session["node_id"],
            agent_id=session["agent_id"],
            session_id=session["session_id"],
            request_id=_request_id(request),
            payload_redacted={"summary_length": len(payload.summary)},
        )
        store.create_event(
            node_id=session["node_id"],
            agent_id=session["agent_id"],
            session_id=session["session_id"],
            event_type="browser_assistance.returned_to_agent",
            payload={"browser_session_id": session_id},
        )
        _update_operator_session_if_exists(
            store,
            session_id,
            "returned_to_agent",
            owner_device_id=device.device_id,
            return_summary=payload.summary,
        )
        return BrowserAssistanceSession.model_validate(updated)

    @app.post(
        "/v1/browser-assistance/sessions/{session_id}/close",
        response_model=BrowserAssistanceSession,
    )
    def close_browser_assistance_session(
        session_id: str,
        request: Request,
        device: VerifiedDevice = signed_device_dependency,
    ) -> BrowserAssistanceSession:
        session = _get_browser_session_or_404(store, session_id)
        require_device_capability(
            store=store,
            settings=resolved_settings,
            device=device,
            capability="browser_assistance",
            request_id=_request_id(request),
            node_id=session["node_id"],
            agent_id=session["agent_id"],
        )
        updated = store.update_browser_assistance_state(session_id, "closed")
        store.append_audit_event(
            event_type="browser_assistance_closed",
            actor_type="device",
            actor_id=device.device_id,
            node_id=session["node_id"],
            agent_id=session["agent_id"],
            session_id=session["session_id"],
            request_id=_request_id(request),
            payload_redacted={},
        )
        store.create_event(
            node_id=session["node_id"],
            agent_id=session["agent_id"],
            session_id=session["session_id"],
            event_type="browser_assistance.closed",
            payload={"browser_session_id": session_id},
        )
        _update_operator_session_if_exists(
            store,
            session_id,
            "closed",
            owner_device_id=device.device_id,
        )
        return BrowserAssistanceSession.model_validate(updated)

    @app.post(
        "/v1/approvals/{approval_id}/responses",
        response_model=ApprovalResponse,
        status_code=status.HTTP_201_CREATED,
    )
    def create_approval_response(
        approval_id: str,
        payload: CreateApprovalResponseRequest,
        request: Request,
        device: VerifiedDevice = signed_device_dependency,
    ) -> ApprovalResponse:
        approval = _get_approval_or_404(store, approval_id)
        require_device_capability(
            store=store,
            settings=resolved_settings,
            device=device,
            capability="approvals",
            request_id=_request_id(request),
            node_id=approval["node_id"],
            agent_id=approval["agent_id"],
        )
        policy_proposal_id = None
        if payload.decision_type in {"approve_once", "approve_session", "approve_agent"}:
            if payload.params_fingerprint != approval.get("params_fingerprint"):
                raise HTTPException(
                    status.HTTP_400_BAD_REQUEST,
                    "params fingerprint mismatch",
                )
        if payload.decision_type == "propose_policy":
            if payload.confirmation_phrase != "PROPOSE POLICY":
                raise HTTPException(
                    status.HTTP_400_BAD_REQUEST,
                    "policy proposal requires explicit confirmation phrase",
                )
            proposal = store.create_approval_policy_proposal(
                {
                    "approval_id": approval_id,
                    "created_by_device_id": device.device_id,
                    "status": "proposed",
                    "warning": "Proposal only; no permanent allow policy was activated.",
                    "constraints": [item.model_dump() for item in payload.constraints],
                }
            )
            policy_proposal_id = proposal["policy_proposal_id"]
        response = store.create_approval_response(
            {
                "approval_id": approval_id,
                "decision_type": payload.decision_type,
                "created_by_device_id": device.device_id,
                "user_message": payload.user_message,
                "alternate_directive": payload.alternate_directive,
                "constraints": [item.model_dump() for item in payload.constraints],
                "policy_proposal_id": policy_proposal_id,
            }
        )
        if payload.decision_type in {"approve_once", "approve_session", "approve_agent", "deny"}:
            transition = {
                "approve_once": ("approved", "approve", "once"),
                "approve_session": ("approved", "approve", "session"),
                "approve_agent": ("approved", "approve", "agent"),
                "deny": ("denied", "deny", "once"),
            }[payload.decision_type]
            _transition_approval(
                store=store,
                settings=resolved_settings,
                approval_id=approval_id,
                target_state=transition[0],
                request_id=_request_id(request),
                principal=device,
                decision=transition[1],
                scope=transition[2],
            )
        store.append_audit_event(
            event_type="approval_response_created",
            actor_type="device",
            actor_id=device.device_id,
            node_id=approval["node_id"],
            agent_id=approval["agent_id"],
            session_id=approval["session_id"],
            approval_id=approval_id,
            request_id=_request_id(request),
            payload_redacted={
                "decision_type": payload.decision_type,
                "constraint_count": len(payload.constraints),
                "policy_proposal_id": policy_proposal_id,
            },
        )
        event_type = (
            "approval.needs_info"
            if payload.decision_type == "needs_info"
            else "approval.response.created"
        )
        store.create_event(
            node_id=approval["node_id"],
            agent_id=approval["agent_id"],
            session_id=approval["session_id"],
            event_type=event_type,
            payload={
                "approval_id": approval_id,
                "approval_response_id": response["approval_response_id"],
                "decision_type": payload.decision_type,
            },
        )
        return ApprovalResponse.model_validate(response)

    @app.get(
        "/v1/approvals/{approval_id}/policy-proposals",
    )
    def list_approval_policy_proposals(
        approval_id: str,
        _device: VerifiedDevice = signed_device_dependency,
    ) -> dict[str, list[ApprovalPolicyProposal]]:
        _get_approval_or_404(store, approval_id)
        responses = store.list_approval_responses(approval_id)
        proposals = []
        for response in responses:
            proposal_id = response.get("policy_proposal_id")
            if proposal_id:
                proposals.append(
                    ApprovalPolicyProposal.model_validate(
                        store.get_approval_policy_proposal(proposal_id)
                    )
                )
        return {"policy_proposals": proposals}

    @app.post(
        "/v1/voice/sessions",
        response_model=VoiceSession,
        status_code=status.HTTP_201_CREATED,
    )
    def create_voice_session(
        payload: CreateVoiceSessionRequest,
        request: Request,
        device: VerifiedDevice = signed_device_dependency,
    ) -> VoiceSession:
        require_device_capability(
            store=store,
            settings=resolved_settings,
            device=device,
            capability="voice",
            request_id=_request_id(request),
            agent_id=payload.agent_id,
        )
        session = _engage_handoff(
            store=store,
            settings=resolved_settings,
            handoff_kind="voice_prompt",
            handoff_ref="new",
            node_id=resolved_settings.node_id,
            agent_id=payload.agent_id,
            work_ref=payload.session_id,
            risk_family=payload.risk_family,
            clearance_ref=None,
            request_id=_request_id(request),
            actor_type="device",
            actor_id=device.device_id,
            engage=lambda: store.create_voice_session(
                {
                    "node_id": resolved_settings.node_id,
                    "agent_id": payload.agent_id,
                    "session_id": payload.session_id,
                    "created_by_device_id": device.device_id,
                    "mode": payload.mode,
                    "state": "active",
                    "risk_family": payload.risk_family,
                }
            ),
        )
        store.append_audit_event(
            event_type="voice_session_created",
            actor_type="device",
            actor_id=device.device_id,
            node_id=session["node_id"],
            agent_id=session["agent_id"],
            session_id=session.get("session_id"),
            voice_session_id=session["voice_session_id"],
            request_id=_request_id(request),
            payload_redacted={"mode": payload.mode},
        )
        store.create_operator_session(
            {
                "session_id": session["voice_session_id"],
                "session_type": "voice",
                "agent_id": session["agent_id"],
                "state": session["state"],
                "owner_device_id": device.device_id,
                "capability_requirements": ["voice"],
                "context": {
                    "hermes_session_id": payload.session_id,
                    "mode": payload.mode,
                    "risk_family": payload.risk_family,
                },
            }
        )
        store.create_event(
            node_id=session["node_id"],
            agent_id=session["agent_id"],
            session_id=session.get("session_id"),
            event_type="voice.session.created",
            payload={"voice_session_id": session["voice_session_id"], "mode": payload.mode},
        )
        return VoiceSession.model_validate(session)

    @app.get("/v1/voice/sessions/{session_id}", response_model=VoiceSession)
    def get_voice_session(
        session_id: str,
        _device: VerifiedDevice = signed_device_dependency,
    ) -> VoiceSession:
        try:
            return VoiceSession.model_validate(store.get_voice_session(session_id))
        except KeyError as exc:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "voice session not found") from exc

    @app.post(
        "/v1/voice/sessions/{session_id}/messages",
        response_model=VoiceMessage,
        status_code=status.HTTP_201_CREATED,
    )
    def create_voice_message(
        session_id: str,
        payload: CreateVoiceMessageRequest,
        request: Request,
        device: VerifiedDevice = signed_device_dependency,
    ) -> VoiceMessage:
        session = _get_voice_session_or_404(store, session_id)
        require_device_capability(
            store=store,
            settings=resolved_settings,
            device=device,
            capability="voice",
            request_id=_request_id(request),
            node_id=session["node_id"],
            agent_id=session["agent_id"],
        )
        message = store.create_voice_message(
            {
                "voice_session_id": session_id,
                "sender_type": "user",
                "body": payload.body,
                "input_mode": payload.input_mode,
            }
        )
        store.append_audit_event(
            event_type="voice_message_created",
            actor_type="device",
            actor_id=device.device_id,
            node_id=session["node_id"],
            agent_id=session["agent_id"],
            session_id=session.get("session_id"),
            voice_session_id=session_id,
            request_id=_request_id(request),
            payload_redacted={"input_mode": payload.input_mode, "body_length": len(payload.body)},
        )
        store.create_event(
            node_id=session["node_id"],
            agent_id=session["agent_id"],
            session_id=session.get("session_id"),
            event_type="voice.message.created",
            payload={
                "voice_session_id": session_id,
                "voice_message_id": message["voice_message_id"],
            },
        )
        return VoiceMessage.model_validate(message)

    @app.post("/v1/voice/sessions/{session_id}/close", response_model=VoiceSession)
    def close_voice_session(
        session_id: str,
        request: Request,
        device: VerifiedDevice = signed_device_dependency,
    ) -> VoiceSession:
        session = _get_voice_session_or_404(store, session_id)
        require_device_capability(
            store=store,
            settings=resolved_settings,
            device=device,
            capability="voice",
            request_id=_request_id(request),
            node_id=session["node_id"],
            agent_id=session["agent_id"],
        )
        updated = store.update_voice_session_state(session_id, "closed")
        store.append_audit_event(
            event_type="voice_session_closed",
            actor_type="device",
            actor_id=device.device_id,
            node_id=session["node_id"],
            agent_id=session["agent_id"],
            session_id=session.get("session_id"),
            voice_session_id=session_id,
            request_id=_request_id(request),
            payload_redacted={},
        )
        store.create_event(
            node_id=session["node_id"],
            agent_id=session["agent_id"],
            session_id=session.get("session_id"),
            event_type="voice.session.closed",
            payload={"voice_session_id": session_id},
        )
        _update_operator_session_if_exists(
            store,
            session_id,
            "closed",
            owner_device_id=device.device_id,
        )
        return VoiceSession.model_validate(updated)

    @app.websocket("/v1/tui/sessions/{session_id}/stream")
    async def tui_stream(websocket: WebSocket, session_id: str) -> None:
        attach_token = websocket.query_params.get("attach_token")
        attach = store.verify_tui_attach_token(attach_token) if attach_token else None
        if attach is None:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return
        try:
            session = store.get_tui_session(session_id)
        except KeyError:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return
        if attach["session_id"] != session_id or (
            session["user_device_id"] != _RELAY_TUI_OWNER
            and session["user_device_id"] != attach["device_id"]
        ):
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return
        if session["state"] in {"closed", "failed"} or not tui_manager.is_running(session_id):
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return

        await tui_manager.attach(session_id)
        await websocket.accept()
        await websocket.send_json(
            {"type": "state", "session_id": session_id, "state": "active"}
        )
        await websocket.send_json(
            {
                "type": "audit_notice",
                "session_id": session_id,
                "message": "TUI I/O metadata is audited; terminal contents are not logged.",
            }
        )
        receive_task = asyncio.create_task(websocket.receive_json())
        try:
            while True:
                output = await tui_manager.next_output(session_id, timeout=0.05)
                if output:
                    await websocket.send_json(
                        {"type": "output", "session_id": session_id, "data": output}
                    )

                if not receive_task.done():
                    await asyncio.sleep(0.01)
                    continue

                frame = validate_tui_frame(receive_task.result())
                if await _handle_tui_frame(
                    frame=frame,
                    session_id=session_id,
                    websocket=websocket,
                    store=store,
                    tui_manager=tui_manager,
                    device_id=attach["device_id"],
                ):
                    return
                receive_task = asyncio.create_task(websocket.receive_json())
        except WebSocketDisconnect:
            await tui_manager.detach(session_id)
        except ValueError as exc:
            await websocket.send_json({"type": "error", "message": str(exc)})
        finally:
            if not receive_task.done():
                receive_task.cancel()

    return app


def _local_node_row(settings: Settings) -> dict[str, Any]:
    """The node row this gateway's own identity implies, used ONLY to seed a row
    that does not exist yet.

    ``capabilities`` is spelled out rather than left to ``upsert_node``'s default
    so the seed is explicit about everything it writes.
    """
    return {
        "node_id": settings.node_id,
        "display_name": settings.node_display_name,
        "environment": settings.node_environment,
        "gateway_base_url": settings.gateway_base_url,
        "node_fingerprint": settings.node_fingerprint,
        "gateway_version": settings.gateway_version,
        "hermes_version": settings.hermes_version,
        "health": "online",
        "tags": ["self-hosted", "tailscale-first"],
        "capabilities": [dict(capability) for capability in DEFAULT_NODE_CAPABILITIES],
    }


def _ensure_local_node(store: SQLiteStore, settings: Settings) -> None:
    """Seed this gateway's own node row when it is ABSENT. Never otherwise.

    Read before write, the same discipline ``store.initialize()`` applies to its
    trust-context backfill, and for the same reason one level up: production boots
    through this factory (``uvicorn.run("hermes_gateway.app:create_app",
    factory=True)``), so an exception here is a hard startup failure. The original
    unconditional ``INSERT ... ON CONFLICT DO UPDATE`` asked SQLite for the write
    lock on EVERY boot, so a gateway restarting while anything else was mid-write
    blocked for the whole busy timeout and then died with "database is locked" on a
    perfectly healthy database.

    Guarding that with a field comparison was not enough, because boot compared
    fields boot does not OWN. ``POST /v1/nodes/register`` is the bridge's endpoint
    for the node row and writes the bridge's real ``hermes_version``, its ``tags``
    and its reachable ``gateway_base_url``. Boot wanted
    ``settings.hermes_version`` (``os.getenv("HERMES_VERSION")``, i.e. ``None``
    unless someone exports it), a hardcoded ``["self-hosted", "tailscale-first"]``
    and the locally configured base URL. Those are permanently unequal to what the
    bridge wrote, so the comparison could never short-circuit: every boot took the
    write lock and clobbered ``hermes_version`` back to NULL, the next registration
    restored it, and the two sides fought forever. Measured out of process on a
    real uvicorn boot: file-change counter +1 per boot and
    ``'2.4.1-bridge' -> None``.

    So boot owns exactly one thing — that a row exists at all, because the node row
    is how the gateway knows its own identity — and owns no columns. Nothing here
    can fight with ``/v1/nodes/register`` because nothing here runs once that
    endpoint (or an earlier boot) has created the row. Fields that genuinely need
    correcting are corrected by the endpoint that owns them: liveness by
    ``/v1/nodes/register`` and ``/v1/health``, identity by re-registration.

    Together with the guard in ``initialize()`` and the already-guarded
    ``seed_mock_data`` (which returns early once agents exist), booting against a
    populated, **already-migrated** database whose rows live under
    ``settings.node_id`` performs zero writes — including after a registration.

    KNOWN GAPS (verified outstanding; the sentence above is scoped, not absolute):

    1. A MIGRATING BOOT STILL WRITES, and that is the next boot after this ships.
       ``initialize()`` writes when the schema is not current. Measured against a
       fixture built by the currently-deployed code, the first boot on this branch
       creates the ``approval_grants`` table and its index (change counter +2), and
       under an ordinary ``BEGIN IMMEDIATE`` holder that boot dies at
       ``store.initialize()`` with "database is locked" after the busy timeout. It
       is a one-shot migration, but the one shot is a hard-startup-failure path on
       a perfectly healthy database.
    2. ``seed_mock_data`` IS STILL A BOOT WRITE, on a different guard. It is on by
       default (``seed_mock_data: bool = True``, ``ACT_SEED_MOCK_DATA``) and skips
       only when ``list_agents(node_id=settings.node_id)`` is non-empty. Both that
       guard and the one below key on ``settings.node_id``, while
       ``/v1/nodes/register`` deliberately stores under ``payload.node_id`` — so a
       populated database whose rows live under another node id (or a renamed
       ``HERMES_NODE_ID``) reaches it. Measured: boot writes nodes + agents +
       sessions rows, and under a write-lock holder dies here in ``upsert_node``.
    3. Zero writes does not imply immunity to "database is locked" — see the
       KNOWN GAP note in ``store.initialize()``: in rollback-journal mode an
       EXCLUSIVE holder blocks readers, so even a write-free boot can fail.
    """
    try:
        store.get_node(settings.node_id)
    except KeyError:
        store.upsert_node(_local_node_row(settings))


def _create_approval_request(
    *,
    store: SQLiteStore,
    settings: Settings,
    request: Request,
    payload: CreateApprovalRequest,
    caller: HermesLocalCaller,
) -> ApprovalRequest:
    node_id = payload.node_id or settings.node_id
    approval_id = new_id("appr")
    risk_family = risk_family_from_request(
        risk_family=payload.risk_family,
        risk_category=payload.risk_category,
        risk_level=payload.risk_level,
    )
    capability, from_extension = capability_from_request(
        capability=payload.capability,
        extensions=payload.extensions,
    )
    resolution = resolve_capability_risk(
        store=store,
        settings=settings,
        node_id=node_id,
        agent_id=payload.agent_id,
        session_id=payload.session_id,
        capability=capability,
        requested_risk_family=risk_family,
        request_id=_request_id(request),
        actor_type="hermes",
        actor_id=payload.agent_id,
    )
    risk_family = resolution.resolved_risk_family
    contract_fields = build_clearance_contract_fields(
        settings=settings,
        approval_id=approval_id,
        payload_redacted=payload.full_payload_redacted,
        extensions=payload.extensions,
        risk_family=risk_family,
        expires_at=payload.expires_at.isoformat().replace("+00:00", "Z"),
        requested_short_code=payload.short_code,
    )
    operator_message, operator_message_audit = sanitize_operator_message(
        raw_message=payload.operator_message,
        settings=settings,
        agent_id=payload.agent_id,
        session_id=payload.session_id,
        risk_family=risk_family,
        requested_tool=payload.requested_tool,
    )
    requested_by = f"local:{caller.host or 'unknown'}"
    risk_vector = payload.risk_vector.model_dump() if payload.risk_vector else None
    # Standing grants (read side): a live grant from an earlier "approve for
    # this session / agent / forever" clears this request without prompting.
    # Looked up BEFORE creation so the row is written in its final state, but the
    # row is always written — an auto-satisfied action is still an attempted
    # action and must appear in the trail.
    standing = standing_grant_for_request(
        store=store,
        settings=settings,
        node_id=node_id,
        agent_id=payload.agent_id,
        session_id=payload.session_id,
        requested_tool=payload.requested_tool,
        params_fingerprint=contract_fields["params_fingerprint"],
        risk_family=risk_family,
        risk_vector=risk_vector,
    )
    approval = store.create_approval(
        {
            "approval_id": approval_id,
            "action_id": payload.action_id,
            "node_id": node_id,
            "agent_id": payload.agent_id,
            "session_id": payload.session_id,
            "requested_tool": payload.requested_tool,
            "capability": capability,
            "risk_level": payload.risk_level,
            "risk_category": payload.risk_category or "unknown_action",
            "risk_family": risk_family,
            "risk_vector": risk_vector,
            **contract_fields,
            "operator_message": operator_message,
            "audit_correlation_id": payload.audit_correlation_id,
            "aircraft": resolution.aircraft,
            "requested_by": requested_by,
            "summary": payload.summary,
            "full_payload_redacted": payload.full_payload_redacted,
            "resource_scope": payload.resource_scope,
            "state": standing.initial_state,
            "options": payload.options or ["deny"],
            "expires_at": payload.expires_at.isoformat().replace("+00:00", "Z"),
        }
    )
    store.append_audit_event(
        event_type="approval_requested",
        actor_type="hermes",
        actor_id=payload.agent_id,
        node_id=node_id,
        agent_id=payload.agent_id,
        session_id=payload.session_id,
        approval_id=approval_id,
        request_id=_request_id(request),
        payload_redacted={
            "requested_tool": payload.requested_tool,
            "risk_level": payload.risk_level,
            "risk_category": payload.risk_category or "unknown_action",
            "risk_family": approval["risk_family"],
            "capability": approval.get("capability"),
            "capability_risk_source": resolution.source,
            "capability_registry_entry_id": resolution.registry_entry_id,
            "operator_message": operator_message_audit,
            "audit_correlation_id": payload.audit_correlation_id,
            "ignored_self_declared_fields": [
                field
                for field, value in {
                    "aircraft": payload.aircraft,
                    "requested_by": payload.requested_by,
                    "params_fingerprint": payload.params_fingerprint,
                    "capability_extension": "agentickvm.capability" if from_extension else None,
                }.items()
                if value is not None
            ],
        },
    )
    store.create_event(
        node_id=node_id,
        agent_id=payload.agent_id,
        session_id=payload.session_id,
        event_type="approval.requested",
        payload={
            "approval_id": approval_id,
            "state": approval["state"],
            "risk_level": payload.risk_level,
            "risk_family": approval["risk_family"],
        },
    )
    if standing.grant is not None:
        approval = record_auto_satisfaction(
            store=store,
            approval=approval,
            grant=standing.grant,
            request_id=_request_id(request),
        )
    elif standing.refusal is not None:
        record_auto_satisfy_refusal(
            store=store,
            approval=approval,
            reason=standing.refusal,
            request_id=_request_id(request),
        )
    return ApprovalRequest.model_validate(approval)


def _create_mobile_notification(
    *,
    store: SQLiteStore,
    settings: Settings,
    request: Request,
    payload: MobileNotifyRequest,
) -> Notification:
    composed = compose_notification(payload)
    notification = store.create_notification(
        {
            "node_id": settings.node_id,
            "agent_id": payload.agent_id,
            "session_id": payload.session_id,
            "action_id": payload.action_id,
            "category": payload.category,
            "urgency": payload.urgency,
            "title_safe": composed.title,
            "body_safe": composed.body,
            "composition_mode": composed.mode,
            "unsafe_input_detected": composed.unsafe_input_detected,
            "dedupe_key": payload.dedupe_key,
            "state": "queued",
        }
    )
    store.append_audit_event(
        event_type="notification_queued",
        actor_type="hermes",
        actor_id=payload.agent_id,
        node_id=settings.node_id,
        agent_id=payload.agent_id,
        session_id=payload.session_id,
        notification_id=notification["notification_id"],
        request_id=_request_id(request),
        payload_redacted={
            "category": payload.category,
            "urgency": payload.urgency,
            "composition_mode": composed.mode,
            "template": composed.template,
            "unsafe_input_detected": composed.unsafe_input_detected,
            "unsafe_reasons": composed.unsafe_reasons,
            "safe_fields": composed.safe_fields,
        },
    )
    store.create_event(
        node_id=settings.node_id,
        agent_id=payload.agent_id,
        session_id=payload.session_id,
        event_type="notification.created",
        payload={
            "notification_id": notification["notification_id"],
                "category": payload.category,
                "urgency": payload.urgency,
                "composition_mode": composed.mode,
            },
        )
    return Notification.model_validate(notification)


def _expire_pairing_if_needed(store: SQLiteStore, pairing: dict[str, Any]) -> dict[str, Any]:
    if pairing["status"] == "pending" and parse_utc(pairing["expires_at"]) <= now_utc():
        store.set_pairing_status(pairing["pairing_id"], "expired")
        pairing = store.get_pairing_session(
            pairing["pairing_id"], include_token="pairing_token_hash" in pairing
        )
    return pairing


def _expire_pending_approvals(store: SQLiteStore) -> None:
    for approval in store.list_approvals(state="pending"):
        if parse_utc(approval["expires_at"]) <= now_utc():
            store.resolve_approval(
                approval["approval_id"],
                "expired",
                decision_metadata={"reason": "expiry_scan"},
            )
            request_id = new_id("req")
            store.append_audit_event(
                event_type="approval_expired",
                actor_type="gateway",
                actor_id="gateway",
                node_id=approval["node_id"],
                agent_id=approval["agent_id"],
                session_id=approval["session_id"],
                approval_id=approval["approval_id"],
                request_id=request_id,
                payload_redacted={"reason": "expiry_scan"},
            )
            store.create_event(
                node_id=approval["node_id"],
                agent_id=approval["agent_id"],
                session_id=approval["session_id"],
                event_type="approval.resolved",
                payload={"approval_id": approval["approval_id"], "state": "expired"},
            )


def _transition_approval(
    *,
    store: SQLiteStore,
    settings: Settings,
    approval_id: str,
    target_state: str,
    request_id: str,
    principal: VerifiedDevice,
    decision: str | None,
    scope: str | None,
) -> ApprovalDecisionResponse:
    try:
        approval = store.get_approval(approval_id)
    except KeyError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "approval not found") from exc

    if approval["state"] != "pending":
        raise HTTPException(status.HTTP_409_CONFLICT, "approval is not pending")

    channel = principal.clearance_channel
    if target_state == "approved":
        channel_decision = enforce_clearance_channel(
            store=store,
            settings=settings,
            approval=approval,
            channel=channel,
            actor_type="device",
            actor_id=principal.device_id,
            request_id=request_id,
        )
    else:
        channel_decision = evaluate_clearance_channel(
            store=store,
            settings=settings,
            approval=approval,
            channel=channel,
        )

    if target_state in {"approved", "denied"} and parse_utc(approval["expires_at"]) <= now_utc():
        store.resolve_approval(
            approval_id,
            "expired",
            decision_metadata={"reason": "decision_after_expiry"},
        )
        store.append_audit_event(
            event_type="approval_expired",
            actor_type="gateway",
            actor_id="gateway",
            node_id=approval["node_id"],
            agent_id=approval["agent_id"],
            session_id=approval["session_id"],
            approval_id=approval_id,
            request_id=request_id,
            payload_redacted={"reason": "decision_after_expiry"},
        )
        store.create_event(
            node_id=approval["node_id"],
            agent_id=approval["agent_id"],
            session_id=approval["session_id"],
            event_type="approval.resolved",
            payload={"approval_id": approval_id, "state": "expired"},
        )
        raise HTTPException(status.HTTP_409_CONFLICT, "approval expired")

    device_channel: str | None = None
    try:
        device_channel = channel_for_device(store.get_device(principal.device_id))
    except KeyError:
        device_channel = None

    # Change 5 — channel policy / risk tiering: the risk family and/or a high-risk
    # per-surface class can mandate the mobile-signed channel. Fail-closed if the
    # deciding channel does not satisfy it. Routed through the canonical combined
    # entry point (the same one the standing-grant gate uses) so the decision path
    # and the auto-satisfy path enforce one identical policy.
    if target_state == "approved":
        required_channels = required_channels_for_request(
            risk_family=approval.get("risk_family"),
            risk_vector=approval.get("risk_vector"),
            # Deliberately NOT passed ``settings`` here, unlike the standing-grant
            # gate. On this path the operator's risk_channel_map is already fully
            # enforced upstream by ``enforce_clearance_channel`` ->
            # ``ClearanceChannelPolicy.evaluate``, which rejects a device whose
            # channel is not in the map's eligible list for the family. What this
            # check adds is the part evaluate cannot express: the static
            # MOBILE_MANDATORY_RISK_FAMILIES *floor* config must not downgrade.
            # Threading settings in as well would be unreachable code — no input
            # exists for which it could change the outcome.
        )
        if not channel_satisfies(device_channel, required_channels):
            store.append_audit_event(
                event_type="approval_channel_rejected",
                actor_type="device",
                actor_id=principal.device_id,
                node_id=approval["node_id"],
                agent_id=approval["agent_id"],
                session_id=approval["session_id"],
                approval_id=approval_id,
                request_id=request_id,
                payload_redacted={"required_channels": list(required_channels or ())},
            )
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                "approval risk class requires a different decision channel",
            )

    # Change 1 — authority provenance.
    approved_by = authority_from_channel(device_channel)
    human_approved = target_state == "approved" and approved_by in {
        "human_mobile",
        "human_local",
    }
    store.resolve_approval(
        approval_id,
        target_state,
        decision_scope=scope,
        decision_actor_device_id=principal.device_id,
        decision_metadata={
            "decision": decision,
            "state": target_state,
            **decision_metadata(channel_decision),
        },
        approved_by=approved_by,
        human_approved=human_approved,
    )
    # Standing grants: a decision carrying a scope other than "once" is the
    # operator saying "and don't ask me again for this". Persist that as an
    # explicit, hard-expiring, revocable grant instead of leaving
    # decision_scope as a write nothing ever reads.
    grant: dict[str, Any] | None = None
    if target_state == "approved":
        grant = mint_grant_for_decision(
            store=store,
            settings=settings,
            approval=approval,
            scope=scope,
            request_id=request_id,
            decided_by_device_id=principal.device_id,
        )
    event_type = {
        "approved": "approval_decision",
        "denied": "approval_decision",
        "expired": "approval_expired",
        "cancelled": "approval_cancelled",
    }[target_state]
    store.append_audit_event(
        event_type=event_type,
        actor_type="device",
        actor_id=principal.device_id,
        node_id=approval["node_id"],
        agent_id=approval["agent_id"],
        session_id=approval["session_id"],
        approval_id=approval_id,
        request_id=request_id,
        payload_redacted={
            "decision": decision,
            "scope": scope,
            "state": target_state,
            "grant_id": grant["grant_id"] if grant else None,
            **decision_metadata(channel_decision),
        },
    )
    store.create_event(
        node_id=approval["node_id"],
        agent_id=approval["agent_id"],
        session_id=approval["session_id"],
        event_type="approval.resolved",
        payload={"approval_id": approval_id, "state": target_state, "scope": scope},
    )
    return ApprovalDecisionResponse(
        approval_id=approval_id,
        state=target_state,  # type: ignore[arg-type]
        applied_scope=scope,  # type: ignore[arg-type]
    )


def _audit_channel_auth_failure(
    *,
    store: SQLiteStore,
    request_id: str,
    approval: dict[str, Any],
    actor_id: str,
    channel: str,
    reason: str,
) -> None:
    store.append_audit_event(
        event_type="clearance_channel_rejected",
        actor_type="device",
        actor_id=actor_id,
        node_id=approval["node_id"],
        agent_id=approval["agent_id"],
        session_id=approval["session_id"],
        approval_id=approval["approval_id"],
        request_id=request_id,
        payload_redacted={
            "channel": channel,
            "risk_family": approval.get("risk_family"),
            "reason": reason,
            "eligibility_result": "rejected",
        },
    )


def _require_permission(device: VerifiedDevice, permission: str) -> None:
    if permission not in device.permissions:
        raise HTTPException(status.HTTP_403_FORBIDDEN, f"device lacks {permission} permission")


def _is_downgrade(store: SQLiteStore, entry: dict[str, Any]) -> bool:
    approved = store.get_approved_capability_risk(
        node_id=entry["node_id"],
        agent_id=entry["agent_id"],
        capability=entry["capability"],
    )
    if approved is None:
        return False
    return _risk_rank(entry["risk_family"]) < _risk_rank(approved["risk_family"])


def _risk_rank(risk_family: str) -> int:
    return {
        "observe": 0,
        "read_only": 1,
        "routine": 2,
        "external_effect": 3,
        "destructive": 4,
        "credential_or_secret": 5,
        "safety_critical": 6,
        "irreversible": 7,
    }.get(risk_family, 3)


def _require_tui_capability(store: SQLiteStore, *, node_id: str, agent_id: str) -> None:
    try:
        node = store.get_node(node_id)
        agent = store.get_agent(node_id, agent_id)
    except KeyError as exc:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "TUI capability unavailable") from exc
    if _has_available_capability(node, "tui") or _has_available_capability(agent, "tui"):
        return
    raise HTTPException(status.HTTP_403_FORBIDDEN, "TUI capability unavailable")


def _has_available_capability(record: dict[str, Any], capability: str) -> bool:
    for item in record.get("capabilities", []):
        if item.get("name") == capability and item.get("status") == "available":
            return True
    return False


def _tui_risk_label(risk_level: str) -> str:
    return {
        "low": "operator terminal - low risk",
        "medium": "operator terminal - medium risk",
        "high": "operator terminal - high risk",
        "critical": "operator terminal - critical risk",
    }.get(risk_level, "operator terminal - high risk")


def _require_tui_start_clearance(
    *,
    store: SQLiteStore,
    node_id: str,
    agent_id: str,
    work_ref: str,
    risk_family: str,
    clearance_ref: str | None,
    params_fingerprint: str,
    request_id: str,
    device: VerifiedDevice,
) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    if risk_family in LOW_RISK_FAMILIES:
        return None, {"eligibility_result": "not_required"}
    return _require_bound_clearance(
        store=store,
        handoff_kind="tui_start",
        handoff_ref="new",
        node_id=node_id,
        agent_id=agent_id,
        work_ref=work_ref,
        risk_family=risk_family,
        clearance_ref=clearance_ref,
        request_id=request_id,
        actor_type="device",
        actor_id=device.device_id,
        params_fingerprint=params_fingerprint,
    )


# Relay (agent terminal mirror) sessions are node-owned and read-only; any paired
# device with the `tui` capability may attach to watch them.
_RELAY_TUI_OWNER = "__relay__"


def _owned_tui_session(
    store: SQLiteStore,
    session_id: str,
    device: VerifiedDevice,
) -> dict[str, Any]:
    try:
        session = store.get_tui_session(session_id)
    except KeyError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "TUI session not found") from exc
    if (
        session["user_device_id"] != _RELAY_TUI_OWNER
        and session["user_device_id"] != device.device_id
    ):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "TUI session belongs to another device")
    return session


def _require_approval_capability(
    *,
    store: SQLiteStore,
    settings: Settings,
    request: Request,
    device: VerifiedDevice,
    approval_id: str,
) -> None:
    approval = _get_approval_or_404(store, approval_id)
    require_device_capability(
        store=store,
        settings=settings,
        device=device,
        capability="approvals",
        request_id=_request_id(request),
        node_id=approval["node_id"],
        agent_id=approval["agent_id"],
    )


def _mission_id_from_context(context: dict[str, Any]) -> str | None:
    value = context.get("mission_id")
    return value if isinstance(value, str) and value else None


def _update_operator_session_if_exists(
    store: SQLiteStore,
    session_id: str,
    state: str,
    *,
    owner_device_id: str | None = None,
    return_summary: str | None = None,
) -> None:
    try:
        store.update_operator_session_state(
            session_id,
            state,
            owner_device_id=owner_device_id,
            return_summary=return_summary,
        )
    except KeyError:
        return


def _get_approval_or_404(store: SQLiteStore, approval_id: str) -> dict[str, Any]:
    try:
        return store.get_approval(approval_id)
    except KeyError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "approval not found") from exc


def _get_assistance_session_or_404(store: SQLiteStore, session_id: str) -> dict[str, Any]:
    try:
        return store.get_assistance_session(session_id)
    except KeyError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "TUA session not found") from exc


def _get_browser_session_or_404(store: SQLiteStore, session_id: str) -> dict[str, Any]:
    try:
        return store.get_browser_assistance_session(session_id)
    except KeyError as exc:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND, "browser assistance session not found"
        ) from exc


def _get_voice_session_or_404(store: SQLiteStore, session_id: str) -> dict[str, Any]:
    try:
        return store.get_voice_session(session_id)
    except KeyError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "voice session not found") from exc


def _record_tui_state_change(
    *,
    store: SQLiteStore,
    session_id: str,
    event_type: str,
    request_id: str,
    actor_device_id: str,
) -> dict[str, Any]:
    target_state = "closed" if event_type == "tui_session_closed" else "detached"
    session = store.update_tui_session_state(session_id, target_state)
    _update_operator_session_if_exists(
        store,
        session_id,
        session["state"],
        owner_device_id=actor_device_id,
    )
    audit = store.append_audit_event(
        event_type=event_type,
        actor_type="device",
        actor_id=actor_device_id,
        node_id=session["node_id"],
        agent_id=session["agent_id"],
        session_id=session_id,
        request_id=request_id,
        payload_redacted={"state": session["state"]},
    )
    session = store.add_tui_audit_ref(session_id, audit["audit_event_id"])
    store.create_event(
        node_id=session["node_id"],
        agent_id=session["agent_id"],
        session_id=session_id,
        event_type="tui.session.state",
        payload={"session_id": session_id, "state": session["state"]},
    )
    return session


async def _handle_tui_frame(
    *,
    frame: dict[str, Any],
    session_id: str,
    websocket: WebSocket,
    store: SQLiteStore,
    tui_manager: LocalPtyManager,
    device_id: str,
) -> bool:
    frame_type = frame["type"]
    if frame_type == "ping":
        await websocket.send_json({"type": "pong", "session_id": session_id})
        return False
    if frame_type == "resize":
        await tui_manager.resize(
            session_id,
            rows=int(frame.get("rows", 24)),
            cols=int(frame.get("cols", 80)),
        )
        return False
    if frame_type == "input":
        text = str(frame.get("data", ""))
        await tui_manager.write(session_id, text)
        _audit_tui_io_metadata(
            store=store,
            session_id=session_id,
            device_id=device_id,
            event_type="tui_input_sent",
            byte_count=len(text.encode("utf-8")),
            line_count=max(text.count("\n"), 1 if text else 0),
        )
        return False
    if frame_type == "paste":
        text = str(frame.get("data", frame.get("text", "")))
        await tui_manager.write(session_id, text)
        _audit_tui_io_metadata(
            store=store,
            session_id=session_id,
            device_id=device_id,
            event_type="tui_paste_sent",
            byte_count=len(text.encode("utf-8")),
            line_count=max(text.count("\n"), 1 if text else 0),
            risk_warnings=_paste_risk_warnings(text),
        )
        return False
    if frame_type == "detach":
        await tui_manager.detach(session_id)
        _record_tui_state_change(
            store=store,
            session_id=session_id,
            event_type="tui_session_detached",
            request_id=new_id("req"),
            actor_device_id=device_id,
        )
        await websocket.send_json(
            {"type": "state", "session_id": session_id, "state": "detached"}
        )
        await websocket.close()
        return True
    if frame_type == "close":
        await tui_manager.close(session_id)
        _record_tui_state_change(
            store=store,
            session_id=session_id,
            event_type="tui_session_closed",
            request_id=new_id("req"),
            actor_device_id=device_id,
        )
        await websocket.send_json({"type": "state", "session_id": session_id, "state": "closed"})
        await websocket.close()
        return True
    return False


def _audit_tui_io_metadata(
    *,
    store: SQLiteStore,
    session_id: str,
    device_id: str,
    event_type: str,
    byte_count: int,
    line_count: int,
    risk_warnings: list[str] | None = None,
) -> None:
    session = store.get_tui_session(session_id)
    audit = store.append_audit_event(
        event_type=event_type,
        actor_type="device",
        actor_id=device_id,
        node_id=session["node_id"],
        agent_id=session["agent_id"],
        session_id=session_id,
        request_id=new_id("req"),
        payload_redacted={
            "byte_count": byte_count,
            "line_count": line_count,
            "risk_warnings": risk_warnings or [],
            "contents_logged": False,
        },
    )
    store.add_tui_audit_ref(session_id, audit["audit_event_id"])


def _paste_risk_warnings(text: str) -> list[str]:
    warnings = []
    if text.count("\n") > 1:
        warnings.append("multiline_paste")
    if any(ord(char) < 32 and char not in "\n\r\t" for char in text):
        warnings.append("control_characters")
    if has_secret_text(text):
        warnings.append("secret_like_text")
    return warnings


def _request_id(request: Request) -> str:
    return request.headers.get("X-Request-Id") or new_id("req")


def _websocket_token(websocket: WebSocket) -> str | None:
    query_token = websocket.query_params.get("access_token")
    if query_token:
        return query_token
    header = websocket.headers.get("Authorization") or websocket.headers.get("authorization")
    if header and header.lower().startswith("bearer "):
        return header.split(" ", 1)[1]
    return None

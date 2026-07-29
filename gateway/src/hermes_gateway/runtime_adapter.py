from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from fastapi import HTTPException, status

from .capabilities import require_runtime_capability
from .capability_registry import capability_from_request, resolve_capability_risk
from .clearance_contract import (
    build_clearance_contract_fields,
    sanitize_operator_message,
)
from .clearance_policy import risk_family_from_request
from .config import Settings
from .grants import (
    record_auto_satisfaction,
    record_auto_satisfy_refusal,
    standing_grant_for_request,
)
from .handoff import engage_handoff as _engage_handoff
from .ids import new_id
from .notification_composer import compose_notification
from .schemas import (
    ApprovalRequest,
    ApprovalResponse,
    BrowserAssistanceSession,
    CreateAssistanceRequest,
    CreateBrowserAssistanceSessionRequest,
    HermesApprovalRequestedRequest,
    Mission,
    MobileNotifyRequest,
    Notification,
    RuntimeApprovalResult,
    RuntimeBrowserAssistanceResult,
    RuntimeContextRequest,
    RuntimeContextResponse,
    RuntimeCreateVoiceSessionRequest,
    RuntimeTuaResult,
    RuntimeVoiceResult,
    VoiceSession,
)
from .security import expires_in, now_utc, parse_utc
from .store import SQLiteStore


@dataclass(frozen=True)
class RuntimeWorkState:
    actor_ref: str
    state: str
    node_ref: str | None = None
    work_ref: str | None = None
    display_name: str | None = None
    unit_ref: str | None = None
    unit_state: str = "running"
    unit_title: str | None = None
    unit_summary: str | None = None
    operation: str | None = None
    target: str | None = None
    capabilities: list[dict[str, Any]] | None = None


@dataclass(frozen=True)
class RuntimeNotice:
    title: str
    body: str
    urgency: str
    category: str
    actor_ref: str
    work_ref: str
    action_ref: str | None = None
    deep_link: str | None = None


@dataclass(frozen=True)
class RuntimeNoticeResult:
    notice_ref: str
    state: str
    raw: Any


@dataclass(frozen=True)
class RuntimeClearanceRequest:
    operation: str
    risk_level: str
    summary: str
    payload_redacted: dict[str, Any]
    actor_ref: str
    work_ref: str
    expires_in_seconds: int
    scopes: list[str] | None = None
    action_ref: str | None = None
    node_ref: str | None = None
    risk_category: str | None = None
    risk_family: str = "external_effect"
    capability: str | None = None
    resource_scope: str | None = None
    operator_message: str | None = None
    audit_correlation_id: str | None = None
    short_code: str | None = None
    params_fingerprint: str | None = None
    extensions: dict[str, dict[str, Any]] | None = None
    aircraft: str | None = None
    requested_by: str | None = None


@dataclass(frozen=True)
class RuntimeClearanceHandle:
    clearance_ref: str
    state: str
    raw: Any


@dataclass(frozen=True)
class RuntimeClearanceDecision:
    clearance_ref: str
    state: str
    selected_scope: str | None
    decision_type: str | None
    alternate_directive: str | None
    user_message: str | None
    constraints: list[dict[str, Any]]
    result: RuntimeApprovalResult


@dataclass(frozen=True)
class RuntimeHandoffRequest:
    handoff_kind: str
    actor_ref: str
    work_ref: str
    reason: str
    node_ref: str | None = None
    clearance_ref: str | None = None
    risk_family: str = "external_effect"
    context_redacted: dict[str, Any] | None = None
    mode: str | None = None


@dataclass(frozen=True)
class RuntimeHandoffHandle:
    handoff_ref: str
    state: str
    raw: Any


@dataclass(frozen=True)
class RuntimeHandoffResult:
    handoff_ref: str
    state: str
    return_summary: str | None
    messages: list[dict[str, Any]]
    raw: Any


class RuntimeAdapter(Protocol):
    def record_work_state(
        self,
        work_state: RuntimeWorkState,
        *,
        request_id: str,
    ) -> Any: ...

    def publish_notice(
        self,
        notice: RuntimeNotice,
        *,
        request_id: str,
    ) -> RuntimeNoticeResult: ...

    def request_clearance(
        self,
        clearance: RuntimeClearanceRequest,
        *,
        request_id: str,
    ) -> RuntimeClearanceHandle: ...

    def check_clearance(
        self,
        clearance_ref: str,
    ) -> RuntimeClearanceDecision: ...

    def cancel_clearance(
        self,
        clearance_ref: str,
        *,
        request_id: str,
        actor_ref: str,
    ) -> RuntimeClearanceDecision: ...

    def request_handoff(
        self,
        handoff: RuntimeHandoffRequest,
        *,
        request_id: str,
        actor_ref: str,
    ) -> RuntimeHandoffHandle: ...

    def check_handoff(
        self,
        handoff_kind: str,
        handoff_ref: str,
    ) -> RuntimeHandoffResult: ...


@dataclass(frozen=True)
class HermesRuntimeAdapter:
    store: SQLiteStore
    settings: Settings

    def record_work_state(
        self,
        work_state: RuntimeWorkState,
        *,
        request_id: str,
    ) -> RuntimeContextResponse:
        return self.register_context(
            payload=RuntimeContextRequest(
                agent_id=work_state.actor_ref,
                display_name=work_state.display_name,
                agent_status=work_state.state,
                mission_id=work_state.unit_ref,
                mission_state=work_state.unit_state,
                session_id=work_state.work_ref,
                mission_title=work_state.unit_title,
                mission_summary=work_state.unit_summary,
                current_tool=work_state.operation,
                current_target=work_state.target,
                node_id=work_state.node_ref,
                capabilities=work_state.capabilities or [],
            ),
            request_id=request_id,
        )

    def publish_notice(
        self,
        notice: RuntimeNotice,
        *,
        request_id: str,
    ) -> RuntimeNoticeResult:
        notification = self.create_notification(
            payload=MobileNotifyRequest(
                title=notice.title,
                body=notice.body,
                urgency=notice.urgency,
                category=notice.category,
                agent_id=notice.actor_ref,
                session_id=notice.work_ref,
                action_id=notice.action_ref,
                deep_link=notice.deep_link,
            ),
            request_id=request_id,
        )
        return RuntimeNoticeResult(
            notice_ref=notification.notification_id,
            state=notification.state,
            raw=notification,
        )

    def request_clearance(
        self,
        clearance: RuntimeClearanceRequest,
        *,
        request_id: str,
    ) -> RuntimeClearanceHandle:
        approval = self.request_approval(
            payload=HermesApprovalRequestedRequest(
                requested_tool=clearance.operation,
                risk_level=clearance.risk_level,
                summary=clearance.summary,
                payload_redacted=clearance.payload_redacted,
                agent_id=clearance.actor_ref,
                session_id=clearance.work_ref,
                expires_in_seconds=clearance.expires_in_seconds,
                suggested_scopes=clearance.scopes,
                action_id=clearance.action_ref,
                node_id=clearance.node_ref,
                risk_category=clearance.risk_category,
                risk_family=clearance.risk_family,
                capability=clearance.capability,
                operator_message=clearance.operator_message,
                audit_correlation_id=clearance.audit_correlation_id,
                short_code=clearance.short_code,
                params_fingerprint=clearance.params_fingerprint,
                extensions=clearance.extensions or {},
                aircraft=clearance.aircraft,
                requested_by=clearance.requested_by,
                resource_scope=clearance.resource_scope,
            ),
            request_id=request_id,
        )
        return RuntimeClearanceHandle(
            clearance_ref=approval.approval_id,
            state=approval.state,
            raw=approval,
        )

    def check_clearance(
        self,
        clearance_ref: str,
    ) -> RuntimeClearanceDecision:
        result = self.approval_result(clearance_ref)
        latest = result.responses[0] if result.responses else None
        return RuntimeClearanceDecision(
            clearance_ref=result.approval_id,
            state=result.state,
            selected_scope=result.selected_scope,
            decision_type=latest.decision_type if latest else None,
            alternate_directive=latest.alternate_directive if latest else None,
            user_message=latest.user_message if latest else None,
            constraints=[constraint.model_dump() for constraint in latest.constraints]
            if latest
            else [],
            result=result,
        )

    def cancel_clearance(
        self,
        clearance_ref: str,
        *,
        request_id: str,
        actor_ref: str,
    ) -> RuntimeClearanceDecision:
        self.cancel_approval(
            approval_id=clearance_ref,
            request_id=request_id,
            actor_id=actor_ref,
        )
        return self.check_clearance(clearance_ref)

    def request_handoff(
        self,
        handoff: RuntimeHandoffRequest,
        *,
        request_id: str,
        actor_ref: str,
    ) -> RuntimeHandoffHandle:
        context_redacted = handoff.context_redacted or {}
        if handoff.handoff_kind == "operator_guidance":
            request = self.create_tua_request(
                payload=CreateAssistanceRequest(
                    agent_id=handoff.actor_ref,
                    session_id=handoff.work_ref,
                    reason=handoff.reason,
                    node_id=handoff.node_ref,
                    approval_id=handoff.clearance_ref,
                    risk_family=handoff.risk_family,
                    context_redacted=context_redacted,
                ),
                request_id=request_id,
                actor_id=actor_ref,
            )
            return RuntimeHandoffHandle(
                handoff_ref=request["request_id"],
                state=request["state"],
                raw=request,
            )
        if handoff.handoff_kind == "browser_review":
            browser = self.create_browser_assistance_session(
                payload=CreateBrowserAssistanceSessionRequest(
                    agent_id=handoff.actor_ref,
                    session_id=handoff.work_ref,
                    reason=handoff.reason,
                    node_id=handoff.node_ref,
                    approval_id=handoff.clearance_ref,
                    risk_family=handoff.risk_family,
                    context_redacted=context_redacted,
                ),
                request_id=request_id,
                actor_id=actor_ref,
            )
            return RuntimeHandoffHandle(
                handoff_ref=browser.browser_session_id,
                state=browser.state,
                raw=browser,
            )
        if handoff.handoff_kind == "voice_prompt":
            voice = self.create_voice_session(
                payload=RuntimeCreateVoiceSessionRequest(
                    agent_id=handoff.actor_ref,
                    session_id=handoff.work_ref,
                    mode=handoff.mode or "text_fallback",
                    node_id=handoff.node_ref,
                    risk_family=handoff.risk_family,
                    context_redacted=context_redacted,
                ),
                request_id=request_id,
                actor_id=actor_ref,
            )
            return RuntimeHandoffHandle(
                handoff_ref=voice.voice_session_id,
                state=voice.state,
                raw=voice,
            )
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "unknown handoff kind")

    def check_handoff(
        self,
        handoff_kind: str,
        handoff_ref: str,
    ) -> RuntimeHandoffResult:
        if handoff_kind == "operator_guidance":
            result = self.tua_result(handoff_ref)
            latest = result.latest_session
            return RuntimeHandoffResult(
                handoff_ref=result.request.request_id,
                state=result.request.state,
                return_summary=result.return_summary,
                messages=[
                    message.model_dump()
                    for message in latest.messages
                ]
                if latest
                else [],
                raw=result,
            )
        if handoff_kind == "browser_review":
            result = self.browser_result(handoff_ref)
            return RuntimeHandoffResult(
                handoff_ref=result.session.browser_session_id,
                state=result.session.state,
                return_summary=result.return_summary,
                messages=[],
                raw=result,
            )
        if handoff_kind == "voice_prompt":
            result = self.voice_result(handoff_ref)
            return RuntimeHandoffResult(
                handoff_ref=result.session.voice_session_id,
                state=result.session.state,
                return_summary=None,
                messages=[message.model_dump() for message in result.messages],
                raw=result,
            )
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "unknown handoff kind")

    def register_context(
        self,
        *,
        payload: RuntimeContextRequest,
        request_id: str,
    ) -> RuntimeContextResponse:
        node_id = payload.node_id or self.settings.node_id
        existing_agent = self._existing_agent(node_id, payload.agent_id)
        agent = self.store.upsert_agent(
            {
                "agent_id": payload.agent_id,
                "node_id": node_id,
                "display_name": payload.display_name
                or existing_agent.get("display_name")
                or payload.agent_id,
                "agent_kind": existing_agent.get("agent_kind") or "primary",
                "status": payload.agent_status,
                "active_session_id": payload.session_id,
                "current_tool": payload.current_tool,
                "current_target": payload.current_target,
                "tags": existing_agent.get("tags", []),
                "capabilities": [item.model_dump() for item in payload.capabilities]
                or existing_agent.get("capabilities", []),
            }
        )
        session = None
        if payload.session_id:
            session = self.store.upsert_session(
                {
                    "session_id": payload.session_id,
                    "node_id": node_id,
                    "agent_id": payload.agent_id,
                    "status": _session_status_from_mission(payload.mission_state),
                    "title": payload.mission_title,
                    "summary": payload.mission_summary,
                    "current_tool": payload.current_tool,
                    "current_target": payload.current_target,
                }
            )
        mission = None
        if payload.mission_id:
            mission = self.store.upsert_mission(
                {
                    "mission_id": payload.mission_id,
                    "node_id": node_id,
                    "agent_id": payload.agent_id,
                    "session_id": payload.session_id,
                    "state": payload.mission_state,
                    "title": payload.mission_title,
                    "summary": payload.mission_summary,
                }
            )
            self.store.create_event(
                node_id=node_id,
                agent_id=payload.agent_id,
                session_id=payload.session_id,
                event_type="mission.state",
                payload={
                    "mission_id": payload.mission_id,
                    "state": payload.mission_state,
                },
            )
        self.store.append_audit_event(
            event_type="runtime_context_registered",
            actor_type="hermes",
            actor_id=payload.agent_id,
            node_id=node_id,
            agent_id=payload.agent_id,
            session_id=payload.session_id,
            request_id=request_id,
            payload_redacted={
                "mission_id": payload.mission_id,
                "agent_status": payload.agent_status,
                "mission_state": payload.mission_state,
            },
        )
        self.store.create_event(
            node_id=node_id,
            agent_id=payload.agent_id,
            session_id=payload.session_id,
            event_type="agent.status",
            payload={"agent_id": payload.agent_id, "status": payload.agent_status},
        )
        return RuntimeContextResponse(
            agent=agent,
            mission=Mission.model_validate(mission) if mission else None,
            session=session,
        )

    def create_notification(
        self,
        *,
        payload: MobileNotifyRequest,
        request_id: str,
    ) -> Notification:
        composed = compose_notification(payload)
        notification = self.store.create_notification(
            {
                "node_id": self.settings.node_id,
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
        self.store.append_audit_event(
            event_type="notification_queued",
            actor_type="hermes",
            actor_id=payload.agent_id,
            node_id=self.settings.node_id,
            agent_id=payload.agent_id,
            session_id=payload.session_id,
            notification_id=notification["notification_id"],
            request_id=request_id,
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
        self.store.create_event(
            node_id=self.settings.node_id,
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

    def request_approval(
        self,
        *,
        payload: HermesApprovalRequestedRequest,
        request_id: str,
    ) -> ApprovalRequest:
        node_id = payload.node_id or self.settings.node_id
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
            store=self.store,
            settings=self.settings,
            node_id=node_id,
            agent_id=payload.agent_id,
            session_id=payload.session_id,
            capability=capability,
            requested_risk_family=risk_family,
            request_id=request_id,
            actor_type="hermes",
            actor_id=payload.agent_id,
        )
        risk_family = resolution.resolved_risk_family
        expires_at = expires_in(payload.expires_in_seconds).isoformat().replace("+00:00", "Z")
        contract_fields = build_clearance_contract_fields(
            settings=self.settings,
            approval_id=approval_id,
            payload_redacted=payload.payload_redacted,
            extensions=payload.extensions,
            risk_family=risk_family,
            expires_at=expires_at,
            requested_short_code=payload.short_code,
        )
        operator_message, operator_message_audit = sanitize_operator_message(
            raw_message=payload.operator_message,
            settings=self.settings,
            agent_id=payload.agent_id,
            session_id=payload.session_id,
            risk_family=risk_family,
            requested_tool=payload.requested_tool,
        )
        # Standing grants (read side). Same lookup and same fail-closed gate as
        # the /v1/approvals path — a guard enforced on one creation path only is
        # not a guard. This payload carries no risk_vector, so the channel
        # requirement can only be imposed by the risk family here.
        standing = standing_grant_for_request(
            store=self.store,
            settings=self.settings,
            node_id=node_id,
            agent_id=payload.agent_id,
            session_id=payload.session_id,
            requested_tool=payload.requested_tool,
            params_fingerprint=contract_fields["params_fingerprint"],
            risk_family=risk_family,
            risk_vector=None,
        )
        approval = self.store.create_approval(
            {
                "approval_id": approval_id,
                "action_id": payload.action_id or new_id("act"),
                "node_id": node_id,
                "agent_id": payload.agent_id,
                "session_id": payload.session_id,
                "requested_tool": payload.requested_tool,
                "capability": capability,
                "risk_level": payload.risk_level,
                "risk_category": payload.risk_category or "unknown_action",
                "risk_family": risk_family,
                **contract_fields,
                "operator_message": operator_message,
                "audit_correlation_id": payload.audit_correlation_id,
                "aircraft": resolution.aircraft,
                "requested_by": "runtime:local",
                "summary": payload.summary,
                "full_payload_redacted": payload.payload_redacted,
                "resource_scope": payload.resource_scope,
                "state": standing.initial_state,
                "options": _approval_options_from_scopes(payload.suggested_scopes),
                "expires_at": expires_at,
            }
        )
        self._set_agent_runtime_state(
            node_id=node_id,
            agent_id=payload.agent_id,
            session_id=payload.session_id,
            # An auto-satisfied request never blocks on a human, so parking the
            # agent in waiting_approval would strand the fleet view on a state
            # no decision will ever leave.
            status="waiting_approval" if not standing.auto_satisfied else "running",
            current_tool=payload.requested_tool,
        )
        self.store.append_audit_event(
            event_type="approval_requested",
            actor_type="hermes",
            actor_id=payload.agent_id,
            node_id=node_id,
            agent_id=payload.agent_id,
            session_id=payload.session_id,
            approval_id=approval_id,
            request_id=request_id,
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
        self.store.create_event(
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
                store=self.store,
                approval=approval,
                grant=standing.grant,
                request_id=request_id,
            )
        elif standing.refusal is not None:
            record_auto_satisfy_refusal(
                store=self.store,
                approval=approval,
                reason=standing.refusal,
                request_id=request_id,
            )
        return ApprovalRequest.model_validate(approval)

    def approval_result(self, approval_id: str) -> RuntimeApprovalResult:
        self.expire_pending_approvals()
        try:
            approval = self.store.get_approval(approval_id)
        except KeyError as exc:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "approval not found") from exc
        responses = [
            ApprovalResponse.model_validate(response)
            for response in self.store.list_approval_responses(approval_id)
        ]
        return RuntimeApprovalResult(
            approval_id=approval["approval_id"],
            state=approval["state"],
            selected_scope=approval["decision_scope"]
            if approval["state"] == "approved"
            else None,
            decided_at=approval["decided_at"],
            decision_metadata=approval["decision_metadata"] or {},
            responses=responses,
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

    def cancel_approval(
        self,
        *,
        approval_id: str,
        request_id: str,
        actor_id: str,
    ) -> RuntimeApprovalResult:
        try:
            approval = self.store.get_approval(approval_id)
        except KeyError as exc:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "approval not found") from exc
        if approval["state"] == "pending":
            self.store.resolve_approval(
                approval_id,
                "cancelled",
                decision_metadata={"reason": "runtime_cancelled"},
            )
            self.store.append_audit_event(
                event_type="approval_cancelled",
                actor_type="hermes",
                actor_id=actor_id,
                node_id=approval["node_id"],
                agent_id=approval["agent_id"],
                session_id=approval["session_id"],
                approval_id=approval_id,
                request_id=request_id,
                payload_redacted={"reason": "runtime_cancelled"},
            )
            self.store.create_event(
                node_id=approval["node_id"],
                agent_id=approval["agent_id"],
                session_id=approval["session_id"],
                event_type="approval.resolved",
                payload={"approval_id": approval_id, "state": "cancelled"},
            )
        return self.approval_result(approval_id)

    def release_approval(self, approval_id: str) -> RuntimeApprovalResult:
        """Two-phase consume, symmetric inverse of commit (BrowserBridge seam).
        Release a reserved clearance back to cancelled so it never dangles.
        404 if missing, 409 if not reserved; one-time consumption preserved."""
        try:
            self.store.release_approval(approval_id)
        except KeyError as exc:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "approval not found") from exc
        except ValueError as exc:
            raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
        return self.approval_result(approval_id)

    def expire_pending_approvals(self) -> None:
        for approval in self.store.list_approvals(state="pending"):
            if parse_utc(approval["expires_at"]) > now_utc():
                continue
            self.store.resolve_approval(
                approval["approval_id"],
                "expired",
                decision_metadata={"reason": "runtime_result_poll"},
            )
            request_id = new_id("req")
            self.store.append_audit_event(
                event_type="approval_expired",
                actor_type="gateway",
                actor_id="gateway",
                node_id=approval["node_id"],
                agent_id=approval["agent_id"],
                session_id=approval["session_id"],
                approval_id=approval["approval_id"],
                request_id=request_id,
                payload_redacted={"reason": "runtime_result_poll"},
            )
            self.store.create_event(
                node_id=approval["node_id"],
                agent_id=approval["agent_id"],
                session_id=approval["session_id"],
                event_type="approval.resolved",
                payload={"approval_id": approval["approval_id"], "state": "expired"},
            )

    def create_tua_request(
        self,
        *,
        payload: CreateAssistanceRequest,
        request_id: str,
        actor_id: str,
    ) -> Any:
        node_id = payload.node_id or self.settings.node_id
        require_runtime_capability(
            store=self.store,
            settings=self.settings,
            capability="tua",
            request_id=request_id,
            actor_id=actor_id,
            node_id=node_id,
            agent_id=payload.agent_id,
        )
        assistance_request = self.store.create_assistance_request(
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
        self._set_agent_runtime_state(
            node_id=node_id,
            agent_id=payload.agent_id,
            session_id=payload.session_id,
            status="waiting_assistance",
        )
        self.store.append_audit_event(
            event_type="tua_request_created",
            actor_type="hermes",
            actor_id=payload.agent_id,
            node_id=node_id,
            agent_id=payload.agent_id,
            session_id=payload.session_id,
            request_id=request_id,
            payload_redacted={"request_id": assistance_request["request_id"]},
        )
        self.store.create_event(
            node_id=node_id,
            agent_id=payload.agent_id,
            session_id=payload.session_id,
            event_type="tua.requested",
            payload={"request_id": assistance_request["request_id"]},
        )
        return assistance_request

    def tua_result(self, request_id: str) -> RuntimeTuaResult:
        try:
            request = self.store.get_assistance_request(request_id)
        except KeyError as exc:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "TUA request not found") from exc
        sessions = self.store.list_assistance_sessions(request_id=request_id)
        latest = sessions[0] if sessions else None
        return RuntimeTuaResult(
            request=request,
            sessions=sessions,
            latest_session=latest,
            return_summary=latest.get("return_summary") if latest else None,
        )

    def create_browser_assistance_session(
        self,
        *,
        payload: CreateBrowserAssistanceSessionRequest,
        request_id: str,
        actor_id: str,
    ) -> BrowserAssistanceSession:
        node_id = payload.node_id or self.settings.node_id
        require_runtime_capability(
            store=self.store,
            settings=self.settings,
            capability="browser_assistance",
            request_id=request_id,
            actor_id=actor_id,
            node_id=node_id,
            agent_id=payload.agent_id,
        )
        session = self.store.create_browser_assistance_session(
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
        self.store.create_operator_session(
            {
                "session_id": session["browser_session_id"],
                "session_type": "browser_assistance",
                "agent_id": payload.agent_id,
                "mission_id": _mission_id_from_context(payload.context_redacted),
                "state": "requested",
                "capability_requirements": ["browser_assistance"],
                "context": payload.context_redacted,
            }
        )
        self._set_agent_runtime_state(
            node_id=node_id,
            agent_id=payload.agent_id,
            session_id=payload.session_id,
            status="waiting_assistance",
        )
        self.store.append_audit_event(
            event_type="browser_assistance_requested",
            actor_type="hermes",
            actor_id=payload.agent_id,
            node_id=node_id,
            agent_id=payload.agent_id,
            session_id=payload.session_id,
            request_id=request_id,
            payload_redacted={"browser_session_id": session["browser_session_id"]},
        )
        self.store.create_event(
            node_id=node_id,
            agent_id=payload.agent_id,
            session_id=payload.session_id,
            event_type="browser_assistance.requested",
            payload={"browser_session_id": session["browser_session_id"]},
        )
        return BrowserAssistanceSession.model_validate(session)

    def browser_result(self, session_id: str) -> RuntimeBrowserAssistanceResult:
        try:
            session = self.store.get_browser_assistance_session(session_id)
        except KeyError as exc:
            raise HTTPException(
                status.HTTP_404_NOT_FOUND,
                "browser assistance session not found",
            ) from exc
        return RuntimeBrowserAssistanceResult(
            session=session,
            return_summary=session.get("return_summary"),
        )

    def create_voice_session(
        self,
        *,
        payload: RuntimeCreateVoiceSessionRequest,
        request_id: str,
        actor_id: str,
    ) -> VoiceSession:
        node_id = payload.node_id or self.settings.node_id
        require_runtime_capability(
            store=self.store,
            settings=self.settings,
            capability="voice",
            request_id=request_id,
            actor_id=actor_id,
            node_id=node_id,
            agent_id=payload.agent_id,
        )
        session = _engage_handoff(
            store=self.store,
            settings=self.settings,
            handoff_kind="voice_prompt",
            handoff_ref="new",
            node_id=node_id,
            agent_id=payload.agent_id,
            work_ref=payload.session_id,
            risk_family=payload.risk_family,
            clearance_ref=None,
            request_id=request_id,
            actor_type="hermes",
            actor_id=actor_id,
            engage=lambda: self.store.create_voice_session(
                {
                    "node_id": node_id,
                    "agent_id": payload.agent_id,
                    "session_id": payload.session_id,
                    "created_by_device_id": f"runtime:{actor_id}",
                    "mode": payload.mode,
                    "state": "active",
                    "risk_family": payload.risk_family,
                }
            ),
        )
        self.store.create_operator_session(
            {
                "session_id": session["voice_session_id"],
                "session_type": "voice",
                "agent_id": payload.agent_id,
                "mission_id": _mission_id_from_context(payload.context_redacted),
                "state": "active",
                "capability_requirements": ["voice"],
                "context": payload.context_redacted | {"risk_family": payload.risk_family},
            }
        )
        self.store.append_audit_event(
            event_type="voice_session_created",
            actor_type="hermes",
            actor_id=actor_id,
            node_id=node_id,
            agent_id=payload.agent_id,
            session_id=payload.session_id,
            voice_session_id=session["voice_session_id"],
            request_id=request_id,
            payload_redacted={"mode": payload.mode, "runtime_created": True},
        )
        self.store.create_event(
            node_id=node_id,
            agent_id=payload.agent_id,
            session_id=payload.session_id,
            event_type="voice.session.created",
            payload={"voice_session_id": session["voice_session_id"], "mode": payload.mode},
        )
        return VoiceSession.model_validate(session)

    def voice_result(self, session_id: str) -> RuntimeVoiceResult:
        try:
            session = self.store.get_voice_session(session_id)
        except KeyError as exc:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "voice session not found") from exc
        return RuntimeVoiceResult(session=session, messages=session["messages"])

    def _set_agent_runtime_state(
        self,
        *,
        node_id: str,
        agent_id: str,
        session_id: str | None,
        status: str,
        current_tool: str | None = None,
    ) -> None:
        existing = self._existing_agent(node_id, agent_id)
        self.store.upsert_agent(
            {
                "agent_id": agent_id,
                "node_id": node_id,
                "display_name": existing.get("display_name") or agent_id,
                "agent_kind": existing.get("agent_kind") or "primary",
                "status": status,
                "active_session_id": session_id,
                "current_tool": current_tool or existing.get("current_tool"),
                "current_target": existing.get("current_target"),
                "tags": existing.get("tags", []),
                "capabilities": existing.get("capabilities", []),
            }
        )
        self.store.create_event(
            node_id=node_id,
            agent_id=agent_id,
            session_id=session_id,
            event_type="agent.status",
            payload={"agent_id": agent_id, "status": status},
        )

    def _existing_agent(self, node_id: str, agent_id: str) -> dict[str, Any]:
        try:
            return self.store.get_agent(node_id, agent_id)
        except KeyError:
            return {}


def _approval_options_from_scopes(scopes: list[str]) -> list[str]:
    scope_options = {
        "once": "approve_once",
        "session": "approve_for_session",
        "agent": "approve_for_agent",
        "permanent": "approve_permanent",
    }
    options = [scope_options[scope] for scope in scopes if scope in scope_options]
    return [*options, "deny"] if options else ["deny"]


def _session_status_from_mission(mission_state: str) -> str:
    if mission_state in {"completed", "cancelled", "failed"}:
        return {"completed": "completed", "cancelled": "cancelled", "failed": "failed"}[
            mission_state
        ]
    if mission_state in {"waiting_approval", "waiting_assistance", "user_controlling"}:
        return "blocked"
    return "active"


def _mission_id_from_context(context: dict[str, Any]) -> str | None:
    value = context.get("mission_id")
    return value if isinstance(value, str) and value else None

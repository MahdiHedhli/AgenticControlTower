from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

Permission = Literal[
    "read_state",
    "chat",
    "approve",
    "intervene",
    "manage_devices",
    "manage_capabilities",
    "voice",
    "tui",
    "browser_assist",
]
Platform = Literal["ios", "android", "local_terminal"]
DeviceStatus = Literal["active", "revoked", "lost", "rotating", "disabled"]
Environment = Literal["homelab", "laptop", "cloud", "workstation", "vps", "work_vm", "custom"]
AgentStatus = Literal[
    "idle",
    "running",
    "blocked",
    "waiting_approval",
    "waiting_assistance",
    "user_controlling",
    "paused",
    "stopping",
    "offline",
    "error",
    "failed",
    "completed",
    "quarantined",
]
SessionStatus = Literal["active", "blocked", "paused", "completed", "failed", "cancelled"]
MissionState = Literal[
    "queued",
    "running",
    "waiting_approval",
    "waiting_assistance",
    "user_controlling",
    "completed",
    "failed",
    "cancelled",
]
ApprovalState = Literal["pending", "approved", "denied", "expired", "cancelled"]
ClearanceContractVersion = Literal["act.clearance.v1", "act.clearance.v2"]
RiskLevel = Literal["low", "medium", "high", "critical"]
RiskFamily = Literal[
    "observe",
    "read_only",
    "routine",
    "external_effect",
    "destructive",
    "credential_or_secret",
    "safety_critical",
    "irreversible",
]
ApprovalScope = Literal["once", "session", "agent", "permanent"]
ClearanceChannel = Literal["mobile_signed", "local_terminal"]
DeploymentTrustContext = Literal["trusted_host", "untrusted_host", "adversarial_host"]
NotificationCategory = Literal[
    "approval_required",
    "security_alert",
    "agent_blocked",
    "task_complete",
    "system_health",
    "voice_callback",
]
NotificationUrgency = Literal["low", "normal", "high", "critical"]
TuiSessionState = Literal["requested", "active", "detached", "closed", "failed"]
AssistanceState = Literal[
    "requested",
    "active",
    "waiting_on_user",
    "user_controlling",
    "returned_to_agent",
    "closed",
    "cancelled",
]
BrowserAssistanceState = Literal[
    "requested",
    "active",
    "user_controlling",
    "returned_to_agent",
    "closed",
    "failed",
]
ApprovalResponseDecisionType = Literal[
    "approve_once",
    "approve_session",
    "approve_agent",
    "deny",
    "modified",
    "needs_info",
    "propose_policy",
]
VoiceSessionState = Literal["active", "closed"]
CapabilityName = Literal[
    "approvals",
    "tui",
    "tua",
    "browser_assistance",
    "voice",
    "notifications",
]
CapabilitySubjectType = Literal["device", "agent", "node", "runtime"]
OperatorSessionType = Literal["tui", "tua", "browser_assistance", "voice"]
OperatorSessionState = Literal[
    "requested",
    "active",
    "detached",
    "user_controlling",
    "returned_to_agent",
    "closed",
    "cancelled",
    "failed",
]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ErrorResponse(BaseModel):
    error: str
    message: str | None = None
    request_id: str


class Capability(BaseModel):
    name: str
    status: Literal[
        "available",
        "disabled",
        "requires_pairing",
        "requires_permission",
        "unsupported",
        "degraded",
    ]


class GatewayHealth(BaseModel):
    node_id: str
    status: Literal["healthy", "degraded", "unhealthy"]
    gateway_version: str
    hermes_version: str | None = None
    checked_at: datetime
    services: dict[str, Literal["healthy", "degraded", "unhealthy", "unavailable"]] = Field(
        default_factory=dict
    )


class NodeRegistration(StrictModel):
    node_id: str | None = None
    display_name: str
    environment: Environment = "homelab"
    gateway_base_url: str
    node_fingerprint: str
    gateway_version: str
    hermes_version: str | None = None
    tags: list[str] = Field(default_factory=list)


class Node(BaseModel):
    node_id: str
    display_name: str
    environment: Environment
    gateway_base_url: str | None = None
    node_fingerprint: str | None = None
    gateway_version: str | None = None
    hermes_version: str | None = None
    health: Literal["online", "degraded", "offline", "unknown"]
    tags: list[str] = Field(default_factory=list)
    capabilities: list[Capability] = Field(default_factory=list)
    agents: list[Agent] = Field(default_factory=list)
    created_at: datetime | None = None
    last_seen_at: datetime | None = None


class DeviceRegistration(StrictModel):
    device_name: str
    platform: Platform
    app_instance_id: str
    app_version: str | None = None
    push_token: str | None = None
    clearance_channel: ClearanceChannel | None = None


class Device(BaseModel):
    device_id: str
    node_id: str | None = None
    device_name: str
    platform: Platform
    clearance_channel: ClearanceChannel = "mobile_signed"
    device_key_algorithm: str = "ed25519"
    status: DeviceStatus
    permissions: list[Permission]
    registered_at: datetime
    last_seen_at: datetime | None = None


class CreatePairingSessionRequest(StrictModel):
    display_name: str
    requested_permissions: list[Permission] = Field(default_factory=list)
    clearance_channel: ClearanceChannel = "local_terminal"
    ttl_seconds: int | None = Field(default=None, ge=-1, le=3600)


class PairingSession(BaseModel):
    pairing_id: str
    pairing_token: str | None = None
    challenge: str
    status: Literal["pending", "completed", "expired", "cancelled"]
    node_id: str
    node_fingerprint: str
    clearance_channel: ClearanceChannel = "local_terminal"
    expires_at: datetime


class CompletePairingRequest(StrictModel):
    pairing_id: str
    challenge_response: str
    device_public_key: str
    device: DeviceRegistration
    # Signing-key algorithm for device_public_key. None defaults to ed25519 (legacy/software).
    # "p256" enrols a Secure-Enclave / Keystore ECDSA P-256 key and REQUIRES a possession proof.
    device_key_algorithm: str | None = None
    # base64url signature over the pairing session `challenge`, proving control of the private key
    # paired with device_public_key. Required when device_key_algorithm == "p256".
    device_key_possession_proof: str | None = None


class AuthTokenSet(BaseModel):
    access_token: str
    refresh_token: str
    expires_at: datetime


class CompletePairingResponse(BaseModel):
    node: Node
    device: Device
    tokens: AuthTokenSet


class RefreshTokenRequest(StrictModel):
    refresh_token: str
    signed_nonce: str


class Agent(BaseModel):
    agent_id: str
    node_id: str
    display_name: str
    agent_kind: str | None = None
    status: AgentStatus
    active_session_id: str | None = None
    current_tool: str | None = None
    current_target: str | None = None
    deployment_trust_context: DeploymentTrustContext = "untrusted_host"
    require_classified_capabilities: bool = False
    tags: list[str] = Field(default_factory=list)
    capabilities: list[Capability] = Field(default_factory=list)
    last_seen_at: datetime | None = None


class Session(BaseModel):
    session_id: str
    conversation_id: str | None = None
    node_id: str
    agent_id: str
    status: SessionStatus
    title: str | None = None
    summary: str | None = None
    current_plan: str | None = None
    current_tool: str | None = None
    current_target: str | None = None
    started_at: datetime
    updated_at: datetime | None = None


class Mission(BaseModel):
    mission_id: str
    node_id: str
    agent_id: str
    session_id: str | None = None
    state: MissionState
    title: str | None = None
    summary: str | None = None
    created_at: datetime
    updated_at: datetime


class RuntimeContextRequest(StrictModel):
    agent_id: str
    display_name: str | None = None
    agent_status: AgentStatus = "running"
    mission_id: str | None = None
    mission_state: MissionState = "running"
    session_id: str | None = None
    mission_title: str | None = None
    mission_summary: str | None = None
    current_tool: str | None = None
    current_target: str | None = None
    node_id: str | None = None
    capabilities: list[Capability] = Field(default_factory=list)


class RuntimeContextResponse(BaseModel):
    agent: Agent
    mission: Mission | None = None
    session: Session | None = None


class ApprovalRequest(BaseModel):
    approval_id: str
    action_id: str
    node_id: str
    agent_id: str
    session_id: str
    requested_tool: str
    capability: str | None = None
    risk_level: RiskLevel
    risk_category: str | None = None
    risk_family: RiskFamily = "external_effect"
    params_fingerprint: str
    short_code: str | None = None
    operator_message: str | None = None
    audit_correlation_id: str | None = None
    tower_id: str | None = None
    contract_version: ClearanceContractVersion = "act.clearance.v2"
    proof: dict[str, Any] | None = None
    extensions: dict[str, dict[str, Any]] = Field(default_factory=dict)
    extensions_digest: str | None = None
    aircraft: str | None = None
    requested_by: str | None = None
    summary: str
    full_payload_redacted: dict[str, Any]
    resource_scope: str | None = None
    state: ApprovalState
    expires_at: datetime
    options: list[str]
    decision_scope: ApprovalScope | None = None
    decided_at: datetime | None = None
    decision_metadata: dict[str, Any] | None = None


class CreateApprovalRequest(StrictModel):
    action_id: str
    agent_id: str
    session_id: str
    requested_tool: str
    risk_level: RiskLevel
    summary: str
    full_payload_redacted: dict[str, Any]
    node_id: str | None = None
    risk_category: str | None = None
    risk_family: RiskFamily
    capability: str | None = None
    params_fingerprint: str | None = None
    operator_message: str | None = None
    audit_correlation_id: str | None = None
    short_code: str | None = None
    extensions: dict[str, dict[str, Any]] = Field(default_factory=dict)
    aircraft: str | None = None
    requested_by: str | None = None
    resource_scope: str | None = None
    options: list[str] = Field(default_factory=lambda: ["approve_once", "deny"])
    expires_at: datetime


class HermesApprovalRequestedRequest(StrictModel):
    requested_tool: str
    risk_level: RiskLevel
    summary: str
    payload_redacted: dict[str, Any]
    agent_id: str
    session_id: str
    expires_in_seconds: int = Field(ge=1, le=86_400)
    suggested_scopes: list[ApprovalScope] = Field(default_factory=lambda: ["once"])
    action_id: str | None = None
    node_id: str | None = None
    risk_category: str | None = None
    risk_family: RiskFamily
    capability: str | None = None
    operator_message: str | None = None
    audit_correlation_id: str | None = None
    short_code: str | None = None
    params_fingerprint: str | None = None
    extensions: dict[str, dict[str, Any]] = Field(default_factory=dict)
    aircraft: str | None = None
    requested_by: str | None = None
    resource_scope: str | None = None


class ApprovalStatusRequest(StrictModel):
    approval_id: str


class ApprovalStatusResponse(BaseModel):
    approval_id: str
    state: ApprovalState
    selected_scope: ApprovalScope | None = None
    decided_at: datetime | None = None
    decision_metadata: dict[str, Any] | None = None
    capability: str | None = None
    risk_family: RiskFamily = "external_effect"
    expires_at: datetime | None = None
    params_fingerprint: str | None = None
    short_code: str | None = None
    operator_message: str | None = None
    audit_correlation_id: str | None = None
    reason: str | None = None
    tower_id: str | None = None
    contract_version: ClearanceContractVersion = "act.clearance.v2"
    proof: dict[str, Any] | None = None
    extensions: dict[str, dict[str, Any]] = Field(default_factory=dict)


class ApprovalDecisionRequest(StrictModel):
    decision_id: str
    decision: Literal["approve", "deny"]
    scope: ApprovalScope
    control: Literal["pause", "kill_task", "kill_agent", "quarantine_agent"] | None = None
    signed_payload: dict[str, Any]
    signature: str


class ApprovalDecisionResponse(BaseModel):
    approval_id: str
    state: ApprovalState
    applied_scope: ApprovalScope | None = None


class LocalTerminalApprovalDecisionRequest(StrictModel):
    decision: Literal["approve", "deny"]
    scope: ApprovalScope = "once"


class UpdateAgentTrustContextRequest(StrictModel):
    deployment_trust_context: DeploymentTrustContext


class InterventionRequest(StrictModel):
    intervention_id: str
    type: Literal[
        "pause",
        "resume",
        "inject_instruction",
        "cancel_task",
        "kill_task",
        "kill_agent",
        "quarantine_agent",
        "emergency_stop",
    ]
    reason: str
    instruction: str | None = None
    signed_payload: dict[str, Any]
    signature: str


class InterventionResponse(BaseModel):
    intervention_id: str
    resulting_state: str


class RuntimeInterventionAck(StrictModel):
    ack_result: Literal["accepted", "rejected"] = "accepted"
    explanation: str | None = None


class RuntimeTuiRelayRequest(StrictModel):
    session_id: str
    agent_id: str
    node_id: str | None = None
    chunk: str = ""


class PushTokenUpdateRequest(StrictModel):
    push_token: str | None = None


class CreateTuiSessionRequest(StrictModel):
    agent_id: str = "agent_mock"
    node_id: str | None = None
    session_context_id: str | None = None
    approval_id: str | None = None
    command: str | None = None
    working_directory: str | None = None
    risk_level: RiskLevel = "high"


class TuiSession(BaseModel):
    session_id: str
    agent_id: str
    node_id: str
    user_device_id: str
    state: TuiSessionState
    command: str
    working_directory: str
    created_at: datetime
    last_activity_at: datetime
    closed_at: datetime | None = None
    risk_level: RiskLevel
    risk_family: RiskFamily = "external_effect"
    risk_label: str
    output_retention_enabled: bool = False
    audit_refs: list[str] = Field(default_factory=list)


class TuiSessionControlResponse(BaseModel):
    session: TuiSession


class TuiAttachTokenResponse(BaseModel):
    attach_token: str
    expires_at: datetime


class CreateAssistanceRequest(StrictModel):
    agent_id: str
    session_id: str
    reason: str
    node_id: str | None = None
    approval_id: str | None = None
    risk_family: RiskFamily = "external_effect"
    context_redacted: dict[str, Any] = Field(default_factory=dict)


class AssistanceRequest(BaseModel):
    request_id: str
    node_id: str
    agent_id: str
    session_id: str
    reason: str
    state: AssistanceState
    approval_id: str | None = None
    risk_family: RiskFamily = "external_effect"
    context_redacted: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    updated_at: datetime


class CreateAssistanceSessionRequest(StrictModel):
    initial_message: str | None = None


class AssistanceSession(BaseModel):
    assistance_session_id: str
    request_id: str
    node_id: str
    agent_id: str
    session_id: str
    state: AssistanceState
    created_by_device_id: str
    return_summary: str | None = None
    created_at: datetime
    updated_at: datetime
    returned_at: datetime | None = None
    closed_at: datetime | None = None
    messages: list[AssistanceMessage] = Field(default_factory=list)


class CreateAssistanceMessageRequest(StrictModel):
    body: str


class AssistanceMessage(BaseModel):
    message_id: str
    assistance_session_id: str
    sender_type: Literal["user", "agent", "system"]
    sender_id: str
    body: str
    created_at: datetime


class ReturnControlRequest(StrictModel):
    summary: str


class CreateBrowserAssistanceSessionRequest(StrictModel):
    agent_id: str
    session_id: str
    reason: str
    node_id: str | None = None
    approval_id: str | None = None
    risk_family: RiskFamily = "external_effect"
    context_redacted: dict[str, Any] = Field(default_factory=dict)


class BrowserAssistanceSession(BaseModel):
    browser_session_id: str
    node_id: str
    agent_id: str
    session_id: str
    reason: str
    state: BrowserAssistanceState
    risk_family: RiskFamily = "external_effect"
    context_redacted: dict[str, Any] = Field(default_factory=dict)
    user_action_notes: list[str] = Field(default_factory=list)
    return_summary: str | None = None
    created_at: datetime
    updated_at: datetime
    returned_at: datetime | None = None
    closed_at: datetime | None = None


class BrowserAssistanceEventRequest(StrictModel):
    note: str


class ApprovalConstraint(BaseModel):
    constraint_type: str
    value_redacted: dict[str, Any]


class CreateApprovalResponseRequest(StrictModel):
    decision_type: ApprovalResponseDecisionType
    params_fingerprint: str | None = None
    user_message: str | None = None
    alternate_directive: str | None = None
    constraints: list[ApprovalConstraint] = Field(default_factory=list)
    confirmation_phrase: str | None = None


class ApprovalResponse(BaseModel):
    approval_response_id: str
    approval_id: str
    decision_type: ApprovalResponseDecisionType
    created_by_device_id: str
    user_message: str | None = None
    alternate_directive: str | None = None
    constraints: list[ApprovalConstraint] = Field(default_factory=list)
    policy_proposal_id: str | None = None
    created_at: datetime


class ApprovalPolicyProposal(BaseModel):
    policy_proposal_id: str
    approval_id: str
    created_by_device_id: str
    status: Literal["proposed", "rejected", "activated"]
    warning: str
    constraints: list[ApprovalConstraint] = Field(default_factory=list)
    created_at: datetime


class CapabilityGrant(BaseModel):
    grant_id: str
    subject_type: CapabilitySubjectType
    subject_id: str
    capability: CapabilityName
    node_id: str
    agent_id: str | None = None
    state: Literal["granted", "revoked"]
    reason: str | None = None
    created_at: datetime
    expires_at: datetime | None = None


class CreateCapabilityGrantRequest(StrictModel):
    subject_type: CapabilitySubjectType
    subject_id: str
    capability: CapabilityName
    node_id: str | None = None
    agent_id: str | None = None
    reason: str | None = None
    expires_at: datetime | None = None


class CapabilityRiskProposalEntry(StrictModel):
    capability: str
    risk_family: RiskFamily


class CapabilityRiskProposalRequest(StrictModel):
    node_id: str | None = None
    agent_id: str
    entries: list[CapabilityRiskProposalEntry]


class CapabilityRiskDecisionRequest(StrictModel):
    decision: Literal["approve", "reject"]


class CapabilityRiskRegistryEntry(BaseModel):
    entry_id: str
    node_id: str
    agent_id: str
    aircraft: str
    capability: str
    risk_family: RiskFamily
    status: Literal["pending", "approved"]
    version: int
    proposed_at: datetime
    proposed_by: str
    approved_by: str | None = None
    approved_at: datetime | None = None


class OperatorSession(BaseModel):
    session_id: str
    session_type: OperatorSessionType
    agent_id: str
    mission_id: str | None = None
    state: OperatorSessionState
    created_at: datetime
    updated_at: datetime
    owner_device_id: str | None = None
    capability_requirements: list[CapabilityName] = Field(default_factory=list)
    context: dict[str, Any] = Field(default_factory=dict)
    return_summary: str | None = None


class RuntimeApprovalResult(BaseModel):
    approval_id: str
    state: ApprovalState
    selected_scope: ApprovalScope | None = None
    decided_at: datetime | None = None
    decision_metadata: dict[str, Any] = Field(default_factory=dict)
    responses: list[ApprovalResponse] = Field(default_factory=list)
    capability: str | None = None
    risk_family: RiskFamily = "external_effect"
    expires_at: datetime | None = None
    params_fingerprint: str | None = None
    short_code: str | None = None
    operator_message: str | None = None
    audit_correlation_id: str | None = None
    reason: str | None = None
    tower_id: str | None = None
    contract_version: ClearanceContractVersion = "act.clearance.v2"
    proof: dict[str, Any] | None = None
    extensions: dict[str, dict[str, Any]] = Field(default_factory=dict)


class RuntimeTuaResult(BaseModel):
    request: AssistanceRequest
    sessions: list[AssistanceSession] = Field(default_factory=list)
    latest_session: AssistanceSession | None = None
    return_summary: str | None = None


class RuntimeBrowserAssistanceResult(BaseModel):
    session: BrowserAssistanceSession
    return_summary: str | None = None


class RuntimeCreateVoiceSessionRequest(StrictModel):
    agent_id: str
    session_id: str | None = None
    node_id: str | None = None
    mode: Literal["push_to_talk", "text_fallback"] = "text_fallback"
    risk_family: RiskFamily = "external_effect"
    context_redacted: dict[str, Any] = Field(default_factory=dict)


class RuntimeVoiceResult(BaseModel):
    session: VoiceSession
    messages: list[VoiceMessage] = Field(default_factory=list)


class CreateVoiceSessionRequest(StrictModel):
    agent_id: str = "agent_mock"
    session_id: str | None = None
    mode: Literal["push_to_talk", "text_fallback"] = "text_fallback"
    risk_family: RiskFamily = "external_effect"


class VoiceSession(BaseModel):
    voice_session_id: str
    node_id: str
    agent_id: str
    session_id: str | None = None
    created_by_device_id: str
    mode: str
    state: VoiceSessionState
    risk_family: RiskFamily = "external_effect"
    created_at: datetime
    closed_at: datetime | None = None
    messages: list[VoiceMessage] = Field(default_factory=list)


class CreateVoiceMessageRequest(StrictModel):
    body: str
    input_mode: Literal["simulated_voice", "text_fallback"] = "text_fallback"


class VoiceMessage(BaseModel):
    voice_message_id: str
    voice_session_id: str
    sender_type: Literal["user", "agent", "system"]
    body: str
    input_mode: str
    created_at: datetime


class MobileNotifyRequest(StrictModel):
    title: str
    body: str
    urgency: NotificationUrgency
    category: NotificationCategory
    agent_id: str
    session_id: str
    action_id: str | None = None
    deep_link: str | None = None
    dedupe_key: str | None = None
    backend_display_name: str | None = None
    subject_display_name: str | None = None
    risk_family: str | None = None
    clearance_category: str | None = None
    action_category: str | None = None
    operation_label: str | None = None
    pending_count: int | None = Field(default=None, ge=0)


class Notification(BaseModel):
    notification_id: str
    node_id: str | None = None
    agent_id: str | None = None
    session_id: str | None = None
    action_id: str | None = None
    category: NotificationCategory
    urgency: NotificationUrgency
    title_safe: str | None = None
    body_safe: str | None = None
    composition_mode: str | None = None
    unsafe_input_detected: bool = False
    state: Literal["queued", "dispatched", "rate_limited", "deduped", "failed", "opened"]
    created_at: datetime


class AuditEvent(BaseModel):
    audit_event_id: str
    event_type: str
    actor_type: Literal["user", "device", "gateway", "hermes", "agent", "system"]
    actor_id: str
    node_id: str
    agent_id: str | None = None
    session_id: str | None = None
    approval_id: str | None = None
    notification_id: str | None = None
    voice_session_id: str | None = None
    request_id: str
    previous_hash: str | None = None
    hash: str
    payload_redacted: dict[str, Any] | None = None
    created_at: datetime


class EventEnvelope(BaseModel):
    event_id: str
    cursor: str
    node_id: str
    agent_id: str | None = None
    session_id: str | None = None
    conversation_id: str | None = None
    type: str
    severity: Literal["debug", "info", "warning", "error", "critical"] = "info"
    occurred_at: datetime
    payload: dict[str, Any] = Field(default_factory=dict)


class Inventory(BaseModel):
    nodes: list[Node]

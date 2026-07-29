from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

from fastapi import HTTPException, status

from .config import Settings
from .store import SQLiteStore

ClearanceChannel = Literal["mobile_signed", "local_terminal"]
DeploymentTrustContext = Literal["trusted_host", "untrusted_host", "adversarial_host"]
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

LOW_RISK_FAMILIES: set[str] = {"observe", "read_only", "routine"}
MOBILE_MANDATORY_RISK_FAMILIES: set[str] = {
    "external_effect",
    "destructive",
    "credential_or_secret",
    "safety_critical",
    "irreversible",
}
ALL_RISK_FAMILIES = LOW_RISK_FAMILIES | MOBILE_MANDATORY_RISK_FAMILIES
ALL_CHANNELS: set[str] = {"mobile_signed", "local_terminal"}
ALL_TRUST_CONTEXTS: set[str] = {"trusted_host", "untrusted_host", "adversarial_host"}


@dataclass(frozen=True)
class ChannelPolicyDecision:
    allowed: bool
    channel: str
    risk_family: str
    eligible_channels: list[str]
    deployment_trust_context: str
    reason: str | None = None


@dataclass(frozen=True)
class ClearanceChannelPolicy:
    enabled_channels: tuple[str, ...] = ("mobile_signed",)
    default_channel: str = "mobile_signed"
    local_terminal_enabled: bool = False
    risk_channel_map: dict[str, tuple[str, ...]] = field(
        default_factory=lambda: {
            "observe": ("mobile_signed", "local_terminal"),
            "read_only": ("mobile_signed", "local_terminal"),
            "routine": ("mobile_signed", "local_terminal"),
            "external_effect": ("mobile_signed",),
            "destructive": ("mobile_signed",),
            "credential_or_secret": ("mobile_signed",),
            "safety_critical": ("mobile_signed",),
            "irreversible": ("mobile_signed",),
        }
    )

    @classmethod
    def from_settings(cls, settings: Settings) -> ClearanceChannelPolicy:
        risk_channel_map = (
            settings.clearance_risk_channel_map
            if settings.clearance_risk_channel_map is not None
            else settings.default_clearance_risk_channel_map
        )
        policy = cls(
            enabled_channels=settings.clearance_enabled_channels,
            default_channel=settings.clearance_default_channel,
            local_terminal_enabled=settings.clearance_local_terminal_enabled,
            risk_channel_map={
                risk: tuple(channels)
                for risk, channels in risk_channel_map.items()
            },
        )
        policy.validate()
        return policy

    def validate(self) -> None:
        invalid_channels = set(self.enabled_channels) - ALL_CHANNELS
        if invalid_channels:
            raise ValueError(f"unknown clearance channels: {sorted(invalid_channels)}")
        if self.default_channel not in self.enabled_channels:
            raise ValueError("default clearance channel must be enabled")
        if "local_terminal" in self.enabled_channels and not self.risk_channel_map:
            raise ValueError("both/local-terminal channel mode requires risk-tier map")
        missing = ALL_RISK_FAMILIES - set(self.risk_channel_map)
        if missing:
            raise ValueError(f"clearance risk-tier map missing: {sorted(missing)}")
        for risk, channels in self.risk_channel_map.items():
            if risk not in ALL_RISK_FAMILIES:
                raise ValueError(f"unknown risk family: {risk}")
            if not channels:
                raise ValueError(f"risk family {risk} has no eligible channels")
            invalid = set(channels) - ALL_CHANNELS
            if invalid:
                raise ValueError(f"unknown channels for {risk}: {sorted(invalid)}")

    def evaluate(
        self,
        *,
        channel: str,
        risk_family: str,
        deployment_trust_context: str,
    ) -> ChannelPolicyDecision:
        if deployment_trust_context not in ALL_TRUST_CONTEXTS:
            deployment_trust_context = "untrusted_host"
        if risk_family not in ALL_RISK_FAMILIES:
            risk_family = "external_effect"
        eligible = [
            item
            for item in self.risk_channel_map.get(risk_family, ("mobile_signed",))
            if item in self.enabled_channels
        ]
        if (
            channel == "local_terminal"
            and (
                not self.local_terminal_enabled
                or deployment_trust_context in {"untrusted_host", "adversarial_host"}
            )
        ):
            reason = (
                "local_terminal_disabled_for_trust_context"
                if deployment_trust_context != "trusted_host"
                else "local_terminal_disabled"
            )
            return ChannelPolicyDecision(
                allowed=False,
                channel=channel,
                risk_family=risk_family,
                eligible_channels=eligible,
                deployment_trust_context=deployment_trust_context,
                reason=reason,
            )
        if channel not in eligible:
            return ChannelPolicyDecision(
                allowed=False,
                channel=channel,
                risk_family=risk_family,
                eligible_channels=eligible,
                deployment_trust_context=deployment_trust_context,
                reason="channel_not_eligible_for_risk_family",
            )
        return ChannelPolicyDecision(
            allowed=True,
            channel=channel,
            risk_family=risk_family,
            eligible_channels=eligible,
            deployment_trust_context=deployment_trust_context,
        )


def risk_family_from_request(
    *,
    risk_family: str | None,
    risk_category: str | None,
    risk_level: str,
) -> str:
    if risk_family in ALL_RISK_FAMILIES:
        return risk_family
    category = (risk_category or "").lower()
    if any(marker in category for marker in ("secret", "credential", "token")):
        return "credential_or_secret"
    if any(marker in category for marker in ("delete", "destructive", "rm", "wipe")):
        return "destructive"
    if any(marker in category for marker in ("submit", "email", "payment", "push", "external")):
        return "external_effect"
    if risk_level == "critical":
        return "safety_critical"
    if risk_level == "high":
        return "external_effect"
    if risk_level == "medium":
        return "routine"
    return "external_effect"


def deployment_trust_context_for_agent(
    *,
    store: SQLiteStore,
    settings: Settings,
    node_id: str,
    agent_id: str,
) -> str:
    try:
        agent = store.get_agent(node_id, agent_id)
    except KeyError:
        return settings.clearance_default_deployment_trust_context
    return agent.get(
        "deployment_trust_context",
        settings.clearance_default_deployment_trust_context,
    )


def enforce_clearance_channel(
    *,
    store: SQLiteStore,
    settings: Settings,
    approval: dict,
    channel: str,
    actor_type: str,
    actor_id: str,
    request_id: str,
) -> ChannelPolicyDecision:
    decision = evaluate_clearance_channel(
        store=store,
        settings=settings,
        approval=approval,
        channel=channel,
    )
    if not decision.allowed:
        store.append_audit_event(
            event_type="clearance_channel_rejected",
            actor_type=actor_type,
            actor_id=actor_id,
            node_id=approval["node_id"],
            agent_id=approval["agent_id"],
            session_id=approval["session_id"],
            approval_id=approval["approval_id"],
            request_id=request_id,
            payload_redacted=decision_metadata(decision) | {"decision": "rejected"},
        )
        raise HTTPException(status.HTTP_403_FORBIDDEN, decision.reason)
    return decision


def evaluate_clearance_channel(
    *,
    store: SQLiteStore,
    settings: Settings,
    approval: dict,
    channel: str,
) -> ChannelPolicyDecision:
    policy = ClearanceChannelPolicy.from_settings(settings)
    deployment_trust_context = deployment_trust_context_for_agent(
        store=store,
        settings=settings,
        node_id=approval["node_id"],
        agent_id=approval["agent_id"],
    )
    return policy.evaluate(
        channel=channel,
        risk_family=approval.get("risk_family") or "external_effect",
        deployment_trust_context=deployment_trust_context,
    )


def decision_metadata(decision: ChannelPolicyDecision) -> dict[str, object]:
    return {
        "channel": decision.channel,
        "risk_family": decision.risk_family,
        "eligible_channels": decision.eligible_channels,
        "deployment_trust_context": decision.deployment_trust_context,
        "eligibility_result": "allowed" if decision.allowed else "rejected",
        "channel_rejection_reason": decision.reason,
    }


# ---------------------------------------------------------------------------
# BrowserBridge seam (additive): risk-class -> required-channel policy +
# authority provenance mapping.
#
# Binds a per-surface browser risk class to the operator channel that must
# make the decision, so "high-risk form-submit -> mobile-mandatory" is
# expressible as policy rather than convention. When an approval carries no
# ``risk_vector`` no channel is required and existing behavior is unchanged;
# once a vector demands a channel the decision is fail-closed.
# ---------------------------------------------------------------------------

# decision channel -> typed authority-provenance class.
_CHANNEL_AUTHORITY = {
    "mobile_signed": "human_mobile",
    "local_terminal": "human_local",
}

# device platform -> decision channel. Mobile platforms decide over the
# Secure-Enclave (mobile_signed) channel; desktop/terminal over local_terminal.
_MOBILE_PLATFORMS = {"ios", "ipados", "android"}
_LOCAL_PLATFORMS = {"macos", "linux", "windows", "local", "terminal", "cli"}


def channel_for_device(device: dict[str, Any] | None) -> str | None:
    """Resolve a device's decision channel. Prefers an explicit
    ``clearance_channel`` (bridge-era devices) and falls back to the device
    ``platform`` so the policy works on the base contract too."""
    if not device:
        return None
    channel = device.get("clearance_channel")
    if channel:
        return channel
    platform = (device.get("platform") or "").lower()
    if platform in _MOBILE_PLATFORMS:
        return "mobile_signed"
    if platform in _LOCAL_PLATFORMS:
        return "local_terminal"
    return None

# Risk-class values considered high enough to mandate the mobile channel.
HIGH_RISK_CLASS_VALUES = {"high", "critical"}
MOBILE_MANDATORY_CHANNELS = ("mobile_signed",)
_RISK_CLASS_KEYS = ("submit_risk_class", "click_risk_class", "field_class")


def authority_from_channel(channel: str | None) -> str:
    """Map a device's clearance channel to a typed authority class.

    Unknown/None channels resolve to ``test_operator`` (e.g. dev/test devices
    not bound to a human-operator channel)."""
    return _CHANNEL_AUTHORITY.get(channel or "", "test_operator")


def required_channels_for_risk_vector(
    risk_vector: dict[str, Any] | None,
) -> tuple[str, ...] | None:
    """Channels permitted to decide an approval carrying this risk vector, or
    ``None`` when the vector imposes no channel requirement."""
    if not risk_vector:
        return None
    for key in _RISK_CLASS_KEYS:
        value = risk_vector.get(key)
        if isinstance(value, str) and value.lower() in HIGH_RISK_CLASS_VALUES:
            return MOBILE_MANDATORY_CHANNELS
    return None


def required_channels_for_risk_family(
    risk_family: str | None,
) -> tuple[str, ...] | None:
    """Channels permitted to decide a request in this risk family.

    The *other* half of the channel policy from
    :func:`required_channels_for_risk_vector`, derived from the canonical
    :data:`MOBILE_MANDATORY_RISK_FAMILIES` set rather than a parallel hardcoded
    list, so a family added there is enforced everywhere with no further edits.

    ``None`` means the family mandates no particular channel. An *unrecognised*
    family fails closed onto the mobile channel: an unclassified action is a
    classification gap, and the safe reading of a gap is "a human decides".
    """
    family = risk_family or ""
    if family not in ALL_RISK_FAMILIES:
        return MOBILE_MANDATORY_CHANNELS
    if family in MOBILE_MANDATORY_RISK_FAMILIES:
        return MOBILE_MANDATORY_CHANNELS
    return None


#: Canonical channel ordering, so a combined requirement is deterministic.
_CHANNEL_PRECEDENCE = ("mobile_signed", "local_terminal")


def required_channels_for_request(
    *,
    risk_family: str | None = None,
    risk_vector: dict[str, Any] | None = None,
) -> tuple[str, ...] | None:
    """**The** canonical answer to "must a human on a specific (mobile-signed)
    channel decide this request?" — covering BOTH halves of the channel policy.

    The channel policy has two independent inputs: the request's ``risk_family``
    (:data:`MOBILE_MANDATORY_RISK_FAMILIES`) and the BrowserBridge per-surface
    ``risk_vector`` (:data:`HIGH_RISK_CLASS_VALUES`). Consulting one and not the
    other is a hole, so every caller — the clearance decision path in ``app`` and
    the standing-grant fail-closed gate in ``grants`` — routes through this one
    function and the two can never drift apart again.

    Returns the channels allowed to decide, or ``None`` when nothing is mandated.
    """
    halves = [
        required
        for required in (
            required_channels_for_risk_family(risk_family),
            required_channels_for_risk_vector(risk_vector),
        )
        if required
    ]
    if not halves:
        return None
    allowed = set(_CHANNEL_PRECEDENCE)
    for required in halves:
        allowed &= set(required)
    if not allowed:
        # Two halves demanding disjoint channels must not produce an empty
        # tuple: channel_satisfies reads a falsy requirement as "no requirement"
        # and would fail *open*. Fall back to the strictest channel instead.
        return MOBILE_MANDATORY_CHANNELS
    return tuple(channel for channel in _CHANNEL_PRECEDENCE if channel in allowed)


def channel_satisfies(
    channel: str | None, required: tuple[str, ...] | None
) -> bool:
    """True if ``channel`` is allowed to decide given the requirement (or there
    is no requirement)."""
    if not required:
        return True
    return (channel or "") in required

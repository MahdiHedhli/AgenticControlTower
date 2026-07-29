"""Standing approval grants — "approve for this session" / "allow forever".

Two halves:

* the **write** side (:func:`mint_grant_for_decision`) turns a human decision
  carrying ``scope`` other than ``once`` into a persisted, hard-expiring grant;
* the **read** side (:func:`standing_grant_for_request` +
  :func:`record_auto_satisfaction`) is consulted at approval *creation* time
  and, on a hit, records the request already approved.

Every fail-closed guard lives here so both request-creation call sites
(``app._create_approval_request`` and ``runtime_adapter.request_approval``) get
exactly the same policy — a guard that only one path enforces is not a guard.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .capability_registry import RISK_FAMILY_RANKS
from .clearance_policy import (
    required_channels_for_request,
    required_channels_for_risk_family,
)
from .config import Settings
from .security import expires_in
from .store import SQLiteStore

#: Authority recorded on an approval that a standing grant cleared. Distinct
#: from every human authority class so ``human_approved`` stays honest.
STANDING_GRANT_AUTHORITY = "standing_grant"

#: Scopes that mint a standing grant. ``once`` is absent by design.
GRANTABLE_SCOPES: frozenset[str] = frozenset({"session", "agent", "permanent"})

#: Risk families excluded by the *risk-ladder* floor, derived from the canonical
#: ladder in capability_registry rather than duplicated, so a newly added high
#: family is excluded automatically.
#:
#: NOT the whole exclusion set. The channel policy excludes more (every family in
#: ``MOBILE_MANDATORY_RISK_FAMILIES`` — notably ``external_effect``, which ranks
#: *below* this floor yet still requires a human on a mobile-signed channel).
#: :func:`standing_grant_block_reason` is the only complete answer; see
#: :data:`GRANT_UNGRANTABLE_RISK_FAMILIES` for the derived union.
_EXCLUSION_FLOOR = RISK_FAMILY_RANKS["destructive"]
GRANT_EXCLUDED_RISK_FAMILIES: frozenset[str] = frozenset(
    family for family, rank in RISK_FAMILY_RANKS.items() if rank >= _EXCLUSION_FLOOR
)

#: Every family a standing grant can never satisfy, both halves of the policy
#: combined. Derived, never enumerated: a family added to either the risk ladder
#: above the floor or to MOBILE_MANDATORY_RISK_FAMILIES lands here for free.
GRANT_UNGRANTABLE_RISK_FAMILIES: frozenset[str] = frozenset(
    family
    for family in RISK_FAMILY_RANKS
    if family in GRANT_EXCLUDED_RISK_FAMILIES
    or required_channels_for_risk_family(family)
)


def risk_family_blocks_standing_grant(risk_family: str | None) -> bool:
    """True when this risk family must always reach a human.

    An *unrecognised* family also blocks: an unclassified action is a
    classification gap, and the safe reading of a gap is "prompt".
    """
    rank = RISK_FAMILY_RANKS.get(risk_family or "")
    if rank is None:
        return True
    return rank >= _EXCLUSION_FLOOR


def grant_ttl_seconds(settings: Settings, scope: str) -> int:
    return {
        "session": settings.grant_ttl_session_seconds,
        "agent": settings.grant_ttl_agent_seconds,
        "permanent": settings.grant_ttl_permanent_seconds,
    }[scope]


def grant_expiry(settings: Settings, scope: str) -> str:
    """Hard expiry for a new grant. Mandatory for every scope, permanent
    included — an unbounded standing authorization is not acceptable."""
    return (
        expires_in(grant_ttl_seconds(settings, scope))
        .isoformat()
        .replace("+00:00", "Z")
    )


def standing_grant_block_reason(
    *,
    settings: Settings,
    risk_family: str | None,
    risk_vector: dict[str, Any] | None,
) -> str | None:
    """The single fail-closed gate, shared by the write and read sides.

    Returns a machine-readable reason string when a standing grant must not be
    minted or consumed, or ``None`` when it may be.
    """
    if not settings.standing_grants_enabled:
        return "standing_grants_disabled"
    if risk_family_blocks_standing_grant(risk_family):
        return "risk_family_excluded"
    if required_channels_for_request(
        risk_family=risk_family,
        risk_vector=risk_vector,
    ):
        # The channel policy mandates a specific (mobile-signed, human) decision
        # channel for this request — because of its risk family, its per-surface
        # risk vector, or both. A stored grant is not a human on a channel, so it
        # must always prompt. Routed through the canonical combined entry point so
        # this gate enforces the WHOLE policy, not one half of it: adding a family
        # to MOBILE_MANDATORY_RISK_FAMILIES blocks auto-satisfy here with no edit.
        return "channel_requirement"
    return None


# ---------------------------------------------------------------------------
# Write side — mint a grant from a human decision
# ---------------------------------------------------------------------------


def mint_grant_for_decision(
    *,
    store: SQLiteStore,
    settings: Settings,
    approval: dict[str, Any],
    scope: str | None,
    request_id: str,
    decided_by_device_id: str | None,
) -> dict[str, Any] | None:
    """Create the standing grant implied by an approval decision.

    Returns the grant, or ``None`` when the decision does not (or must not)
    produce one. Refusals for a reason the operator would care about are
    audited as ``capability_grant_refused``; plain ``once`` is not, because
    "no standing authority" is the normal case, not an event.
    """
    if scope not in GRANTABLE_SCOPES:
        return None

    reason = standing_grant_block_reason(
        settings=settings,
        risk_family=approval.get("risk_family"),
        risk_vector=approval.get("risk_vector"),
    )
    if reason is not None:
        store.append_audit_event(
            event_type="capability_grant_refused",
            actor_type="device" if decided_by_device_id else "gateway",
            actor_id=decided_by_device_id or "gateway",
            node_id=approval["node_id"],
            agent_id=approval["agent_id"],
            session_id=approval["session_id"],
            approval_id=approval["approval_id"],
            request_id=request_id,
            payload_redacted={
                "scope": scope,
                "reason": reason,
                "requested_tool": approval.get("requested_tool"),
                "risk_family": approval.get("risk_family"),
            },
        )
        return None

    scoped = _scope_key_fields_for_decision(approval, scope)
    grant = store.create_approval_grant(
        {
            "node_id": approval["node_id"],
            "agent_id": approval["agent_id"],
            "requested_tool": approval["requested_tool"],
            "capability": approval.get("capability"),
            "risk_family": approval["risk_family"],
            "scope": scope,
            "state": "active",
            "source_approval_id": approval["approval_id"],
            "granted_by_device_id": decided_by_device_id,
            "expires_at": grant_expiry(settings, scope),
            **scoped,
        }
    )
    # A privilege-escalating write must be auditable on its own, not inferable
    # from the approval decision that happened to carry a scope.
    store.append_audit_event(
        event_type="capability_grant_created",
        actor_type="device" if decided_by_device_id else "gateway",
        actor_id=decided_by_device_id or "gateway",
        node_id=approval["node_id"],
        agent_id=approval["agent_id"],
        session_id=approval["session_id"],
        approval_id=approval["approval_id"],
        request_id=request_id,
        payload_redacted={
            "grant_id": grant["grant_id"],
            "scope": scope,
            "requested_tool": grant["requested_tool"],
            "capability": grant.get("capability"),
            "risk_family": grant["risk_family"],
            "session_id": grant.get("session_id"),
            "params_fingerprint": grant.get("params_fingerprint"),
            "expires_at": grant["expires_at"],
            "ttl_seconds": grant_ttl_seconds(settings, scope),
            "source_approval_id": grant["source_approval_id"],
        },
    )
    store.create_event(
        node_id=approval["node_id"],
        agent_id=approval["agent_id"],
        session_id=approval["session_id"],
        event_type="capability_grant.created",
        payload={
            "grant_id": grant["grant_id"],
            "scope": scope,
            "requested_tool": grant["requested_tool"],
            "expires_at": grant["expires_at"],
        },
    )
    return grant


def _scope_key_fields_for_decision(approval: dict[str, Any], scope: str) -> dict[str, Any]:
    """Which request attributes the grant is keyed on.

    ``session`` pins the exact command (params_fingerprint) inside one session.
    ``agent`` and ``permanent`` deliberately do not, because their purpose is to
    cover repeated invocations whose parameters differ.
    """
    if scope == "session":
        return {
            "session_id": approval["session_id"],
            "params_fingerprint": approval["params_fingerprint"],
        }
    return {"session_id": None, "params_fingerprint": None}


# ---------------------------------------------------------------------------
# Read side — consume a grant at request-creation time
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class StandingGrantResolution:
    """Outcome of the request-creation lookup.

    ``grant`` is the grant that clears this request. ``refusal`` is set when a
    grant *did* match but a fail-closed guard forbade using it — that is worth
    auditing, because the operator granted something the gateway is now
    declining to honour. Both ``None`` is the ordinary "nothing granted" case
    and produces no event.
    """

    grant: dict[str, Any] | None = None
    refusal: str | None = None

    @property
    def auto_satisfied(self) -> bool:
        return self.grant is not None

    @property
    def initial_state(self) -> str:
        """State the approval row must be created in.

        Created directly in its final state so there is no window in which a
        phone could see (and act on) a request that is already cleared.
        """
        return "approved" if self.grant is not None else "pending"


def standing_grant_for_request(
    *,
    store: SQLiteStore,
    settings: Settings,
    node_id: str,
    agent_id: str,
    session_id: str,
    requested_tool: str,
    params_fingerprint: str,
    risk_family: str,
    risk_vector: dict[str, Any] | None,
) -> StandingGrantResolution:
    """Whether a live standing grant already authorizes this request.

    Called immediately before ``store.create_approval`` on every
    request-creation path. Never mutates anything: the caller records the
    approval either way, because the audit trail must show every attempted
    action, cleared or not.
    """
    if not settings.standing_grants_enabled:
        return StandingGrantResolution()
    grant = store.find_matching_grant(
        node_id=node_id,
        agent_id=agent_id,
        session_id=session_id,
        requested_tool=requested_tool,
        params_fingerprint=params_fingerprint,
        risk_family=risk_family,
    )
    if grant is None:
        return StandingGrantResolution()
    # A grant existing is not authority to use it. The same gate the write side
    # applies is re-applied here, so a grant that predates a policy change (or
    # a request that carries a channel-mandating risk vector the granted one did
    # not) still fails closed.
    reason = standing_grant_block_reason(
        settings=settings,
        risk_family=risk_family,
        risk_vector=risk_vector,
    )
    if reason is not None:
        return StandingGrantResolution(refusal=reason)
    return StandingGrantResolution(grant=grant)


def record_auto_satisfaction(
    *,
    store: SQLiteStore,
    approval: dict[str, Any],
    grant: dict[str, Any],
    request_id: str,
) -> dict[str, Any]:
    """Stamp the decision fields on an approval a standing grant cleared.

    The approval row already exists (created in state ``approved``); this
    records *how* it got there — scope, non-human authority — through the same
    ``resolve_approval`` write path a human decision uses, and audits it as
    ``approval_auto_satisfied`` carrying the grant id.
    """
    store.resolve_approval(
        approval["approval_id"],
        "approved",
        decision_scope=grant["scope"],
        decision_actor_device_id=grant.get("granted_by_device_id"),
        decision_metadata={
            "decision": "approve",
            "state": "approved",
            "auto_satisfied": True,
            "grant_id": grant["grant_id"],
            "grant_scope": grant["scope"],
            "grant_expires_at": grant["expires_at"],
            "source_approval_id": grant["source_approval_id"],
        },
        approved_by=STANDING_GRANT_AUTHORITY,
        # Not a human decision. human_approved stays False so anything that
        # requires a live human (aircraft strict verification, audit review)
        # can still tell the difference.
        human_approved=False,
    )
    store.append_audit_event(
        event_type="approval_auto_satisfied",
        actor_type="gateway",
        actor_id=STANDING_GRANT_AUTHORITY,
        node_id=approval["node_id"],
        agent_id=approval["agent_id"],
        session_id=approval["session_id"],
        approval_id=approval["approval_id"],
        request_id=request_id,
        payload_redacted={
            "grant_id": grant["grant_id"],
            "scope": grant["scope"],
            "requested_tool": approval["requested_tool"],
            "capability": approval.get("capability"),
            "risk_family": approval["risk_family"],
            "params_fingerprint": approval["params_fingerprint"],
            "grant_expires_at": grant["expires_at"],
            "source_approval_id": grant["source_approval_id"],
            "granted_by_device_id": grant.get("granted_by_device_id"),
            "human_approved": False,
        },
    )
    store.create_event(
        node_id=approval["node_id"],
        agent_id=approval["agent_id"],
        session_id=approval["session_id"],
        event_type="approval.resolved",
        payload={
            "approval_id": approval["approval_id"],
            "state": "approved",
            "scope": grant["scope"],
            "grant_id": grant["grant_id"],
            "auto_satisfied": True,
        },
    )
    return store.get_approval(approval["approval_id"])


def record_auto_satisfy_refusal(
    *,
    store: SQLiteStore,
    approval: dict[str, Any],
    reason: str,
    request_id: str,
) -> None:
    """Audit a matching grant the gateway declined to honour."""
    store.append_audit_event(
        event_type="approval_auto_satisfy_refused",
        actor_type="gateway",
        actor_id=STANDING_GRANT_AUTHORITY,
        node_id=approval["node_id"],
        agent_id=approval["agent_id"],
        session_id=approval["session_id"],
        approval_id=approval["approval_id"],
        request_id=request_id,
        payload_redacted={
            "reason": reason,
            "requested_tool": approval["requested_tool"],
            "risk_family": approval["risk_family"],
        },
    )

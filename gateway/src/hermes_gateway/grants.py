"""Standing approval grants — "approve for this session" / "allow forever".

Two halves:

* the **write** side (:func:`mint_grant_for_decision`) turns a human decision
  carrying ``scope`` other than ``once`` into a persisted, hard-expiring grant;
* the **read** side (:func:`resolve_standing_grant`) is consulted at approval
  *creation* time and, on a hit, lets the request be recorded already approved.

Every fail-closed guard lives here so both request-creation call sites
(``app._create_approval_request`` and ``runtime_adapter.request_approval``) get
exactly the same policy — a guard that only one path enforces is not a guard.
"""

from __future__ import annotations

from typing import Any

from .capability_registry import RISK_FAMILY_RANKS
from .clearance_policy import required_channels_for_risk_vector
from .config import Settings
from .security import expires_in
from .store import SQLiteStore

#: Authority recorded on an approval that a standing grant cleared. Distinct
#: from every human authority class so ``human_approved`` stays honest.
STANDING_GRANT_AUTHORITY = "standing_grant"

#: Scopes that mint a standing grant. ``once`` is absent by design.
GRANTABLE_SCOPES: frozenset[str] = frozenset({"session", "agent", "permanent"})

#: Risk families that may never be satisfied by a standing grant, derived from
#: the canonical ladder in capability_registry rather than duplicated, so a
#: newly added high family is excluded automatically.
_EXCLUSION_FLOOR = RISK_FAMILY_RANKS["destructive"]
GRANT_EXCLUDED_RISK_FAMILIES: frozenset[str] = frozenset(
    family for family, rank in RISK_FAMILY_RANKS.items() if rank >= _EXCLUSION_FLOOR
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
    if required_channels_for_risk_vector(risk_vector):
        # This risk class mandates a specific (mobile-signed) decision channel.
        # A standing grant is not that channel, so it must always prompt.
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

    scoped = _scope_key_fields(approval, scope)
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


def _scope_key_fields(approval: dict[str, Any], scope: str) -> dict[str, Any]:
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

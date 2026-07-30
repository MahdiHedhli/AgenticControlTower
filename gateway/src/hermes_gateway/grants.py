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

KNOWN GAP, operationally the important one: revoking a DEVICE does not revoke the
standing grants it minted. ``revoke_device`` flips ``status`` and kills auth
tokens, but the device row survives and this module resolves it without a status
filter, so an unpaired device's grants keep auto-approving until they expire (up
to the permanent TTL) or are revoked one by one via
``POST /v1/approval-grants/<id>/revoke``. Details and the second, narrower
channel-resolution divergence are documented on
:func:`grant_channel_authority_block_reason`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .capability_registry import RISK_FAMILY_RANKS
from .clearance_policy import (
    channel_for_device,
    evaluate_clearance_channel_for,
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

#: The CONFIG-INDEPENDENT floor of families a standing grant can never satisfy —
#: both halves of the static policy combined. Derived, never enumerated: a family
#: added to either the risk ladder above the floor or to
#: MOBILE_MANDATORY_RISK_FAMILIES lands here for free.
#:
#: A module constant cannot see operator configuration, so this is a floor and not
#: the whole answer: ``ACT_CLEARANCE_RISK_CHANNEL_MAP`` can make further families
#: mobile-mandatory. :func:`grant_ungrantable_risk_families` is the effective set
#: for a given deployment, and :func:`standing_grant_block_reason` is what the
#: gateway actually enforces.
GRANT_UNGRANTABLE_RISK_FAMILIES: frozenset[str] = frozenset(
    family
    for family in RISK_FAMILY_RANKS
    if family in GRANT_EXCLUDED_RISK_FAMILIES
    or required_channels_for_risk_family(family)
)


def grant_ungrantable_risk_families(settings: Settings) -> frozenset[str]:
    """Every family a standing grant can never satisfy *in this deployment*.

    :data:`GRANT_UNGRANTABLE_RISK_FAMILIES` plus whatever the operator's
    effective channel policy adds. Config can add, never remove.
    """
    return GRANT_UNGRANTABLE_RISK_FAMILIES | frozenset(
        family
        for family in RISK_FAMILY_RANKS
        if required_channels_for_risk_family(family, settings=settings)
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


def standing_grant_policy_block_reason(
    *,
    settings: Settings,
    risk_family: str | None,
    risk_vector: dict[str, Any] | None,
) -> str | None:
    """The CONFIG-and-request half of the gate: kill switch, risk-ladder floor,
    and the channel requirements the risk family / risk vector impose on their own.

    Deliberately NOT the whole gate and deliberately not named as if it were —
    it knows nothing about *who* granted the standing authority, so on its own it
    cannot tell a family the operator restricted to ``local_terminal`` from a
    family with no channel requirement at all. :func:`standing_grant_block_reason`
    is what mint and consume call; this is one of its two halves, exposed only so
    the pure-policy half can be unit-tested without a store.
    """
    if not settings.standing_grants_enabled:
        return "standing_grants_disabled"
    if risk_family_blocks_standing_grant(risk_family):
        return "risk_family_excluded"
    if required_channels_for_request(
        risk_family=risk_family,
        risk_vector=risk_vector,
        # The EFFECTIVE policy, not just the module constants. The gateway runs on
        # ClearanceChannelPolicy.from_settings(settings), whose risk_channel_map is
        # operator-supplied (ACT_CLEARANCE_RISK_CHANNEL_MAP); a gate that read only
        # the static set was blind to every family the operator had configured as
        # mobile-mandatory and would auto-satisfy it from a stored grant. Threading
        # settings through the ONE shared gate covers both callers at once — mint
        # (mint_grant_for_decision) and consume (standing_grant_for_request).
        settings=settings,
    ):
        # The channel policy mandates a specific (mobile-signed, human) decision
        # channel for this request — because of its risk family, its per-surface
        # risk vector, or both. A stored grant is not a human on a channel, so it
        # must always prompt. Routed through the canonical combined entry point so
        # this gate enforces the WHOLE policy, not one half of it: adding a family
        # to MOBILE_MANDATORY_RISK_FAMILIES *or* to the operator's mobile-only map
        # blocks auto-satisfy here with no edit.
        return "channel_requirement"
    return None


def grant_channel_authority_block_reason(
    *,
    store: SQLiteStore,
    settings: Settings,
    node_id: str,
    agent_id: str,
    risk_family: str | None,
    granted_by_device_id: str | None,
) -> str | None:
    """The AUTHORITY half of the gate: does the granting device's channel actually
    have the standing to decide *this* request?

    A standing grant is a **prior human decision**, so it should carry the channel
    authority of the device that minted it and no more. The question asked here is
    the *channel* question the live decision path asks of a phone tapping "approve"
    — :func:`evaluate_clearance_channel_for`, i.e. ``ClearanceChannelPolicy.evaluate``
    on the effective operator policy plus the agent's deployment trust context —
    with the *granting* device's channel substituted for the deciding device's.

    It is NOT the whole question the live path asks. See "KNOWN GAPS" below: this
    function reproduces the live path's channel evaluation only, not its device
    *eligibility* checks, so the two can disagree about the same device.

    Why the family-level half above cannot answer this: it projects the policy onto
    the single question "is this family mobile-mandatory". An operator who restricts
    a family to the OTHER human channel (``routine: ("local_terminal",)``) imposes
    a real human-channel requirement that projection cannot see, so the request
    looked unconstrained and a stored grant cleared it. Asking ``evaluate`` instead
    keeps the whole map in play. And the naive alternative — "block whenever the
    policy imposes any requirement" — is not available: ``validate()`` requires
    ``risk_channel_map`` to cover every family and the lookup default is
    ``("mobile_signed",)``, so every family always imposes something and the
    feature would be dead rather than safe.

    Consequence, which is the intended posture: a ``mobile_signed`` grant may
    auto-satisfy families the policy lets ``mobile_signed`` decide and may NOT
    auto-satisfy a family restricted to ``local_terminal`` (and vice-versa).

    Fail-closed when the granting authority is *unresolvable*: no granting device
    recorded, the device row gone (deleted/never existed), a device whose channel
    cannot be resolved, or a policy that will not validate. "We cannot tell whose
    authority this was" is never an answer that permits auto-satisfy.

    KNOWN GAPS (verified outstanding, not fixed here — do not read the paragraphs
    above as covering these):

    1. REVOKED GRANTING DEVICE STILL CARRIES AUTHORITY. ``store.get_device`` is a
       bare ``SELECT * FROM devices WHERE device_id = ?`` with no ``status``
       predicate (``storage/identity.py``), and ``revoke_device`` only flips
       ``status`` to ``'revoked'`` — the row survives with its recorded
       ``clearance_channel``. The live decision path rejects a non-active device
       with 403 ``device is not active`` (``signing.py``, ``device["status"] !=
       "active"``) *before* it ever reaches channel evaluation; this function never
       asks. Precondition: operator unpairs a device (``DELETE /v1/devices/<id>``)
       that had already minted standing grants. Effect: that device is immediately
       403 on the live path, yet each of its existing grants — session, agent, and
       permanent scope alike, including an ``agent``-scope grant consumed in a
       brand-new session — keeps auto-approving with ``approved_by=standing_grant``
       and no refusal audited, for up to the full permanent TTL. None of the four
       unresolvable cases above fires, because the row is present and its channel
       resolves. Only per-grant revocation (``POST /v1/approval-grants/<id>/revoke``)
       clears them; device revocation does not cascade. So a grant can outlive the
       authority that minted it.
    2. CHANNEL-RESOLUTION DIVERGENCE. The live path reads
       ``device.get("clearance_channel", "local_terminal")`` (``signing.py``) while
       this function uses :func:`channel_for_device`, which falls back to
       ``platform`` when ``clearance_channel`` is empty. Precondition: a device row
       with ``clearance_channel=''`` and a mobile ``platform``. Effect: the live
       path 403s ('' is not an eligible channel) while this function resolves
       ``mobile_signed`` and auto-satisfies. Reaching that state needs a direct DB
       write today, since the pairing schema types the field as a ``Literal``.
    """
    if not granted_by_device_id:
        return "grant_channel_authority_unresolved"
    try:
        # KNOWN GAP 1 (see docstring): no status filter here, and none below. A
        # 'revoked' device row still resolves and still confers channel authority,
        # so its standing grants keep auto-approving after the operator unpaired it
        # even though the live path 403s that same device as not active.
        device = store.get_device(granted_by_device_id)
    except KeyError:
        return "grant_channel_authority_unresolved"
    # KNOWN GAP 2 (see docstring): platform fallback here vs the live path's
    # 'local_terminal' default, so an empty clearance_channel resolves differently.
    channel = channel_for_device(device)
    if not channel:
        return "grant_channel_authority_unresolved"
    try:
        decision = evaluate_clearance_channel_for(
            store=store,
            settings=settings,
            node_id=node_id,
            agent_id=agent_id,
            risk_family=risk_family,
            channel=channel,
        )
    except ValueError:
        # An operator policy that will not validate must not widen the gate.
        return "grant_channel_authority_unresolved"
    if not decision.allowed:
        return "grant_channel_authority_insufficient"
    return None


def standing_grant_block_reason(
    *,
    store: SQLiteStore,
    settings: Settings,
    node_id: str,
    agent_id: str,
    risk_family: str | None,
    risk_vector: dict[str, Any] | None,
    granted_by_device_id: str | None,
) -> str | None:
    """The single fail-closed gate, shared by the write and read sides.

    Returns a machine-readable reason string when a standing grant must not be
    minted or consumed, or ``None`` when it may be. Both halves, in order:
    :func:`standing_grant_policy_block_reason` (kill switch, risk ladder, the
    channel requirements the family/vector impose) then
    :func:`grant_channel_authority_block_reason` (the granting device's channel
    authority over this request). The policy half runs first so its coarser,
    config-independent refusal reasons stay stable in the audit trail.

    Every caller goes through here — ``mint_grant_for_decision`` and
    ``standing_grant_for_request`` — which is why the ``granted_by_device_id``
    argument is required rather than defaulted: a call site that does not know
    whose authority it is honouring must not compile, let alone silently pass.
    """
    reason = standing_grant_policy_block_reason(
        settings=settings,
        risk_family=risk_family,
        risk_vector=risk_vector,
    )
    if reason is not None:
        return reason
    return grant_channel_authority_block_reason(
        store=store,
        settings=settings,
        node_id=node_id,
        agent_id=agent_id,
        risk_family=risk_family,
        granted_by_device_id=granted_by_device_id,
    )


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
        store=store,
        settings=settings,
        node_id=approval["node_id"],
        agent_id=approval["agent_id"],
        risk_family=approval.get("risk_family"),
        risk_vector=approval.get("risk_vector"),
        # The device deciding *is* the device that would mint the grant, so the
        # authority half is asked about it here and about
        # ``grant["granted_by_device_id"]`` on the consume side — the same device,
        # the same question, one gate.
        granted_by_device_id=decided_by_device_id,
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
    # not, or one whose granting device no longer has the standing to decide this
    # family) still fails closed.
    reason = standing_grant_block_reason(
        store=store,
        settings=settings,
        node_id=node_id,
        agent_id=agent_id,
        risk_family=risk_family,
        risk_vector=risk_vector,
        granted_by_device_id=grant.get("granted_by_device_id"),
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

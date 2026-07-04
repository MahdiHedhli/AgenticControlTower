# ACT — Clearance Contract Extension for the BrowserBridge Seam (handoff)

**Status:** not started. This is an inbound handoff: BrowserBridge attempted to
delegate its human-authority decision to ACT (the suite's "one tower" thesis) and
**stopped with a finding against ACT's clearance contract** — as written, ACT
cannot carry BrowserBridge's authority metadata or express reserve→commit. This
doc is the work order to unblock the seam with additive, backward-compatible
changes, without weakening any existing ACT invariant.

**Source finding (cross-repo):**
`/Users/mhedhli/Documents/Coding/ACS/BrowserBridge/docs/act-integration.md`
(BrowserBridge repo, sibling under `ACS/`). Suite framing:
`/Users/mhedhli/Documents/Coding/ACS/HANDOFF.md` §5.

Line numbers below were verified against `gateway/src/hermes_gateway/` on
`main` at handoff time; re-verify on open before editing.

## The five changes (additive, backward-compatible)

1. **Authority provenance.** Add typed fields to `ApprovalRequest` / the resolve
   response: `approved_by` (enum, e.g. `human_mobile | human_local | test_operator`)
   and `human_approved: bool`. Do NOT rely on the untyped `decision_metadata`
   bag, and stop dropping the decision actor where provenance is required.
   - Today: `ApprovalRequest` has no provenance fields — `schemas.py:290-307`.
     `decision_actor_device_id` / `decision_metadata_json` exist only as DB
     columns (`store.py:152-153`) and are set in `resolve_approval`
     (`store.py:908-915`), not surfaced as a typed, enforced part of the contract.

2. **Per-surface risk vector.** Allow a structured risk descriptor alongside the
   scalar `RiskLevel` so `field_class` / `submit_risk_class` / `click_risk_class`
   round-trip.
   - Today: `RiskLevel = Literal["low","medium","high","critical"]` — a scalar
     (`schemas.py:48`); no per-surface vector.

3. **Two-phase reserve→commit.** Add `reserved` and `committed` states (or a
   two-phase consume API) so a consumer can reserve at validation and commit only
   at execution dispatch, preserving one-time consumption + concurrency
   serialization.
   - Today: `resolve_approval` performs a single atomic
     `pending → {approved,denied,expired,cancelled}` transition
     (`store.py:908`); there is no intermediate `reserved`/`committed` state.

4. **Panic dominance.** Implement emergency-stop to BULK-INVALIDATE pending AND
   approved-but-unconsumed clearances.
   - Today: `intervention_placeholder` is a stub — it logs an
     `intervention_placeholder_requested` event and returns
     `resulting_state="not_executed_placeholder"` (`app.py:949-966`); it does not
     cancel approvals.

5. **Channel policy / risk tiering.** Bind risk class → required channel so
   "high-risk form-submit → mobile-mandatory" is expressible as policy, not
   convention.
   - Today: authorization is permission-by-capability —
     `require_device_capability` keyed by `DEVICE_PERMISSION_BY_CAPABILITY`
     (`capabilities.py:28,38`); there is no risk-class → channel binding.

## Invariants you must NOT regress

One-time consumption, replay denial (nonce store), host/device binding (loopback +
signed requests), mandatory audit, fail-closed behavior. Every new field is
optional/defaulted so existing consumers (Hermes — adapter #1 behind the
`RuntimeAdapter` boundary) keep working unchanged.

## Approach

1. Write characterization tests pinning current contract behavior FIRST (mirror
   the existing gateway test style) so the additive changes prove
   backward-compatibility.
2. Land changes 1–5 as separate, individually-green commits with tests.
3. Update `docs/api/openapi.yaml` and `docs/architecture/approval-framework.md`
   to match. Do not overstate capability.

## Done criteria

- Gateway suite green; new tests cover provenance round-trip, risk-vector
  round-trip, reserve→commit (incl. commit-after-reserve and reserve-then-panic),
  and panic invalidating approved-but-unconsumed clearances.
- A short reply doc (e.g. `docs/implementation/browserbridge-seam-contract.md`)
  stating which BrowserBridge requirements (R1–R4 + channel policy) are now
  satisfiable, so BrowserBridge Sprint 2 can resume against the real contract.

## Out of scope / STOP

Do not implement the BrowserBridge side here. Do not weaken auth/replay/panic. If
a change cannot be made additive without breaking an existing consumer, record it
and stop rather than forcing it.

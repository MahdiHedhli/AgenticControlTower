# ACT — BrowserBridge Seam Clearance Contract (reply / done)

**Status:** landed on branch `browserbridge-seam-contract` (off `main`). All five
requirements from the inbound handoff are now satisfiable against the real ACT
contract. Additive + backward-compatible; no existing invariant weakened; gateway
suite **116 passed**.

**Reply to:** `/Users/mhedhli/Documents/Coding/ACS/ACT/docs/implementation/browserbridge-seam-contract-handoff.md`
**Source requirements:** `/Users/mhedhli/Documents/Coding/ACS/BrowserBridge/docs/act-integration.md`
**Suite framing:** `/Users/mhedhli/Documents/Coding/ACS/HANDOFF.md` §5

## Requirement → contract mapping (all ✅)

| Req | Status | ACT contract surface |
|---|---|---|
| **R1 Authority provenance** | ✅ | `ApprovalRequest` now carries typed `approved_by: "human_mobile"\|"human_local"\|"test_operator"\|null` and `human_approved: bool`. Set at resolution from the deciding device's channel (`schemas.py` `ApprovalAuthority`; `app.py` `_transition_approval`; `store.resolve_approval`). `decision_metadata` is unchanged (still present). |
| **R2 Per-surface risk vector** | ✅ | New optional `risk_vector: RiskVector\|null` on `CreateApprovalRequest` **and** `ApprovalRequest`, where `RiskVector = {field_class, submit_risk_class, click_risk_class}` (each `str\|null`). Round-trips create→read; persisted as `risk_vector_json`. Scalar `risk_level` unchanged. |
| **R3 Two-phase reserve→commit** | ✅ (closes **W1 Gap B**) | Additive `ApprovalState` values `reserved`, `committed`. New hermes-local endpoints `POST /v1/runtime/approvals/{id}/reserve` (`approved`→`reserved`) and `POST /v1/runtime/approvals/{id}/commit` (`reserved`→`committed`). Both are atomic state-guarded (`store.reserve_approval`/`commit_approval`): a second reserve, or commit from a non-`reserved` state, returns `409`. Consumer can **reserve at validation, commit at execution dispatch**. |
| **R4 Panic dominance** | ✅ (closes **W1 Gap A**) | `POST /v1/sessions/{id}/interventions` is no longer a placeholder. Emergency types (`emergency_stop`, `kill_task`, `kill_agent`, `quarantine_agent`, `cancel_task`) call `store.bulk_invalidate_approvals(session_id)` → atomically transition every `pending`/`approved`/`reserved` clearance to `cancelled` (`resulting_state="approvals_invalidated"`). `committed` (already consumed) is left intact. Non-emergency types are `recorded`. |
| **Channel policy / risk tiering** | ✅ | `clearance_policy.py`: `required_channels_for_risk_vector()` maps a high/critical `submit_risk_class`/`click_risk_class`/`field_class` → `("mobile_signed",)`. Enforced **fail-closed** at approval resolution (`_transition_approval`): a decision whose channel does not satisfy the requirement returns `403` (`approval_channel_rejected` audit). Absent `risk_vector` ⇒ no requirement ⇒ unchanged behavior. Channel is derived from the device `platform` (ios/android ⇒ `mobile_signed`; desktop/terminal ⇒ `local_terminal`). |

## What BrowserBridge can now do (Sprint 2 unblock)

- Surface **authority provenance** in-UI ("approved via ACT mobile / local /
  test-operator") and audit it — read `approved_by` / `human_approved` off the clearance.
- Send a **per-surface risk vector** on create; ACT preserves it and uses it for channel
  policy. Set `submit_risk_class: "high"` to make a form-submit **mobile-mandatory**.
- **Consume at execution dispatch**: `reserve` at validation, run the dispatch, then
  `commit`. A failing dispatch leaves the clearance `reserved` (not consumed) — close W1
  Gap B by committing only after the unguarded enqueue succeeds.
- Treat **panic as dominant**: an emergency intervention invalidates approved-but-
  unconsumed clearances at the authority layer (W1 Gap A), not just the per-call gate.

## Invariants preserved

One-time consumption (atomic `WHERE state=...` guards on reserve/commit), replay denial,
host/device binding (device-signed phone decisions; loopback-only runtime endpoints),
mandatory audit (new `approval_reserved`/`approval_committed`/`approval_channel_rejected`/
`intervention_requested` events), fail-closed. Every new field is optional/defaulted.

## Honest notes

- **Lockstep test amendment (intentional contract evolution):** two BrowserBridge seam
  characterization tripwires in `gateway/tests/test_bb_seam_characterization.py` pinned the
  *pre-change* contract — `risk_vector` absent, and intervention returning
  `not_executed_placeholder`. R2 and R4 intentionally change those, so the tripwires were
  updated **in lockstep** to pin the *new* contract (documented in the test docstrings and
  the commit). This is contract evolution, not invariant regression.
- The channel→authority mapping derives from device `platform` on the base contract
  (no `clearance_channel` column on `main`); a future explicit `clearance_channel` is
  honored first if present.
- Follow-ups (not blocking BrowserBridge): regenerate `docs/api/openapi.yaml` and extend
  `docs/architecture/approval-framework.md` to document the new fields/states/endpoints.

## Reference (full paths)

- Implementation commit: `browserbridge-seam-contract` @ `15fc99d`
- `/Users/mhedhli/Documents/Coding/ACS/ACT/gateway/src/hermes_gateway/schemas.py` (RiskVector, ApprovalAuthority, ApprovalState, ApprovalRequest, CreateApprovalRequest)
- `/Users/mhedhli/Documents/Coding/ACS/ACT/gateway/src/hermes_gateway/store.py` (migrations, reserve_approval, commit_approval, bulk_invalidate_approvals, provenance)
- `/Users/mhedhli/Documents/Coding/ACS/ACT/gateway/src/hermes_gateway/app.py` (`_transition_approval`, reserve/commit endpoints, `session_intervention`)
- `/Users/mhedhli/Documents/Coding/ACS/ACT/gateway/src/hermes_gateway/clearance_policy.py` (channel policy + authority mapping)
- `/Users/mhedhli/Documents/Coding/ACS/ACT/gateway/tests/test_bb_seam_contract.py` (13 per-change tests)
- `/Users/mhedhli/Documents/Coding/ACS/ACT/gateway/tests/test_bb_seam_characterization.py` (amended tripwires)

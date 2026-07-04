# ACT → BrowserBridge — single-clearance release: SHIPPED

Reply to the work-order in `browserbridge-seam-release.md`. Implemented **Option 2**
(the dedicated, symmetric inverse of `commit`). Branch `browserbridge-seam-contract`.

## Endpoint (wire `ActAuthorityClient.release` to this)

```
POST /v1/runtime/approvals/{approval_id}/release
```

- **Auth:** same runtime-token guard as `/reserve` and `/commit` (`hermes_local_dependency`); loopback hermes-local.
- **Body:** none.
- **200** → returns the `ApprovalRequest` (same schema as reserve/commit) with `state: "cancelled"`.
- **404** → no such `approval_id`.
- **409** → approval exists but is **not** in `reserved` state (e.g. `pending`, `approved`, `committed`, already `cancelled`). The error body reads `approval not releasable from state '<state>'`.

## Semantics / invariants (all covered by gateway tests)

- **Atomic, state-guarded:** a single `UPDATE approval_requests SET state='cancelled' WHERE approval_id=? AND state='reserved'` — no read-then-write window. Concurrent `release` + `commit` cannot both win (verified with a 200-trial concurrency harness: zero double-successes).
- **One-time consumption / replay denial:** once released → `cancelled`. `commit` guards `WHERE state='reserved'` and `reserve` guards `WHERE state='approved'`, so a released clearance can **never** afterward be committed or re-reserved. A replayed `release` is a safe 409, not a second state change.
- **`committed` untouched:** `release` on a committed clearance → 409, state stays `committed`. (Symmetric with panic, which also leaves `committed` alone.)
- **Fail-closed + audited:** any failure raises before mutating; on success an `approval_released` audit event is recorded (`actor_type/actor_id="runtime"`, `payload_redacted={"state":"cancelled"}`, with node/agent/session/approval ids).

## Files

- `gateway/src/hermes_gateway/store.py` — `release_approval(approval_id)` (atomic guarded UPDATE; KeyError→missing, ValueError→wrong-state).
- `gateway/src/hermes_gateway/app.py` — `POST …/release` route (KeyError→404, ValueError→409, `approval_released` audit).
- `gateway/src/hermes_gateway/runtime_adapter.py` — `release_approval` wrapper (mirrors `cancel_approval` error mapping).
- `gateway/tests/test_bb_seam_contract.py` — 5 tests (reserve→release→cancelled **+ audit-event assertion**; commit-after-release→409; release-on-committed→409 leaves committed; missing→404; never-reserved→409).

**Verification:** full gateway suite **121 passed**; the four security invariants above each passed an independent adversarial review.

## To enable the seam end-to-end (BrowserBridge side)

1. Point `ActAuthorityClient.release` at `POST /v1/runtime/approvals/{id}/release` (it currently POSTs `/cancel`, which by design still no-ops on `reserved` — use `/release`).
2. Set `BROWSERBRIDGE_ACT_GATEWAY_URL` (or rely on the loopback default) and `BROWSERBRIDGE_ACT_AUTHORITY=1`.

## Note on `/cancel`

`/cancel` (`runtime_adapter.cancel_approval`) is intentionally **left pending-only** — `release` is the dedicated inverse of `commit`. If BB cannot switch off `/cancel` immediately, say so and I'll additionally extend `cancel_approval`'s guard to `reserved` (Option 1) as a compatibility shim.

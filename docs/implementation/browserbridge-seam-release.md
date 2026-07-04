# ACT — single-clearance release of a `reserved` clearance (finding / work order)

**Status:** not started. Inbound finding from the BrowserBridge seam wiring. The
two-phase reserve→commit you landed works; what's missing is a way to **release a
single `reserved` clearance** without committing it. BrowserBridge needs this to
honor the locked wiring ordering; the seam stays disabled until it exists.

## The gap

`cancel_approval` (`gateway/src/hermes_gateway/runtime_adapter.py:646`) only acts
when `approval["state"] == "pending"`:

```python
if approval["state"] == "pending":
    self.store.resolve_approval(approval_id, "cancelled", ...)
    ...
return self.approval_result(approval_id)   # any other state: silent no-op
```

So `POST /v1/runtime/approvals/{id}/cancel` on a **`reserved`** clearance is a
no-op — it returns the unchanged `reserved` state. Session-wide panic
`bulk_invalidate_approvals` does transition `reserved → cancelled`, but there is no
**single-clearance** release.

## Why BrowserBridge needs it

The agreed seam ordering is: ACT **reserve** → BrowserBridge local consume +
dispatch → **commit** on execution, **release** on non-execution
(`mock_success`) or on any dispatch failure/abort — *a reservation is never left
dangling*. Without a single-clearance release, a reserved-but-not-executed
clearance dangles as `reserved` (only clearable by session-wide panic or expiry),
which violates the fail-closed "release, not consume" invariant.

## Requested change (additive, backward-compatible)

Make releasing a `reserved` clearance a real, single-clearance operation. Either:

1. Extend `cancel_approval` to also handle `reserved` (and `approved`) →
   `cancelled` (atomic `WHERE state IN ('pending','approved','reserved')`),
   mirroring `bulk_invalidate`'s guard but for one approval; **or**
2. Add a dedicated `POST /v1/runtime/approvals/{id}/release`
   (`reserved → cancelled`, atomic, 409 if not `reserved`, 404 if missing) — the
   symmetric inverse of `commit`.

Either is fine for BrowserBridge; it POSTs to `/cancel` today and will adopt
`/release` if you add one. Preserve the existing invariants (one-time consumption,
replay denial, audit event e.g. `approval_released`/`approval_cancelled`,
fail-closed). `committed` clearances must remain untouched.

## Done criteria

A single `reserved` clearance can be released to `cancelled` via one runtime call;
covered by a gateway test (reserve → release → state is `cancelled`; a subsequent
commit is rejected). Reply by noting the endpoint/semantics so BrowserBridge can
wire `ActAuthorityClient.release` to it and enable the seam.

## References

- BrowserBridge side (built, flag-gated off): `BrowserBridge/packages/mcp-server/src/act-authority.ts`
  (`withActClearance`, `ActAuthorityClient.release`); plan: `BrowserBridge/docs/act-seam-wiring-plan.md`.
- ACT today: `gateway/src/hermes_gateway/runtime_adapter.py:635` (`cancel_approval`),
  `store.py:1018` (`bulk_invalidate_approvals`), `app.py:397` (`/cancel` route).

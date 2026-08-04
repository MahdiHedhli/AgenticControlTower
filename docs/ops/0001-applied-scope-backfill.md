# OPS-0001: Applied-scope backfill for pre-4193f3d approvals

## Status

**Applied to production 2026-08-04T15:36:02Z**, on operator go-ahead. See
*Run record* below.

## Date

2026-08-04

## Summary

Three approved rows in the production gateway database record standing
authority (`decision_scope` = `session` ×2, `agent` ×1) that was never minted:
`approval_grants` has 0 rows. They were written before
[`4193f3d`][fix], which changed the decision write so `decision_scope` holds the
scope that was actually **applied** rather than the one **requested**.

This document proposes correcting those three rows, records the evidence that
`once` is the correct value, and explains the discontinuity a reader of the
audit trail will see at 2026-08-04.

## The discontinuity, stated plainly

For approvals decided **before 4193f3d**, `approval_requests.decision_scope`
means *the scope the operator asked for*. For approvals decided **after**, it
means *the scope the gateway applied*, with the request preserved separately in
the new nullable `requested_scope` column.

That is a change in the meaning of a column, not just its value. Three legacy
rows are actively false under the new reading, because what they asked for is
not what they got.

## Evidence

All three rows are `requested_tool = terminal`, `risk_family = external_effect`,
`risk_level = high`, decided between 05:41Z and 05:53Z on 2026-08-04.

Two independent lines of evidence establish that the applied scope was `once`:

1. **Policy made a grant impossible.** `external_effect` is a member of
   `MOBILE_MANDATORY_RISK_FAMILIES` in `clearance_policy.py`, which
   `grants.py` folds into `GRANT_UNGRANTABLE_RISK_FAMILIES`. That set is a
   config-independent **floor** — an operator's `risk_channel_map` can add
   families to it but never remove one. No configuration, past or present,
   could have let these three mint a standing grant.

2. **The audit log already says so.** Each of the three carries a
   `capability_grant_refused` event written *immediately before* its
   `approval_decision`:

   ```
   appr_fctzBamn_lI_oMWM  {"scope": "session", "reason": "channel_requirement", ...}
   appr_Ntqs-byZcFmAZD6l  {"scope": "session", "reason": "channel_requirement", ...}
   appr_0zaNnmLnWG037CYX  {"scope": "agent",   "reason": "channel_requirement", ...}
   ```

   These are the only three `capability_grant_refused` events in the database,
   so the set of affected rows is derivable from the audit log alone, without
   reference to `decision_scope`.

The gateway refused to mint the grant, recorded the refusal in the
tamper-evident log, and then wrote the requested scope into the projection
anyway. **The audit log was never wrong. Only the projection is.**

## Blast radius: reporting, not authority

Enforcement was never affected. `standing_grant_for_request` (the auto-satisfy
path) queries `approval_grants` and never reads `decision_scope`; with zero
grant rows it could never have cleared anything. No action was ever
auto-approved on the strength of these rows.

What the rows did corrupt is every surface that *reports* the decision — the
four `4193f3d` enumerates, of which the consequential one is
`GET /v1/runtime/approvals/{id}/result`, where `selected_scope` told the **agent**
it held session- or agent-wide authority for a high-risk `terminal` action.

## Decision

**Backfill the three rows.** For each:

```sql
UPDATE approval_requests
SET requested_scope = decision_scope,   -- preserve what was asked
    decision_scope  = 'once'            -- record what was applied
WHERE approval_id = ? AND state = 'approved'
  AND requested_scope IS NULL AND decision_scope = ?;
```

This reproduces exactly what the fixed code writes for the same decision
(`app.py`):

```python
applied_scope = scope if (grant is not None or target_state != "approved") else "once"
store.resolve_approval(..., decision_scope=applied_scope, requested_scope=scope, ...)
```

### Why not leave them

Leaving them was the honest-going-forward option, and it was rejected because
the cost is not merely historical. The column is read by the agent-facing
runtime result surface, and these sessions are recent. An audit trail whose
state projection contradicts its own tamper-evident log — which already records
the refusal — is worse than one that has been reconciled and annotated. The
usual argument for leaving history alone (rewriting an audit record destroys
evidence) does not apply here, because nothing is destroyed: see below.

### Why this is not history rewriting

- `audit_events` is **never modified or deleted**. ADR-0007's append-only,
  hash-chained guarantee attaches to that table. The original
  `approval_decision` events keep saying `session`/`agent` — that is the true
  record of what the gateway asserted at the time, and erasing it would be the
  actual tampering.
- `approval_requests` is a mutable state projection by design (`pending` →
  `approved`, `decided_at` written on decision). Correcting a column there is
  not an audit-log write.
- The requested scope is **preserved**, not discarded — it moves to
  `requested_scope`, which is the column the fix added to hold it.
- The chain is **extended, not rewritten**: one new `approval_scope_backfilled`
  event per corrected row, appended through the store's own
  `append_audit_event` so `previous_hash` is computed the same way the gateway
  computes it. Each names the before/after values, the evidence event, and this
  migration id.

### Scope of the change: exactly three rows

The migration deliberately does **not** normalise the other 130 legacy rows.
Their `requested_scope` stays `NULL`, which correctly reads as "predates the
column". Backfilling `requested_scope = 'once'` across the already-truthful
rows would fabricate a record of a request nobody made and would destroy the
`NULL` marker that distinguishes legacy rows from post-fix ones.

Denied, expired, and cancelled rows are untouched, matching `4193f3d`'s own
rule that only an approval can apply a scope.

## Procedure

Script: [`gateway/scripts/migrate_0001_applied_scope_backfill.py`](../../gateway/scripts/migrate_0001_applied_scope_backfill.py).
Dry-run by default; `--apply` writes.

1. **Dry run** (read-only, no dependencies):

   ```bash
   python3 gateway/scripts/migrate_0001_applied_scope_backfill.py
   ```

   Expect exactly 3 correctable rows and 0 in "NOT CORRECTED".

2. **Stop the gateway.** Required — see *Concurrency* below. `--apply` refuses
   to run while the pid in `~/.hermes/act/gateway.pid` is alive.

3. **Apply.** Must run under the gateway's own interpreter so the audit append
   uses the deployed hash-chain code. A timestamped backup is written first.

   ```bash
   ~/.hermes/act/venv/bin/python gateway/scripts/migrate_0001_applied_scope_backfill.py --apply --actor-id <operator>
   ```

4. **Verify** against the backup the previous step printed:

   ```bash
   ~/.hermes/act/venv/bin/python gateway/scripts/migrate_0001_applied_scope_backfill.py --verify --baseline <backup>
   ```

5. **Restart the gateway.**

### Ordering relative to deploy

The migration requires the `requested_scope` column, which `_ensure_column`
adds at startup — so it must run **after** a gateway containing `4193f3d` has
opened the database at least once. On the production host that has already
happened (the running build is post-fix and the column exists), so the
migration can run at any convenient stop.

## Verification

`--verify` checks, and all passed on a `.backup` copy of production:

| Check | Result |
| --- | --- |
| Row count unchanged | 133 → 133 |
| Correctable rows remaining | 0 |
| Corrected rows read `decision_scope = 'once'` | 3/3 |
| Corrected rows preserve the request in `requested_scope` | 3/3 |
| `approval_grants` still empty (no authority created) | 0 rows |
| Audit events self-hash recompute | 9743 events, 0 mismatches |
| New chain forks introduced | 0 |
| Columns changed vs baseline | only `decision_scope` / `requested_scope` |

Re-running `--apply` on a migrated database is a no-op: the selection predicate
requires `requested_scope IS NULL`, which no longer holds.

## Safety properties, each exercised on a copy

- **Refuses to guess.** A row matching the structural predicate but lacking a
  `capability_grant_refused` event aborts the run rather than being rewritten.
- **A grant protects its row.** The grant-existence check does not filter on
  grant state, so a minted-then-revoked grant still excludes its approval —
  revocation means authority really was applied.
- **Never touches post-fix rows.** `requested_scope IS NULL` cannot match them.
- **Refuses to run against a live gateway**, aborting before the backup step.

## Run record

Applied 2026-08-04T15:36:02Z by `mhedhli@42-corp.com`.

The gateway is launchd-managed (`app.act.gateway`, `KeepAlive=true`), so it was
stopped with `launchctl bootout gui/$(id -u)/app.act.gateway` — a plain `kill`
would have been respawned immediately — and restored with
`launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/app.act.gateway.plist`.
It came back clean on `http://127.0.0.1:8788` with no errors in
`logs/gateway.err.log`.

Backup taken before the write:
`~/.hermes/act/gateway.sqlite3.pre-0001-applied-scope-backfill-20260804-153602`

Resulting state:

| approval_id | state | `decision_scope` (applied) | `requested_scope` |
| --- | --- | --- | --- |
| `appr_fctzBamn_lI_oMWM` | approved | `once` | `session` |
| `appr_Ntqs-byZcFmAZD6l` | approved | `once` | `session` |
| `appr_0zaNnmLnWG037CYX` | approved | `once` | `agent` |

Three `approval_scope_backfilled` events were appended at 15:36:02Z. The
original `approval_decision` and `capability_grant_refused` events for all three
approvals remain byte-identical — nothing was erased.

`--verify` against the backup: 133 → 133 rows, 0 correctable remaining,
`approval_grants` still 0, 11346 audit events recomputed with 0 self-hash
mismatches, 21 linkage breaks (all pre-existing, **0 introduced**), and no
column other than `decision_scope` / `requested_scope` changed.

## Rollback

Restore the backup the apply step wrote (`gateway.sqlite3.pre-0001-applied-scope-backfill-<ts>`)
with the gateway stopped. The migration writes no state outside this database.
Stop and start it via `launchctl bootout` / `bootstrap` as above.

## Concurrency, and a pre-existing finding

`--apply` requires a stopped gateway because `append_audit_event` reads
`latest_audit_hash()` and inserts in two separate transactions. Two concurrent
writers therefore read the same chain head and fork it.

**This is not hypothetical: the production chain already contains 21 such forks**,
all on `runtime_context_registered`, between 2026-07-03 and 2026-08-03. Example
— sequences 174 and 175 share a `previous_hash`, and 175's `created_at` is
*earlier* than 174's:

```
173  aud_rCBNJbKea4khJWR4  prev=356fb326  hash=07e00a43   ...31.470126Z
174  aud_eY6GqPTpsFlazIX2  prev=07e00a43  hash=11b58b58   ...31.552700Z
175  aud_yab5dIgSqYcVIVXE  prev=07e00a43  hash=289d7365   ...31.541983Z   <- fork
```

Every event's own hash verifies; only the linkage is forked, so this is a
concurrency defect in the append path, not evidence of tampering. It is
**pre-existing and out of scope for this migration** — which is why `--verify`
asserts that the migration introduces *no new* break rather than that zero
exist. Tracked separately; it should be fixed by making the read-and-append
atomic in one transaction.

[fix]: https://github.com/MahdiHedhli/AgenticControlTower/commit/4193f3d

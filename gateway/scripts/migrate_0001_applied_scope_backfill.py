#!/usr/bin/env python3
"""One-shot backfill: reconcile ``approval_requests.decision_scope`` with the
scope that was actually APPLIED, for rows written before 4193f3d.

Before 4193f3d the decision write put the *requested* scope into
``decision_scope``. Four surfaces read that one column — ``GET /v1/approvals/
{id}``, the ``approval.resolved`` event, the ``approval_decision`` audit event,
and ``GET /v1/runtime/approvals/{id}/result`` (``selected_scope``, read by the
AGENT). So a request whose standing grant was refused still reads back as
though it carried session-wide or agent-wide authority.

This script does not guess what was applied. For every row it touches, the
append-only audit log already contains a ``capability_grant_refused`` event
naming the scope and the refusal reason — the gateway refused to mint the
grant, said so in the tamper-evident record, and then wrote the requested
scope into the projection anyway. The backfill reproduces exactly what the
fixed code would have written for the same decision::

    applied_scope = scope if (grant is not None or target_state != "approved") else "once"
    store.resolve_approval(..., decision_scope=applied_scope, requested_scope=scope, ...)

i.e. ``decision_scope='once'``, ``requested_scope=<what was asked>``. The
requested scope is preserved, not discarded.

WHAT THIS DOES NOT TOUCH
------------------------
* ``audit_events`` rows are never modified or deleted. The original
  ``approval_decision`` events keep saying ``session``/``agent``; that is the
  historical record of what the gateway asserted at the time, and erasing it
  would be the actual tampering. The discontinuity is explained by a NEW
  appended event per corrected row (chain extended, never rewritten).
* ``approval_grants`` is never written. This changes no authority: the
  enforcement path (``standing_grant_for_request``) reads ``approval_grants``
  and never reads ``decision_scope``, so these rows never conferred real
  standing authority. Only the *reporting* was wrong.
* Rows that are not provably wrong. ``requested_scope IS NULL`` is the legacy
  marker; rows the fixed code wrote are never selected. Denied / expired /
  cancelled rows are left exactly as they are, matching 4193f3d's own rule
  that only an approval can apply a scope.
* The 130 legacy rows that are already truthful. Their ``requested_scope``
  stays NULL, which correctly reads as "predates the column" rather than
  fabricating a value.

Usage (dry-run and verify need no dependencies; --apply imports the gateway
package so the audit append uses the store's own hash-chain logic)::

    python3 gateway/scripts/migrate_0001_applied_scope_backfill.py
    ~/.hermes/act/venv/bin/python gateway/scripts/migrate_0001_applied_scope_backfill.py --apply --actor-id <operator>
    python3 gateway/scripts/migrate_0001_applied_scope_backfill.py --verify --baseline <backup.sqlite3>

Idempotent: after a successful apply the selection predicate matches nothing,
because ``requested_scope`` is no longer NULL on the corrected rows.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

MIGRATION_ID = "0001-applied-scope-backfill"

DEFAULT_DB = Path.home() / ".hermes" / "act" / "gateway.sqlite3"
DEFAULT_PID = Path.home() / ".hermes" / "act" / "gateway.pid"

#: Scopes that claim standing authority. ``once`` claims none, so a row already
#: reading ``once`` has nothing to correct.
STANDING_SCOPES = ("session", "agent", "permanent")

#: Rows to correct. Every clause is load-bearing:
#:
#: * ``state = 'approved'`` — only an approval can apply a scope.
#: * ``decision_scope IN (...)`` — a row already reading ``once`` is truthful.
#: * ``requested_scope IS NULL`` — the legacy marker. Rows written by the fixed
#:   code always populate it, so they can never be selected. This is also what
#:   makes the migration idempotent.
#: * ``NOT EXISTS (grant)`` — matched on ``source_approval_id`` with NO filter
#:   on grant state, so a grant that was minted and later revoked still
#:   protects its row. A revoked grant means authority really was applied once.
SELECT_SQL = f"""
    SELECT approval_id, node_id, agent_id, session_id, requested_tool,
           risk_family, decision_scope, decided_at
    FROM approval_requests AS ar
    WHERE ar.state = 'approved'
      AND ar.decision_scope IN ({",".join("?" * len(STANDING_SCOPES))})
      AND ar.requested_scope IS NULL
      AND NOT EXISTS (
          SELECT 1 FROM approval_grants AS ag
          WHERE ag.source_approval_id = ar.approval_id
      )
    ORDER BY ar.decided_at
"""


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def connect_ro(path: Path) -> sqlite3.Connection:
    db = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    db.row_factory = sqlite3.Row
    return db


def fail(message: str) -> None:
    print(f"ABORT: {message}", file=sys.stderr)
    sys.exit(1)


def refusal_evidence(db: sqlite3.Connection, approval_id: str) -> dict | None:
    """The audit log's own record that the standing grant was refused.

    This is the proof that ``once`` is what was applied. A row without it is
    not corrected — see :func:`select_rows`.
    """
    row = db.execute(
        """
        SELECT payload_redacted_json
        FROM audit_events
        WHERE approval_id = ? AND event_type = 'capability_grant_refused'
        ORDER BY sequence DESC LIMIT 1
        """,
        (approval_id,),
    ).fetchone()
    if row is None:
        return None
    try:
        return json.loads(row["payload_redacted_json"] or "{}")
    except json.JSONDecodeError:
        return None


def select_rows(db: sqlite3.Connection) -> tuple[list[dict], list[dict]]:
    """Return ``(correctable, unprovable)``.

    ``unprovable`` rows match the structural predicate but have no
    ``capability_grant_refused`` event, or one naming a different scope. We
    cannot show from the record what was applied, so we refuse to rewrite them
    and make the operator look. "Probably once" is not an audit trail.
    """
    correctable: list[dict] = []
    unprovable: list[dict] = []
    for row in db.execute(SELECT_SQL, STANDING_SCOPES).fetchall():
        entry = dict(row)
        evidence = refusal_evidence(db, entry["approval_id"])
        entry["evidence"] = evidence
        if evidence is None or evidence.get("scope") != entry["decision_scope"]:
            unprovable.append(entry)
        else:
            correctable.append(entry)
    return correctable, unprovable


def preflight(db: sqlite3.Connection) -> None:
    columns = {r["name"] for r in db.execute("PRAGMA table_info(approval_requests)")}
    if "requested_scope" not in columns:
        fail(
            "approval_requests.requested_scope does not exist — this database has "
            "not yet been opened by a gateway containing 4193f3d. Start the fixed "
            "gateway once (the column is added by _ensure_column at startup), then "
            "re-run. Backfilling before the fix would be undone by nothing, but the "
            "column must exist to hold the preserved requested scope."
        )


def gateway_running(pid_path: Path) -> int | None:
    """The gateway must be stopped before --apply.

    Two reasons, both real: a concurrent decision would race this script on the
    audit chain (``previous_hash`` is read-then-written, so two writers can fork
    the chain), and a live gateway may resolve an approval mid-migration.
    """
    if not pid_path.exists():
        return None
    try:
        pid = int(pid_path.read_text().strip())
    except (ValueError, OSError):
        return None
    try:
        import os

        os.kill(pid, 0)
    except (ProcessLookupError, PermissionError, OSError):
        return None
    return pid


def describe(rows: list[dict], heading: str) -> None:
    print(f"\n{heading} ({len(rows)}):")
    if not rows:
        print("  (none)")
        return
    for row in rows:
        evidence = row.get("evidence") or {}
        reason = evidence.get("reason", "NO REFUSAL EVENT")
        print(
            f"  {row['approval_id']}  {row['requested_tool']:<10} "
            f"{row['risk_family']:<16} decided={row['decided_at']}"
        )
        print(
            f"    decision_scope: {row['decision_scope']!r} -> 'once'   "
            f"requested_scope: NULL -> {row['decision_scope']!r}   "
            f"[audit: {reason}]"
        )


def cmd_report(db_path: Path, apply: bool, actor_id: str, pid_path: Path) -> int:
    with connect_ro(db_path) as db:
        preflight(db)
        total_before = db.execute("SELECT count(*) FROM approval_requests").fetchone()[0]
        grants_before = db.execute("SELECT count(*) FROM approval_grants").fetchone()[0]
        correctable, unprovable = select_rows(db)

    print(f"database        : {db_path}")
    print(f"approval_requests: {total_before} rows")
    print(f"approval_grants  : {grants_before} rows")
    describe(correctable, "CORRECTABLE — audit log proves the grant was refused")
    describe(unprovable, "NOT CORRECTED — no matching refusal evidence")

    if unprovable:
        fail(
            f"{len(unprovable)} row(s) match the structural predicate but the audit "
            "log does not prove what scope was applied. Refusing to guess. Review "
            "them by hand and decide explicitly."
        )

    if not correctable:
        print("\nNothing to do — already migrated, or no affected rows.")
        return 0

    if not apply:
        print("\nDRY RUN — nothing written. Re-run with --apply to write.")
        return 0

    pid = gateway_running(pid_path)
    if pid is not None:
        fail(
            f"gateway is running (pid {pid}). Stop it before --apply: a live "
            "decision would race this script on the audit hash chain."
        )

    backup = db_path.with_name(
        f"{db_path.name}.pre-{MIGRATION_ID}-"
        f"{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
    )
    shutil.copy2(db_path, backup)
    print(f"\nbackup written  : {backup}")

    try:
        from hermes_gateway.store import SQLiteStore
    except ImportError:
        fail(
            "cannot import hermes_gateway — run --apply with the gateway's own "
            "interpreter so the audit append uses the deployed hash-chain code:\n"
            "  ~/.hermes/act/venv/bin/python gateway/scripts/"
            f"migrate_0001_applied_scope_backfill.py --apply --actor-id {actor_id}"
        )

    store = SQLiteStore(db_path)
    request_id = f"migration-{MIGRATION_ID}-{utc_now_iso()}"

    # One transaction for the projection rewrite. The audit appends follow,
    # deliberately outside it: append_audit_event opens its own connection and
    # reads latest_audit_hash, so nesting it here would deadlock on the write
    # lock this transaction holds.
    conn = sqlite3.connect(db_path)
    try:
        with conn:
            for row in correctable:
                changed = conn.execute(
                    """
                    UPDATE approval_requests
                    SET requested_scope = decision_scope,
                        decision_scope = 'once'
                    WHERE approval_id = ?
                      AND state = 'approved'
                      AND requested_scope IS NULL
                      AND decision_scope = ?
                    """,
                    (row["approval_id"], row["decision_scope"]),
                ).rowcount
                if changed != 1:
                    raise RuntimeError(
                        f"{row['approval_id']}: expected to update 1 row, got "
                        f"{changed}. Rolled back; database unchanged."
                    )
    finally:
        conn.close()
    print(f"updated         : {len(correctable)} row(s)")

    for row in correctable:
        store.append_audit_event(
            event_type="approval_scope_backfilled",
            actor_type="operator",
            actor_id=actor_id,
            node_id=row["node_id"],
            agent_id=row["agent_id"],
            session_id=row["session_id"],
            approval_id=row["approval_id"],
            request_id=request_id,
            payload_redacted={
                "migration": MIGRATION_ID,
                "reason": (
                    "decision_scope recorded the REQUESTED scope; the standing "
                    "grant was refused, so the scope APPLIED was 'once'"
                ),
                "decision_scope_before": row["decision_scope"],
                "decision_scope_after": "once",
                "requested_scope_before": None,
                "requested_scope_after": row["decision_scope"],
                "evidence_event": "capability_grant_refused",
                "evidence_reason": (row.get("evidence") or {}).get("reason"),
                "fixed_by_commit": "4193f3d",
            },
        )
    print(f"audit appended  : {len(correctable)} 'approval_scope_backfilled' event(s)")
    print(f"\nDone. Verify with:\n  --verify --baseline {backup}")
    return 0


def audit_chain_report(
    path: Path,
) -> tuple[int, int, list[str]] | None:
    """Recompute the audit chain. Returns ``(events, self_hash_mismatches,
    linkage_break_event_ids)``, or None when the gateway package is unavailable.

    Nothing here trusts a stored hash: every event's hash is recomputed from its
    own recorded columns with the same ``content_hash`` the gateway uses.
    """
    try:
        from hermes_gateway.security import content_hash
    except ImportError:
        return None

    breaks: list[str] = []
    self_hash_bad = 0
    previous: str | None = None
    with connect_ro(path) as db:
        rows = db.execute(
            """
            SELECT audit_event_id, event_type, actor_type, actor_id, node_id,
                   request_id, previous_hash, hash, payload_redacted_json, created_at
            FROM audit_events ORDER BY sequence
            """
        ).fetchall()
        for entry in rows:
            if entry["previous_hash"] != previous:
                breaks.append(entry["audit_event_id"])
            expected = content_hash(
                {
                    "audit_event_id": entry["audit_event_id"],
                    "event_type": entry["event_type"],
                    "actor_type": entry["actor_type"],
                    "actor_id": entry["actor_id"],
                    "node_id": entry["node_id"],
                    "request_id": entry["request_id"],
                    "previous_hash": entry["previous_hash"],
                    "payload_redacted": json.loads(entry["payload_redacted_json"] or "{}"),
                    "created_at": entry["created_at"],
                }
            )
            if expected != entry["hash"]:
                self_hash_bad += 1
            previous = entry["hash"]
    return len(rows), self_hash_bad, breaks


def cmd_verify(db_path: Path, baseline: Path | None) -> int:
    """Post-conditions. Every check states what it proves."""
    failures: list[str] = []
    with connect_ro(db_path) as db:
        preflight(db)
        total = db.execute("SELECT count(*) FROM approval_requests").fetchone()[0]
        grants = db.execute("SELECT count(*) FROM approval_grants").fetchone()[0]
        remaining, unprovable = select_rows(db)
        backfilled = [
            dict(r)
            for r in db.execute(
                """
                SELECT approval_id, decision_scope, requested_scope
                FROM approval_requests
                WHERE approval_id IN (
                    SELECT approval_id FROM audit_events
                    WHERE event_type = 'approval_scope_backfilled'
                )
                """
            ).fetchall()
        ]

        print(f"approval_requests            : {total} rows")
        print(f"approval_grants              : {grants} rows")
        print(f"rows still matching predicate: {len(remaining) + len(unprovable)}")
        print(f"rows carrying a backfill event: {len(backfilled)}")

        # 1. The migration is complete: nothing correctable is left.
        if remaining:
            failures.append(f"{len(remaining)} correctable row(s) remain")

        # 2. Every corrected row reads 'once' applied, with the request preserved.
        for row in backfilled:
            if row["decision_scope"] != "once":
                failures.append(
                    f"{row['approval_id']}: decision_scope is "
                    f"{row['decision_scope']!r}, expected 'once'"
                )
            if row["requested_scope"] not in STANDING_SCOPES:
                failures.append(
                    f"{row['approval_id']}: requested_scope is "
                    f"{row['requested_scope']!r}, expected the preserved request"
                )

        # 3. No authority was created. This migration must never mint a grant.
        if grants != 0:
            print(
                f"  note: approval_grants has {grants} row(s) — expected 0 on this "
                "database. Confirm none were created by this migration."
            )

    # 4. The audit chain. Two distinct properties, with different verdicts:
    #
    #    * a SELF-HASH mismatch means an event's recorded content no longer
    #      matches its own hash — tampering, always a hard failure;
    #    * a LINKAGE break means previous_hash does not point at the preceding
    #      row's hash. This database has 21 of these BEFORE any migration runs,
    #      all on concurrent `runtime_context_registered` writes, because
    #      append_audit_event reads latest_audit_hash() and inserts in two
    #      separate transactions — two writers read the same head and fork the
    #      chain. Pre-existing and out of this migration's scope, so the check
    #      is that the migration adds NO NEW break, not that zero exist.
    #      (This is also why --apply refuses to run against a live gateway:
    #      appending while the gateway writes would fork the chain again.)
    chain_now = audit_chain_report(db_path)
    if chain_now is None:
        print(
            "audit chain                  : SKIPPED (run with "
            "~/.hermes/act/venv/bin/python to recompute)"
        )
    else:
        events, self_hash_bad, breaks = chain_now
        print(
            f"audit chain                  : {events} events recomputed, "
            f"{self_hash_bad} self-hash mismatch(es), {len(breaks)} linkage break(s)"
        )
        if self_hash_bad:
            failures.append(
                f"{self_hash_bad} audit event(s) do not match their own hash — "
                "content was altered"
            )
        if baseline is not None:
            chain_before = audit_chain_report(baseline)
            if chain_before is not None:
                _, _, breaks_before = chain_before
                new_breaks = set(breaks) - set(breaks_before)
                print(
                    f"  linkage breaks pre-existing: {len(breaks_before)}, "
                    f"introduced by migration: {len(new_breaks)}"
                )
                if new_breaks:
                    failures.append(
                        f"migration introduced {len(new_breaks)} new chain "
                        f"break(s): {sorted(new_breaks)}"
                    )

    # 5. Nothing but the two scope columns moved, and no rows appeared/vanished.
    if baseline is not None:
        with connect_ro(baseline) as base:
            base_rows = {
                r["approval_id"]: dict(r)
                for r in base.execute("SELECT * FROM approval_requests")
            }
        with connect_ro(db_path) as db:
            now_rows = {
                r["approval_id"]: dict(r)
                for r in db.execute("SELECT * FROM approval_requests")
            }
        if set(base_rows) != set(now_rows):
            failures.append(
                f"row set changed: {len(base_rows)} -> {len(now_rows)} approvals"
            )
        drifted = 0
        for approval_id, before in base_rows.items():
            after = now_rows.get(approval_id)
            if after is None:
                continue
            for column, old in before.items():
                if after[column] == old:
                    continue
                if column in ("decision_scope", "requested_scope"):
                    drifted += 1
                    continue
                failures.append(
                    f"{approval_id}: unexpected change to {column!r}: "
                    f"{old!r} -> {after[column]!r}"
                )
        print(
            f"baseline comparison          : {len(base_rows)} rows, "
            f"{drifted} scope-column change(s), no other column changed"
        )

    if failures:
        print("\nFAILED:")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print("\nAll checks passed.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, default=DEFAULT_DB)
    parser.add_argument("--pid-file", type=Path, default=DEFAULT_PID)
    parser.add_argument(
        "--apply", action="store_true", help="write (default is a dry run)"
    )
    parser.add_argument(
        "--actor-id", default="", help="operator identity recorded in the audit event"
    )
    parser.add_argument("--verify", action="store_true")
    parser.add_argument(
        "--baseline", type=Path, help="pre-migration copy, for column-drift comparison"
    )
    args = parser.parse_args()

    if not args.db.exists():
        fail(f"no such database: {args.db}")
    if args.verify:
        return cmd_verify(args.db, args.baseline)
    if args.apply and not args.actor_id:
        fail("--apply requires --actor-id (recorded as the audit actor)")
    return cmd_report(args.db, args.apply, args.actor_id, args.pid_file)


if __name__ == "__main__":
    sys.exit(main())

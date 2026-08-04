"""The audit hash chain must not fork under concurrent appends.

Production accumulated 21 forked links among ~11k events (all
``runtime_context_registered``, 2026-07-03..2026-08-03): two writers each read
the same chain head and both appended with that ``previous_hash``. Every
individual event's own hash still verified, so the damage was not a bad hash --
it was that ADR-0007 sells the chain as tamper evidence, and a chain that forks
on ordinary concurrency cannot evidence anything.

Why these tests are shaped this way: a test that spawns threads and hopes to
observe the interleaving is flaky, and a flaky test for a corruption bug is
worse than none -- it gets muted. So the invariant is pinned directly instead:
the head read and the append must happen inside ONE write transaction, on ONE
connection. That is a statement about the code that is true or false
deterministically, on every run.
"""

from __future__ import annotations

import sqlite3

import pytest

from hermes_gateway.store import SQLiteStore


def _append(store: SQLiteStore, event_type: str = "runtime_context_registered"):
    return store.append_audit_event(
        event_type=event_type,
        actor_type="agent",
        actor_id="agent_test",
        node_id="node_test",
        request_id="req_test",
        payload_redacted={"k": "v"},
    )


@pytest.fixture()
def store(tmp_path) -> SQLiteStore:
    s = SQLiteStore(tmp_path / "chain.sqlite3")
    s.initialize()
    return s


def test_head_read_and_append_share_one_write_transaction(store, monkeypatch):
    """The regression test proper: fails before the fix, passes after.

    Before the fix ``append_audit_event`` called ``latest_audit_hash()``, which
    opened its *own* connection and ran the SELECT in autocommit (Python's
    sqlite3 only implicitly BEGINs before DML, never before a SELECT), then
    opened a *second* connection to INSERT. So the SELECT and the INSERT landed
    on different connections with no lock held between them -- exactly the gap
    two writers slipped through.

    Recording the statement order per-connection catches all three regressions
    at once: dropping BEGIN IMMEDIATE, reading the head before taking the write
    lock, or splitting the read back onto its own connection.
    """
    seen: list[tuple[int, str]] = []
    real_connect = SQLiteStore.connect
    counter = {"n": 0}

    def recording_connect(self):
        cm = real_connect(self)
        db = cm.__enter__()
        counter["n"] += 1
        conn_no = counter["n"]
        # Connection.execute is a read-only attribute, so the statement stream is
        # captured with sqlite3's own tracer rather than by wrapping the method.
        db.set_trace_callback(
            lambda sql, _c=conn_no: seen.append((_c, " ".join(str(sql).split())[:40].upper()))
        )
        try:
            yield db
        finally:
            db.set_trace_callback(None)
            cm.__exit__(None, None, None)

    import contextlib

    monkeypatch.setattr(SQLiteStore, "connect", contextlib.contextmanager(recording_connect))

    _append(store)

    # Ignore the PRAGMAs store.connect() issues on every connection.
    stmts = [(c, s) for c, s in seen if not s.startswith("PRAGMA")]
    kinds = [
        (c, "BEGIN" if s.startswith("BEGIN") else "SELECT" if s.startswith("SELECT") else "INSERT" if s.startswith("INSERT") else "OTHER")
        for c, s in stmts
    ]
    relevant = [(c, k) for c, k in kinds if k in {"BEGIN", "SELECT", "INSERT"}]
    # append_audit_event ends with get_audit_event(), which opens a second
    # connection to read the row back. That read-back is after the commit and is
    # not part of the race, so the invariant is only asserted over the statements
    # up to and including the INSERT.
    assert "INSERT" in [k for _, k in relevant], "no INSERT was issued"
    relevant = relevant[: [k for _, k in relevant].index("INSERT") + 1]

    begins = [c for c, k in relevant if k == "BEGIN"]
    assert begins, "append_audit_event issued no BEGIN -- the head read is not lock-protected"

    begin_sql = [s for _, s in stmts if s.startswith("BEGIN")]
    assert any("IMMEDIATE" in s for s in begin_sql), (
        f"BEGIN must be IMMEDIATE to take the write lock up front; got {begin_sql}"
    )

    # The head SELECT and the INSERT must be on the SAME connection, after the BEGIN.
    order = [k for _, k in relevant]
    assert order.index("BEGIN") < order.index("SELECT") < order.index("INSERT"), (
        f"expected BEGIN -> SELECT(head) -> INSERT on one connection, got {order}"
    )
    conns = {c for c, k in relevant}
    assert len(conns) == 1, (
        "the head read and the append ran on different connections -- "
        "that is precisely the two-transaction gap that forked the chain"
    )


def test_write_lock_is_held_across_the_head_read(store, tmp_path):
    """A competing writer cannot append while another append is mid-flight.

    This is the cross-process half: BEGIN IMMEDIATE takes a *file* lock, so the
    guarantee holds against a second gateway process on the same DB, not merely
    against another thread. That case is not hypothetical here -- two gateways
    have been pointed at this database by accident before.
    """
    _append(store)

    blocker = sqlite3.connect(store.database_path, timeout=0.1)
    blocker.execute("BEGIN IMMEDIATE")
    try:
        with pytest.raises(sqlite3.OperationalError, match="locked"):
            _append(store)
    finally:
        blocker.rollback()
        blocker.close()

    # Once the competing writer releases, appends resume normally.
    _append(store)


def test_chain_stays_linear(store):
    """No two events may share a previous_hash, and each links to the last."""
    events = [_append(store) for _ in range(25)]

    with store.connect() as db:
        rows = db.execute(
            "SELECT sequence, previous_hash, hash FROM audit_events ORDER BY sequence"
        ).fetchall()

    assert len(rows) == len(events)
    assert rows[0]["previous_hash"] is None

    prevs = [r["previous_hash"] for r in rows if r["previous_hash"] is not None]
    assert len(prevs) == len(set(prevs)), "duplicate previous_hash -- the chain forked"

    for earlier, later in zip(rows, rows[1:]):
        assert later["previous_hash"] == earlier["hash"], (
            f"sequence {later['sequence']} does not link to {earlier['sequence']}"
        )

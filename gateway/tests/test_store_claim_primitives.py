"""One-time authority must be spendable exactly once.

Same defect class as the audit-chain fork, in the two places where it decides
whether a human's single approval authorizes one action or two.

`_require_bound_clearance` read the row through `get_approval()` -- its own
connection, SELECT in autocommit -- and the consumption marker was written much
later, AFTER the effect (`handoff.engage()`, `await
tui_manager.create_runtime(...)`). Two engagements presenting the same clearance
both read it unconsumed and both ran. Likewise every decision surface checked
`state == "pending"` on one connection and wrote unguarded on another, so
approve racing deny left the row denied while the approve path's standing grant
survived it.

These are store-level tests on purpose: they pin the primitives the whole
gateway now depends on, deterministically, without racing threads.
"""

from __future__ import annotations

import pytest

from hermes_gateway.store import SQLiteStore


@pytest.fixture()
def store(tmp_path) -> SQLiteStore:
    s = SQLiteStore(tmp_path / "claims.sqlite3")
    s.initialize()
    return s


def _approval(store: SQLiteStore, approval_id: str = "appr_1") -> dict:
    return store.create_approval(
        {
            "approval_id": approval_id,
            "action_id": f"act_{approval_id}",
            "node_id": "node_1",
            "agent_id": "agent_1",
            "session_id": "sess_1",
            "requested_tool": "shell",
            "params_fingerprint": f"fp_{approval_id}",
            "summary": "Run a command",
            "risk_level": "high",
            "risk_family": "external_effect",
            "state": "pending",
            "expires_at": "2099-01-01T00:00:00Z",
            "full_payload_redacted": {},
        }
    )


def test_a_clearance_can_be_consumed_exactly_once(store) -> None:
    """The blocker: one human approval must not authorize two engagements."""
    _approval(store)

    assert store.consume_approval_once("appr_1", {"handoff_consumed_by": "sess_a"})
    assert not store.consume_approval_once(
        "appr_1", {"handoff_consumed_by": "sess_b"}
    ), "a second engagement spent the same clearance -- one approval, two sessions"


def test_tui_and_handoff_markers_are_the_same_authority(store) -> None:
    """Either marker means spent. They are two names for one clearance, so a
    handoff must not be able to re-spend what a TUI start already consumed."""
    _approval(store)

    assert store.consume_approval_once("appr_1", {"tui_consumed_by": "tui_a"})
    assert not store.consume_approval_once(
        "appr_1", {"handoff_consumed_by": "sess_b"}
    ), "a handoff re-spent a clearance the TUI path had already consumed"


def test_a_falsy_marker_cannot_un_spend_a_clearance(store) -> None:
    """"Spent" is encoded as a NON-EMPTY marker value, so writing an empty one
    would hand the clearance back. handoff.py guards this at the write."""
    _approval(store)
    assert store.consume_approval_once("appr_1", {"handoff_consumed_by": "sess_a"})

    store.update_approval_decision_metadata("appr_1", {"handoff_consumed_by": ""})

    assert not store.consume_approval_once(
        "appr_1", {"tui_consumed_by": "tui_b"}
    ), "an empty marker un-spent the clearance"


def test_only_one_caller_can_move_an_approval_out_of_pending(store) -> None:
    """Approve racing deny: the loser must mint nothing and write nothing."""
    _approval(store)

    assert store.claim_approval_transition("appr_1", "approved")
    assert not store.claim_approval_transition(
        "appr_1", "denied"
    ), "two decisions both claimed one approval -- two grants, or standing "
    assert store.get_approval("appr_1")["state"] == "approved"


def test_claiming_a_missing_or_already_decided_approval_is_false(store) -> None:
    assert not store.claim_approval_transition("appr_missing", "expired")
    _approval(store, "appr_2")
    store.claim_approval_transition("appr_2", "approved")
    assert not store.claim_approval_transition("appr_2", "expired"), (
        "the expiry sweep stomped a state a decision had already written"
    )


def test_metadata_merge_survives_a_stored_null(store) -> None:
    """A literal "null" in the column parses to None, and `None | metadata` is a
    TypeError. get_approval() normalized that for free; reading the raw column
    does not, so the merge does it explicitly."""
    _approval(store)
    with store.connect() as db:
        db.execute(
            "UPDATE approval_requests SET decision_metadata_json = 'null' "
            "WHERE approval_id = ?",
            ("appr_1",),
        )

    merged = store.update_approval_decision_metadata("appr_1", {"k": "v"})
    assert merged["decision_metadata"]["k"] == "v"
    assert store.consume_approval_once("appr_1", {"tui_consumed_by": "t"})


def test_merge_does_not_drop_existing_keys(store) -> None:
    _approval(store)
    store.update_approval_decision_metadata("appr_1", {"eligibility_result": "allowed"})
    store.consume_approval_once("appr_1", {"handoff_consumed_by": "sess_a"})

    metadata = store.get_approval("appr_1")["decision_metadata"]
    assert metadata["eligibility_result"] == "allowed", (
        "the consumption claim clobbered the eligibility marker the clearance "
        "gate also reads"
    )
    assert metadata["handoff_consumed_by"] == "sess_a"

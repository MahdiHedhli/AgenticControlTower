"""The Live stream must show what is happening now, not what happened in June.

Two independent gateway defects, both fixed here.

(1) NEVER TAILED. After accept() the handler sent one batch and then entered a
loop whose only writes were events it minted itself -- a heartbeat on each 30s
timeout, a pong on a client ping. It never re-read event_envelopes, so anything
recorded AFTER the connect never reached a connected client. "Live" only ever
showed heartbeats, and the mobile cursor had nothing to advance on.

(2) COLD START SERVED THE ARCHIVE. With no cursor the code called
list_events_after(None), and _cursor_sequence(None) returns 0, so the query was
`sequence > 0 ... LIMIT 500` -- the OLDEST rows in the table. Against the live
DB that was 2026-06-19 onward: the "replays events from June" symptom.
"""

from __future__ import annotations

import pytest

from hermes_gateway.store import SQLiteStore


@pytest.fixture()
def store(tmp_path) -> SQLiteStore:
    s = SQLiteStore(tmp_path / "events.sqlite3")
    s.initialize()
    return s


def _event(store: SQLiteStore, n: int) -> dict:
    return store.create_event(
        node_id="node_1", event_type="test.event", payload={"n": n}
    )


def test_no_cursor_returns_the_newest_events_not_the_oldest(store) -> None:
    """The regression test proper: fails before the fix, passes after."""
    for n in range(50):
        _event(store, n)

    recent = store.list_recent_events(limit=10)

    assert len(recent) == 10
    payload_ns = [event["payload"]["n"] for event in recent]
    assert payload_ns == list(range(40, 50)), (
        f"expected the newest 10 events, got {payload_ns[:3]}... -- serving the "
        "oldest rows is what replayed June on every cold launch"
    )


def test_recent_events_are_returned_oldest_first(store) -> None:
    """A live view appends downward, so the batch must read in chronological
    order even though it is selected from the newest end."""
    for n in range(5):
        _event(store, n)

    recent = store.list_recent_events(limit=5)
    cursors = [event["cursor"] for event in recent]
    assert cursors == sorted(cursors)


def test_a_cursor_still_pages_forward_from_that_point(store) -> None:
    """The cursor path is untouched: a client that HAS a cursor must still get
    everything after it, so a reconnect does not skip events."""
    first = [_event(store, n) for n in range(5)]
    after = first[2]["cursor"]
    later = [_event(store, n) for n in range(5, 8)]

    pending = store.list_events_after(after=after)
    ns = [event["payload"]["n"] for event in pending]
    assert ns == [3, 4, 5, 6, 7], f"cursor paging lost or repeated events: {ns}"
    assert later[-1]["cursor"] == pending[-1]["cursor"]


def test_tailing_from_the_last_sent_cursor_yields_nothing_twice(store) -> None:
    """The loop advances `cursor` per frame. Re-polling with the last cursor
    must return only NEW rows -- otherwise every poll resends the batch."""
    for n in range(3):
        _event(store, n)
    batch = store.list_events_after(after=None)
    cursor = batch[-1]["cursor"]

    assert store.list_events_after(after=cursor) == []

    fresh = _event(store, 99)
    pending = store.list_events_after(after=cursor)
    assert [event["event_id"] for event in pending] == [fresh["event_id"]]


def test_an_empty_store_tails_without_error(store) -> None:
    assert store.list_recent_events(limit=10) == []
    assert store.list_events_after(after=None) == []

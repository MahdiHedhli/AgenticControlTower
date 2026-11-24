"""A TUI attach token admits exactly one WebSocket attach.

``verify_tui_attach_token`` stamped ``used_at`` on every successful verify but
never read it back, so a minted token could be replayed for its whole TTL: a
token lifted from a log line, a proxy or a shoulder-surfed URL re-opened the
terminal stream as many times as the holder liked. Every legitimate client
mints a fresh token per attach (the mobile ``_attachRelay`` re-mints on every
re-attach; nothing reconnects with an old URL), so single-use costs no flow.

A replayed token must fail exactly the way an unknown token does -- ``None`` --
so the stream endpoint keeps closing with the same 1008 and tells a replayer
nothing it would not tell a guesser.
"""

from __future__ import annotations

import threading

import pytest

from hermes_gateway.security import new_token
from hermes_gateway.store import SQLiteStore


@pytest.fixture()
def store(tmp_path) -> SQLiteStore:
    s = SQLiteStore(tmp_path / "attach.sqlite3")
    s.initialize()
    return s


def _mint(store: SQLiteStore, *, ttl_seconds: int = 60) -> str:
    token = new_token()
    store.create_tui_attach_token(
        token=token,
        session_id="tui_sess_1",
        device_id="dev_1",
        ttl_seconds=ttl_seconds,
    )
    return token


def test_first_verify_succeeds_and_is_scoped(store: SQLiteStore) -> None:
    token = _mint(store)

    attach = store.verify_tui_attach_token(token)

    assert attach is not None
    assert attach["session_id"] == "tui_sess_1"
    assert attach["device_id"] == "dev_1"


def test_second_verify_of_same_token_fails_like_an_unknown_token(
    store: SQLiteStore,
) -> None:
    token = _mint(store)
    assert store.verify_tui_attach_token(token) is not None

    replay = store.verify_tui_attach_token(token)
    unknown = store.verify_tui_attach_token(new_token())

    assert replay is None
    assert replay == unknown


def test_spending_one_token_does_not_spend_another(store: SQLiteStore) -> None:
    first = _mint(store)
    second = _mint(store)

    assert store.verify_tui_attach_token(first) is not None
    assert store.verify_tui_attach_token(second) is not None
    assert store.verify_tui_attach_token(first) is None
    assert store.verify_tui_attach_token(second) is None


def test_expired_token_still_fails(store: SQLiteStore) -> None:
    token = _mint(store, ttl_seconds=-1)

    assert store.verify_tui_attach_token(token) is None
    assert store.verify_tui_attach_token(token) is None


def test_concurrent_double_verify_admits_exactly_one(store: SQLiteStore) -> None:
    """Two attaches racing on one token: exactly one wins.

    Deterministic in both directions, not a hope-for-the-interleaving test:
    before the fix there is no used_at guard at all, so both verifies succeed on
    every run whatever the scheduling; after it, the claim is one guarded write
    under the database write lock, so exactly one succeeds on every run.
    """
    token = _mint(store)
    barrier = threading.Barrier(2)
    results: list[dict | None] = []
    errors: list[BaseException] = []
    lock = threading.Lock()

    def attach() -> None:
        try:
            barrier.wait(timeout=5)
            outcome = store.verify_tui_attach_token(token)
        except BaseException as exc:  # surfaced below, never swallowed
            with lock:
                errors.append(exc)
            return
        with lock:
            results.append(outcome)

    threads = [threading.Thread(target=attach) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)

    assert not errors, errors
    assert len(results) == 2
    winners = [result for result in results if result is not None]
    assert len(winners) == 1
    assert winners[0]["session_id"] == "tui_sess_1"

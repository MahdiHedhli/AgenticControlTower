"""``SQLiteStore.connect`` must close the connection AND keep the transaction.

The defect these tests pin: ``connect()`` returned a raw ``sqlite3.Connection``
and every one of the ~200 call sites spells ``with self.connect() as db:``. That
reads like "closes at the end of the block", but a Connection's context manager
is a *transaction* manager — it commits/rolls back and leaves the descriptor
open. Nothing pools connections, so the gateway leaked one fd per DB touch,
crossed launchd's 256-fd soft limit, and then failed every open with
``unable to open database file`` (617 occurrences in the production err log),
surfacing as HTTP 500s on Approvals/Inventory/Agents/Missions.

The trap in the fix: a context manager that only closes would silently stop
committing every write in the gateway. So the tests below assert BOTH halves —
descriptors do not accumulate, and commit-on-success / rollback-on-exception
still hold.
"""

from __future__ import annotations

import gc
import sqlite3
from pathlib import Path

import pytest

from hermes_gateway.store import SQLiteStore


def _store(tmp_path: Path) -> SQLiteStore:
    store = SQLiteStore(str(tmp_path / "gateway.sqlite3"))
    with store.connect() as db:
        db.execute("CREATE TABLE IF NOT EXISTS probe (k TEXT PRIMARY KEY)")
    return store


def _rows(store: SQLiteStore) -> list[str]:
    with store.connect() as db:
        return [row["k"] for row in db.execute("SELECT k FROM probe ORDER BY k")]


def test_connection_is_closed_when_the_block_exits(tmp_path: Path) -> None:
    with _store(tmp_path).connect() as db:
        db.execute("SELECT 1")
    with pytest.raises(sqlite3.ProgrammingError, match="closed database"):
        db.execute("SELECT 1")


def test_connection_is_closed_even_when_the_block_raises(tmp_path: Path) -> None:
    store = _store(tmp_path)
    with pytest.raises(RuntimeError):
        with store.connect() as db:
            raise RuntimeError("boom")
    with pytest.raises(sqlite3.ProgrammingError, match="closed database"):
        db.execute("SELECT 1")


def test_a_clean_block_still_commits(tmp_path: Path) -> None:
    """The regression that a close-only context manager would introduce."""
    store = _store(tmp_path)
    with store.connect() as db:
        db.execute("INSERT INTO probe (k) VALUES ('committed')")
    assert _rows(store) == ["committed"]


def test_a_raising_block_still_rolls_back(tmp_path: Path) -> None:
    store = _store(tmp_path)
    with store.connect() as db:
        db.execute("INSERT INTO probe (k) VALUES ('kept')")

    with pytest.raises(RuntimeError):
        with store.connect() as db:
            db.execute("INSERT INTO probe (k) VALUES ('rolled-back')")
            raise RuntimeError("boom")

    assert _rows(store) == ["kept"]


def test_sqlite_errors_inside_the_block_roll_back(tmp_path: Path) -> None:
    """A constraint violation is the realistic rollback path, not a bare raise."""
    store = _store(tmp_path)
    with store.connect() as db:
        db.execute("INSERT INTO probe (k) VALUES ('kept')")

    with pytest.raises(sqlite3.IntegrityError):
        with store.connect() as db:
            db.execute("INSERT INTO probe (k) VALUES ('second')")
            db.execute("INSERT INTO probe (k) VALUES ('kept')")  # PK collision

    assert _rows(store) == ["kept"]


def test_repeated_use_does_not_accumulate_open_connections(tmp_path: Path) -> None:
    """In-process proxy for the fd measurement: count live Connection objects.

    An out-of-process ``lsof`` count is the field measurement; this keeps the
    invariant enforced in CI where lsof is not dependable.
    """
    store = _store(tmp_path)

    def live_connections() -> int:
        gc.collect()
        return sum(1 for obj in gc.get_objects() if isinstance(obj, sqlite3.Connection))

    for index in range(20):
        with store.connect() as db:
            db.execute("INSERT INTO probe (k) VALUES (?)", (f"warm-{index}",))
    baseline = live_connections()

    for index in range(200):
        with store.connect() as db:
            db.execute("INSERT INTO probe (k) VALUES (?)", (f"row-{index}",))

    assert live_connections() <= baseline
    assert len(_rows(store)) == 220

"""Startup must not die with "database is locked" on a healthy database.

Reproduce-first: against an already-migrated, populated database, a gateway
booting while anything else held the write lock raised
``sqlite3.OperationalError: database is locked`` after ~5.4 s — SQLite's default
5 s busy timeout expiring. Two independent causes, one test each:

* ``initialize()`` issued an *unconditional* ``UPDATE agents`` backfill, so every
  startup asked for the write lock even when the schema was already current;
* every connection took SQLite's default 5 s busy timeout, so even a startup that
  legitimately has to migrate gives up quickly instead of waiting for the current
  writer.

The production database is live and non-trivial, so neither is acceptable.
"""

from __future__ import annotations

import sqlite3
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest

from hermes_gateway import store as store_module
from hermes_gateway.store import SQLiteStore


@contextmanager
def write_lock_held(db_path: Path, *, release_after: float | None = None) -> Iterator[None]:
    """Hold SQLite's write lock on ``db_path`` from another connection.

    ``release_after`` releases it on a timer (the "wait it out" case); otherwise
    it is held for the whole ``with`` body (the "must not need it at all" case).
    """
    holding = threading.Event()
    release = threading.Event()
    failure: list[BaseException] = []

    def hold() -> None:
        connection = sqlite3.connect(str(db_path), timeout=60)
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("CREATE TABLE IF NOT EXISTS _lock_probe (k TEXT)")
            connection.execute("INSERT INTO _lock_probe (k) VALUES ('held')")
            holding.set()
            if release_after is not None:
                time.sleep(release_after)
            else:
                release.wait(60)
            connection.commit()
        except BaseException as exc:  # surfaced in the test, never swallowed
            failure.append(exc)
            holding.set()
        finally:
            connection.close()

    thread = threading.Thread(target=hold, daemon=True)
    thread.start()
    assert holding.wait(30), "competing writer never acquired the write lock"
    assert not failure, failure
    try:
        yield
    finally:
        release.set()
        thread.join(60)
        assert not failure, failure


def migrated_store(tmp_path: Path) -> SQLiteStore:
    """A store whose schema is already current, with real rows in it."""
    db_path = tmp_path / "gateway.sqlite3"
    store = SQLiteStore(db_path)
    store.initialize()
    store.upsert_node(
        {
            "node_id": "node_lock",
            "display_name": "Lock Test Tower",
            "environment": "homelab",
            "gateway_base_url": "http://127.0.0.1:8787/v1",
            "node_fingerprint": "lock-fingerprint",
            "gateway_version": "0.1.0",
            "health": "online",
        }
    )
    store.upsert_agent(
        {
            "node_id": "node_lock",
            "agent_id": "agent_lock",
            "display_name": "Lock Test Agent",
            "status": "idle",
            "deployment_trust_context": "trusted_host",
        }
    )
    return store


def test_startup_on_a_current_schema_needs_no_write_lock(tmp_path: Path) -> None:
    """A startup that has nothing to migrate must not ask for the write lock.

    The competing writer holds the lock for the whole call. Pre-fix the
    unconditional ``UPDATE agents`` backfill blocked here and raised
    "database is locked" once the busy timeout expired.
    """
    store = migrated_store(tmp_path)
    db_path = Path(store.database_path)

    with write_lock_held(db_path):
        started = time.monotonic()
        SQLiteStore(db_path).initialize()
        elapsed = time.monotonic() - started

    # Not merely "did not raise": it must not have *waited* either, which is the
    # observable difference between "took no write lock" and "got lucky".
    assert elapsed < 2.0, f"startup waited {elapsed:.1f}s on the write lock"
    # And the migration still did its job.
    assert store.get_agent("node_lock", "agent_lock")["deployment_trust_context"] == (
        "trusted_host"
    )


def test_startup_still_backfills_when_a_row_needs_it(tmp_path: Path) -> None:
    """The read-before-write guard must not turn the backfill into a no-op."""
    store = migrated_store(tmp_path)
    with store.connect() as db:
        db.execute(
            "UPDATE agents SET deployment_trust_context = '' WHERE agent_id = ?",
            ("agent_lock",),
        )

    SQLiteStore(store.database_path).initialize()

    assert store.get_agent("node_lock", "agent_lock")["deployment_trust_context"] == (
        "untrusted_host"
    )


def test_connections_use_a_generous_busy_timeout(tmp_path: Path) -> None:
    """Every connection comes off the one chokepoint with the timeout applied."""
    store = migrated_store(tmp_path)
    with store.connect() as db:
        timeout_ms = db.execute("PRAGMA busy_timeout").fetchone()[0]
    assert timeout_ms == int(store_module.SQLITE_BUSY_TIMEOUT_SECONDS * 1000)
    # 5000 is SQLite's default, i.e. the value that produced the reported failure.
    assert timeout_ms > 5000


def test_a_migration_waits_out_a_contended_write_lock(tmp_path: Path) -> None:
    """A startup that genuinely has to migrate must wait for the current writer.

    The database file exists but holds none of the gateway schema, so
    ``initialize()`` must write. The competing writer releases after 1 s, which is
    inside the configured busy timeout and outside the tiny one below.
    """
    db_path = tmp_path / "gateway.sqlite3"
    seed = sqlite3.connect(str(db_path))
    seed.execute("CREATE TABLE scratch (k TEXT)")
    seed.commit()
    seed.close()

    with write_lock_held(db_path, release_after=1.0):
        SQLiteStore(db_path).initialize()

    assert SQLiteStore(db_path).list_approval_grants() == []


def test_the_busy_timeout_is_what_does_the_waiting(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Cut the timeout below the contention and the same migration fails again —
    so the constant, not luck, is what carries the previous test."""
    db_path = tmp_path / "gateway.sqlite3"
    seed = sqlite3.connect(str(db_path))
    seed.execute("CREATE TABLE scratch (k TEXT)")
    seed.commit()
    seed.close()
    monkeypatch.setattr(store_module, "SQLITE_BUSY_TIMEOUT_SECONDS", 0.05)

    with write_lock_held(db_path, release_after=1.0):
        with pytest.raises(sqlite3.OperationalError, match="database is locked"):
            SQLiteStore(db_path).initialize()

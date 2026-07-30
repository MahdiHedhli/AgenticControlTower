""""Startup" is ``create_app()``, not ``store.initialize()``.

The read-before-write guard in ``initialize()`` fixed the trust-context backfill,
but production boots through the factory —
``uvicorn.run("hermes_gateway.app:create_app", factory=True)`` — and the line
right after ``store.initialize()`` was ``_ensure_local_node(store, settings)`` ->
``store.upsert_node()``, an unconditional ``INSERT ... ON CONFLICT DO UPDATE`` on
every single boot. Measured on a real out-of-process uvicorn boot against an
already-migrated, populated database with a competing writer holding the write
lock, that raised ``sqlite3.OperationalError: database is locked`` from
``app.py:_ensure_local_node`` -> ``store.upsert_node`` and the process exited: a
hard boot failure with the identical symptom, on a perfectly healthy database.

Guarding that upsert with a field comparison was necessary but not sufficient,
because boot compared fields boot does not OWN. ``POST /v1/nodes/register`` is the
bridge's endpoint for the node row and writes the bridge's real ``hermes_version``,
its ``tags`` and its reachable ``gateway_base_url``; boot wanted
``settings.hermes_version`` (``os.getenv("HERMES_VERSION")`` — ``None`` unless
exported), a hardcoded tag list and the locally configured base URL. Permanently
unequal, so the comparison never short-circuited: every boot took the write lock
AND clobbered ``hermes_version`` back to NULL, the next registration restored it,
and the two fought forever. Measured out of process: change counter +1 per boot
and ``'2.4.1-bridge' -> None``.

The discipline these tests pin: boot owns that the row EXISTS and owns no columns,
so booting against a populated database performs ZERO writes — including after a
registration has set the bridge-owned fields — while an absent row is still seeded.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from hermes_gateway.app import create_app
from hermes_gateway.config import Settings
from hermes_gateway.store import SQLiteStore
from test_store_startup_locking import write_lock_held


def boot_settings(tmp_path: Path) -> Settings:
    return Settings(
        node_id="node_boot",
        node_display_name="Boot Test Tower",
        node_fingerprint="boot-test-fingerprint",
        gateway_base_url="http://127.0.0.1:8787/v1",
        database_path=str(tmp_path / "gateway.sqlite3"),
        pairing_ttl_seconds=60,
    )


def change_counter(db_path: str) -> int:
    """SQLite's own file-change counter, bytes 24..28 of the database header.

    It advances on every write transaction that touches the file and on nothing
    else, which makes "this boot performed zero writes" an exact measurement
    rather than an inference from timings.
    """
    with open(db_path, "rb") as handle:
        return int.from_bytes(handle.read(100)[24:28], "big")


def booted_once(tmp_path: Path) -> Settings:
    """A database in the state a live gateway leaves behind: current schema, local
    node row present, seed agent present."""
    settings = boot_settings(tmp_path)
    create_app(settings)
    return settings


def test_boot_against_a_current_database_performs_zero_writes(tmp_path: Path) -> None:
    settings = booted_once(tmp_path)
    before = change_counter(settings.database_path)

    create_app(settings)

    assert change_counter(settings.database_path) == before


def test_boot_survives_a_held_write_lock(tmp_path: Path) -> None:
    """The whole point. The competing writer holds the lock for the entire call,
    so a boot that asks for it either blocks or dies; pre-fix it died inside
    ``_ensure_local_node``."""
    settings = booted_once(tmp_path)
    db_path = Path(settings.database_path)

    with write_lock_held(db_path):
        create_app(settings)

    # Not merely "did not raise": it must not have needed the lock at all, which
    # holding it for the whole call is what proves.
    assert SQLiteStore(db_path).get_node(settings.node_id)["node_id"] == "node_boot"


def test_boot_creates_the_local_node_when_it_is_absent(tmp_path: Path) -> None:
    """Read-before-write must not turn registration into a no-op on a fresh
    database — the node row is how the gateway knows its own identity."""
    settings = boot_settings(tmp_path)

    create_app(settings)

    node = SQLiteStore(settings.database_path).get_node(settings.node_id)
    assert node["display_name"] == "Boot Test Tower"
    assert node["gateway_base_url"] == "http://127.0.0.1:8787/v1"
    assert node["health"] == "online"
    assert node["tags"] == ["self-hosted", "tailscale-first"]
    assert [capability["name"] for capability in node["capabilities"]] == [
        "events_websocket",
        "pairing",
        "mobile_notify",
        "approvals",
    ]


#: What the bridge sends to ``POST /v1/nodes/register``: a real Hermes version, its
#: own tags, and the address the node is actually reachable on. Every one of these
#: is a field boot used to overwrite with a local-only value.
BRIDGE_REGISTRATION: dict[str, Any] = {
    "node_id": "node_boot",
    "display_name": "Boot Test Tower",
    "environment": "homelab",
    "gateway_base_url": "http://100.64.0.7:8787/v1",
    "node_fingerprint": "boot-test-fingerprint",
    "gateway_version": "0.1.0",
    "hermes_version": "2.4.1-bridge",
    "tags": ["bridge-registered"],
}


def register_from_bridge(settings: Settings) -> dict:
    """Drive the real endpoint, from loopback so the Hermes-local guard admits it."""
    with TestClient(create_app(settings), client=("127.0.0.1", 50000)) as client:
        response = client.post("/v1/nodes/register", json=BRIDGE_REGISTRATION)
        assert response.status_code == 201, response.text
        return response.json()


def test_boot_after_a_registration_performs_zero_writes(tmp_path: Path) -> None:
    """THE case the field comparison could not pass. Once the bridge has
    registered, boot's idea of hermes_version / tags / gateway_base_url differs
    from the stored row *permanently*, so a comparing boot writes every single time
    and clobbers the bridge's values on the way past."""
    settings = booted_once(tmp_path)
    registered = register_from_bridge(settings)
    assert registered["hermes_version"] == "2.4.1-bridge"
    assert settings.hermes_version is None, (
        "the premise: HERMES_VERSION is unset in production, so boot can only ever "
        "want NULL here"
    )
    before = change_counter(settings.database_path)

    create_app(settings)

    assert change_counter(settings.database_path) == before
    node = SQLiteStore(settings.database_path).get_node(settings.node_id)
    assert node["hermes_version"] == "2.4.1-bridge"
    assert node["tags"] == ["bridge-registered"]
    assert node["gateway_base_url"] == "http://100.64.0.7:8787/v1"


#: Row-mutating authorizer actions. Scoped to DML on purpose: the authorizer fires
#: when a statement is PREPARED, and ``initialize()``'s idempotent
#: ``CREATE TABLE/INDEX IF NOT EXISTS`` script authorizes SQLITE_CREATE_* (plus an
#: INSERT on ``sqlite_master``) on every boot even though every one of those
#: statements is a runtime no-op — which is exactly what the change counter, which
#: only advances on a real write transaction, is here to establish. So: the counter
#: covers "did the file change", and this covers "did any boot statement try to
#: touch a ROW", the class of write that caused the fight with /v1/nodes/register.
ROW_WRITE_ACTIONS: frozenset[int] = frozenset(
    {sqlite3.SQLITE_INSERT, sqlite3.SQLITE_UPDATE, sqlite3.SQLITE_DELETE}
)


def test_boot_attempts_no_row_write_at_all(tmp_path: Path, monkeypatch: Any) -> None:
    """The change counter proves the file was not modified. This proves the boot
    never even asked: a tracing authorizer is installed on every connection the
    gateway opens, so an attempted INSERT/UPDATE/DELETE is recorded whether or not
    SQLite ends up dirtying a page."""
    settings = booted_once(tmp_path)
    register_from_bridge(settings)

    attempted: list[tuple[int, Any, Any]] = []
    original_connect = SQLiteStore.connect

    def traced_connect(self: SQLiteStore) -> sqlite3.Connection:
        connection = original_connect(self)

        def authorizer(action: int, arg1: Any, arg2: Any, *_rest: Any) -> int:
            # sqlite_master rows are the CREATE ... IF NOT EXISTS statements above.
            if action in ROW_WRITE_ACTIONS and arg1 != "sqlite_master":
                attempted.append((action, arg1, arg2))
            return sqlite3.SQLITE_OK

        connection.set_authorizer(authorizer)
        return connection

    monkeypatch.setattr(SQLiteStore, "connect", traced_connect)
    before = change_counter(settings.database_path)

    create_app(settings)

    assert attempted == [], attempted
    assert change_counter(settings.database_path) == before

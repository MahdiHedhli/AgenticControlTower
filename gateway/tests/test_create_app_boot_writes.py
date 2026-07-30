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

The discipline these tests pin: booting against a current, populated database
performs ZERO writes, so it cannot contend for the write lock at all — while a
database that is absent or has genuinely drifted still gets written.
"""

from __future__ import annotations

from pathlib import Path

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


def test_boot_rewrites_the_local_node_when_it_has_drifted(tmp_path: Path) -> None:
    """The other half: a stored row that no longer matches this gateway's identity
    must still be corrected, or the guard would be silently pinning stale state."""
    settings = booted_once(tmp_path)
    store = SQLiteStore(settings.database_path)
    with store.connect() as db:
        db.execute(
            "UPDATE nodes SET gateway_version = ?, health = ? WHERE node_id = ?",
            ("0.0.0-stale", "offline", settings.node_id),
        )
    before = change_counter(settings.database_path)

    create_app(settings)

    node = store.get_node(settings.node_id)
    assert node["gateway_version"] == settings.gateway_version
    assert node["health"] == "online"
    assert change_counter(settings.database_path) > before

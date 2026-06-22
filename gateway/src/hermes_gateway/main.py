from __future__ import annotations

import dataclasses
import fcntl
import os
import sys
from pathlib import Path

import uvicorn

from .config import Settings

# Loopback-only prod/bridge contract. Overridable via env, but never 0.0.0.0
# by default and never auto-falling-back to another port.
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8788

# Env var pointing at a TOML config for the supervised serve path.
CONFIG_ENV_VAR = "ACT_GATEWAY_CONFIG"
DEFAULT_CONFIG_PATH = Path.home() / ".hermes" / "act" / "gateway.toml"


class SingletonError(RuntimeError):
    """Raised when another gateway already owns the DB+port for this host."""


def acquire_singleton_lock(pid_path: str | Path):
    """Acquire an exclusive, non-blocking advisory flock on ``pid_path`` so
    exactly one gateway process owns the DB+port on this host.

    Returns the open file object holding the lock; the caller MUST keep a
    reference to it for the process lifetime. The lock releases automatically
    when the fd is closed or the process dies. Raises ``SingletonError`` if the
    lock is already held by another process.
    """
    pid_path = Path(pid_path)
    pid_path.parent.mkdir(parents=True, exist_ok=True)
    # Keep the fd open for the lifetime of the process; do not use a context
    # manager that would close (and release) it.
    handle = open(pid_path, "a+")  # noqa: SIM115
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        handle.close()
        raise SingletonError(
            f"another gateway already holds {pid_path}; refusing to start"
        ) from exc
    # Record our pid while holding the lock.
    handle.seek(0)
    handle.truncate()
    handle.write(f"{os.getpid()}\n")
    handle.flush()
    return handle


def _pid_path_for(settings: Settings) -> Path:
    """The singleton pid/lock file lives next to the database."""
    db_dir = settings.database_file.parent
    return db_dir / "gateway.pid"


def _load_settings() -> Settings:
    """Build Settings for the supervised serve path. Prefer an explicit TOML
    config (ACT_GATEWAY_CONFIG, default ~/.hermes/act/gateway.toml) when it
    exists; otherwise fall back to the existing env-based construction."""
    config_path = Path(os.getenv(CONFIG_ENV_VAR, str(DEFAULT_CONFIG_PATH))).expanduser()
    if config_path.exists():
        return Settings.from_file(config_path)
    return Settings.from_env()


def _absolutize_db(settings: Settings) -> Settings:
    """Anchor a relative database_path at ``$HOME`` (never the CWD) so the
    singleton lock derived from it is stable across working directories. A
    relative default would otherwise let two gateways started from different
    CWDs each lock a different file and both run."""
    db = Path(settings.database_path).expanduser()
    if not db.is_absolute():
        db = Path.home() / db
    return dataclasses.replace(settings, database_path=str(db))


def _assert_no_mock_data(settings: Settings) -> None:
    """A durable, Hermes-supervised gateway must never serve mock/fake agents."""
    if settings.seed_mock_data:
        raise SystemExit(
            "refusing to start: seed_mock_data is enabled. A supervised gateway "
            "must serve only real (bridge-fed) agents. Set seed_mock_data=false "
            "in the config (or ACT_SEED_MOCK_DATA=0)."
        )


def main() -> None:
    """Supervised serve entrypoint: load settings, enforce the no-mock
    fail-safe, acquire the host singleton, then bind uvicorn on loopback."""
    from .app import create_app

    settings = _load_settings()
    settings = _absolutize_db(settings)
    _assert_no_mock_data(settings)

    pid_path = _pid_path_for(settings)
    try:
        lock_handle = acquire_singleton_lock(pid_path)
    except SingletonError as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1) from exc
    # Keep a reference on the module so the lock is never garbage-collected.
    global _LOCK_HANDLE
    _LOCK_HANDLE = lock_handle

    # Env wins; else the configured bind_host (e.g. 0.0.0.0 for a tailnet-reachable
    # deployment); else the loopback default. Every endpoint is device-auth gated.
    host = os.getenv("HERMES_GATEWAY_HOST") or settings.bind_host or DEFAULT_HOST
    port = int(os.getenv("HERMES_GATEWAY_PORT", str(DEFAULT_PORT)))

    uvicorn.run(
        create_app(settings),
        host=host,
        port=port,
    )


_LOCK_HANDLE = None


if __name__ == "__main__":
    main()

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from hermes_gateway import main as gateway_main
from hermes_gateway.config import Settings
from hermes_gateway.main import (
    SingletonError,
    acquire_singleton_lock,
)


def test_from_file_overrides_defaults(tmp_path: Path) -> None:
    db_path = str(tmp_path / "custom" / "gateway.sqlite3")
    config = tmp_path / "gateway.toml"
    config.write_text(
        "\n".join(
            [
                f'database_path = "{db_path}"',
                "seed_mock_data = false",
                'node_id = "node_supervised"',
                "pairing_ttl_seconds = 120",
                'allowed_hermes_callers = ["hermes-a", "hermes-b"]',
            ]
        )
    )

    settings = Settings.from_file(config)

    assert settings.database_path == db_path
    assert settings.seed_mock_data is False
    assert settings.node_id == "node_supervised"
    assert settings.pairing_ttl_seconds == 120
    # list TOML values normalise to tuples to match dataclass defaults.
    assert settings.allowed_hermes_callers == ("hermes-a", "hermes-b")
    # Untouched fields keep their defaults.
    assert settings.node_display_name == Settings.node_display_name


def test_from_file_ignores_unknown_keys(tmp_path: Path) -> None:
    config = tmp_path / "gateway.toml"
    config.write_text('node_id = "node_x"\nnot_a_field = "ignored"\n')
    settings = Settings.from_file(config)
    assert settings.node_id == "node_x"


def test_serve_path_refuses_mock_data() -> None:
    settings = Settings(seed_mock_data=True)
    with pytest.raises(SystemExit) as excinfo:
        gateway_main._assert_no_mock_data(settings)
    assert "seed_mock_data" in str(excinfo.value)


def test_serve_path_allows_real_data() -> None:
    settings = Settings(seed_mock_data=False)
    # Should not raise.
    gateway_main._assert_no_mock_data(settings)


def test_load_settings_prefers_config_file(tmp_path, monkeypatch) -> None:
    config = tmp_path / "gateway.toml"
    config.write_text('node_id = "from_toml"\nseed_mock_data = false\n')
    monkeypatch.setenv("ACT_GATEWAY_CONFIG", str(config))
    settings = gateway_main._load_settings()
    assert settings.node_id == "from_toml"
    assert settings.seed_mock_data is False


def test_load_settings_falls_back_to_env(tmp_path, monkeypatch) -> None:
    missing = tmp_path / "does-not-exist.toml"
    monkeypatch.setenv("ACT_GATEWAY_CONFIG", str(missing))
    settings = gateway_main._load_settings()
    # Falls back to env/default construction.
    assert settings.node_id == Settings.node_id


def test_singleton_guard_second_acquire_fails(tmp_path: Path) -> None:
    pid_path = tmp_path / "gateway.pid"
    first = acquire_singleton_lock(pid_path)
    try:
        # The pid file records our pid while the lock is held.
        assert pid_path.read_text().strip().isdigit()
        with pytest.raises(SingletonError):
            acquire_singleton_lock(pid_path)
    finally:
        first.close()


def test_lock_path_is_cwd_independent(tmp_path: Path, monkeypatch) -> None:
    # Regression: a relative database_path must anchor at $HOME, not the CWD,
    # so the singleton lock cannot fork into per-working-directory files and
    # let two gateways both "win".
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    settings = Settings(database_path="rel/gateway.sqlite3")

    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    monkeypatch.chdir(tmp_path / "a")
    path_a = gateway_main._pid_path_for(gateway_main._absolutize_db(settings))
    monkeypatch.chdir(tmp_path / "b")
    path_b = gateway_main._pid_path_for(gateway_main._absolutize_db(settings))

    assert path_a == path_b  # identical regardless of CWD
    assert path_a == home.resolve() / "rel" / "gateway.pid"
    assert "/a/" not in str(path_a) and "/b/" not in str(path_a)


def test_singleton_guard_blocks_across_processes(tmp_path: Path) -> None:
    # Real cross-process test: a separate process holding the flock must block
    # us from acquiring it (the kernel enforces flock across processes).
    import subprocess
    import textwrap
    import time

    pid_path = tmp_path / "gateway.pid"
    ready = tmp_path / "ready"
    script = textwrap.dedent(
        f"""
        import fcntl, time
        h = open({str(pid_path)!r}, "a+")
        fcntl.flock(h.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        open({str(ready)!r}, "w").write("locked")
        time.sleep(30)
        """
    )
    proc = subprocess.Popen([sys.executable, "-c", script])
    try:
        for _ in range(200):
            if ready.exists():
                break
            time.sleep(0.05)
        assert ready.exists(), "subprocess failed to acquire the lock"
        with pytest.raises(SingletonError):
            acquire_singleton_lock(pid_path)
    finally:
        proc.terminate()
        proc.wait(timeout=5)

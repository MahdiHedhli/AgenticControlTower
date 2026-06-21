"""Hermetic tests for the act-clearance bridge plugin (Phase 3).

The plugin lives in a hyphenated package dir (``act-clearance``) and is loaded
from disk, so it is imported here by file path via importlib. Every test uses a
tmp HOME + monkeypatch so nothing touches the real ``~/.hermes``.

Run from the repo root (or anywhere) with:

    uv run --directory gateway pytest -q ../integrations/hermes/act-clearance/tests

or, with a plain interpreter that has pytest available:

    python -m pytest integrations/hermes/act-clearance/tests -q
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

# --- load the hyphenated plugin module by path ------------------------------

_PLUGIN_PATH = Path(__file__).resolve().parents[1] / "__init__.py"
_spec = importlib.util.spec_from_file_location("act_clearance_plugin", _PLUGIN_PATH)
assert _spec and _spec.loader
plugin = importlib.util.module_from_spec(_spec)
sys.modules["act_clearance_plugin"] = plugin
_spec.loader.exec_module(plugin)


@pytest.fixture(autouse=True)
def _reset_toml_cache():
    """Each test gets a fresh act.toml cache (the loader memoizes per process)."""
    plugin._TOML_CACHE["loaded"] = False
    plugin._TOML_CACHE["data"] = {}
    yield
    plugin._TOML_CACHE["loaded"] = False
    plugin._TOML_CACHE["data"] = {}


@pytest.fixture
def home(tmp_path, monkeypatch):
    """Redirect HOME so act.toml resolves under a tmp dir."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    return tmp_path


def _write_act_toml(home: Path, body: str) -> Path:
    p = home / ".hermes" / "act" / "act.toml"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body)
    return p


# --- precedence: ENV > act.toml > default -----------------------------------


def test_env_wins_over_toml(home, monkeypatch):
    _write_act_toml(home, 'gateway_url = "http://toml-host:1/v1"\nagent_id = "from_toml"\n')
    monkeypatch.setenv("ACT_GATEWAY_URL", "http://env-host:9/v1")
    monkeypatch.setenv("ACT_CLEARANCE_AGENT_ID", "from_env")
    plugin._TOML_CACHE["loaded"] = False  # ensure re-read with this HOME
    assert plugin._gateway() == "http://env-host:9/v1"
    assert plugin._agent_id() == "from_env"


def test_toml_used_when_env_absent(home, monkeypatch):
    monkeypatch.delenv("ACT_GATEWAY_URL", raising=False)
    monkeypatch.delenv("ACT_CLEARANCE_AGENT_ID", raising=False)
    monkeypatch.delenv("ACT_CLEARANCE_AGENT_NAME", raising=False)
    _write_act_toml(
        home,
        'gateway_url = "http://toml-host:1/v1"\n'
        'agent_id = "from_toml"\n'
        'agent_name = "Toml Agent"\n',
    )
    plugin._TOML_CACHE["loaded"] = False
    assert plugin._gateway() == "http://toml-host:1/v1"
    assert plugin._agent_id() == "from_toml"
    assert plugin._agent_name() == "Toml Agent"


def test_default_when_neither(home, monkeypatch):
    for var in ("ACT_GATEWAY_URL", "ACT_CLEARANCE_AGENT_ID", "ACT_CLEARANCE_AGENT_NAME"):
        monkeypatch.delenv(var, raising=False)
    # no act.toml on disk at all
    plugin._TOML_CACHE["loaded"] = False
    assert plugin._gateway() == plugin._DEFAULT_GATEWAY.rstrip("/")
    assert plugin._agent_id() == "hermes_agent"
    assert plugin._agent_name() == "Hermes Agent"


def test_empty_env_falls_through_to_toml(home, monkeypatch):
    # An env var set to empty/whitespace must NOT shadow act.toml.
    _write_act_toml(home, 'agent_id = "from_toml"\n')
    monkeypatch.setenv("ACT_CLEARANCE_AGENT_ID", "   ")
    plugin._TOML_CACHE["loaded"] = False
    assert plugin._agent_id() == "from_toml"


# --- tool lists (CSV env vs TOML array) -------------------------------------


def test_tools_env_csv_wins_over_toml_array(home, monkeypatch):
    _write_act_toml(home, 'gated_tools = ["only_toml"]\n')
    monkeypatch.setenv("ACT_CLEARANCE_GATED_TOOLS", "a,b,c")
    plugin._TOML_CACHE["loaded"] = False
    assert plugin._tools("ACT_CLEARANCE_GATED_TOOLS", "gated_tools", "x") == ["a", "b", "c"]


def test_tools_toml_array_used_when_env_absent(home, monkeypatch):
    monkeypatch.delenv("ACT_CLEARANCE_GATED_TOOLS", raising=False)
    _write_act_toml(home, 'gated_tools = ["send_email", "git_push"]\n')
    plugin._TOML_CACHE["loaded"] = False
    assert plugin._is_in("ACT_CLEARANCE_GATED_TOOLS", "gated_tools", "x", "git_push")
    assert not plugin._is_in("ACT_CLEARANCE_GATED_TOOLS", "gated_tools", "x", "ls")


# --- enable from toml / env -------------------------------------------------


def test_enabled_from_toml_without_env(home, monkeypatch):
    monkeypatch.delenv("ACT_CLEARANCE_ENABLED", raising=False)
    _write_act_toml(home, "enabled = true\n")
    plugin._TOML_CACHE["loaded"] = False
    assert plugin._enabled() is True


def test_enabled_still_true_from_env(home, monkeypatch):
    # No act.toml (or enabled=false) but env gate is truthy -> enabled.
    _write_act_toml(home, "enabled = false\n")
    monkeypatch.setenv("ACT_CLEARANCE_ENABLED", "1")
    plugin._TOML_CACHE["loaded"] = False
    assert plugin._enabled() is True


def test_disabled_when_neither(home, monkeypatch):
    monkeypatch.delenv("ACT_CLEARANCE_ENABLED", raising=False)
    plugin._TOML_CACHE["loaded"] = False
    assert plugin._enabled() is False


# --- tolerant loader --------------------------------------------------------


def test_act_toml_missing_is_empty(home, monkeypatch):
    plugin._TOML_CACHE["loaded"] = False
    assert plugin._act_toml() == {}


def test_act_toml_garbage_is_empty(home, monkeypatch):
    _write_act_toml(home, "this is = = not valid toml [[[\n")
    plugin._TOML_CACHE["loaded"] = False
    assert plugin._act_toml() == {}  # tolerant of parse errors


# --- self-heal --------------------------------------------------------------


def test_self_heal_kickstarts_when_unhealthy(home, monkeypatch):
    monkeypatch.delenv("ACT_GATEWAY_URL", raising=False)
    plugin._TOML_CACHE["loaded"] = False

    calls = {}

    def fake_urlopen(req, timeout=1.0):  # noqa: ARG001
        raise OSError("connection refused")

    def fake_run(cmd, **kwargs):  # noqa: ARG001
        calls["cmd"] = cmd
        import subprocess

        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(plugin.urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(plugin.subprocess, "run", fake_run)
    monkeypatch.setattr(plugin.os, "getuid", lambda: 501)

    plugin._self_heal_gateway()

    assert calls["cmd"] == [
        "launchctl",
        "kickstart",
        "-k",
        "gui/501/app.act.gateway",
    ]


def test_self_heal_no_kickstart_when_healthy(home, monkeypatch):
    plugin._TOML_CACHE["loaded"] = False

    class _Resp:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    monkeypatch.setattr(plugin.urllib.request, "urlopen", lambda req, timeout=1.0: _Resp())

    ran = {"called": False}

    def fake_run(cmd, **kwargs):  # noqa: ARG001
        ran["called"] = True

    monkeypatch.setattr(plugin.subprocess, "run", fake_run)
    plugin._self_heal_gateway()
    assert ran["called"] is False


def test_self_heal_swallows_probe_exception(home, monkeypatch):
    plugin._TOML_CACHE["loaded"] = False

    def boom(*a, **k):
        raise RuntimeError("kaboom")

    # Both the probe and the subprocess explode; nothing may propagate.
    monkeypatch.setattr(plugin.urllib.request, "urlopen", boom)
    monkeypatch.setattr(plugin.subprocess, "run", boom)
    monkeypatch.setattr(plugin.os, "getuid", lambda: 501)
    # Must not raise.
    plugin._self_heal_gateway()


def test_health_url_derives_from_gateway(home, monkeypatch):
    monkeypatch.setenv("ACT_GATEWAY_URL", "http://127.0.0.1:8788/v1")
    plugin._TOML_CACHE["loaded"] = False
    assert plugin._health_url() == "http://127.0.0.1:8788/v1/health"

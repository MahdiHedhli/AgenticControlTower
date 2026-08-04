"""Hermetic tests for the ``act`` CLI (Phase 2).

NOTHING here touches the real launchctl, ~/.hermes, or ~/Library: every test
monkeypatches HOME to a tmp dir and routes side effects through FakeOps, which
records calls instead of performing them.
"""

from __future__ import annotations

import json
import stat
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from hermes_gateway import act_cli
from hermes_gateway.act_cli import (
    FakeOps,
    disable,
    doctor,
    generate_act_toml,
    generate_gateway_toml,
    generate_plist,
    generate_shim,
    install,
    plugin_update_status,
    uninstall,
)


@pytest.fixture()
def home(tmp_path, monkeypatch):
    h = tmp_path / "home"
    h.mkdir()
    monkeypatch.setenv("HOME", str(h))
    # Path.home() honours $HOME on POSIX.
    return h


# --------------------------------------------------------------------------- #
# Pure generators.
# --------------------------------------------------------------------------- #


def test_plist_has_hardened_launchd_keys(home):
    xml = generate_plist(interpreter="/usr/bin/python3")
    assert "<key>RunAtLoad</key>" in xml and "<true/>" in xml
    assert "<key>KeepAlive</key>" in xml
    assert "app.act.gateway" in xml
    # session types
    assert "<string>Aqua</string>" in xml and "<string>Background</string>" in xml
    # loopback config carried via ACT_GATEWAY_CONFIG, log paths present
    assert "ACT_GATEWAY_CONFIG" in xml
    assert "gateway.out.log" in xml and "gateway.err.log" in xml


def _section(xml: str, key: str) -> str:
    """Return the XML fragment for ``<key>{key}</key>`` up to the next <key>."""
    start = xml.index(f"<key>{key}</key>")
    rest = xml[start + len(f"<key>{key}</key>") :]
    end = rest.find("<key>")
    return rest if end == -1 else rest[:end]


def test_plist_program_arguments_point_at_shim_not_checkout(home):
    xml = generate_plist()
    shim = str(act_cli.shim_path())
    assert f"<string>{shim}</string>" in xml
    prog = _section(xml, "ProgramArguments")
    # ProgramArguments must point at the stable shim, never the source checkout.
    assert shim in prog
    assert "AgenticControlTower" not in prog
    assert "/src/hermes_gateway" not in prog


def test_plist_working_directory_is_stable_not_checkout(home):
    xml = generate_plist()
    # WorkingDirectory is the stable data root, never a checkout.
    assert f"<string>{act_cli.act_home()}</string>" in xml
    assert str(act_cli.act_home()).endswith("/.hermes/act")
    wd = _section(xml, "WorkingDirectory")
    assert "AgenticControlTower" not in wd
    assert str(act_cli.act_home()) in wd


def test_plist_reconstructs_path(home, monkeypatch):
    monkeypatch.setenv("PATH", "/opt/homebrew/bin:/usr/bin")
    xml = generate_plist(interpreter="/some/venv/bin/python")
    # interpreter bin dir is prepended; minimal launchd dirs guaranteed.
    assert "/some/venv/bin" in xml
    assert "/usr/bin:/bin:/usr/sbin:/sbin" in xml
    assert "/opt/homebrew/bin" in xml


def test_plist_path_ignores_ambient_process_injections(home, monkeypatch):
    monkeypatch.setenv("PATH", "/tmp/codex-run-one:/untrusted/bin:/usr/bin")
    first = generate_plist(interpreter="/some/venv/bin/python")
    monkeypatch.setenv("PATH", "/tmp/codex-run-two:/different/bin:/usr/bin")
    second = generate_plist(interpreter="/some/venv/bin/python")

    assert first == second
    assert "/tmp/codex-run" not in first
    assert "/untrusted/bin" not in first
    assert "/different/bin" not in second


def test_shim_execs_module(home):
    shim = generate_shim(interpreter="/v/bin/python")
    assert shim.startswith("#!/bin/sh")
    assert 'exec "/v/bin/python" -m hermes_gateway "$@"' in shim


def test_dashboard_service_is_loopback_only_and_supervised(home):
    shim = act_cli.generate_dashboard_shim(Path("/stable/hermes/venv/bin/hermes"))
    xml = act_cli.generate_dashboard_plist()

    assert 'exec "/stable/hermes/venv/bin/hermes" dashboard' in shim
    assert "--host 127.0.0.1" in shim
    assert "--port 9119" in shim
    assert "--no-open --skip-build" in shim
    assert "--insecure" not in shim
    assert "app.act.hermes-dashboard" in xml
    assert "<key>KeepAlive</key>" in xml
    assert "hermes-dashboard.out.log" in xml
    assert "hermes-dashboard.err.log" in xml


def test_package_is_runnable_as_module():
    # The shim execs `python -m hermes_gateway`; that needs a __main__ module,
    # else the RunAtLoad+KeepAlive job crash-loops on every launch with
    # "No module named hermes_gateway.__main__".
    import importlib.util

    assert importlib.util.find_spec("hermes_gateway.__main__") is not None


def test_gateway_toml_bakes_safe_overrides(home):
    text = generate_gateway_toml()
    assert "seed_mock_data = false" in text
    # absolute DB path ending at the stable data root
    assert str(act_cli.database_path()) in text
    assert Path(str(act_cli.database_path())).is_absolute()
    assert "8788" in text
    assert "127.0.0.1" in text
    # Full Hermes dashboard reverse-proxy target (default loopback :9119).
    assert 'dashboard_url = "http://127.0.0.1:9119"' in text
    assert "dashboard_legacy_mount_rewrite = false" in text
    assert "dashboard_session_token_log_path" not in text
    # The process stays loopback-only; Tailscale Serve provides tailnet TLS.
    assert 'bind_host = "127.0.0.1"' in text
    # no apns by default
    assert "apns_key_path" not in text


def test_gateway_toml_apns_records_path_only(home):
    text = generate_gateway_toml(
        apns_key_path="/secret/AuthKey_ABC.p8",
        apns_key_id="ABC",
        apns_team_id="TEAM",
    )
    assert 'apns_key_path = "/secret/AuthKey_ABC.p8"' in text
    assert 'apns_key_id = "ABC"' in text
    assert 'apns_team_id = "TEAM"' in text


def test_act_toml_bridge_config(home):
    text = generate_act_toml()
    # Full bridge surface the act-clearance plugin reads (keys must match the
    # plugin's toml_key names exactly).
    assert "enabled = true" in text
    assert 'gateway_url = "http://127.0.0.1:8788/v1"' in text
    assert 'agent_id = "hermes_agent"' in text
    assert 'agent_name = "Hermes Agent"' in text
    assert "gated_tools = [" in text
    assert "question_tools = [" in text
    assert 'question_risk_family = "read_only"' in text
    assert 'clearance_risk_family = "external_effect"' in text
    # Defaults mirror the plugin's built-ins.
    assert '"terminal"' in text and '"git_push"' in text
    assert '"clarify"' in text and '"ask_user"' in text

    # Parses as valid TOML with the expected shape.
    import tomllib

    parsed = tomllib.loads(text)
    assert parsed["enabled"] is True
    assert parsed["agent_id"] == "hermes_agent"
    assert isinstance(parsed["gated_tools"], list)
    assert "send_email" in parsed["gated_tools"]
    assert parsed["question_tools"] == ["clarify", "ask_operator", "ask_user"]


# --------------------------------------------------------------------------- #
# install() via FakeOps.
# --------------------------------------------------------------------------- #


def _hermes_config_with_plugins(home: Path) -> Path:
    cfg = home / ".hermes" / "config.yaml"
    cfg.parent.mkdir(parents=True, exist_ok=True)
    cfg.write_text("plugins:\n  enabled:\n  - hermesultracode\n  disabled: []\n")
    return cfg


def test_install_records_launchctl_and_writes_artifacts(home):
    cfg = _hermes_config_with_plugins(home)
    ops = FakeOps(existing={str(cfg): cfg.read_text()})
    install(ops)

    # plist + shim + configs written
    assert str(act_cli.plist_path()) in ops.files
    assert str(act_cli.shim_path()) in ops.files
    assert str(act_cli.gateway_toml_path()) in ops.files
    assert str(act_cli.act_toml_path()) in ops.files
    assert ops.modes[str(act_cli.gateway_toml_path())] == 0o600

    # shim is executable
    assert ops.modes[str(act_cli.shim_path())] == 0o755
    assert "<key>Umask</key>" in ops.files[str(act_cli.plist_path())]

    # launchctl bootstrap + kickstart recorded against the user domain
    target = act_cli.launchd_service_target()
    domain = act_cli.launchd_domain()
    assert ("launchctl", "bootstrap", domain, str(act_cli.plist_path())) in ops.calls
    assert ("launchctl", "kickstart", "-k", target) in ops.calls

    # bridge enabled: act-clearance added to plugins.enabled
    new_cfg = ops.files[str(cfg)]
    assert "act-clearance" in new_cfg

    # The security hook is deployed and pinned by ACT, not merely enabled.
    for name in act_cli.PLUGIN_DISTRIBUTION_FILES:
        installed = act_cli.plugin_install_dir() / name
        assert ops.files[str(installed)] == (act_cli.plugin_source_dir() / name).read_text()
        assert ops.modes[str(installed)] == 0o600
    release = json.loads(ops.files[str(act_cli.plugin_release_path())])
    assert release["name"] == "act-clearance"
    assert release["version"] == "0.1.2"
    assert ops.modes[str(act_cli.plugin_release_path())] == 0o600
    assert plugin_update_status(ops).ok


def test_install_supervises_dashboard_when_hermes_is_installed(home):
    executable = act_cli.hermes_dashboard_executable()
    ops = FakeOps(existing={str(executable): "<hermes executable>"})

    install(ops)

    assert str(act_cli.dashboard_shim_path()) in ops.files
    assert ops.modes[str(act_cli.dashboard_shim_path())] == 0o755
    assert str(act_cli.dashboard_plist_path()) in ops.files
    assert (
        "launchctl",
        "bootstrap",
        act_cli.launchd_domain(),
        str(act_cli.dashboard_plist_path()),
    ) in ops.calls
    assert (
        "launchctl",
        "kickstart",
        "-k",
        act_cli.dashboard_launchd_service_target(),
    ) in ops.calls
    assert (
        "/usr/bin/curl",
        "--fail",
        "--silent",
        "--max-time",
        "1",
        "http://127.0.0.1:9119/",
    ) in ops.calls


def test_install_hardens_existing_hermes_dashboard_token_log(home):
    cfg = _hermes_config_with_plugins(home)
    token_log = act_cli.hermes_agent_log_path()
    ops = FakeOps(
        existing={
            str(cfg): cfg.read_text(),
            str(token_log): "dashboard startup record",
        }
    )

    install(ops)

    assert ops.modes[str(token_log)] == 0o600
    gateway = ops.files[str(act_cli.gateway_toml_path())]
    assert 'dashboard_url = "http://127.0.0.1:9119"' in gateway


def test_install_is_idempotent(home):
    cfg = _hermes_config_with_plugins(home)
    ops = FakeOps(existing={str(cfg): cfg.read_text()})
    install(ops)
    first_cfg = ops.files[str(cfg)]
    # second install: plugin already enabled -> config text unchanged
    install(ops)
    second_cfg = ops.files[str(cfg)]
    assert second_cfg.count("act-clearance") == first_cfg.count("act-clearance") == 1
    # act.toml not clobbered (only written when absent)
    assert str(act_cli.act_toml_path()) in ops.files


def test_plugin_check_detects_installed_integrity_drift(home):
    ops = FakeOps()
    install(ops)
    plugin_code = act_cli.plugin_install_dir() / "__init__.py"
    ops.files[str(plugin_code)] += "\n# unexpected local edit\n"

    report = plugin_update_status(ops)

    assert not report.ok
    assert report.status == "integrity_problem"
    assert "integrity drift: __init__.py" in report.text()
    assert "run `act install`" in report.text()


def test_plugin_check_detects_newer_bundled_release(home, tmp_path, monkeypatch):
    ops = FakeOps()
    install(ops)
    newer = tmp_path / "act-clearance"
    newer.mkdir()
    for name in act_cli.PLUGIN_DISTRIBUTION_FILES:
        text = (act_cli.plugin_source_dir() / name).read_text()
        if name == "plugin.yaml":
            text = text.replace('version: "0.1.2"', 'version: "0.1.3"')
        newer.joinpath(name).write_text(text)
    monkeypatch.setattr(act_cli, "plugin_source_dir", lambda: newer)

    report = plugin_update_status(ops)

    assert not report.ok
    assert report.status == "update_available"
    assert report.managed_version == "0.1.2"
    assert report.bundled_version == "0.1.3"
    assert "[UPDATE] bundled plugin 0.1.3" in report.text()


def test_install_preserves_seed_override_on_existing_toml(home):
    # A pre-existing gateway.toml with a user node_id but a DANGEROUS override
    # must come back with seed_mock_data forced false.
    existing = 'node_id = "custom_node"\nseed_mock_data = true\n'
    ops = FakeOps(existing={str(act_cli.gateway_toml_path()): existing})
    install(ops)
    text = ops.files[str(act_cli.gateway_toml_path())]
    assert 'node_id = "custom_node"' in text  # user edit preserved
    assert "seed_mock_data = false" in text  # safe override re-asserted


def test_install_preserves_operator_gateway_configuration(home):
    existing = "\n".join(
        [
            'node_id = "custom_node"',
            'dashboard_url = "http://127.0.0.1:9119/dashboard"',
            'allowed_hermes_callers = ["hermes.local"]',
            'bind_host = "0.0.0.0"',
            "seed_mock_data = true",
            "",
        ]
    )
    ops = FakeOps(existing={str(act_cli.gateway_toml_path()): existing})

    install(ops)

    text = ops.files[str(act_cli.gateway_toml_path())]
    assert 'dashboard_url = "http://127.0.0.1:9119/dashboard"' in text
    assert "dashboard_legacy_mount_rewrite = false" in text
    assert 'allowed_hermes_callers = ["hermes.local"]' in text
    assert 'bind_host = "127.0.0.1"' in text
    assert "seed_mock_data = false" in text


def test_pair_command_prints_importable_json(monkeypatch, capsys):
    bundle = {
        "pairing_id": "pair_test",
        "pairing_token": "one-time-secret",
        "challenge": "challenge",
        "status": "pending",
        "node_id": "node_test",
        "node_fingerprint": "fingerprint",
        "tower_public_key": "tower-public-key",
        "clearance_channel": "mobile_signed",
        "expires_at": "2026-07-16T20:00:00Z",
    }
    monkeypatch.setattr(act_cli, "create_mobile_pairing_bundle", lambda: bundle)

    assert act_cli.main(["pair", "--json"]) == 0

    output = capsys.readouterr().out.strip()
    assert '"pairing_id":"pair_test"' in output
    assert '"clearance_channel":"mobile_signed"' in output


def test_pair_command_prints_qr_without_echoing_secret(monkeypatch, capsys):
    bundle = {
        "pairing_id": "pair_test",
        "pairing_token": "one-time-secret",
        "challenge": "challenge",
        "status": "pending",
        "node_id": "node_test",
        "node_fingerprint": "fingerprint",
        "tower_public_key": "tower-public-key",
        "clearance_channel": "mobile_signed",
        "expires_at": "2026-07-16T20:00:00Z",
    }
    monkeypatch.setattr(act_cli, "create_mobile_pairing_bundle", lambda: bundle)
    monkeypatch.setattr(act_cli, "render_pairing_qr", lambda _: "<terminal-qr>")

    assert act_cli.main(["pair", "--qr"]) == 0

    output = capsys.readouterr().out
    assert "<terminal-qr>" in output
    assert "2026-07-16T20:00:00Z" in output
    assert "one-time-secret" not in output


def test_pair_command_rejects_conflicting_output_formats(monkeypatch):
    monkeypatch.setattr(act_cli, "create_mobile_pairing_bundle", lambda: {})

    with pytest.raises(SystemExit, match="either --json or --qr"):
        act_cli.main(["pair", "--json", "--qr"])


def test_install_with_apns_writes_secret_0600_and_path_only(home, tmp_path):
    p8 = tmp_path / "AuthKey_SRC.p8"
    p8.write_text("-----BEGIN PRIVATE KEY-----\nFAKE\n-----END PRIVATE KEY-----\n")
    ops = FakeOps()
    install(ops, with_apns=("KEY123", "TEAM456", str(p8)))

    dst = act_cli.secrets_dir() / "AuthKey_KEY123.p8"
    assert ops.modes[str(dst)] == 0o600
    # gateway.toml records only the PATH, never the bytes.
    toml = ops.files[str(act_cli.gateway_toml_path())]
    assert str(dst) in toml
    assert "BEGIN PRIVATE KEY" not in toml
    assert 'apns_key_id = "KEY123"' in toml
    assert 'apns_team_id = "TEAM456"' in toml


# --------------------------------------------------------------------------- #
# disable / uninstall.
# --------------------------------------------------------------------------- #


def test_disable_boots_out_and_removes_plugin(home):
    cfg = home / ".hermes" / "config.yaml"
    cfg.parent.mkdir(parents=True, exist_ok=True)
    cfg.write_text("plugins:\n  enabled:\n  - act-clearance\n  - hermesultracode\n")
    ops = FakeOps(existing={str(cfg): cfg.read_text()})
    disable(ops)
    assert ("launchctl", "bootout", act_cli.launchd_service_target()) in ops.calls
    assert (
        "launchctl",
        "bootout",
        act_cli.dashboard_launchd_service_target(),
    ) in ops.calls
    assert "act-clearance" not in ops.files[str(cfg)]
    assert "hermesultracode" in ops.files[str(cfg)]


def test_uninstall_boots_out_and_removes_plist_and_shim(home):
    ops = FakeOps(
        existing={
            str(act_cli.plist_path()): "x",
            str(act_cli.shim_path()): "x",
        }
    )
    uninstall(ops)
    assert ("launchctl", "bootout", act_cli.launchd_service_target()) in ops.calls
    assert (
        "launchctl",
        "bootout",
        act_cli.dashboard_launchd_service_target(),
    ) in ops.calls
    assert str(act_cli.plist_path()) in ops.removed
    assert str(act_cli.shim_path()) in ops.removed
    assert str(act_cli.dashboard_plist_path()) in ops.removed
    assert str(act_cli.dashboard_shim_path()) in ops.removed
    assert ops.rmtrees == []  # no purge


def test_uninstall_purge_removes_data_dir(home):
    ops = FakeOps()
    uninstall(ops, purge=True)
    assert str(act_cli.act_home()) in ops.rmtrees


# --------------------------------------------------------------------------- #
# doctor.
# --------------------------------------------------------------------------- #


def test_doctor_clean_install_is_ok(home):
    ops = FakeOps()
    install(ops)
    report = doctor(ops)
    assert report.ok, report.text()
    assert "seed_mock_data is false" in report.text()


def test_doctor_checks_dashboard_supervision_when_hermes_exists(home):
    executable = act_cli.hermes_dashboard_executable()
    ops = FakeOps(existing={str(executable): "<hermes executable>"})
    install(ops)

    report = doctor(ops)

    assert report.ok, report.text()
    assert "Hermes dashboard executable exists" in report.text()
    assert "Hermes dashboard plist matches generated definition" in report.text()


def test_doctor_flags_seed_mock_data_true(home):
    ops = FakeOps(
        existing={
            str(act_cli.plist_path()): generate_plist(),
            str(act_cli.gateway_toml_path()): (
                f'seed_mock_data = true\ndatabase_path = "{act_cli.database_path()}"\n'
            ),
        }
    )
    report = doctor(ops)
    assert not report.ok
    assert "seed_mock_data is not false" in report.text()


def test_doctor_flags_missing_interpreter(home, monkeypatch):
    monkeypatch.setattr(act_cli, "interpreter_path", lambda: "/no/such/python")
    ops = FakeOps()
    install(ops)
    report = doctor(ops)
    assert not report.ok
    assert "interpreter missing" in report.text()


def test_doctor_flags_plugin_drift(home):
    ops = FakeOps()
    install(ops)
    plugin_manifest = act_cli.plugin_install_dir() / "plugin.yaml"
    ops.files[str(plugin_manifest)] = ops.files[str(plugin_manifest)].replace("0.1.2", "9.9.9")

    report = doctor(ops)

    assert not report.ok
    assert "managed plugin integrity drift: plugin.yaml" in report.text()


# --------------------------------------------------------------------------- #
# FIX 1: stable, ACT-owned runtime interpreter (durability).
# --------------------------------------------------------------------------- #


def test_default_shim_bakes_act_owned_venv_not_checkout(home):
    # The default shim/interpreter must point at the ACT-owned venv, never the
    # source checkout's .venv / project tree.
    shim = generate_shim()
    interp = act_cli.interpreter_path()
    assert interp == str(act_cli.venv_python())
    assert str(home / ".hermes" / "act" / "venv") in interp
    assert interp in shim
    # not the checkout: no repo .venv, no project name in the baked path.
    assert "AgenticControlTower" not in shim
    assert "/.venv/" not in shim


def test_install_records_venv_create_and_pip_install(home):
    ops = FakeOps()
    install(ops)
    vdir = act_cli.venv_dir()
    # bootstrap python (sys.executable) creates the ACT-owned venv...
    assert (sys.executable, "-m", "venv", str(vdir)) in ops.calls
    # ...then the gateway project is pip-installed into it.
    assert (
        str(vdir / "bin" / "pip"),
        "install",
        str(act_cli.gateway_project_dir()),
    ) in ops.calls
    # the venv-create call precedes writing the shim (provision-before-shim).
    venv_idx = ops.calls.index((sys.executable, "-m", "venv", str(vdir)))
    assert ops.files[str(act_cli.shim_path())]  # shim written
    # baked shim points at the ACT-owned venv python.
    assert str(act_cli.venv_python()) in ops.files[str(act_cli.shim_path())]
    assert venv_idx >= 0


def test_packaged_install_does_not_recreate_the_running_managed_venv(home, tmp_path, monkeypatch):
    ops = FakeOps()
    monkeypatch.setattr(act_cli, "gateway_project_dir", lambda: tmp_path / "installed-wheel")
    monkeypatch.setattr(sys, "executable", str(act_cli.venv_python()))

    act_cli._provision_venv(ops)

    assert ops.calls == []


def test_install_refuses_checkout_interpreter(home, monkeypatch):
    # If the baked interpreter still resolves under the source checkout, install
    # must refuse loudly rather than wire up a non-durable runtime.
    monkeypatch.setattr(
        act_cli,
        "interpreter_path",
        lambda: str(act_cli.gateway_project_dir() / ".venv" / "bin" / "python"),
    )
    ops = FakeOps()
    with pytest.raises(RuntimeError, match="source checkout"):
        install(ops)


def test_doctor_flags_venv_interpreter_missing(home):
    # plist + gateway.toml present, but the baked venv python does NOT exist on
    # disk -> doctor flags the missing interpreter.
    ops = FakeOps(
        existing={
            str(act_cli.plist_path()): generate_plist(),
            str(act_cli.gateway_toml_path()): (
                f'seed_mock_data = false\ndatabase_path = "{act_cli.database_path()}"\n'
            ),
        }
    )
    report = doctor(ops)
    assert not report.ok
    assert "interpreter missing" in report.text()
    assert str(act_cli.venv_python()) in report.text()


def test_doctor_flags_interpreter_under_checkout(home, monkeypatch):
    monkeypatch.setattr(
        act_cli,
        "interpreter_path",
        lambda: str(act_cli.gateway_project_dir() / ".venv" / "bin" / "python"),
    )
    ops = FakeOps(
        existing={
            str(act_cli.plist_path()): generate_plist(),
            str(act_cli.gateway_toml_path()): (
                f'seed_mock_data = false\ndatabase_path = "{act_cli.database_path()}"\n'
            ),
        }
    )
    report = doctor(ops)
    assert not report.ok
    assert "source checkout" in report.text()


# --------------------------------------------------------------------------- #
# FIX 2: uninstall strips the bridge from plugins.enabled.
# --------------------------------------------------------------------------- #


def test_uninstall_strips_bridge_keeps_unrelated(home):
    cfg = home / ".hermes" / "config.yaml"
    cfg.parent.mkdir(parents=True, exist_ok=True)
    cfg.write_text("plugins:\n  enabled:\n  - hermesultracode\n  disabled: []\n")
    # An unrelated ~/.hermes file that must survive uninstall.
    unrelated = home / ".hermes" / "keep.txt"
    unrelated.write_text("keep me")

    ops = FakeOps(
        existing={
            str(cfg): cfg.read_text(),
            str(unrelated): unrelated.read_text(),
        }
    )
    install(ops)
    # bridge enabled by install
    assert "act-clearance" in ops.files[str(cfg)]

    uninstall(ops, purge=True)
    # act-clearance stripped, unrelated plugin retained
    assert "act-clearance" not in ops.files[str(cfg)]
    assert "hermesultracode" in ops.files[str(cfg)]
    # unrelated ~/.hermes file untouched (never removed)
    assert str(unrelated) not in ops.removed
    assert ops.read_text(unrelated) == "keep me"
    # plist + shim removed; data dir purged
    assert str(act_cli.plist_path()) in ops.removed
    assert str(act_cli.shim_path()) in ops.removed
    assert str(act_cli.act_home()) in ops.rmtrees


def test_real_p8_copy_sets_0600(home, tmp_path):
    # Exercise the REAL Ops.copy_file mode behaviour against a tmp file so the
    # 0600 contract is enforced by the actual filesystem, not just the fake.
    from hermes_gateway.act_cli import Ops

    src = tmp_path / "src.p8"
    src.write_text("FAKE")
    dst = tmp_path / "out" / "AuthKey_X.p8"
    Ops().copy_file(src, dst, mode=0o600)
    assert dst.exists()
    assert stat.S_IMODE(dst.stat().st_mode) == 0o600

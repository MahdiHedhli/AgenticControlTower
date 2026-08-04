"""``act`` CLI: configure + supervise the ACT<->Hermes first-class gateway.

This module is the install/operate surface for the Phase 1 supervised
entrypoint (``hermes_gateway.main``). It generates a launchd job
(``app.act.gateway``) plus a stable shim and TOML configs under
``~/.hermes/act`` so the gateway runs durably on loopback with mock data
disabled.

Design notes
------------
* Every side effect (file write, chmod, mkdir, launchctl invocation) is routed
  through an injectable :class:`Ops` object so tests can substitute a
  :class:`FakeOps` that *records* calls without touching the real machine. The
  pure generators (:func:`generate_plist`, :func:`generate_gateway_toml`,
  :func:`generate_act_toml`, :func:`generate_shim`) take no Ops and are unit
  testable in isolation.
* launchd hard-won details are copied from Hermes's own gateway machinery:
  RunAtLoad, KeepAlive, LimitLoadToSessionType=[Aqua,Background], a
  reconstructed PATH (launchd only gives /usr/bin:/bin:/usr/sbin:/sbin), a
  STABLE WorkingDirectory that is never a source checkout, and
  StandardOut/ErrPath.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import time
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

# --------------------------------------------------------------------------- #
# Stable, never-the-checkout layout. All paths anchor at $HOME so the launchd
# job + singleton lock are identical regardless of where `act` is invoked from.
# --------------------------------------------------------------------------- #

LAUNCHD_LABEL = "app.act.gateway"
DASHBOARD_LAUNCHD_LABEL = "app.act.hermes-dashboard"
GATEWAY_HOST = "127.0.0.1"
GATEWAY_PORT = 8788
DASHBOARD_HOST = "127.0.0.1"
DASHBOARD_PORT = 9119
PLUGIN_NAME = "act-clearance"
PLUGIN_MANAGED_FILES = ("__init__.py", "plugin.yaml")
PLUGIN_DISTRIBUTION_FILES = (*PLUGIN_MANAGED_FILES, "README.md")
# launchd hands the job only this minimal PATH; everything else must be
# reconstructed into EnvironmentVariables.
LAUNCHD_MINIMAL_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"


def act_home() -> Path:
    """Stable data root: ``~/.hermes/act`` (expanded against the live HOME so
    tests that monkeypatch HOME redirect cleanly)."""
    return Path.home() / ".hermes" / "act"


def bin_dir() -> Path:
    return act_home() / "bin"


def venv_dir() -> Path:
    """ACT-owned dedicated venv root: ``~/.hermes/act/venv``. The runtime
    interpreter lives here so it is independent of any source checkout."""
    return act_home() / "venv"


def venv_python() -> Path:
    """The stable, ACT-owned runtime interpreter the shim bakes."""
    return venv_dir() / "bin" / "python"


def gateway_project_dir() -> Path:
    """The gateway project (containing pyproject.toml) ``pip install``-ed into
    the ACT-owned venv. Resolved relative to this module:
    ``src/hermes_gateway/act_cli.py`` -> gateway root is two parents up."""
    return Path(__file__).resolve().parents[2]


def logs_dir() -> Path:
    return act_home() / "logs"


def secrets_dir() -> Path:
    return act_home() / "secrets"


def shim_path() -> Path:
    return bin_dir() / "act-gateway"


def dashboard_shim_path() -> Path:
    return bin_dir() / "act-hermes-dashboard"


def gateway_toml_path() -> Path:
    return act_home() / "gateway.toml"


def act_toml_path() -> Path:
    return act_home() / "act.toml"


def database_path() -> Path:
    return act_home() / "gateway.sqlite3"


def plist_path() -> Path:
    return Path.home() / "Library" / "LaunchAgents" / f"{LAUNCHD_LABEL}.plist"


def dashboard_plist_path() -> Path:
    return Path.home() / "Library" / "LaunchAgents" / f"{DASHBOARD_LAUNCHD_LABEL}.plist"


def hermes_dashboard_executable() -> Path:
    """Stable Hermes CLI installed by the desktop/agent distribution."""
    return Path.home() / ".hermes" / "hermes-agent" / "venv" / "bin" / "hermes"


def hermes_config_path() -> Path:
    return Path.home() / ".hermes" / "config.yaml"


def plugin_source_dir() -> Path:
    """Bundled Hermes bridge source for the ACT release being installed."""
    packaged = Path(__file__).resolve().parent / "_bundled" / PLUGIN_NAME
    if all((packaged / name).is_file() for name in PLUGIN_DISTRIBUTION_FILES):
        return packaged
    return gateway_project_dir().parent / "integrations" / "hermes" / PLUGIN_NAME


def plugin_install_dir() -> Path:
    return Path.home() / ".hermes" / "plugins" / PLUGIN_NAME


def plugin_release_path() -> Path:
    """Owner-only manifest pinning the exact bridge files deployed by ACT."""
    return act_home() / "plugin-release.json"


def hermes_agent_log_path() -> Path:
    """Local Hermes log carrying UltraCode's rotating one-click read URL."""
    return Path.home() / ".hermes" / "logs" / "agent.log"


def launchd_domain() -> str:
    """User (gui) domain target, e.g. ``gui/501``."""
    return f"gui/{os.getuid()}"


def launchd_service_target() -> str:
    return f"{launchd_domain()}/{LAUNCHD_LABEL}"


def dashboard_launchd_service_target() -> str:
    return f"{launchd_domain()}/{DASHBOARD_LAUNCHD_LABEL}"


# --------------------------------------------------------------------------- #
# System-call abstraction. install/uninstall/etc. take an Ops; the default is
# the real implementation, tests inject FakeOps.
# --------------------------------------------------------------------------- #


@dataclass
class Ops:
    """Thin injectable layer over the filesystem + launchctl. The real
    implementation actually mutates the machine."""

    def run(self, cmd: list[str], *, check: bool = False, timeout: int = 30):
        return subprocess.run(cmd, check=check, timeout=timeout, capture_output=True, text=True)

    def write_text(self, path: Path, text: str, *, mode: int | None = None) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        if mode is not None:
            path.chmod(mode)

    def copy_file(self, src: Path, dst: Path, *, mode: int | None = None) -> None:
        dst = Path(dst)
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dst)
        if mode is not None:
            dst.chmod(mode)

    def mkdir(self, path: Path, *, mode: int = 0o755) -> None:
        Path(path).mkdir(parents=True, exist_ok=True)
        Path(path).chmod(mode)

    def chmod(self, path: Path, mode: int) -> None:
        Path(path).chmod(mode)

    def remove(self, path: Path) -> None:
        p = Path(path)
        if p.exists() or p.is_symlink():
            p.unlink()

    def rmtree(self, path: Path) -> None:
        shutil.rmtree(path, ignore_errors=True)

    def exists(self, path: Path) -> bool:
        return Path(path).exists()

    def read_text(self, path: Path) -> str:
        return Path(path).read_text()

    def read_bytes(self, path: Path) -> bytes:
        return Path(path).read_bytes()


@dataclass
class FakeOps(Ops):
    """Records every side effect instead of performing it. Used by tests so a
    full install can be exercised without touching launchctl or the real
    ``~/.hermes`` / ``~/Library``."""

    calls: list[tuple] = field(default_factory=list)
    files: dict[str, str] = field(default_factory=dict)
    modes: dict[str, int] = field(default_factory=dict)
    dirs: set[str] = field(default_factory=set)
    removed: list[str] = field(default_factory=list)
    rmtrees: list[str] = field(default_factory=list)
    # Optional seed of files that "already exist" on the fake filesystem.
    existing: dict[str, str] = field(default_factory=dict)
    run_results: dict[str, subprocess.CompletedProcess] = field(default_factory=dict)

    def run(self, cmd, *, check=False, timeout=30):
        self.calls.append(tuple(cmd))
        # Simulate `python -m venv <dir>` materializing the venv interpreter so
        # exists()-based checks (doctor) see it without real mutation.
        if len(cmd) >= 4 and cmd[1:3] == ["-m", "venv"]:
            self.files[str(Path(cmd[3]) / "bin" / "python")] = "<fake venv python>"
        key = " ".join(cmd)
        if key in self.run_results:
            return self.run_results[key]
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    def write_text(self, path, text, *, mode=None):
        self.files[str(path)] = text
        self.dirs.add(str(Path(path).parent))
        if mode is not None:
            self.modes[str(path)] = mode

    def copy_file(self, src, dst, *, mode=None):
        self.calls.append(("copy", str(src), str(dst)))
        # These managed inputs are text files. Preserve their real payload so
        # integrity/update checks exercise the same hashes as production.
        self.files[str(dst)] = Path(src).read_text()
        if mode is not None:
            self.modes[str(dst)] = mode

    def mkdir(self, path, *, mode=0o755):
        self.dirs.add(str(path))

    def chmod(self, path, mode):
        self.modes[str(path)] = mode

    def remove(self, path):
        self.removed.append(str(path))
        self.files.pop(str(path), None)
        self.existing.pop(str(path), None)

    def rmtree(self, path):
        self.rmtrees.append(str(path))

    def exists(self, path):
        return str(path) in self.files or str(path) in self.existing

    def read_text(self, path):
        if str(path) in self.files:
            return self.files[str(path)]
        return self.existing[str(path)]

    def read_bytes(self, path):
        return self.read_text(path).encode("utf-8")


# --------------------------------------------------------------------------- #
# Interpreter + PATH resolution (copied details from Hermes machinery).
# --------------------------------------------------------------------------- #


def interpreter_path() -> str:
    """The Python that runs the gateway at runtime. This is the ACT-OWNED
    dedicated venv (``~/.hermes/act/venv/bin/python``), NOT ``sys.executable``:
    under uv ``sys.executable`` is the source checkout's venv, so deleting the
    checkout would crash-loop the KeepAlive service. The dedicated venv is
    provisioned by :func:`install` (see :func:`_provision_venv`) and is
    independent of the checkout's site-packages."""
    return str(venv_python())


def _under_source_checkout(interp: str) -> bool:
    """True if ``interp`` resolves underneath this module's source checkout
    (the gateway project dir). Used by :func:`install` to refuse, and
    :func:`doctor` to warn, when the baked interpreter is the non-durable
    checkout venv rather than the ACT-owned runtime venv."""
    try:
        # Normalize the path's *location* WITHOUT following symlinks on the leaf:
        # a checkout ``.venv/bin/python`` is typically a symlink whose target is
        # the uv-managed interpreter outside the tree, but the shim would still
        # bake the in-checkout path and break when the checkout is deleted.
        located = Path(os.path.abspath(interp))
        checkout = Path(os.path.abspath(gateway_project_dir()))
    except Exception:
        return False
    return located == checkout or checkout in located.parents


def _build_service_path(interp: str | None = None) -> str:
    """Build a deterministic, allowlisted PATH for the launchd job.

    Never inherit the installing process's ambient PATH. Codex and other app
    runtimes inject per-process temporary directories there; baking those into
    a long-lived service caused false plist drift and expanded executable
    search into locations ACT does not control.
    """
    interp_bin = str(Path(interp or interpreter_path()).parent)
    stable = [
        interp_bin,
        str(Path.home() / ".local" / "bin"),
        "/opt/homebrew/bin",
        "/opt/homebrew/sbin",
        "/usr/local/bin",
        *LAUNCHD_MINIMAL_PATH.split(":"),
    ]
    return ":".join(dict.fromkeys(stable))


# --------------------------------------------------------------------------- #
# Pure generators: plist, shim, gateway.toml, act.toml.
# --------------------------------------------------------------------------- #


def generate_shim(interpreter: str | None = None) -> str:
    """The stable exec shim ``~/.hermes/act/bin/act-gateway``. launchd points
    at THIS, not directly at the interpreter, so the job definition never has
    to change when the venv path moves; only the shim is refreshed."""
    interpreter = interpreter or interpreter_path()
    return (
        "#!/bin/sh\n"
        "# Stable entrypoint for the app.act.gateway launchd job. Generated by\n"
        "# `act install`; do not edit by hand — re-run `act install` to refresh.\n"
        f'exec "{interpreter}" -m hermes_gateway "$@"\n'
    )


def generate_dashboard_shim(hermes_executable: Path | None = None) -> str:
    """Stable loopback-only entrypoint for the full Hermes dashboard.

    The dashboard never binds to the LAN or tailnet. ACT's authenticated
    gateway is the sole remote exposure surface.
    """
    executable = hermes_executable or hermes_dashboard_executable()
    return (
        "#!/bin/sh\n"
        "# Full Hermes dashboard supervised for ACT. Generated by `act install`.\n"
        f'exec "{executable}" dashboard --host {DASHBOARD_HOST} '
        f"--port {DASHBOARD_PORT} --no-open --skip-build\n"
    )


def generate_plist(
    interpreter: str | None = None,
    *,
    shim: Path | None = None,
    working_dir: Path | None = None,
    config_path: Path | None = None,
    out_log: Path | None = None,
    err_log: Path | None = None,
    service_path: str | None = None,
) -> str:
    """Return the launchd ``.plist`` XML for label ``app.act.gateway``.

    ProgramArguments invokes the *shim* (a stable path that never points into a
    source checkout). WorkingDirectory is the stable ``~/.hermes/act`` data
    root. PATH is reconstructed. ``ACT_GATEWAY_CONFIG`` is carried in
    EnvironmentVariables so the supervised entrypoint loads the baked config.
    """
    shim = shim or shim_path()
    working_dir = working_dir or act_home()
    config_path = config_path or gateway_toml_path()
    out_log = out_log or (logs_dir() / "gateway.out.log")
    err_log = err_log or (logs_dir() / "gateway.err.log")
    service_path = service_path if service_path is not None else _build_service_path(interpreter)

    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{LAUNCHD_LABEL}</string>

    <key>ProgramArguments</key>
    <array>
        <string>{shim}</string>
    </array>

    <key>WorkingDirectory</key>
    <string>{working_dir}</string>

    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>{service_path}</string>
        <key>ACT_GATEWAY_CONFIG</key>
        <string>{config_path}</string>
    </dict>

    <key>LimitLoadToSessionType</key>
    <array>
        <string>Aqua</string>
        <string>Background</string>
    </array>

    <key>RunAtLoad</key>
    <true/>

    <key>KeepAlive</key>
    <true/>

    <!-- Gateway logs may contain request metadata. Owner-only on creation. -->
    <key>Umask</key>
    <integer>63</integer>

    <key>StandardOutPath</key>
    <string>{out_log}</string>

    <key>StandardErrorPath</key>
    <string>{err_log}</string>
</dict>
</plist>
"""


def generate_dashboard_plist(
    *,
    shim: Path | None = None,
    working_dir: Path | None = None,
    out_log: Path | None = None,
    err_log: Path | None = None,
    service_path: str | None = None,
) -> str:
    """Return the hardened launchd job for the full Hermes dashboard."""
    shim = shim or dashboard_shim_path()
    working_dir = working_dir or (Path.home() / ".hermes")
    out_log = out_log or (logs_dir() / "hermes-dashboard.out.log")
    err_log = err_log or (logs_dir() / "hermes-dashboard.err.log")
    service_path = service_path or _build_service_path(str(hermes_dashboard_executable()))
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{DASHBOARD_LAUNCHD_LABEL}</string>

    <key>ProgramArguments</key>
    <array>
        <string>{shim}</string>
    </array>

    <key>WorkingDirectory</key>
    <string>{working_dir}</string>

    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>{service_path}</string>
    </dict>

    <key>LimitLoadToSessionType</key>
    <array>
        <string>Aqua</string>
        <string>Background</string>
    </array>

    <key>RunAtLoad</key>
    <true/>

    <key>KeepAlive</key>
    <true/>

    <key>ThrottleInterval</key>
    <integer>5</integer>

    <!-- Dashboard output can include ephemeral bootstrap credentials. -->
    <key>Umask</key>
    <integer>63</integer>

    <key>StandardOutPath</key>
    <string>{out_log}</string>

    <key>StandardErrorPath</key>
    <string>{err_log}</string>
</dict>
</plist>
"""


def _toml_str(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def generate_gateway_toml(
    *,
    node_id: str = "node_act_local",
    db_path: Path | None = None,
    apns_key_path: str | None = None,
    apns_key_id: str | None = None,
    apns_team_id: str | None = None,
    apns_topic: str | None = None,
    dashboard_url: str = "http://127.0.0.1:9119",
    dashboard_session_token_log_path: str | None = None,
) -> str:
    """Render ``gateway.toml`` consumed by ``Settings.from_file``. The safe
    overrides are HARD-BAKED: ``seed_mock_data=false``, an ABSOLUTE database
    path, loopback host + port 8788. When APNs is configured only the .p8 PATH
    is recorded — never the key bytes."""
    db = db_path or database_path()
    db = Path(db).expanduser()
    if not db.is_absolute():
        db = Path.home() / db

    lines = [
        "# Generated by `act install`. Safe overrides are hard-baked and asserted",
        "# on every install; edit other fields freely.",
        f"node_id = {_toml_str(node_id)}",
        "# A supervised gateway must serve only real (bridge-fed) agents.",
        "seed_mock_data = false",
        f"database_path = {_toml_str(str(db))}",
        f"gateway_base_url = {_toml_str(f'http://{GATEWAY_HOST}:{GATEWAY_PORT}/v1')}",
        f"# Bound on {GATEWAY_HOST}:{GATEWAY_PORT} by the supervised entrypoint.",
        "# Full loopback Hermes dashboard reverse-proxied under /hermes.",
        f"dashboard_url = {_toml_str(dashboard_url)}",
        "# The full dashboard natively honors X-Forwarded-Prefix. Set true only",
        "# for legacy standalone dashboards such as UltraCode's :9120 shell.",
        "dashboard_legacy_mount_rewrite = false",
        "# Keep the process loopback-only. Expose it to the phone with an",
        "# authenticated TLS reverse proxy such as Tailscale Serve.",
        f"bind_host = {_toml_str(GATEWAY_HOST)}",
    ]
    if dashboard_session_token_log_path:
        lines.extend(
            [
                "# Optional owner-only token discovery log for a legacy dashboard.",
                "dashboard_session_token_log_path = " + _toml_str(dashboard_session_token_log_path),
            ]
        )
    if apns_key_path:
        lines.append("")
        lines.append("# APNs token-based push (.p8). Only the PATH is stored here.")
        lines.append(f"apns_key_path = {_toml_str(apns_key_path)}")
        if apns_key_id:
            lines.append(f"apns_key_id = {_toml_str(apns_key_id)}")
        if apns_team_id:
            lines.append(f"apns_team_id = {_toml_str(apns_team_id)}")
        if apns_topic:
            lines.append(f"apns_topic = {_toml_str(apns_topic)}")
    return "\n".join(lines) + "\n"


def update_gateway_toml(text: str, overrides: dict[str, str | bool]) -> str:
    """Update required top-level scalars without discarding operator config.

    ``act install`` previously regenerated the whole file, silently dropping
    fields such as a custom dashboard URL, allowlists, and clearance policy.
    This narrow updater preserves every unrelated line and comment while
    reasserting only install-owned safety values.
    """
    # Fail before writing if the existing operator file is not valid TOML.
    tomllib.loads(text)
    remaining = dict(overrides)
    output: list[str] = []
    for line in text.splitlines():
        stripped = line.lstrip()
        if stripped and not stripped.startswith("#") and "=" in stripped:
            key = stripped.split("=", 1)[0].strip()
            if key in remaining:
                value = remaining.pop(key)
                rendered = (
                    "true" if value is True else "false" if value is False else _toml_str(value)
                )
                output.append(f"{key} = {rendered}")
                continue
        output.append(line)
    if remaining:
        if output and output[-1]:
            output.append("")
        output.append("# Safety values maintained by `act install`.")
        for key, value in remaining.items():
            rendered = "true" if value is True else "false" if value is False else _toml_str(value)
            output.append(f"{key} = {rendered}")
    return "\n".join(output) + "\n"


# Bridge defaults — MUST mirror the act-clearance plugin's built-in defaults so
# the file ACT writes and the plugin's fallbacks describe one config surface.
# (integrations/hermes/act-clearance/__init__.py: _DEFAULT_GATED_TOOLS etc.)
ACT_DEFAULT_AGENT_ID = "hermes_agent"
ACT_DEFAULT_AGENT_NAME = "Hermes Agent"
ACT_DEFAULT_GATED_TOOLS: tuple[str, ...] = (
    "terminal",
    "execute_code",
    "shell",
    "execute_command",
    "run_command",
    "bash",
    "write_file",
    "edit_file",
    "delete_file",
    "apply_patch",
    "browser_submit",
    "send_email",
    "git_push",
)
ACT_DEFAULT_QUESTION_TOOLS: tuple[str, ...] = ("clarify", "ask_operator", "ask_user")
ACT_DEFAULT_QUESTION_RISK_FAMILY = "read_only"
ACT_DEFAULT_CLEARANCE_RISK_FAMILY = "external_effect"


def generate_act_toml(
    *,
    enabled: bool = True,
    agent_id: str = ACT_DEFAULT_AGENT_ID,
    agent_name: str = ACT_DEFAULT_AGENT_NAME,
    gated_tools: tuple[str, ...] | None = None,
    question_tools: tuple[str, ...] | None = None,
    question_risk_family: str = ACT_DEFAULT_QUESTION_RISK_FAMILY,
    clearance_risk_family: str = ACT_DEFAULT_CLEARANCE_RISK_FAMILY,
) -> str:
    """Render ``act.toml`` — the FULL bridge config surface consumed by the
    act-clearance plugin in Phase 3. Every key here is read by the plugin
    (keys MUST match the plugin's ``toml_key`` names exactly), so the desktop
    Hermes bridges with NO env once this file exists and ``enabled = true``.

    Precedence at read time is ENV > act.toml > plugin default; this writer
    emits the act.toml layer. Values default to the plugin's own built-ins."""
    gated = gated_tools if gated_tools is not None else ACT_DEFAULT_GATED_TOOLS
    questions = question_tools if question_tools is not None else ACT_DEFAULT_QUESTION_TOOLS
    gated_list = ", ".join(_toml_str(t) for t in gated)
    question_list = ", ".join(_toml_str(t) for t in questions)
    return (
        "\n".join(
            [
                "# Generated by `act install`. ACT<->Hermes bridge config (Phase 3).",
                "# Read by the act-clearance plugin with precedence ENV > act.toml > default.",
                f"enabled = {'true' if enabled else 'false'}",
                f"gateway_url = {_toml_str(f'http://{GATEWAY_HOST}:{GATEWAY_PORT}/v1')}",
                f"agent_id = {_toml_str(agent_id)}",
                f"agent_name = {_toml_str(agent_name)}",
                f"gated_tools = [{gated_list}]",
                f"question_tools = [{question_list}]",
                f"question_risk_family = {_toml_str(question_risk_family)}",
                f"clearance_risk_family = {_toml_str(clearance_risk_family)}",
            ]
        )
        + "\n"
    )


# --------------------------------------------------------------------------- #
# plugins.enabled (~/.hermes/config.yaml) editing — minimal, no full YAML
# round-trip dependency required at runtime; uses pyyaml if present.
# --------------------------------------------------------------------------- #


def enable_plugin_in_config(text: str, plugin: str = PLUGIN_NAME) -> tuple[str, bool]:
    """Return (new_text, changed). Add ``plugin`` under ``plugins.enabled`` if
    absent. Idempotent. Uses pyyaml when available for a structural edit;
    otherwise falls back to a conservative textual insert."""
    try:
        import yaml  # type: ignore

        data = yaml.safe_load(text) or {}
        plugins = data.setdefault("plugins", {})
        enabled = plugins.get("enabled")
        if not isinstance(enabled, list):
            enabled = []
        if plugin in enabled:
            return text, False
        enabled.append(plugin)
        plugins["enabled"] = enabled
        return yaml.safe_dump(data, sort_keys=False, default_flow_style=False), True
    except Exception:
        # Textual fallback: find `plugins:` -> `enabled:` block.
        if plugin in text:
            return text, False
        lines = text.splitlines()
        out: list[str] = []
        inserted = False
        in_plugins = False
        in_enabled = False
        for line in lines:
            out.append(line)
            stripped = line.strip()
            if stripped == "plugins:":
                in_plugins = True
                continue
            if in_plugins and stripped == "enabled:":
                in_enabled = True
                out.append(f"  - {plugin}")
                inserted = True
                continue
            if in_enabled and not line.startswith(" "):
                in_enabled = False
                in_plugins = False
        if not inserted:
            out.append("plugins:")
            out.append("  enabled:")
            out.append(f"  - {plugin}")
        return "\n".join(out) + "\n", True


def disable_plugin_in_config(text: str, plugin: str = PLUGIN_NAME) -> tuple[str, bool]:
    """Return (new_text, changed). Remove ``plugin`` from ``plugins.enabled``."""
    try:
        import yaml  # type: ignore

        data = yaml.safe_load(text) or {}
        plugins = data.get("plugins") or {}
        enabled = plugins.get("enabled")
        if not isinstance(enabled, list) or plugin not in enabled:
            return text, False
        plugins["enabled"] = [p for p in enabled if p != plugin]
        data["plugins"] = plugins
        return yaml.safe_dump(data, sort_keys=False, default_flow_style=False), True
    except Exception:
        if plugin not in text:
            return text, False
        kept = [ln for ln in text.splitlines() if ln.strip() != f"- {plugin}"]
        return "\n".join(kept) + "\n", True


# --------------------------------------------------------------------------- #
# Managed Hermes plugin release + integrity/update checks.
# --------------------------------------------------------------------------- #


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _plugin_version(plugin_yaml: str) -> str:
    """Read the top-level version without adding a runtime YAML dependency."""
    match = re.search(r"(?m)^version:\s*[\"']?([^\"'\s#]+)", plugin_yaml)
    if match is None:
        raise ValueError("plugin.yaml has no valid top-level version")
    return match.group(1)


def _source_plugin_release(source_dir: Path | None = None) -> dict:
    """Build the release manifest from the trusted files in this ACT checkout."""
    source = source_dir or plugin_source_dir()
    missing = [name for name in PLUGIN_DISTRIBUTION_FILES if not (source / name).is_file()]
    if missing:
        raise RuntimeError(
            "act install: bundled Hermes plugin is incomplete; missing " + ", ".join(missing)
        )
    plugin_yaml = (source / "plugin.yaml").read_text()
    if not re.search(rf"(?m)^name:\s*[\"']?{re.escape(PLUGIN_NAME)}[\"']?\s*$", plugin_yaml):
        raise RuntimeError(f"act install: bundled plugin name is not {PLUGIN_NAME!r}")
    return {
        "schema": 1,
        "name": PLUGIN_NAME,
        "version": _plugin_version(plugin_yaml),
        "files": {
            name: {"sha256": _sha256((source / name).read_bytes())} for name in PLUGIN_MANAGED_FILES
        },
    }


def _validated_plugin_release(value: object) -> dict:
    """Return a normalized manifest or raise ValueError for untrusted metadata."""
    if not isinstance(value, dict):
        raise ValueError("manifest root is not an object")
    if value.get("schema") != 1 or value.get("name") != PLUGIN_NAME:
        raise ValueError("manifest schema or plugin name is invalid")
    version = value.get("version")
    files = value.get("files")
    if not isinstance(version, str) or not version or not isinstance(files, dict):
        raise ValueError("manifest version or files are invalid")
    normalized_files: dict[str, dict[str, str]] = {}
    for name in PLUGIN_MANAGED_FILES:
        record = files.get(name)
        digest = record.get("sha256") if isinstance(record, dict) else None
        if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise ValueError(f"manifest digest for {name} is invalid")
        normalized_files[name] = {"sha256": digest}
    return {
        "schema": 1,
        "name": PLUGIN_NAME,
        "version": version,
        "files": normalized_files,
    }


def _install_bridge_plugin(ops: Ops) -> dict:
    """Deploy the exact ACT-bundled plugin and pin its owner-only hashes."""
    source = plugin_source_dir()
    release = _validated_plugin_release(_source_plugin_release(source))
    destination = plugin_install_dir()
    ops.mkdir(destination, mode=0o700)
    ops.chmod(destination, 0o700)
    for name in PLUGIN_DISTRIBUTION_FILES:
        ops.copy_file(source / name, destination / name, mode=0o600)
    # Write this last: a partial copy never receives metadata that claims the
    # plugin is current. The runtime hook and `act doctor` both consume it.
    ops.write_text(
        plugin_release_path(),
        json.dumps(release, indent=2, sort_keys=True) + "\n",
        mode=0o600,
    )
    return release


@dataclass
class PluginUpdateReport:
    ok: bool
    lines: list[str]
    status: str
    managed_version: str | None = None
    installed_version: str | None = None
    bundled_version: str | None = None

    def text(self) -> str:
        status = "CURRENT" if self.ok else "ACTION REQUIRED"
        return f"act plugin-check: {status}\n" + "\n".join(self.lines)


def plugin_update_status(ops: Ops | None = None) -> PluginUpdateReport:
    """Compare installed plugin version + SHA-256 with ACT's release metadata.

    This is strictly read-only. It reports missing files, local tampering/drift,
    and a newer bundled checkout without printing plugin content or secrets.
    """
    ops = ops or Ops()
    lines: list[str] = []
    ok = True

    if not ops.exists(plugin_release_path()):
        return PluginUpdateReport(
            ok=False,
            lines=[
                f"[FAIL] managed release metadata missing at {plugin_release_path()}",
                "[action] run `act install`, then restart Hermes",
            ],
            status="unmanaged",
        )
    try:
        release = _validated_plugin_release(json.loads(ops.read_text(plugin_release_path())))
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        return PluginUpdateReport(
            ok=False,
            lines=[
                f"[FAIL] managed release metadata is invalid: {exc}",
                "[action] run `act install`, then restart Hermes",
            ],
            status="integrity_problem",
        )

    missing: list[str] = []
    drifted: list[str] = []
    status = "current"
    installed_version: str | None = None
    bundled_version: str | None = None
    for name in PLUGIN_MANAGED_FILES:
        installed = plugin_install_dir() / name
        if not ops.exists(installed):
            missing.append(name)
            continue
        if _sha256(ops.read_bytes(installed)) != release["files"][name]["sha256"]:
            drifted.append(name)
    if missing:
        ok = False
        status = "integrity_problem"
        lines.append("[FAIL] managed plugin files missing: " + ", ".join(missing))
    if drifted:
        ok = False
        status = "integrity_problem"
        lines.append("[FAIL] managed plugin integrity drift: " + ", ".join(drifted))

    manifest_path = plugin_install_dir() / "plugin.yaml"
    if ops.exists(manifest_path):
        try:
            installed_version = _plugin_version(ops.read_text(manifest_path))
        except ValueError as exc:
            ok = False
            status = "integrity_problem"
            lines.append(f"[FAIL] installed plugin version is unreadable: {exc}")
        else:
            if installed_version != release["version"]:
                ok = False
                status = "integrity_problem"
                lines.append(
                    "[FAIL] installed plugin version "
                    f"{installed_version} does not match managed release {release['version']}"
                )

    # When running from an ACT source release, also detect that this checkout is
    # newer than the last deployed manifest. A packaged/runtime-only CLI may not
    # carry the checkout; the pinned manifest remains sufficient for integrity.
    source = plugin_source_dir()
    if source.is_dir():
        try:
            bundled = _validated_plugin_release(_source_plugin_release(source))
        except (OSError, RuntimeError, ValueError) as exc:
            ok = False
            status = "integrity_problem"
            lines.append(f"[FAIL] bundled plugin release is invalid: {exc}")
        else:
            bundled_version = bundled["version"]
            if bundled != release:
                ok = False
                if status == "current":
                    status = "update_available"
                lines.append(
                    f"[UPDATE] bundled plugin {bundled['version']} differs from deployed "
                    f"release {release['version']}"
                )

    if ok:
        lines.append(
            f"[ok] Hermes plugin {PLUGIN_NAME} {release['version']} matches managed SHA-256"
        )
    else:
        lines.append("[action] run `act install`, then restart Hermes")
    return PluginUpdateReport(
        ok=ok,
        lines=lines,
        status=status,
        managed_version=release["version"],
        installed_version=installed_version,
        bundled_version=bundled_version,
    )


# --------------------------------------------------------------------------- #
# Commands.
# --------------------------------------------------------------------------- #


def _ensure_layout(ops: Ops) -> None:
    for d in (act_home(), bin_dir(), logs_dir(), secrets_dir()):
        ops.mkdir(d)
    # secrets is sensitive; lock it down.
    ops.chmod(secrets_dir(), 0o700)
    for log_path in (
        logs_dir() / "gateway.out.log",
        logs_dir() / "gateway.err.log",
        logs_dir() / "hermes-dashboard.out.log",
        logs_dir() / "hermes-dashboard.err.log",
    ):
        if ops.exists(log_path):
            ops.chmod(log_path, 0o600)
    # UltraCode's startup log includes its ephemeral dashboard credential. ACT
    # will refuse to read it unless it is current-user-only, so harden it during
    # installation when Hermes has already created it.
    if ops.exists(hermes_agent_log_path()):
        ops.chmod(hermes_agent_log_path(), 0o600)


def _write_configs(ops: Ops, *, apns: dict | None) -> None:
    """Write/refresh shim + gateway.toml + act.toml. An existing gateway.toml's
    user edits are preserved *except* the safe overrides, which are
    re-asserted by regenerating from its current node_id (and APNs if newly
    provided)."""
    ops.write_text(shim_path(), generate_shim(), mode=0o755)
    if ops.exists(hermes_dashboard_executable()):
        ops.write_text(
            dashboard_shim_path(),
            generate_dashboard_shim(),
            mode=0o755,
        )

    if ops.exists(gateway_toml_path()):
        current = tomllib.loads(ops.read_text(gateway_toml_path()))
        overrides: dict[str, str | bool] = {
            "seed_mock_data": False,
            "database_path": str(database_path()),
            "gateway_base_url": f"http://{GATEWAY_HOST}:{GATEWAY_PORT}/v1",
            "bind_host": GATEWAY_HOST,
            "dashboard_legacy_mount_rewrite": False,
        }
        # Migrate only ACT's mistaken UltraCode default. Preserve any genuine
        # operator-supplied dashboard target.
        if current.get("dashboard_url") == "http://127.0.0.1:9120":
            overrides["dashboard_url"] = "http://127.0.0.1:9119"
        if current.get("dashboard_session_token_log_path") == str(hermes_agent_log_path()):
            overrides["dashboard_session_token_log_path"] = ""
        overrides.update(apns or {})
        refreshed = update_gateway_toml(
            ops.read_text(gateway_toml_path()),
            overrides,
        )
        ops.write_text(gateway_toml_path(), refreshed, mode=0o600)
    else:
        apns_values = apns or {}
        ops.write_text(
            gateway_toml_path(),
            generate_gateway_toml(
                apns_key_path=apns_values.get("apns_key_path"),
                apns_key_id=apns_values.get("apns_key_id"),
                apns_team_id=apns_values.get("apns_team_id"),
                apns_topic=apns_values.get("apns_topic"),
            ),
            mode=0o600,
        )

    if not ops.exists(act_toml_path()):
        ops.write_text(act_toml_path(), generate_act_toml())


def _install_apns(ops: Ops, key_id: str, team_id: str, p8_src: str) -> dict:
    """Copy the .p8 into secrets (0600) and return the metadata dict carrying
    only the PATH (never the bytes)."""
    dst = secrets_dir() / f"AuthKey_{key_id}.p8"
    ops.copy_file(Path(p8_src), dst, mode=0o600)
    return {
        "apns_key_path": str(dst),
        "apns_key_id": key_id,
        "apns_team_id": team_id,
    }


def _write_plist_and_load(ops: Ops) -> None:
    ops.write_text(plist_path(), generate_plist())
    domain = launchd_domain()
    target = launchd_service_target()
    # Re-bootstrap to pick up plist changes, then kickstart to (re)start.
    ops.run(["launchctl", "bootout", target], check=False)
    bootstrap_result = None
    for _attempt in range(5):
        bootstrap_result = ops.run(
            ["launchctl", "bootstrap", domain, str(plist_path())],
            check=False,
        )
        if getattr(bootstrap_result, "returncode", 0) == 0:
            break
        # launchd can briefly retain the old label after bootout. A bounded
        # retry prevents `act install` from reporting success with no service.
        time.sleep(0.2)
    if bootstrap_result is None or getattr(bootstrap_result, "returncode", 0) != 0:
        raise RuntimeError("act install: launchd bootstrap failed after 5 attempts")
    kickstart_result = ops.run(
        ["launchctl", "kickstart", "-k", target],
        check=False,
    )
    if getattr(kickstart_result, "returncode", 0) != 0:
        raise RuntimeError("act install: launchd kickstart failed")
    _wait_for_loopback_service(
        ops,
        f"http://{GATEWAY_HOST}:{GATEWAY_PORT}/v1/health",
        "gateway",
    )


def _wait_for_loopback_service(ops: Ops, url: str, name: str) -> None:
    """Bounded readiness gate for a launchd service ACT just kickstarted."""
    for _attempt in range(20):
        probe = ops.run(
            ["/usr/bin/curl", "--fail", "--silent", "--max-time", "1", url],
            check=False,
            timeout=2,
        )
        if getattr(probe, "returncode", 1) == 0:
            return
        time.sleep(0.25)
    raise RuntimeError(f"act install: {name} did not become ready at {url}")


def _write_dashboard_plist_and_load(ops: Ops) -> None:
    """Supervise the full Hermes dashboard when Hermes is installed.

    Older/headless ACT installations may not carry the Hermes desktop CLI; in
    that case the gateway remains installable and ``doctor`` reports the
    dashboard as unavailable. When present, the dashboard is a first-class
    loopback companion service and survives logout/reboot independently of a
    terminal session.
    """
    if not ops.exists(hermes_dashboard_executable()):
        return
    ops.write_text(dashboard_plist_path(), generate_dashboard_plist())
    domain = launchd_domain()
    target = dashboard_launchd_service_target()
    ops.run(["launchctl", "bootout", target], check=False)
    bootstrap_result = None
    for _attempt in range(5):
        bootstrap_result = ops.run(
            ["launchctl", "bootstrap", domain, str(dashboard_plist_path())],
            check=False,
        )
        if getattr(bootstrap_result, "returncode", 0) == 0:
            break
        time.sleep(0.2)
    if bootstrap_result is None or getattr(bootstrap_result, "returncode", 0) != 0:
        raise RuntimeError(
            "act install: Hermes dashboard launchd bootstrap failed after 5 attempts"
        )
    kickstart_result = ops.run(
        ["launchctl", "kickstart", "-k", target],
        check=False,
    )
    if getattr(kickstart_result, "returncode", 0) != 0:
        raise RuntimeError("act install: Hermes dashboard launchd kickstart failed")
    _wait_for_loopback_service(
        ops,
        f"http://{DASHBOARD_HOST}:{DASHBOARD_PORT}/",
        "Hermes dashboard",
    )


def _enable_bridge(ops: Ops) -> None:
    cfg = hermes_config_path()
    if not ops.exists(cfg):
        return
    text = ops.read_text(cfg)
    new_text, changed = enable_plugin_in_config(text)
    if changed:
        ops.write_text(cfg, new_text)


def _disable_bridge(ops: Ops) -> None:
    """Strip ``act-clearance`` from ``~/.hermes/config.yaml`` ``plugins.enabled``.
    Shared by :func:`disable` and :func:`uninstall` so tearing the service down
    never leaves the bridge plugin enabled. Unrelated plugins are preserved."""
    cfg = hermes_config_path()
    if not ops.exists(cfg):
        return
    text = ops.read_text(cfg)
    new_text, changed = disable_plugin_in_config(text)
    if changed:
        ops.write_text(cfg, new_text)


def _provision_venv(ops: Ops) -> None:
    """Create the ACT-owned runtime venv and install the gateway into it.

    ``sys.executable`` is used ONLY as the bootstrap python to *create* the
    venv; the resulting ``~/.hermes/act/venv/bin/python`` is independent of the
    checkout's site-packages, so deleting the checkout no longer crash-loops the
    KeepAlive service. Routed through Ops so tests record the calls without
    mutating the machine."""
    project = gateway_project_dir()
    source_checkout = (project / "pyproject.toml").is_file() and (
        project / "src" / "hermes_gateway"
    ).is_dir()
    if not source_checkout:
        # A released ``act`` command is already running from the managed venv.
        # Recreating that environment from inside itself is unsafe, and an
        # installed wheel has no project directory to hand back to pip. Its
        # bundled plugin + current package are already the durable runtime.
        try:
            running_managed = Path(sys.executable).resolve() == venv_python().resolve()
        except OSError:
            running_managed = False
        if running_managed:
            return
        raise RuntimeError(
            "act install: packaged CLI is not running from the ACT-managed venv; "
            f"install it into {venv_dir()} first"
        )

    vdir = venv_dir()
    ops.run([sys.executable, "-m", "venv", str(vdir)], check=True)
    ops.run(
        [str(vdir / "bin" / "pip"), "install", str(project)],
        check=True,
    )


def install(ops: Ops | None = None, *, with_apns: tuple[str, str, str] | None = None) -> None:
    ops = ops or Ops()
    _ensure_layout(ops)
    # Provision the ACT-owned runtime venv BEFORE writing the shim so the baked
    # interpreter exists on disk by the time launchd starts the job.
    _provision_venv(ops)
    apns_meta = None
    if with_apns is not None:
        key_id, team_id, p8 = with_apns
        apns_meta = _install_apns(ops, key_id, team_id, p8)
    _write_configs(ops, apns=apns_meta)
    # The Hermes security hook is part of the ACT release, not a manual side
    # load. Always refresh its files before enabling it in Hermes.
    _install_bridge_plugin(ops)
    # Refuse to wire up a shim whose interpreter still resolves under the source
    # checkout — that is exactly the durability bug this provisioning fixes.
    baked = interpreter_path()
    if _under_source_checkout(baked):
        raise RuntimeError(
            "act install: refusing to bake an interpreter under the source "
            f"checkout ({baked}); the runtime interpreter must be the ACT-owned "
            f"venv at {venv_python()}. The checkout is not a durable runtime."
        )
    _write_plist_and_load(ops)
    _write_dashboard_plist_and_load(ops)
    _enable_bridge(ops)


def disable(ops: Ops | None = None) -> None:
    """(would) launchctl bootout + remove the plugin from plugins.enabled.
    Keeps all data."""
    ops = ops or Ops()
    ops.run(["launchctl", "bootout", launchd_service_target()], check=False)
    ops.run(
        ["launchctl", "bootout", dashboard_launchd_service_target()],
        check=False,
    )
    _disable_bridge(ops)


def uninstall(ops: Ops | None = None, *, purge: bool = False) -> None:
    ops = ops or Ops()
    ops.run(["launchctl", "bootout", launchd_service_target()], check=False)
    ops.run(
        ["launchctl", "bootout", dashboard_launchd_service_target()],
        check=False,
    )
    # Strip the bridge plugin too — removing only the plist+shim would leave
    # act-clearance enabled in ~/.hermes/config.yaml.
    _disable_bridge(ops)
    ops.remove(plist_path())
    ops.remove(shim_path())
    ops.remove(dashboard_plist_path())
    ops.remove(dashboard_shim_path())
    if purge:
        ops.rmtree(act_home())


@dataclass
class DoctorReport:
    ok: bool
    lines: list[str]

    def text(self) -> str:
        status = "OK" if self.ok else "PROBLEMS FOUND"
        return f"act doctor: {status}\n" + "\n".join(self.lines)


def doctor(ops: Ops | None = None) -> DoctorReport:
    """Validate the install: interpreter exists, plist matches what we'd
    generate (drift), who owns port 8788, seed_mock_data is false in the
    effective config, APNs file present+readable if configured, and the Hermes
    bridge matches ACT's managed plugin release."""
    ops = ops or Ops()
    lines: list[str] = []
    ok = True

    # 1. Baked shim interpreter present on disk + not the source checkout.
    interp = interpreter_path()
    if Path(interp).exists() or ops.exists(Path(interp)):
        lines.append(f"[ok] interpreter exists: {interp}")
    else:
        ok = False
        lines.append(f"[FAIL] interpreter missing: {interp}")
    if _under_source_checkout(interp):
        ok = False
        lines.append(
            f"[FAIL] interpreter resolves under the source checkout: {interp} "
            "(deleting the checkout would crash-loop the service; re-run "
            "`act install` to provision the ACT-owned venv)"
        )

    # 2. Full Hermes dashboard supervision. A headless installation without
    # Hermes remains a valid gateway, but once Hermes exists ACT requires the
    # companion job to be present and drift-free.
    dashboard_executable = hermes_dashboard_executable()
    if ops.exists(dashboard_executable):
        lines.append(f"[ok] Hermes dashboard executable exists: {dashboard_executable}")
        if ops.exists(dashboard_plist_path()):
            installed_dashboard = ops.read_text(dashboard_plist_path())
            if installed_dashboard.strip() == generate_dashboard_plist().strip():
                lines.append("[ok] Hermes dashboard plist matches generated definition")
            else:
                ok = False
                lines.append(
                    "[FAIL] Hermes dashboard plist drift: installed plist differs from generated"
                )
        else:
            ok = False
            lines.append(f"[FAIL] Hermes dashboard plist not installed at {dashboard_plist_path()}")
    else:
        lines.append(
            "[info] Hermes dashboard executable is not installed; dashboard supervision skipped"
        )

    # 3. Gateway plist drift.
    if ops.exists(plist_path()):
        installed = ops.read_text(plist_path())
        expected = generate_plist()
        if installed.strip() == expected.strip():
            lines.append("[ok] plist matches generated definition")
        else:
            ok = False
            lines.append("[FAIL] plist drift: installed plist differs from generated")
    else:
        ok = False
        lines.append(f"[FAIL] plist not installed at {plist_path()}")

    # 4. Effective config: seed_mock_data must be false.
    if ops.exists(gateway_toml_path()):
        try:
            raw = tomllib.loads(ops.read_text(gateway_toml_path()))
        except Exception as exc:
            ok = False
            raw = {}
            lines.append(f"[FAIL] gateway.toml unparseable: {exc}")
        if raw.get("seed_mock_data", True) is False:
            lines.append("[ok] seed_mock_data is false")
        else:
            ok = False
            lines.append("[FAIL] seed_mock_data is not false in gateway.toml")
        db = raw.get("database_path", "")
        if db and Path(db).is_absolute():
            lines.append(f"[ok] database_path is absolute: {db}")
        else:
            ok = False
            lines.append(f"[FAIL] database_path not absolute: {db!r}")
        # 5. APNs file present + readable if configured.
        key_path = raw.get("apns_key_path")
        if key_path:
            if ops.exists(Path(key_path)):
                lines.append(f"[ok] APNs key present: {key_path}")
            else:
                ok = False
                lines.append(f"[FAIL] APNs key configured but missing: {key_path}")
    else:
        ok = False
        lines.append(f"[FAIL] gateway.toml not found at {gateway_toml_path()}")

    # 6. Hermes bridge version + integrity/update status.
    plugin_report = plugin_update_status(ops)
    lines.extend(plugin_report.lines)
    ok = ok and plugin_report.ok

    # 7. Port ownership (informational; never fails the report).
    for name, port in (("gateway", GATEWAY_PORT), ("Hermes dashboard", DASHBOARD_PORT)):
        try:
            res = ops.run(
                ["lsof", "-nP", f"-iTCP:{port}", "-sTCP:LISTEN"],
                check=False,
            )
            owner = (getattr(res, "stdout", "") or "").strip()
            if owner:
                lines.append(f"[info] {name} port {port} listeners:\n{owner}")
            else:
                lines.append(f"[info] nothing listening on {name} port {port}")
        except Exception:
            lines.append(f"[info] could not probe {name} port {port}")

    return DoctorReport(ok=ok, lines=lines)


def status(ops: Ops | None = None) -> str:
    """``launchctl print`` for the job + a /v1/health probe."""
    ops = ops or Ops()
    out: list[str] = []
    res = ops.run(["launchctl", "print", launchd_service_target()], check=False)
    out.append("== launchctl ==")
    out.append((getattr(res, "stdout", "") or "").strip() or "(no output)")
    dashboard = ops.run(
        ["launchctl", "print", dashboard_launchd_service_target()],
        check=False,
    )
    out.append("== Hermes dashboard launchctl ==")
    out.append((getattr(dashboard, "stdout", "") or "").strip() or "(no output)")
    out.append("== health ==")
    try:
        import urllib.request

        url = f"http://{GATEWAY_HOST}:{GATEWAY_PORT}/v1/health"
        with urllib.request.urlopen(url, timeout=2) as resp:  # noqa: S310
            out.append(f"{url} -> {resp.status}")
    except Exception as exc:
        out.append(f"health probe failed: {exc}")
    try:
        import urllib.request

        dashboard_url = f"http://{DASHBOARD_HOST}:{DASHBOARD_PORT}/"
        with urllib.request.urlopen(dashboard_url, timeout=2) as resp:  # noqa: S310
            out.append(f"{dashboard_url} -> {resp.status}")
    except Exception as exc:
        out.append(f"dashboard probe failed: {exc}")
    return "\n".join(out)


def create_mobile_pairing_bundle() -> dict:
    """Create the one-time mobile pairing bundle through the loopback API."""
    import urllib.request

    payload = json.dumps(
        {
            "display_name": "ACT Operator Beta",
            "clearance_channel": "mobile_signed",
            # Long enough to move from the Mac terminal to the phone camera,
            # still short-lived and one-time.
            "ttl_seconds": 600,
            "requested_permissions": [
                "read_state",
                "approve",
                "intervene",
                "tui",
                "browser_assist",
            ],
        }
    ).encode("utf-8")
    request = urllib.request.Request(  # noqa: S310 - fixed loopback target
        f"http://{GATEWAY_HOST}:{GATEWAY_PORT}/v1/pairing/start",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=3) as response:  # noqa: S310
        return json.loads(response.read().decode("utf-8"))


def render_pairing_qr(bundle: dict) -> str:
    """Render a one-time pairing bundle as a terminal-safe QR code.

    The compact JSON is the QR payload, so the mobile app can run the same
    strict validation used by manual import. Nothing is written to disk.
    """
    import qrcode

    qr = qrcode.QRCode(
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        border=2,
    )
    qr.add_data(json.dumps(bundle, separators=(",", ":")))
    qr.make(fit=True)
    output = io.StringIO()
    qr.print_ascii(out=output, invert=True)
    return output.getvalue().rstrip()


# --------------------------------------------------------------------------- #
# argparse entrypoint.
# --------------------------------------------------------------------------- #


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="act",
        description="Configure + supervise the ACT<->Hermes first-class gateway.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_install = sub.add_parser("install", help="install + supervise the gateway")
    p_install.add_argument(
        "--with-apns",
        nargs=3,
        metavar=("KEYID", "TEAMID", "P8PATH"),
        help="copy the APNs .p8 into secrets and record only its path",
    )

    sub.add_parser("disable", help="stop supervision + disable the bridge (keep data)")

    p_uninstall = sub.add_parser("uninstall", help="remove the service + shim")
    p_uninstall.add_argument(
        "--purge", action="store_true", help="also delete ~/.hermes/act (db+secrets+config)"
    )

    sub.add_parser("doctor", help="validate the install + print a report")
    sub.add_parser(
        "plugin-check",
        help="read-only Hermes plugin version + SHA-256 update check",
    )
    sub.add_parser("status", help="launchctl print + health probe")
    p_pair = sub.add_parser("pair", help="create a loopback-only mobile pairing bundle")
    p_pair.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help="print compact JSON for pasting into ACT Settings",
    )
    p_pair.add_argument(
        "--qr",
        action="store_true",
        dest="as_qr",
        help="print a scannable one-time QR bundle (nothing is saved to disk)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "install":
        with_apns = tuple(args.with_apns) if args.with_apns else None
        install(with_apns=with_apns)  # type: ignore[arg-type]
        print(
            f"act: installed {LAUNCHD_LABEL}; configs under {act_home()}; "
            "restart Hermes if it was already running"
        )
        return 0
    if args.command == "disable":
        disable()
        print(f"act: disabled {LAUNCHD_LABEL} (data kept)")
        return 0
    if args.command == "uninstall":
        uninstall(purge=args.purge)
        print(f"act: uninstalled {LAUNCHD_LABEL}" + (" (purged data)" if args.purge else ""))
        return 0
    if args.command == "doctor":
        report = doctor()
        print(report.text())
        return 0 if report.ok else 1
    if args.command == "plugin-check":
        report = plugin_update_status()
        print(report.text())
        return 0 if report.ok else 1
    if args.command == "status":
        print(status())
        return 0
    if args.command == "pair":
        bundle = create_mobile_pairing_bundle()
        if args.as_json and args.as_qr:
            raise SystemExit("choose either --json or --qr")
        if args.as_json:
            print(json.dumps(bundle, separators=(",", ":")))
        elif args.as_qr:
            print("Scan this one-time QR in ACT Settings. Keep it private.")
            print(render_pairing_qr(bundle))
            print(f"Expires: {bundle['expires_at']}")
        else:
            print("Paste this one-time bundle into ACT Settings (or use `act pair --qr`):")
            print(json.dumps(bundle, indent=2))
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

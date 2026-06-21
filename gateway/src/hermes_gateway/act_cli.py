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
import os
import shutil
import subprocess
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

# --------------------------------------------------------------------------- #
# Stable, never-the-checkout layout. All paths anchor at $HOME so the launchd
# job + singleton lock are identical regardless of where `act` is invoked from.
# --------------------------------------------------------------------------- #

LAUNCHD_LABEL = "app.act.gateway"
GATEWAY_HOST = "127.0.0.1"
GATEWAY_PORT = 8788
PLUGIN_NAME = "act-clearance"
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


def gateway_toml_path() -> Path:
    return act_home() / "gateway.toml"


def act_toml_path() -> Path:
    return act_home() / "act.toml"


def database_path() -> Path:
    return act_home() / "gateway.sqlite3"


def plist_path() -> Path:
    return Path.home() / "Library" / "LaunchAgents" / f"{LAUNCHD_LABEL}.plist"


def hermes_config_path() -> Path:
    return Path.home() / ".hermes" / "config.yaml"


def launchd_domain() -> str:
    """User (gui) domain target, e.g. ``gui/501``."""
    return f"gui/{os.getuid()}"


def launchd_service_target() -> str:
    return f"{launchd_domain()}/{LAUNCHD_LABEL}"


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
        # Record the destination as a written file (bytes are not the payload
        # that matters for these tests — the mode + path are).
        self.files[str(dst)] = f"<copied from {src}>"
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
    """Reconstruct a sane PATH for the launchd job. launchd provides only
    ``/usr/bin:/bin:/usr/sbin:/sbin`` — missing Homebrew, the venv, etc. We
    prepend the interpreter's own bin dir, then layer the user's current PATH,
    then guarantee the minimal system dirs, de-duplicated and order-preserving.
    """
    priority: list[str] = []
    interp_bin = str(Path(interp or interpreter_path()).parent)
    priority.append(interp_bin)
    current = [p for p in os.environ.get("PATH", "").split(":") if p]
    minimal = LAUNCHD_MINIMAL_PATH.split(":")
    return ":".join(dict.fromkeys(priority + current + minimal))


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
    service_path = (
        service_path if service_path is not None else _build_service_path(interpreter)
    )

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
    dashboard_url: str = "http://127.0.0.1:9120",
) -> str:
    """Render ``gateway.toml`` consumed by ``Settings.from_file``. The safe
    overrides are HARD-BAKED: ``seed_mock_data=false``, an ABSOLUTE database
    path, loopback host + port 8788. When APNs is configured only the .p8 PATH
    is recorded — never the key bytes."""
    db = (db_path or database_path())
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
        f'# Bound on {GATEWAY_HOST}:{GATEWAY_PORT} by the supervised entrypoint.',
        "# Loopback Hermes dashboard reverse-proxied under /hermes (gateway-gated).",
        f"dashboard_url = {_toml_str(dashboard_url)}",
    ]
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
    return "\n".join(
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
    ) + "\n"


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
# Commands.
# --------------------------------------------------------------------------- #


def _ensure_layout(ops: Ops) -> None:
    for d in (act_home(), bin_dir(), logs_dir(), secrets_dir()):
        ops.mkdir(d)
    # secrets is sensitive; lock it down.
    ops.chmod(secrets_dir(), 0o700)


def _write_configs(ops: Ops, *, apns: dict | None) -> None:
    """Write/refresh shim + gateway.toml + act.toml. An existing gateway.toml's
    user edits are preserved *except* the safe overrides, which are
    re-asserted by regenerating from its current node_id (and APNs if newly
    provided)."""
    ops.write_text(shim_path(), generate_shim(), mode=0o755)

    node_id = "node_act_local"
    existing_apns: dict = {}
    if ops.exists(gateway_toml_path()):
        try:
            raw = tomllib.loads(ops.read_text(gateway_toml_path()))
            node_id = raw.get("node_id", node_id)
            for k in ("apns_key_path", "apns_key_id", "apns_team_id", "apns_topic"):
                if raw.get(k):
                    existing_apns[k] = raw[k]
        except Exception:
            pass

    merged_apns = {**existing_apns, **(apns or {})}
    ops.write_text(
        gateway_toml_path(),
        generate_gateway_toml(
            node_id=node_id,
            apns_key_path=merged_apns.get("apns_key_path"),
            apns_key_id=merged_apns.get("apns_key_id"),
            apns_team_id=merged_apns.get("apns_team_id"),
            apns_topic=merged_apns.get("apns_topic"),
        ),
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
    ops.run(["launchctl", "bootstrap", domain, str(plist_path())], check=False)
    ops.run(["launchctl", "kickstart", "-k", target], check=False)


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
    vdir = venv_dir()
    ops.run([sys.executable, "-m", "venv", str(vdir)])
    ops.run([str(vdir / "bin" / "pip"), "install", str(gateway_project_dir())])


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
    _enable_bridge(ops)


def disable(ops: Ops | None = None) -> None:
    """(would) launchctl bootout + remove the plugin from plugins.enabled.
    Keeps all data."""
    ops = ops or Ops()
    ops.run(["launchctl", "bootout", launchd_service_target()], check=False)
    _disable_bridge(ops)


def uninstall(ops: Ops | None = None, *, purge: bool = False) -> None:
    ops = ops or Ops()
    ops.run(["launchctl", "bootout", launchd_service_target()], check=False)
    # Strip the bridge plugin too — removing only the plist+shim would leave
    # act-clearance enabled in ~/.hermes/config.yaml.
    _disable_bridge(ops)
    ops.remove(plist_path())
    ops.remove(shim_path())
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
    effective config, APNs file present+readable if configured."""
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

    # 2. Plist drift.
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

    # 3. Effective config: seed_mock_data must be false.
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
        # 4. APNs file present + readable if configured.
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

    # 5. Port ownership (informational; never fails the report).
    try:
        res = ops.run(["lsof", "-nP", f"-iTCP:{GATEWAY_PORT}", "-sTCP:LISTEN"], check=False)
        owner = (getattr(res, "stdout", "") or "").strip()
        if owner:
            lines.append(f"[info] port {GATEWAY_PORT} listeners:\n{owner}")
        else:
            lines.append(f"[info] nothing listening on port {GATEWAY_PORT}")
    except Exception:
        lines.append(f"[info] could not probe port {GATEWAY_PORT}")

    return DoctorReport(ok=ok, lines=lines)


def status(ops: Ops | None = None) -> str:
    """``launchctl print`` for the job + a /v1/health probe."""
    ops = ops or Ops()
    out: list[str] = []
    res = ops.run(["launchctl", "print", launchd_service_target()], check=False)
    out.append("== launchctl ==")
    out.append((getattr(res, "stdout", "") or "").strip() or "(no output)")
    out.append("== health ==")
    try:
        import urllib.request

        url = f"http://{GATEWAY_HOST}:{GATEWAY_PORT}/v1/health"
        with urllib.request.urlopen(url, timeout=2) as resp:  # noqa: S310
            out.append(f"{url} -> {resp.status}")
    except Exception as exc:
        out.append(f"health probe failed: {exc}")
    return "\n".join(out)


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
    sub.add_parser("status", help="launchctl print + health probe")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "install":
        with_apns = tuple(args.with_apns) if args.with_apns else None
        install(with_apns=with_apns)  # type: ignore[arg-type]
        print(f"act: installed {LAUNCHD_LABEL}; configs under {act_home()}")
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
    if args.command == "status":
        print(status())
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

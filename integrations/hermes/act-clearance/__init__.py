"""act-control — Hermes <-> Agentic Control Tower (ACT) control-plane bridge.

An in-process Hermes plugin that makes the operator's phone a first-class control
surface for the real Hermes agent. Two planes:

* MONITORING (Hermes -> ACT, push): session/tool lifecycle hooks upsert the real
  agent / session / mission into the gateway via hermes-local POST /v1/runtime/context
  so the app's dashboard / agents / task-visibility show the REAL agent live.
* CONTROL (ACT -> Hermes):
  - Clearance gate: risky tools block via pre_tool_call until the operator approves
    on the phone (fail-closed).
  - Interactive questions: designated "ask" tools raise an ACT TUA request and block
    until the operator answers on the phone; the answer is returned to the agent.

Safety / sandboxing (unchanged): opt-in via Hermes ``plugins.enabled`` AND a hard env
gate ``ACT_CLEARANCE_ENABLED`` (default OFF) — every hook is a no-op unless enabled, so
installing the files cannot disrupt a live agent. Pushes are hermes-local (loopback);
phone reads/decisions stay device-signed. Redaction: tool name + arg KEYS only.

Stdlib only (urllib/json/threading/subprocess + tomllib) so it runs in any
Hermes venv.

Config (Phase 3): every reader resolves with strict precedence ENV > act.toml >
built-in default. ``~/.hermes/act/act.toml`` is written by ``act install`` and
loaded once (cached, tolerant). ENV still wins for debugging, so the desktop app
can bridge with NO env once act.toml exists and has ``enabled = true``. The
gateway is also kept up via a best-effort self-heal on register().

Env: ACT_CLEARANCE_ENABLED, ACT_GATEWAY_URL (default http://127.0.0.1:8788/v1),
ACT_CLEARANCE_AGENT_ID (default hermes_agent), ACT_CLEARANCE_AGENT_NAME,
ACT_CLEARANCE_GATED_TOOLS, ACT_QUESTION_TOOLS (default clarify,ask_operator,ask_user),
ACT_QUESTION_RISK_FAMILY, ACT_CLEARANCE_RISK_FAMILY (floor for UNCLASSIFIED gated
tools only), ACT_CLEARANCE_RISK_FAMILY_<TOOL> (per-tool tighten-only override),
ACT_CLEARANCE_MIN_RISK_FAMILY (blanket tighten-only floor), ACT_CLEARANCE_TIMEOUT,
ACT_CLEARANCE_POLL.
act.toml keys: enabled, gateway_url, agent_id, agent_name, gated_tools,
question_tools, question_risk_family, clearance_risk_family, min_risk_family,
[tool_risk_families] (per-tool table).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional

try:  # tomllib is stdlib on 3.11+; degrade gracefully on older runtimes.
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - exercised only on <3.11 venvs.
    tomllib = None  # type: ignore[assignment]

_DEFAULT_GATEWAY = "http://127.0.0.1:8788/v1"
_DEFAULT_GATED_TOOLS = (
    "terminal,execute_code,shell,execute_command,run_command,bash,"
    "write_file,edit_file,delete_file,apply_patch,browser_submit,send_email,git_push"
)
_DEFAULT_QUESTION_TOOLS = "clarify,ask_operator,ask_user"
_DEFAULT_QUESTION_RISK_FAMILY = "read_only"
# Floor for a gated tool the map below does not know about. An unclassified
# risky tool must never land in a grant-eligible family.
_DEFAULT_CLEARANCE_RISK_FAMILY = "external_effect"
# Scope names the tower accepts on a clearance. Anything else is dropped.
_VALID_SCOPES = ("once", "session", "agent", "permanent")
_PLUGIN_NAME = "act-clearance"
_PLUGIN_VERSION = "0.1.4"
_PLUGIN_MANAGED_FILES = ("__init__.py", "plugin.yaml")

# launchd Label of the supervised gateway (must match act_cli.LAUNCHD_LABEL).
_GATEWAY_LAUNCHD_LABEL = "app.act.gateway"

_TRUTHY = {"1", "true", "yes", "on"}


# --- config: ENV > act.toml > built-in default ------------------------------


def _act_toml_path() -> Path:
    return Path.home() / ".hermes" / "act" / "act.toml"


def _plugin_release_path() -> Path:
    return Path.home() / ".hermes" / "act" / "plugin-release.json"


def _runtime_update_violation() -> Optional[str]:
    """Verify the loaded hook is the release ACT installed.

    The hard-coded runtime version catches the important hot-update case: the
    plugin files and manifest may already be new while a long-running Hermes
    process still has the prior Python module in memory. File hashes also make
    local drift fail closed at the risky-tool boundary.
    """
    try:
        release = json.loads(_plugin_release_path().read_text())
    except FileNotFoundError:
        return (
            "managed release metadata is missing; run `act install` and restart Hermes"
        )
    except (OSError, ValueError, TypeError):
        return "managed release metadata is unreadable; run `act install` and restart Hermes"
    if not isinstance(release, dict):
        return (
            "managed release metadata is invalid; run `act install` and restart Hermes"
        )
    if release.get("schema") != 1 or release.get("name") != _PLUGIN_NAME:
        return (
            "managed release identity is invalid; run `act install` and restart Hermes"
        )
    managed_version = release.get("version")
    if managed_version != _PLUGIN_VERSION:
        return (
            f"loaded version {_PLUGIN_VERSION} is stale (installed {managed_version!r}); "
            "restart Hermes"
        )
    files = release.get("files")
    if not isinstance(files, dict):
        return (
            "managed release file list is invalid; run `act install` and restart Hermes"
        )
    plugin_dir = Path(__file__).resolve().parent
    for name in _PLUGIN_MANAGED_FILES:
        record = files.get(name)
        expected = record.get("sha256") if isinstance(record, dict) else None
        if not isinstance(expected, str) or len(expected) != 64:
            return f"managed digest for {name} is invalid; run `act install`"
        try:
            actual = hashlib.sha256((plugin_dir / name).read_bytes()).hexdigest()
        except OSError:
            return f"managed plugin file {name} is missing; run `act install`"
        if actual != expected:
            return f"managed plugin file {name} has integrity drift; run `act install`"
    return None


_TOML_CACHE: Dict[str, Any] = {"loaded": False, "data": {}}


def _act_toml() -> Dict[str, Any]:
    """Load ``~/.hermes/act/act.toml`` once (cached). Tolerant: a missing file,
    a parse error, or a missing tomllib all yield ``{}`` and never raise — the
    plugin must keep working with no file at all."""
    if _TOML_CACHE["loaded"]:
        return _TOML_CACHE["data"]
    data: Dict[str, Any] = {}
    if tomllib is not None:
        try:
            with open(_act_toml_path(), "rb") as fh:
                loaded = tomllib.load(fh)
            if isinstance(loaded, dict):
                data = loaded
        except (OSError, ValueError):  # missing file / unreadable / parse error
            data = {}
        except Exception:  # never let config loading break a hook
            data = {}
    _TOML_CACHE["data"] = data
    _TOML_CACHE["loaded"] = True
    return data


def _cfg(env_name: str, toml_key: str, default: Optional[str]) -> Optional[str]:
    """Resolve a single config value with strict precedence ENV > act.toml >
    default. ENV wins whenever it is set non-empty (preserves the legacy
    debugging escape hatch). Otherwise fall back to the act.toml value for
    ``toml_key`` if present, else ``default``."""
    env_val = os.getenv(env_name)
    if env_val is not None and env_val.strip() != "":
        return env_val
    toml_val = _act_toml().get(toml_key)
    if toml_val is not None:
        return toml_val if isinstance(toml_val, str) else str(toml_val)
    return default


def _enabled() -> bool:
    """Enabled if the ENV gate is truthy (unchanged) OR act.toml has
    ``enabled = true``. Lets the desktop app bridge with NO env once act.toml
    exists. (The plugins.enabled config.yaml gate is separate and still
    required.)"""
    env_val = os.getenv("ACT_CLEARANCE_ENABLED", "").strip().lower()
    if env_val in _TRUTHY:
        return True
    return _act_toml().get("enabled") is True


def _gateway() -> str:
    return (
        _cfg("ACT_GATEWAY_URL", "gateway_url", _DEFAULT_GATEWAY) or _DEFAULT_GATEWAY
    ).rstrip("/")


def _agent_id() -> str:
    return _cfg("ACT_CLEARANCE_AGENT_ID", "agent_id", "hermes_agent") or "hermes_agent"


def _suggested_scopes() -> List[str]:
    """Scopes offered to the operator on the phone.

    Default stays "once" so enabling standing grants is an explicit opt-in: a
    scope the plugin never asks for is a scope the operator can never be shown,
    however well the tower enforces it. Unknown scope names are dropped rather
    than forwarded, and "once" is always offered so there is never a request the
    operator can only answer with a standing grant.
    """
    raw = _cfg("ACT_CLEARANCE_SUGGESTED_SCOPES", "suggested_scopes", "once") or "once"
    scopes = [s.strip() for s in raw.split(",") if s.strip() in _VALID_SCOPES]
    if "once" not in scopes:
        scopes.insert(0, "once")
    return scopes


def _agent_name() -> str:
    return (
        _cfg("ACT_CLEARANCE_AGENT_NAME", "agent_name", "Hermes Agent") or "Hermes Agent"
    )


def _control_capabilities() -> List[Dict[str, str]]:
    # Declare the control capabilities so the gateway permits operator-guidance
    # (tua), terminal (tui), browser-assist, and voice handoffs for this agent.
    return [
        {"name": name, "status": "available"}
        for name in ("tua", "tui", "browser_assist", "voice")
    ]


def _tools(env_name: str, toml_key: str, default: str) -> List[str]:
    """Resolve a tool list with ENV > act.toml > default precedence. The ENV
    form is a CSV string; the act.toml form may be a TOML array (list) or a CSV
    string. Returns a clean list of tool names."""
    env_val = os.getenv(env_name)
    if env_val is not None and env_val.strip() != "":
        return [t.strip() for t in env_val.split(",") if t.strip()]
    toml_val = _act_toml().get(toml_key)
    if isinstance(toml_val, list):
        return [str(t).strip() for t in toml_val if str(t).strip()]
    if isinstance(toml_val, str) and toml_val.strip():
        return [t.strip() for t in toml_val.split(",") if t.strip()]
    return [t.strip() for t in default.split(",") if t.strip()]


def _is_in(env_name: str, toml_key: str, default: str, tool: str) -> bool:
    items = _tools(env_name, toml_key, default)
    return "*" in items or tool in items


def _question_risk_family() -> str:
    return (
        _cfg(
            "ACT_QUESTION_RISK_FAMILY",
            "question_risk_family",
            _DEFAULT_QUESTION_RISK_FAMILY,
        )
        or _DEFAULT_QUESTION_RISK_FAMILY
    ).strip()


def _timeout() -> float:
    try:
        return float(os.getenv("ACT_CLEARANCE_TIMEOUT", "180"))
    except ValueError:
        return 180.0


def _poll() -> float:
    try:
        return float(os.getenv("ACT_CLEARANCE_POLL", "2"))
    except ValueError:
        return 2.0


# --- risk classification: per-tool families + read-only shell classifier -----
#
# Why this exists: a blanket ``external_effect`` on every gated tool was both
# dishonest and useless. Dishonest because `delete_file` is not the same risk as
# `git status`; useless because `external_effect` is in the tower's
# MOBILE_MANDATORY_RISK_FAMILIES, so EVERY clearance this plugin raised was
# structurally ineligible for a standing grant — the operator could pick "for
# this session" on the phone and the tower would refuse it
# (capability_grant_refused / channel_requirement). This module now says what
# each tool can actually do, and computes a per-call downgrade for shell
# invocations that are PROVABLY read-only.

#: Mirror of hermes_gateway.capability_registry.RISK_FAMILY_RANKS. Duplicated
#: (not imported) because this plugin is stdlib-only and loads inside an
#: arbitrary Hermes venv with no ACT package on sys.path. A parity test in the
#: ACT repo pins the two together — change BOTH sides.
_RISK_FAMILY_RANKS: Dict[str, int] = {
    "observe": 0,
    "read_only": 1,
    "routine": 2,
    "external_effect": 3,
    "destructive": 4,
    "credential_or_secret": 5,
    "safety_critical": 6,
    "irreversible": 7,
}

#: Families the tower will never satisfy from a standing grant (mirror of
#: clearance_policy.MOBILE_MANDATORY_RISK_FAMILIES). Informational here: the
#: plugin does not enforce it, it just must not pretend a tool is below it.
_MOBILE_MANDATORY_RISK_FAMILIES = frozenset(
    {
        "external_effect",
        "destructive",
        "credential_or_secret",
        "safety_critical",
        "irreversible",
    }
)

#: Per-tool CAPABILITY CEILING — what the tool *can* do, not what this call is
#: likely doing. Rationale per group:
#:
#: * Shell / arbitrary execution: the ceiling is unbounded (any binary, any
#:   network egress, any deletion), so ``external_effect`` is a FLOOR rather than
#:   a description. Ranking them ``irreversible`` would be more honest about the
#:   ceiling but would make every terminal call read as maximally severe on the
#:   phone and destroy the signal that separates them from ``delete_file``;
#:   ``external_effect`` is already mobile-mandatory, so nothing is unlocked by
#:   the lower rank. Individual invocations that are provably read-only are
#:   downgraded per-call by :func:`_is_provably_read_only_command`.
#: * Local file mutation: ``destructive`` rather than ``irreversible``.
#:   ``irreversible`` is the top of the tower's ladder and is reserved for
#:   effects with no local undo path at all; a clobbered or deleted working-tree
#:   file destroys prior content, which is exactly what ``destructive`` names.
#:   Both sit above the tower's standing-grant exclusion floor
#:   (rank >= destructive), so the security outcome is identical and the lower of
#:   the two keeps ``irreversible`` meaningful for things that truly cannot be
#:   undone.
#: * Effects that leave this machine: ``external_effect``, the family the tower
#:   defines for exactly that.
_TOOL_RISK_FAMILIES: Dict[str, str] = {
    "terminal": "external_effect",
    "bash": "external_effect",
    "shell": "external_effect",
    "execute_command": "external_effect",
    "run_command": "external_effect",
    "execute_code": "external_effect",
    "write_file": "destructive",
    "edit_file": "destructive",
    "apply_patch": "destructive",
    "delete_file": "destructive",
    "git_push": "external_effect",
    "send_email": "external_effect",
    "browser_submit": "external_effect",
}

#: Family -> scalar risk_level sent alongside it. The tower prefers a valid
#: ``risk_family`` and only falls back to ``risk_level``, but shipping
#: ``risk_level="high"`` next to ``risk_family="read_only"`` would be a lie to
#: the notification composer, so the two are derived from one source.
_RISK_LEVEL_FOR_FAMILY: Dict[str, str] = {
    "observe": "low",
    "read_only": "low",
    "routine": "medium",
    "external_effect": "high",
    "destructive": "critical",
    "credential_or_secret": "critical",
    "safety_critical": "critical",
    "irreversible": "critical",
}

#: Tools whose arguments carry a SHELL COMMAND LINE that the classifier below can
#: reason about. ``execute_code`` is deliberately absent: its payload is a
#: program in a general-purpose language, and no allowlist over source text can
#: prove that read-only.
_SHELL_CLASSIFIABLE_TOOLS = frozenset(
    {"terminal", "bash", "shell", "execute_command", "run_command"}
)

#: Argument keys that may carry the command string. Exactly one must be present.
_SHELL_COMMAND_KEYS = ("command", "cmd")

#: Every other key permitted to appear alongside it. An unrecognised key may
#: change execution semantics (``shell``, ``env``, ``stdin``, ``args``...), and an
#: unknown key means we cannot claim to know what will run — so its presence
#: fails closed to the floor.
_SHELL_BENIGN_ARG_KEYS = frozenset(
    {
        "command",
        "cmd",
        "cwd",
        "workdir",
        "working_directory",
        "directory",
        "timeout",
        "timeout_ms",
        "timeout_seconds",
        "description",
        "explanation",
        "session_id",
    }
)

#: ALLOWLIST of characters a provably-read-only command may contain. Everything
#: else — every shell metacharacter (``; | & $ ` > < ( ) { } [ ] * ? ~ ! #``),
#: the backslash escape, newline/carriage return, control characters, and every
#: non-ASCII codepoint (so NBSP / RTL-override / homoglyph tricks cannot smuggle
#: anything past the parser) — is rejected. An allowlist is used rather than a
#: denylist precisely because the denylist can never be finished.
_SAFE_COMMAND_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789"
    " _-./:=,+@'\""
)

_MAX_COMMAND_CHARS = 2048
_MAX_COMMAND_TOKENS = 32

#: Substrings that make an operand look like it addresses a credential store.
#: Reading a secret has no side effect, but the tower has a dedicated
#: ``credential_or_secret`` family and calling such a read "read_only" would be
#: the same category error this change exists to fix. Deliberately over-broad:
#: a false positive costs a standing grant, a false negative leaks a key.
_SENSITIVE_OPERAND_MARKERS = (
    ".env",
    ".ssh",
    ".aws",
    ".gnupg",
    ".kube",
    ".docker",
    ".npmrc",
    ".pypirc",
    ".netrc",
    ".pem",
    ".key",
    ".p12",
    ".pfx",
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    "credential",
    "secret",
    "passwd",
    "password",
    "shadow",
    "keychain",
    "keyring",
    "token",
    "apikey",
    "api_key",
)

_NUMERIC_SHORT_FLAG = re.compile(r"-[0-9]{1,6}")


def _cmd_spec(
    flags: Any = (),
    operands: bool = False,
    numeric_short_flags: bool = False,
) -> Dict[str, Any]:
    return {
        "flags": frozenset(flags),
        "operands": operands,
        "numeric_short_flags": numeric_short_flags,
    }


#: Read-only programs and the ONLY flags each may carry.
#:
#: Per-program flag ALLOWLISTS, not a denylist of dangerous flags. A denylist has
#: to enumerate ``-o/--output``, ``--exec``, ``-exec``, ``--write``, ``-i``,
#: ``--upload-pack``, ``--ext-diff``, pager/editor overrides, and whatever the
#: next release of the tool adds — and a single miss is an arbitrary write. An
#: allowlist is wrong in the safe direction: a flag nobody thought about is
#: simply not classifiable, and the call falls back to the floor.
_READ_ONLY_PROGRAMS: Dict[str, Dict[str, Any]] = {
    "pwd": _cmd_spec(),
    "which": _cmd_spec(flags=("-a",), operands=True),
    "file": _cmd_spec(flags=("-b", "-i", "-h", "-L"), operands=True),
    # No flags: macOS `stat -f` takes a format string and GNU `stat -f` reports a
    # filesystem; neither is worth the parsing surface.
    "stat": _cmd_spec(operands=True),
    "ls": _cmd_spec(
        flags=(
            "-l",
            "-a",
            "-A",
            "-la",
            "-al",
            "-lA",
            "-h",
            "-lh",
            "-hl",
            "-lah",
            "-1",
            "-t",
            "-r",
            "-S",
            "-R",
            "-F",
            "-d",
            "-ltr",
            "-lrt",
            "--color=never",
            "--color=auto",
        ),
        operands=True,
    ),
    "wc": _cmd_spec(flags=("-l", "-w", "-c", "-m"), operands=True),
    "du": _cmd_spec(flags=("-h", "-s", "-sh", "-hs", "-c", "-a", "-d"), operands=True),
    "cat": _cmd_spec(flags=("-n", "-b", "-s"), operands=True),
    "head": _cmd_spec(
        flags=("-n", "-c", "-q", "-v"), operands=True, numeric_short_flags=True
    ),
    # `-f` (follow) is absent on purpose: it never returns.
    "tail": _cmd_spec(
        flags=("-n", "-c", "-q", "-v"), operands=True, numeric_short_flags=True
    ),
}

#: git is special-cased: argv[1] must be one of these subcommands, and NO
#: top-level git flag is accepted at all. That single rule kills ``git -c
#: core.pager=...`` / ``-c alias.x=!sh`` config injection, ``--exec-path``,
#: ``-C``, ``--git-dir`` and ``--work-tree`` retargeting in one line rather than
#: leaving them to be individually remembered.
#:
#: Residual risk, accepted and documented: git honours the *repository's*
#: ``.git/config`` (pager, external diff drivers), so running git inside a
#: hostile repository is not provably side-effect-free no matter what this
#: classifier does. ``--no-ext-diff`` is allowlisted so a caller can say so, and
#: git run non-interactively does not spawn a pager. Cloning a hostile repo is
#: itself a gated action.
_GIT_SUBCOMMANDS: Dict[str, Dict[str, Any]] = {
    "status": _cmd_spec(
        flags=(
            "-s",
            "--short",
            "--porcelain",
            "-b",
            "--branch",
            "--long",
            "--no-color",
            "-uno",
            "-unormal",
            "-uall",
            "--untracked-files=no",
            "--untracked-files=normal",
            "--untracked-files=all",
        )
    ),
    "log": _cmd_spec(
        flags=(
            "--oneline",
            "--stat",
            "--numstat",
            "--shortstat",
            "--name-only",
            "--name-status",
            "--graph",
            "--decorate",
            "--no-decorate",
            "--no-color",
            "--abbrev-commit",
            "--no-merges",
            "--merges",
            "--first-parent",
            "--reverse",
            "--no-ext-diff",
            "-n",
            "--date=short",
            "--date=iso",
            "--date=relative",
            "--pretty=oneline",
            "--pretty=short",
            "--pretty=medium",
            "--pretty=full",
        ),
        operands=True,
        numeric_short_flags=True,
    ),
    "diff": _cmd_spec(
        flags=(
            "--stat",
            "--numstat",
            "--shortstat",
            "--cached",
            "--staged",
            "--name-only",
            "--name-status",
            "--no-color",
            "--no-ext-diff",
            "--check",
            "-w",
            "--ignore-all-space",
        ),
        operands=True,
    ),
    "show": _cmd_spec(
        flags=(
            "--stat",
            "--numstat",
            "--name-only",
            "--name-status",
            "--oneline",
            "--no-color",
            "--no-ext-diff",
            "--pretty=oneline",
            "--pretty=short",
        ),
        operands=True,
    ),
    # No operands: `git branch <name>` CREATES a branch, and `-d/-m/-u` are
    # absent from the flag allowlist.
    "branch": _cmd_spec(
        flags=(
            "-a",
            "--all",
            "-r",
            "--remotes",
            "-v",
            "-vv",
            "--list",
            "--show-current",
            "--no-color",
        )
    ),
    "rev-parse": _cmd_spec(
        flags=(
            "--abbrev-ref",
            "--short",
            "--show-toplevel",
            "--git-dir",
            "--is-inside-work-tree",
            "--verify",
            "--quiet",
        ),
        operands=True,
    ),
    "describe": _cmd_spec(
        flags=("--tags", "--always", "--dirty", "--long"), operands=True
    ),
    # No operands: `git remote add|remove|set-url` are all positional.
    "remote": _cmd_spec(flags=("-v", "--verbose")),
}


def _rank(family: str) -> int:
    """Rank of a family; an unknown name ranks at the floor, never below it."""
    return _RISK_FAMILY_RANKS.get(family, _RISK_FAMILY_RANKS["external_effect"])


def _is_sensitive_operand(token: str) -> bool:
    lowered = token.lower()
    return any(marker in lowered for marker in _SENSITIVE_OPERAND_MARKERS)


def _tokens_match_spec(tokens: List[str], spec: Dict[str, Any]) -> bool:
    operands_only = False
    for token in tokens:
        if not token:  # an explicitly empty quoted argument
            return False
        if token == "--":
            if operands_only or not spec["operands"]:
                return False
            operands_only = True
            continue
        if not operands_only and token.startswith("-"):
            if token in spec["flags"]:
                continue
            if spec["numeric_short_flags"] and _NUMERIC_SHORT_FLAG.fullmatch(token):
                continue
            return False
        if not spec["operands"]:
            return False
        if _is_sensitive_operand(token):
            return False
    return True


def _is_provably_read_only_command(command: Any) -> bool:
    """Is this command line PROVABLY free of side effects?

    Fail-closed by construction: every gate is an allowlist and the function
    returns ``False`` for anything it does not positively recognise. In
    particular a chain or pipeline can never be classified read-only even when
    every element looks safe, because the character allowlist rejects the
    operators outright — the command is never split on ``;``/``|``/``&&`` and
    re-checked element-wise, which is the usual way this kind of classifier is
    defeated.
    """
    if not isinstance(command, str):
        return False
    if not command or len(command) > _MAX_COMMAND_CHARS:
        return False
    if any(ch not in _SAFE_COMMAND_CHARS for ch in command):
        return False
    if not command.strip():
        return False
    try:
        tokens = shlex.split(command)
    except ValueError:  # unbalanced quoting
        return False
    if not tokens or len(tokens) > _MAX_COMMAND_TOKENS:
        return False

    program, rest = tokens[0], tokens[1:]
    if program == "git":
        if not rest or rest[0].startswith("-"):
            return False  # no top-level git flags, ever
        spec = _GIT_SUBCOMMANDS.get(rest[0])
        return spec is not None and _tokens_match_spec(rest[1:], spec)
    spec = _READ_ONLY_PROGRAMS.get(program)
    return spec is not None and _tokens_match_spec(rest, spec)


def _extract_shell_command(args: Any) -> Optional[str]:
    """The command string these tool args will run, or ``None`` if we cannot say.

    Reads the same tool-argument mapping that ``_redacted_payload`` fingerprints,
    so classification and the clearance are computed from one source of truth.
    The extracted string is used for classification ONLY: it is never logged,
    never added to ``payload_redacted``, and never sent to the gateway — the
    redaction invariant (tool name + argument KEYS) is unchanged.
    """
    if not isinstance(args, dict):
        return None
    if any(str(key) not in _SHELL_BENIGN_ARG_KEYS for key in args):
        return None
    present = [key for key in _SHELL_COMMAND_KEYS if key in args]
    if len(present) != 1:
        return None
    value = args[present[0]]
    if not isinstance(value, str):
        return None
    return value


def _unclassified_floor() -> str:
    """Family for a gated tool :data:`_TOOL_RISK_FAMILIES` does not know about.

    This is what the legacy ``ACT_CLEARANCE_RISK_FAMILY`` / act.toml
    ``clearance_risk_family`` key now means, and it is deliberately NOT wired up
    as a blanket floor over every tool. ``act install`` STAMPS that key with the
    historical blanket value (``clearance_risk_family = "external_effect"`` is
    sitting in the live act.toml right now), so honouring it as "raise every tool
    to at least this" would re-break the exact workflow this change exists to
    fix — the per-tool map and the read-only classifier would be overridden back
    to a mobile-mandatory family on every install. An operator who genuinely
    wants a blanket floor says so with ``min_risk_family``, which nothing stamps.

    Clamped upward at :data:`_DEFAULT_CLEARANCE_RISK_FAMILY`: an unclassified
    risky tool must never be configurable into a grant-eligible family.
    """
    configured = _cfg("ACT_CLEARANCE_RISK_FAMILY", "clearance_risk_family", None)
    if isinstance(configured, str) and configured.strip() in _RISK_FAMILY_RANKS:
        candidate = configured.strip()
        if _rank(candidate) > _rank(_DEFAULT_CLEARANCE_RISK_FAMILY):
            return candidate
    return _DEFAULT_CLEARANCE_RISK_FAMILY


def _classified_risk_family(tool_name: str, args: Any) -> str:
    """Baseline family for THIS call, before operator overrides."""
    baseline = _TOOL_RISK_FAMILIES.get(tool_name) or _unclassified_floor()
    if tool_name not in _SHELL_CLASSIFIABLE_TOOLS:
        return baseline
    command = _extract_shell_command(args)
    if command is None:
        return baseline
    return "read_only" if _is_provably_read_only_command(command) else baseline


def _risk_family_env_key(tool_name: str) -> str:
    suffix = "".join(ch if ch.isalnum() else "_" for ch in tool_name).upper()
    return f"ACT_CLEARANCE_RISK_FAMILY_{suffix}"


def _tighten_candidates(tool_name: str) -> List[str]:
    """Operator knobs that may RAISE this tool's family, most specific first.

    Per-tool: ``ACT_CLEARANCE_RISK_FAMILY_<TOOL>`` (ENV) or the act.toml
    ``[tool_risk_families]`` table. Blanket: ``ACT_CLEARANCE_MIN_RISK_FAMILY``
    (ENV) or act.toml ``min_risk_family``. Both follow the existing
    ENV > act.toml precedence; both are tighten-only (see
    :func:`_risk_family_for_tool`).
    """
    candidates: List[str] = []
    env_val = os.getenv(_risk_family_env_key(tool_name))
    if env_val is not None and env_val.strip():
        candidates.append(env_val.strip())
    else:
        table = _act_toml().get("tool_risk_families")
        if isinstance(table, dict):
            toml_val = table.get(tool_name)
            if isinstance(toml_val, str) and toml_val.strip():
                candidates.append(toml_val.strip())
    minimum = _cfg("ACT_CLEARANCE_MIN_RISK_FAMILY", "min_risk_family", None)
    if isinstance(minimum, str) and minimum.strip():
        candidates.append(minimum.strip())
    return candidates


def _risk_family_for_tool(tool_name: str, args: Any = None) -> str:
    """THE risk family this plugin asserts for a gated tool call.

    Configuration may TIGHTEN and never loosen: a candidate is applied only when
    it names a real tower family AND ranks strictly above what is resolved so
    far. An unknown family name, or one that would downgrade the call, is
    ignored rather than honoured — otherwise ``min_risk_family = "read_only"``
    in a stale act.toml would silently make every gated tool grant-eligible,
    which is the failure mode a clearance plugin must not have.
    """
    resolved = _classified_risk_family(tool_name, args)
    for candidate in _tighten_candidates(tool_name):
        if candidate in _RISK_FAMILY_RANKS and _rank(candidate) > _rank(resolved):
            resolved = candidate
    return resolved


def _risk_level_for_family(family: str) -> str:
    return _RISK_LEVEL_FOR_FAMILY.get(family, "high")


# --- HTTP (stdlib) ----------------------------------------------------------


def _request(
    method: str, path: str, payload: Optional[Dict[str, Any]], timeout: float
) -> Dict[str, Any]:
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    headers = {"Content-Type": "application/json"} if data is not None else {}
    req = urllib.request.Request(
        f"{_gateway()}{path}", data=data, headers=headers, method=method
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read().decode("utf-8")
    return json.loads(body) if body else {}


def _post(path: str, payload: Dict[str, Any], timeout: float = 10.0) -> Dict[str, Any]:
    return _request("POST", path, payload, timeout)


def _get(path: str, timeout: float = 10.0) -> Dict[str, Any]:
    return _request("GET", path, None, timeout)


# --- clearance contract (act.clearance.v2, mirrors ACT gateway) --------------
#
# Stdlib mirror of hermes_gateway.security.canonical_json/content_hash and
# hermes_gateway.clearance_contract.build_params_fingerprint/build_short_code.
# Kept byte-identical by a parity test in the ACT repo
# (gateway/tests/test_act_clearance_plugin.py) — change BOTH sides together.

_CONTRACT_VERSION = "act.clearance.v2"
_PROOF_ALGORITHM = "Ed25519"
_PROOF_CANONICALIZATION = "ACT-CLEARANCE-PROOF-V1"


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _content_hash(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _params_fingerprint(
    payload_redacted: Dict[str, Any], extensions: Optional[Dict[str, Any]]
) -> str:
    return _content_hash(
        {"payload_redacted": payload_redacted, "extensions": extensions or {}}
    )


def _derived_short_code(approval_id: str, params_fingerprint: str) -> str:
    return (
        hashlib.sha256(f"{approval_id}:{params_fingerprint}".encode())
        .hexdigest()[:10]
        .upper()
    )


def _clearance_violation(
    status: Dict[str, Any],
    approval_id: str,
    expected_fingerprint: str,
) -> Optional[str]:
    """Verify an 'approved' clearance envelope before treating it as allow.

    Fail-closed binding checks the plugin can do with stdlib only: the returned
    clearance must be bound to the EXACT params this plugin submitted
    (canonical params_fingerprint), carry the short code derived from that
    fingerprint (the plugin never requests a custom short code), and carry a
    structurally valid tower proof for the expected contract. Full Ed25519
    signature verification is performed by the signed-device surface (the
    phone); a gateway that lies about these fields cannot make this plugin
    execute a tool whose params it did not fingerprint itself.
    """
    fingerprint = status.get("params_fingerprint")
    if fingerprint != expected_fingerprint:
        return (
            "params_fingerprint mismatch: clearance is not bound to the "
            f"requested params (got {fingerprint!r})"
        )
    short_code = status.get("short_code")
    if short_code != _derived_short_code(approval_id, expected_fingerprint):
        return f"short_code mismatch: {short_code!r} is not derived from the canonical fingerprint"
    if status.get("contract_version") != _CONTRACT_VERSION:
        return f"unexpected contract_version {status.get('contract_version')!r}"
    proof = status.get("proof")
    if not isinstance(proof, dict) or not proof.get("signature"):
        return "missing clearance proof"
    if proof.get("algorithm") != _PROOF_ALGORITHM:
        return f"unexpected proof algorithm {proof.get('algorithm')!r}"
    if proof.get("canonicalization") != _PROOF_CANONICALIZATION:
        return f"unexpected proof canonicalization {proof.get('canonicalization')!r}"
    return None


# --- redaction --------------------------------------------------------------


def _redacted_payload(tool_name: str, args: Any) -> Dict[str, Any]:
    keys: List[str] = []
    if isinstance(args, dict):
        keys = sorted(str(k) for k in args.keys())
    return {"tool": tool_name, "arg_keys": keys}


def _target_hint(args: Any) -> Optional[str]:
    """A short, non-secret hint about what the tool is acting on (keys/short values)."""
    if not isinstance(args, dict):
        return None
    for key in ("path", "file", "command", "url", "target", "name"):
        val = args.get(key)
        if isinstance(val, str) and val:
            return val[:80]
    return ", ".join(sorted(str(k) for k in args.keys()))[:80] or None


def _block(message: str) -> Dict[str, str]:
    return {"action": "block", "message": f"ACT — {message}"}


# --- monitoring: push real agent/session into ACT ---------------------------


def _post_context(**fields: Any) -> None:
    """Best-effort agent/session/mission upsert. Monitoring fails OPEN (never
    blocks the agent)."""
    if not _enabled():
        return
    payload: Dict[str, Any] = {
        "agent_id": _agent_id(),
        "display_name": _agent_name(),
        # Heartbeat lets the signed mobile status endpoint distinguish updated
        # files from the older module a long-running Hermes process may still
        # have loaded in memory.
        "bridge_plugin_name": _PLUGIN_NAME,
        "bridge_plugin_version": _PLUGIN_VERSION,
    }
    payload.update({k: v for k, v in fields.items() if v is not None})
    try:
        _post("/runtime/context", payload, timeout=5.0)
    except (urllib.error.URLError, OSError, ValueError):
        pass


def _on_session_start(session_id: str = "", model: str = "", **_: Any) -> None:
    if session_id:
        _current_session["id"] = session_id
    _post_context(
        agent_status="running",
        session_id=session_id or None,
        mission_state="running",
        mission_title="Hermes session" if session_id else None,
        capabilities=_control_capabilities(),
    )


def _on_post_tool_call(
    tool_name: str = "",
    status: str = "",
    session_id: str = "",
    **_: Any,
) -> None:
    _post_context(
        agent_status="error" if status == "error" else "running",
        current_tool=None,
        session_id=session_id or None,
    )


def _on_session_end(
    session_id: str = "",
    completed: bool = False,
    interrupted: bool = False,
    **_: Any,
) -> None:
    # on_session_end fires per turn; only reflect a terminal state when the turn
    # actually completed or was interrupted (avoid flapping the status).
    if not (completed or interrupted):
        return
    _post_context(
        agent_status="idle",
        session_id=session_id or None,
        mission_state="failed" if interrupted and not completed else "completed",
    )


# --- control: interactive question relay (TUA) ------------------------------


def _question_text(tool_name: str, args: Any) -> str:
    if isinstance(args, dict):
        for key in ("question", "prompt", "message", "text", "ask"):
            val = args.get(key)
            if isinstance(val, str) and val.strip():
                return val.strip()
    return f"The agent is asking via '{tool_name}'."


def _question_choices(args: Any) -> Optional[List[str]]:
    if isinstance(args, dict):
        choices = args.get("choices") or args.get("options")
        if isinstance(choices, list):
            return [str(c) for c in choices]
    return None


def _relay_question(tool_name: str, args: Any, session_id: str) -> Dict[str, str]:
    """Raise a TUA assistance request and block until the operator answers on the
    phone; return the answer to the agent (delivered via the block message)."""
    reason = _question_text(tool_name, args)
    context: Dict[str, Any] = {"asked_via": tool_name}
    choices = _question_choices(args)
    if choices:
        context["choices"] = choices
    try:
        created = _post(
            "/runtime/tua/requests",
            {
                "agent_id": _agent_id(),
                "session_id": session_id or "hermes_session",
                "reason": reason,
                # A question is not a risky action — use a LOW-risk family so the
                # operator can engage it directly. Non-low-risk handoffs require a
                # prior bound clearance (engage_handoff) and would 403 on engage.
                "risk_family": _question_risk_family(),
                "context_redacted": context,
            },
        )
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return _block(f"could not reach the operator (fail-closed): {exc}")

    request_id = created.get("request_id")
    if not request_id:
        return _block("gateway did not return a question id (fail-closed)")

    answer = _poll_question_answer(request_id, _timeout(), _poll())
    if answer is None:
        return _block("operator did not answer in time (fail-closed)")
    return {"action": "block", "message": f"The operator answered: {answer}"}


# The createSession initial message the app posts; not the operator's answer.
_SESSION_BOILERPLATE = "Opened from Agentic Control Tower."


def _poll_question_answer(
    request_id: str, timeout_s: float, poll_s: float
) -> Optional[str]:
    """Block until the operator answers. The answer is the operator's typed
    message (the createSession boilerplate is ignored). A session returned/closed
    without a typed reply falls back to the return summary."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            result = _get(f"/runtime/tua/requests/{request_id}/result")
        except (urllib.error.URLError, OSError, ValueError):
            time.sleep(poll_s)
            continue
        latest = result.get("latest_session") or {}
        replies = [
            str(message.get("body"))
            for message in (latest.get("messages") or [])
            if message.get("sender_type") == "user"
            and message.get("body")
            and str(message.get("body")).strip() != _SESSION_BOILERPLATE
        ]
        if replies:
            return replies[-1]
        state = latest.get("state") or (result.get("request") or {}).get("state")
        if state in ("returned_to_agent", "closed"):
            return (
                result.get("return_summary")
                or "Operator returned control without a message."
            )
        time.sleep(poll_s)
    return None


# --- control: clearance gate (existing, fail-closed) ------------------------


def _relay_clearance(
    tool_name: str, args: Any, session_id: str
) -> Optional[Dict[str, str]]:
    # Honest per-tool family (capability ceiling), with a per-call downgrade to
    # read_only when the shell command is provably side-effect-free. This is what
    # decides whether the tower can honour a standing grant at all.
    risk_family = _risk_family_for_tool(tool_name, args)
    timeout_s = _timeout()
    payload_redacted = _redacted_payload(tool_name, args)
    extensions: Dict[str, Dict[str, Any]] = {}
    # Canonical fingerprint over the exact params being cleared (mirrors ACT's
    # build_params_fingerprint). The gateway recomputes it server-side; we
    # verify the returned clearance is bound to this exact value (fail-closed).
    expected_fingerprint = _params_fingerprint(payload_redacted, extensions)
    # short_code is intentionally NOT client-supplied: the plugin verifies the
    # server-derived code sha256(approval_id:fingerprint)[:10], which binds the
    # code the operator sees to the fingerprint we computed.
    try:
        created = _post(
            "/hermes/tools/approval_requested",
            {
                "requested_tool": tool_name,
                "risk_level": _risk_level_for_family(risk_family),
                "risk_family": risk_family,
                "summary": f"Hermes agent requests to run '{tool_name}'.",
                "payload_redacted": payload_redacted,
                "agent_id": _agent_id(),
                "session_id": session_id or "hermes_session",
                "expires_in_seconds": int(timeout_s) + 30,
                "suggested_scopes": _suggested_scopes(),
                "params_fingerprint": expected_fingerprint,
                "extensions": extensions,
                "operator_message": f"Hermes agent requests to run '{tool_name}'.",
            },
        )
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return _block(f"gateway unreachable, blocking (fail-closed): {exc}")

    approval_id = created.get("approval_id")
    if not approval_id:
        return _block("gateway did not return an approval id (fail-closed)")

    deadline = time.monotonic() + timeout_s
    poll_s = _poll()
    while time.monotonic() < deadline:
        try:
            status = _post(
                "/hermes/tools/approval_status", {"approval_id": approval_id}
            )
        except (urllib.error.URLError, OSError, ValueError):
            time.sleep(poll_s)
            continue
        state = status.get("state")
        if state == "approved":
            violation = _clearance_violation(status, approval_id, expected_fingerprint)
            if violation is not None:
                return _block(
                    f"clearance verification failed (fail-closed): {violation}"
                )
            return None  # allow — verified clearance
        if state in {"denied", "expired", "cancelled"}:
            return _block(f"operator {state} this action on their phone")
        time.sleep(poll_s)
    return _block("timed out waiting for operator approval (fail-closed)")


# --- the pre_tool_call hook (questions + monitoring + clearance) -------------

# --- control: interventions (operator pause / steer / stop) -----------------

_STOP_TYPES = {
    "cancel_task",
    "kill_task",
    "kill_agent",
    "quarantine_agent",
    "emergency_stop",
}


def _drain_pending_interventions(session_id: str) -> List[Dict[str, Any]]:
    try:
        query = (
            "/runtime/interventions/pending?session_id="
            + urllib.parse.quote(session_id or "hermes_session")
            + "&agent_id="
            + urllib.parse.quote(_agent_id())
        )
        resp = _get(query, timeout=5.0)
    except (urllib.error.URLError, OSError, ValueError):
        return []
    items = resp.get("interventions") if isinstance(resp, dict) else None
    return items or []


def _ack_intervention(intervention_id: str, ack_result: str = "accepted") -> None:
    if not intervention_id:
        return
    try:
        _post(
            f"/runtime/interventions/{intervention_id}/ack",
            {"ack_result": ack_result},
            timeout=5.0,
        )
    except (urllib.error.URLError, OSError, ValueError):
        pass


def _pause_until_resume_or_stop(
    session_id: str, pause_id: str
) -> Optional[Dict[str, str]]:
    """Hold the agent at the tool boundary until a resume or stop arrives (or a
    timeout). Returns a block dict (stopped) or None (resume / proceed)."""
    _post_context(agent_status="paused", session_id=session_id or None)
    _ack_intervention(pause_id)
    deadline = time.monotonic() + _timeout()
    poll_s = _poll()
    while time.monotonic() < deadline:
        for item in _drain_pending_interventions(session_id):
            itype = item.get("type")
            iid = item.get("intervention_id", "")
            if itype in _STOP_TYPES:
                _post_context(agent_status="stopping", session_id=session_id or None)
                _ack_intervention(iid)
                return _block(f"operator stopped this agent while paused ({itype})")
            if itype == "resume":
                _ack_intervention(iid)
                _post_context(agent_status="running", session_id=session_id or None)
                return None
        time.sleep(poll_s)
    # Timed out paused — resume rather than hang the agent forever.
    _post_context(agent_status="running", session_id=session_id or None)
    return None


def _apply_interventions(session_id: str) -> Optional[Dict[str, str]]:
    """Apply pending operator interventions at the tool boundary. Returns a block
    dict to stop/steer the tool, or None to proceed. Fail-open on errors."""
    for item in _drain_pending_interventions(session_id):
        itype = item.get("type")
        iid = item.get("intervention_id", "")
        if itype in _STOP_TYPES:
            _post_context(agent_status="stopping", session_id=session_id or None)
            _ack_intervention(iid)
            return _block(f"operator stopped this agent ({itype})")
        if itype == "inject_instruction":
            _ack_intervention(iid)
            instruction = item.get("instruction") or item.get("reason") or ""
            return {"action": "block", "message": f"Operator guidance: {instruction}"}
        if itype == "pause":
            blocked = _pause_until_resume_or_stop(session_id, iid)
            if blocked is not None:
                return blocked
    return None


# --- TUI mirror: stream the agent's terminal output to the phone ------------

# transform_terminal_output carries no session_id, so we track the live session
# from the lifecycle hooks that do.
_current_session: Dict[str, str] = {"id": ""}


def _on_transform_terminal_output(
    command: str = "",
    output: str = "",
    **_: Any,
) -> None:
    """Mirror terminal command + output to the phone's TUI screen. Returns None
    so the agent's output is never modified (mirror only, fail-open)."""
    if not _enabled():
        return None
    chunk = ""
    if command:
        chunk += f"$ {command}\n"
    if output:
        chunk += output if output.endswith("\n") else output + "\n"
    if not chunk:
        return None
    try:
        _post(
            "/runtime/tui/relay",
            {
                "session_id": _current_session.get("id") or "hermes_session",
                "agent_id": _agent_id(),
                "chunk": chunk,
            },
            timeout=5.0,
        )
    except (urllib.error.URLError, OSError, ValueError):
        pass
    return None


def _on_pre_tool_call(
    tool_name: str = "",
    args: Any = None,
    session_id: str = "",
    **_: Any,
) -> Optional[Dict[str, str]]:
    if not _enabled() or not tool_name:
        return None
    if session_id:
        _current_session["id"] = session_id

    # 1) Interactive question: route the agent's question to the phone.
    if _is_in(
        "ACT_QUESTION_TOOLS", "question_tools", _DEFAULT_QUESTION_TOOLS, tool_name
    ):
        return _relay_question(tool_name, args, session_id)

    # 2) Monitoring: reflect that the agent is now running this tool (fail-open).
    _post_context(
        agent_status="running",
        current_tool=tool_name,
        current_target=_target_hint(args),
        session_id=session_id or None,
    )

    # 3) Interventions: apply any pending operator pause/steer/stop (fail-open
    #    for drain errors, fail-closed once a stop/steer command is applied).
    intervention = _apply_interventions(session_id)
    if intervention is not None:
        return intervention

    # 4) Clearance gate for risky tools (fail-closed).
    if _is_in(
        "ACT_CLEARANCE_GATED_TOOLS", "gated_tools", _DEFAULT_GATED_TOOLS, tool_name
    ):
        update_violation = _runtime_update_violation()
        if update_violation is not None:
            return _block(
                f"plugin update check failed (fail-closed): {update_violation}"
            )
        return _relay_clearance(tool_name, args, session_id)

    return None


# --- self-heal: cheap is-it-up probe + launchctl kickstart -----------------


def _health_url() -> str:
    """Derive the gateway health endpoint from the configured gateway URL.
    ``http://127.0.0.1:8788/v1`` -> ``http://127.0.0.1:8788/v1/health``."""
    return f"{_gateway()}/health"


def _gateway_healthy(timeout: float = 1.0) -> bool:
    """Cheap GET of the gateway health endpoint. Any non-2xx / error -> False."""
    req = urllib.request.Request(_health_url(), method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
        return 200 <= getattr(resp, "status", 0) < 300


def _kickstart_gateway() -> None:
    """``launchctl kickstart -k gui/<uid>/app.act.gateway``. If the LaunchAgent
    is not installed this fails harmlessly (non-zero exit) — we never check the
    result."""
    target = f"gui/{os.getuid()}/{_GATEWAY_LAUNCHD_LABEL}"
    subprocess.run(  # noqa: S603
        ["launchctl", "kickstart", "-k", target],
        capture_output=True,
        timeout=10,
    )


def _self_heal_gateway() -> None:
    """Best-effort: if the gateway health probe is NOT healthy, kickstart the
    LaunchAgent. FULLY error-swallowing — this runs on a background thread and
    must NEVER raise into the Hermes register/hook path. This is an is-it-up +
    kickstart, NOT a cold bootstrap."""
    try:
        healthy = False
        try:
            healthy = _gateway_healthy()
        except Exception:
            healthy = False
        if healthy:
            return
        try:
            _kickstart_gateway()
        except Exception:
            pass
    except Exception:
        pass


def _local_interactive_terminal() -> bool:
    """Pairing secrets may only be rendered to a directly attached terminal."""
    return bool(sys.stdin.isatty() and sys.stdout.isatty())


def _run_local_pairing_cli() -> None:
    """Run ACT's one-time QR ceremony without exposing it as an agent tool.

    This handler is reachable only as ``hermes act-pair``. It is intentionally
    not a slash command: Hermes plugin slash commands are gateway-dispatchable
    from chat platforms, where returning an enrollment secret would cross the
    local-operator trust boundary.
    """
    if not _local_interactive_terminal():
        raise SystemExit(
            "act-pair: refusing to render an enrollment secret without a local "
            "interactive terminal"
        )

    violation = _runtime_update_violation()
    if violation is not None:
        raise SystemExit(f"act-pair: {violation}")

    act_cli = Path.home() / ".hermes" / "act" / "venv" / "bin" / "act"
    if not act_cli.is_file() or not os.access(act_cli, os.X_OK):
        raise SystemExit(f"act-pair: managed ACT CLI is unavailable at {act_cli}")

    print("This QR can enroll a new operator device with ACT clearance authority.")
    print("It is one-time, expires after 10 minutes, and must remain private.")
    if input("Type PAIR to generate it locally: ").strip() != "PAIR":
        print("Pairing cancelled.")
        return

    completed = subprocess.run(
        [str(act_cli), "pair", "--qr"],
        check=False,
    )
    if completed.returncode != 0:
        raise SystemExit(f"act-pair: ACT exited with status {completed.returncode}")


def _register_pairing_cli(ctx) -> None:
    def setup(_subparser) -> None:
        # No JSON/export flag by design. The plugin surface renders only a
        # short-lived QR to a local interactive terminal.
        return None

    def handler(_args) -> None:
        _run_local_pairing_cli()

    ctx.register_cli_command(
        "act-pair",
        help="Generate a local, one-time ACT mobile pairing QR.",
        setup_fn=setup,
        handler_fn=handler,
        description=(
            "Operator-only ACT pairing ceremony. Requires a local interactive "
            "terminal and explicit confirmation; never exposed as an agent tool "
            "or gateway slash command."
        ),
    )


def register(ctx) -> None:
    ctx.register_hook("pre_tool_call", _on_pre_tool_call)
    ctx.register_hook("post_tool_call", _on_post_tool_call)
    ctx.register_hook("on_session_start", _on_session_start)
    ctx.register_hook("on_session_end", _on_session_end)
    ctx.register_hook("transform_terminal_output", _on_transform_terminal_output)
    # Operator-only bootstrap convenience. Keep this a top-level local CLI
    # command; register_command() would also expose it through remote gateways.
    try:
        _register_pairing_cli(ctx)
    except Exception:
        # A convenience command must never prevent the clearance hooks from
        # loading on an older or partially compatible Hermes runtime.
        pass
    # Self-heal: once enabled, ensure the supervised gateway is actually up. This
    # is a cheap is-it-up + kickstart on a background thread — non-blocking and
    # fully error-swallowing so it can never raise into the Hermes register path.
    if _enabled():
        threading.Thread(target=_self_heal_gateway, daemon=True).start()
    # Make the agent visible immediately (idle) so the fleet shows it before the
    # first tool call. Best-effort; no-op unless enabled.
    threading.Thread(
        target=_post_context,
        kwargs={"agent_status": "idle", "capabilities": _control_capabilities()},
        daemon=True,
    ).start()

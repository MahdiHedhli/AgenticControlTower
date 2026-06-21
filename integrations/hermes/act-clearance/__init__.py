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
ACT_QUESTION_RISK_FAMILY, ACT_CLEARANCE_RISK_FAMILY, ACT_CLEARANCE_TIMEOUT,
ACT_CLEARANCE_POLL.
act.toml keys: enabled, gateway_url, agent_id, agent_name, gated_tools,
question_tools, question_risk_family, clearance_risk_family.
"""

from __future__ import annotations

import json
import os
import subprocess
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
_DEFAULT_CLEARANCE_RISK_FAMILY = "external_effect"

# launchd Label of the supervised gateway (must match act_cli.LAUNCHD_LABEL).
_GATEWAY_LAUNCHD_LABEL = "app.act.gateway"

_TRUTHY = {"1", "true", "yes", "on"}


# --- config: ENV > act.toml > built-in default ------------------------------

def _act_toml_path() -> Path:
    return Path.home() / ".hermes" / "act" / "act.toml"


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
    return (_cfg("ACT_GATEWAY_URL", "gateway_url", _DEFAULT_GATEWAY) or _DEFAULT_GATEWAY).rstrip("/")


def _agent_id() -> str:
    return _cfg("ACT_CLEARANCE_AGENT_ID", "agent_id", "hermes_agent") or "hermes_agent"


def _agent_name() -> str:
    return _cfg("ACT_CLEARANCE_AGENT_NAME", "agent_name", "Hermes Agent") or "Hermes Agent"


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
        _cfg("ACT_QUESTION_RISK_FAMILY", "question_risk_family", _DEFAULT_QUESTION_RISK_FAMILY)
        or _DEFAULT_QUESTION_RISK_FAMILY
    ).strip()


def _clearance_risk_family() -> str:
    return (
        _cfg("ACT_CLEARANCE_RISK_FAMILY", "clearance_risk_family", _DEFAULT_CLEARANCE_RISK_FAMILY)
        or _DEFAULT_CLEARANCE_RISK_FAMILY
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


# --- HTTP (stdlib) ----------------------------------------------------------

def _request(method: str, path: str, payload: Optional[Dict[str, Any]], timeout: float) -> Dict[str, Any]:
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    headers = {"Content-Type": "application/json"} if data is not None else {}
    req = urllib.request.Request(f"{_gateway()}{path}", data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read().decode("utf-8")
    return json.loads(body) if body else {}


def _post(path: str, payload: Dict[str, Any], timeout: float = 10.0) -> Dict[str, Any]:
    return _request("POST", path, payload, timeout)


def _get(path: str, timeout: float = 10.0) -> Dict[str, Any]:
    return _request("GET", path, None, timeout)


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
    payload: Dict[str, Any] = {"agent_id": _agent_id(), "display_name": _agent_name()}
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


def _poll_question_answer(request_id: str, timeout_s: float, poll_s: float) -> Optional[str]:
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
            return result.get("return_summary") or "Operator returned control without a message."
        time.sleep(poll_s)
    return None


# --- control: clearance gate (existing, fail-closed) ------------------------

def _relay_clearance(tool_name: str, args: Any, session_id: str) -> Optional[Dict[str, str]]:
    risk_family = _clearance_risk_family()
    timeout_s = _timeout()
    try:
        created = _post(
            "/hermes/tools/approval_requested",
            {
                "requested_tool": tool_name,
                "risk_level": "high",
                "risk_family": risk_family,
                "summary": f"Hermes agent requests to run '{tool_name}'.",
                "payload_redacted": _redacted_payload(tool_name, args),
                "agent_id": _agent_id(),
                "session_id": session_id or "hermes_session",
                "expires_in_seconds": int(timeout_s) + 30,
                "suggested_scopes": ["once"],
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
            status = _post("/hermes/tools/approval_status", {"approval_id": approval_id})
        except (urllib.error.URLError, OSError, ValueError):
            time.sleep(poll_s)
            continue
        state = status.get("state")
        if state == "approved":
            return None  # allow
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
    if _is_in("ACT_QUESTION_TOOLS", "question_tools", _DEFAULT_QUESTION_TOOLS, tool_name):
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
    if _is_in("ACT_CLEARANCE_GATED_TOOLS", "gated_tools", _DEFAULT_GATED_TOOLS, tool_name):
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


def register(ctx) -> None:
    ctx.register_hook("pre_tool_call", _on_pre_tool_call)
    ctx.register_hook("post_tool_call", _on_post_tool_call)
    ctx.register_hook("on_session_start", _on_session_start)
    ctx.register_hook("on_session_end", _on_session_end)
    ctx.register_hook("transform_terminal_output", _on_transform_terminal_output)
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

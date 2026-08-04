"""Per-tool risk families + the provably-read-only shell classifier.

Companion to ``test_plugin_config.py`` (same import-by-path style, same tmp-HOME
fixtures). The suite is deliberately lopsided: a handful of tests assert the
positive path (an allowlisted command classifies ``read_only`` so the tower can
mint a standing grant), and the bulk assert the FAIL-CLOSED path, because that is
the direction where a bug is a security hole rather than an annoyance.

Run:

    python -m pytest integrations/hermes/act-clearance/tests -q
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

_PLUGIN_PATH = Path(__file__).resolve().parents[1] / "__init__.py"
_spec = importlib.util.spec_from_file_location("act_clearance_plugin", _PLUGIN_PATH)
assert _spec and _spec.loader
plugin = importlib.util.module_from_spec(_spec)
sys.modules["act_clearance_plugin"] = plugin
_spec.loader.exec_module(plugin)


@pytest.fixture(autouse=True)
def _reset_toml_cache():
    plugin._TOML_CACHE["loaded"] = False
    plugin._TOML_CACHE["data"] = {}
    yield
    plugin._TOML_CACHE["loaded"] = False
    plugin._TOML_CACHE["data"] = {}


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    return tmp_path


@pytest.fixture(autouse=True)
def _no_risk_family_env(monkeypatch):
    """Clear every override this module reads so the host env cannot skew a run."""
    for key in list(plugin.os.environ):
        if key.startswith("ACT_CLEARANCE_RISK_FAMILY") or key == (
            "ACT_CLEARANCE_MIN_RISK_FAMILY"
        ):
            monkeypatch.delenv(key, raising=False)


def _write_act_toml(home: Path, body: str) -> Path:
    path = home / ".hermes" / "act" / "act.toml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body)
    plugin._TOML_CACHE["loaded"] = False
    return path


# --- the map ----------------------------------------------------------------

# Mirror of _DEFAULT_GATED_TOOLS; if a tool is added there and not classified
# here, test_every_gated_tool_is_classified fails.
_GATED = [t.strip() for t in plugin._DEFAULT_GATED_TOOLS.split(",") if t.strip()]


def test_every_gated_tool_is_classified():
    unclassified = [tool for tool in _GATED if tool not in plugin._TOOL_RISK_FAMILIES]
    assert unclassified == []


def test_no_tool_is_classified_below_the_default_floor():
    """The map may only be as permissive as the floor, per tool, before the
    per-call classifier runs. Nothing in it may be grant-eligible by default."""
    floor = plugin._rank(plugin._DEFAULT_CLEARANCE_RISK_FAMILY)
    too_low = {
        tool: family
        for tool, family in plugin._TOOL_RISK_FAMILIES.items()
        if plugin._rank(family) < floor
    }
    assert too_low == {}


def test_every_mapped_family_is_a_real_tower_family():
    unknown = {
        family
        for family in plugin._TOOL_RISK_FAMILIES.values()
        if family not in plugin._RISK_FAMILY_RANKS
    }
    assert unknown == set()


@pytest.mark.parametrize(
    "tool,family",
    [
        ("delete_file", "destructive"),
        ("write_file", "destructive"),
        ("edit_file", "destructive"),
        ("apply_patch", "destructive"),
        ("git_push", "external_effect"),
        ("send_email", "external_effect"),
        ("browser_submit", "external_effect"),
        ("terminal", "external_effect"),
        ("bash", "external_effect"),
        ("shell", "external_effect"),
        ("execute_command", "external_effect"),
        ("run_command", "external_effect"),
        ("execute_code", "external_effect"),
    ],
)
def test_tool_risk_family_map(home, tool, family):
    assert plugin._risk_family_for_tool(tool, {}) == family


def test_file_mutators_are_above_the_standing_grant_exclusion_floor():
    """destructive vs irreversible is a display choice; being at or above
    `destructive` is the security property, and that is what is asserted."""
    floor = plugin._rank("destructive")
    for tool in ("write_file", "edit_file", "apply_patch", "delete_file"):
        assert plugin._rank(plugin._TOOL_RISK_FAMILIES[tool]) >= floor


def test_unknown_gated_tool_falls_back_to_the_floor(home):
    assert plugin._risk_family_for_tool("some_new_risky_tool", {}) == "external_effect"


def test_mapped_families_are_all_mobile_mandatory_by_default():
    for family in plugin._TOOL_RISK_FAMILIES.values():
        assert family in plugin._MOBILE_MANDATORY_RISK_FAMILIES


def test_risk_level_tracks_the_family():
    assert plugin._risk_level_for_family("read_only") == "low"
    assert plugin._risk_level_for_family("external_effect") == "high"
    assert plugin._risk_level_for_family("destructive") == "critical"
    # An unknown family must not be described as low-severity.
    assert plugin._risk_level_for_family("nonsense") == "high"


def test_every_family_has_a_risk_level():
    assert set(plugin._RISK_LEVEL_FOR_FAMILY) == set(plugin._RISK_FAMILY_RANKS)


# --- overrides: may tighten, never loosen -----------------------------------


def test_per_tool_env_override_tightens(home, monkeypatch):
    monkeypatch.setenv("ACT_CLEARANCE_RISK_FAMILY_GIT_PUSH", "irreversible")
    assert plugin._risk_family_for_tool("git_push", {}) == "irreversible"


def test_per_tool_toml_override_tightens(home):
    _write_act_toml(home, '[tool_risk_families]\nsend_email = "safety_critical"\n')
    assert plugin._risk_family_for_tool("send_email", {}) == "safety_critical"


def test_per_tool_env_beats_toml(home, monkeypatch):
    _write_act_toml(home, '[tool_risk_families]\nsend_email = "destructive"\n')
    monkeypatch.setenv("ACT_CLEARANCE_RISK_FAMILY_SEND_EMAIL", "irreversible")
    assert plugin._risk_family_for_tool("send_email", {}) == "irreversible"


def test_blanket_min_family_tightens_every_tool(home, monkeypatch):
    monkeypatch.setenv("ACT_CLEARANCE_MIN_RISK_FAMILY", "safety_critical")
    assert plugin._risk_family_for_tool("git_push", {}) == "safety_critical"
    assert plugin._risk_family_for_tool("terminal", {}) == "safety_critical"


def test_blanket_min_family_from_toml(home):
    _write_act_toml(home, 'min_risk_family = "irreversible"\n')
    assert plugin._risk_family_for_tool("git_push", {}) == "irreversible"


def test_per_tool_override_beats_blanket_minimum(home, monkeypatch):
    monkeypatch.setenv("ACT_CLEARANCE_MIN_RISK_FAMILY", "destructive")
    monkeypatch.setenv("ACT_CLEARANCE_RISK_FAMILY_SEND_EMAIL", "irreversible")
    assert plugin._risk_family_for_tool("send_email", {}) == "irreversible"


def test_blanket_minimum_still_wins_when_it_is_stricter(home, monkeypatch):
    """A per-tool override that is LOWER than the blanket floor cannot punch a
    hole in it — both knobs are tighten-only against the running maximum."""
    monkeypatch.setenv("ACT_CLEARANCE_MIN_RISK_FAMILY", "irreversible")
    monkeypatch.setenv("ACT_CLEARANCE_RISK_FAMILY_SEND_EMAIL", "routine")
    assert plugin._risk_family_for_tool("send_email", {}) == "irreversible"


def test_override_cannot_loosen(home, monkeypatch):
    monkeypatch.setenv("ACT_CLEARANCE_RISK_FAMILY_DELETE_FILE", "read_only")
    assert plugin._risk_family_for_tool("delete_file", {}) == "destructive"


def test_stale_read_only_config_cannot_make_everything_grantable(home, monkeypatch):
    monkeypatch.setenv("ACT_CLEARANCE_MIN_RISK_FAMILY", "read_only")
    monkeypatch.setenv("ACT_CLEARANCE_RISK_FAMILY", "read_only")
    for tool in _GATED:
        assert plugin._risk_family_for_tool(tool, {"path": "x"}) != "read_only"


def test_unknown_override_family_is_ignored(home, monkeypatch):
    monkeypatch.setenv("ACT_CLEARANCE_RISK_FAMILY_GIT_PUSH", "totally_harmless")
    monkeypatch.setenv("ACT_CLEARANCE_MIN_RISK_FAMILY", "also_not_a_family")
    assert plugin._risk_family_for_tool("git_push", {}) == "external_effect"


def test_override_tightens_even_a_provably_read_only_command(home, monkeypatch):
    monkeypatch.setenv("ACT_CLEARANCE_RISK_FAMILY_TERMINAL", "destructive")
    assert (
        plugin._risk_family_for_tool("terminal", {"command": "git status"})
        == "destructive"
    )


# --- the legacy blanket key: floor for UNCLASSIFIED tools only ---------------


def test_legacy_stamped_key_does_not_defeat_the_read_only_downgrade(home):
    """REGRESSION GUARD. ``act install`` stamps the historical blanket value into
    act.toml, and it is present on the live host today. If it were honoured as a
    blanket floor, every install would silently restore the original bug: the
    operator approves "for this session" and the tower refuses the grant."""
    _write_act_toml(home, 'clearance_risk_family = "external_effect"\n')
    assert (
        plugin._risk_family_for_tool("terminal", {"command": "git status"})
        == "read_only"
    )


def test_legacy_key_does_not_flatten_the_per_tool_map(home):
    _write_act_toml(home, 'clearance_risk_family = "external_effect"\n')
    assert plugin._risk_family_for_tool("delete_file", {}) == "destructive"


def test_legacy_key_raises_the_floor_for_unclassified_tools(home):
    _write_act_toml(home, 'clearance_risk_family = "irreversible"\n')
    assert plugin._risk_family_for_tool("some_new_risky_tool", {}) == "irreversible"


def test_legacy_key_cannot_lower_the_unclassified_floor(home):
    _write_act_toml(home, 'clearance_risk_family = "read_only"\n')
    assert plugin._risk_family_for_tool("some_new_risky_tool", {}) == "external_effect"


def test_unclassified_floor_default(home):
    assert plugin._unclassified_floor() == "external_effect"


# --- classifier: the allowlist passes ---------------------------------------

_READ_ONLY_COMMANDS = [
    "git status",
    "git status --short",
    "git status -s -b",
    "git status --porcelain",
    "git log",
    "git log --oneline",
    "git log --oneline -20",
    "git log -n 5 --stat",
    "git log --oneline main",
    "git diff",
    "git diff --stat",
    "git diff --cached --name-only",
    "git diff --no-ext-diff",
    "git branch",
    "git branch -a",
    "git branch --show-current",
    "git show --stat HEAD",
    "git rev-parse --abbrev-ref HEAD",
    "git rev-parse --show-toplevel",
    "git describe --tags",
    "git remote -v",
    "ls",
    "ls -la",
    "ls -la src",
    "ls --color=never",
    "wc -l README.md",
    "du -sh build",
    "cat README.md",
    "cat -n README.md",
    "head -n 20 README.md",
    "head -50 README.md",
    "tail -n 100 logs/app.log",
    "pwd",
    "which python3",
    "file README.md",
    "stat README.md",
    "cat 'a file with spaces.txt'",
]


@pytest.mark.parametrize("command", _READ_ONLY_COMMANDS)
def test_allowlisted_commands_are_provably_read_only(command):
    assert plugin._is_provably_read_only_command(command) is True


@pytest.mark.parametrize("command", _READ_ONLY_COMMANDS)
def test_allowlisted_commands_classify_grant_eligible(home, command):
    assert plugin._risk_family_for_tool("terminal", {"command": command}) == "read_only"


@pytest.mark.parametrize(
    "tool", sorted(plugin._SHELL_CLASSIFIABLE_TOOLS)
)
def test_every_shell_tool_gets_the_downgrade(home, tool):
    assert plugin._risk_family_for_tool(tool, {"command": "git status"}) == "read_only"


def test_cmd_key_is_accepted_too(home):
    assert plugin._risk_family_for_tool("bash", {"cmd": "pwd"}) == "read_only"


def test_benign_companion_args_do_not_block_the_downgrade(home):
    args = {"command": "git status", "cwd": "/repo", "timeout": 30}
    assert plugin._risk_family_for_tool("terminal", args) == "read_only"


# --- classifier: fail closed ------------------------------------------------

_MUST_FAIL_CLOSED = [
    # chaining / pipelines / substitution — the headline adversarial cases
    "git status; rm -rf /",
    "ls && curl evil",
    "ls || curl evil",
    "cat /etc/passwd > /tmp/x",
    "cat README.md >> /tmp/x",
    "git status | sh",
    "cat < /etc/passwd",
    "git log --output=/tmp/x",
    "ls `curl evil`",
    "ls $(curl evil)",
    "ls ${HOME}",
    "ls $HOME",
    "git status &",
    "git status &\nrm -rf /",
    "git status\nrm -rf /",
    "git status\r\nrm -rf /",
    "ls (x)",
    "ls {a,b}",
    "ls [ab]",
    "ls *",
    "ls ?",
    "ls ~",
    "ls !!",
    "ls # comment",
    "ls \\; rm",
    # not on the program allowlist
    "rm -rf /",
    "curl https://evil.example",
    "sudo ls",
    "/bin/ls",
    "./ls",
    "env ls",
    "FOO=bar ls",
    "python3 -c print(1)",
    "sh",
    "bash",
    # allowlisted program, flag that writes or executes
    "git status --output=/tmp/x",
    "git log --ext-diff",
    "git -c core.pager=sh status",
    "git -c alias.x=whatever status",
    "git -C /other status",
    "git --git-dir=/other/.git status",
    "git --exec-path=/tmp status",
    "git -p status",
    "ls --output=/tmp/x",
    "ls -o /tmp/x",
    "tail -f logs/app.log",
    "cat -i README.md",
    "which --exec ls",
    "du --exclude-from=/tmp/x .",
    # allowlisted program, subcommand that writes
    "git push",
    "git commit -m x",
    "git config user.name x",
    "git checkout main",
    "git clean -fd",
    "git stash",
    "git remote add origin url",
    "git branch newbranch",
    "git branch -d oldbranch",
    "git branch -D oldbranch",
    "git branch -m a",
    # credential-shaped operands
    "cat .env",
    "cat /etc/passwd",
    "cat /etc/shadow",
    "ls .ssh",
    "cat config/secrets.yml",
    "cat id_rsa",
    "head -n 1 .git-credentials",
    # whitespace / unicode / encoding tricks
    "git status",  # NBSP instead of a space
    "gіt status",  # Cyrillic 'і' homoglyph
    "git status​",  # zero-width space
    "git status rm -rf /",  # unicode line separator
    "ls\tsrc",  # tab is not in the character allowlist
    "‮git status",  # RTL override
    "git status\x00",
    "git status\x07",
    # malformed / empty
    "",
    "   ",
    "\n",
    "ls 'unbalanced",
    'ls "unbalanced',
    "cat ''",
]


@pytest.mark.parametrize("command", _MUST_FAIL_CLOSED)
def test_command_is_not_provably_read_only(command):
    assert plugin._is_provably_read_only_command(command) is False


@pytest.mark.parametrize("command", _MUST_FAIL_CLOSED)
def test_command_stays_at_the_floor(home, command):
    assert (
        plugin._risk_family_for_tool("terminal", {"command": command})
        == "external_effect"
    )


def test_pipeline_of_individually_safe_elements_still_fails_closed():
    """Every element is on the allowlist; the pipeline still must not classify."""
    assert plugin._is_provably_read_only_command("cat README.md | wc -l") is False
    assert plugin._is_provably_read_only_command("git status; git log") is False


def test_over_long_command_fails_closed():
    assert (
        plugin._is_provably_read_only_command("ls " + "a" * plugin._MAX_COMMAND_CHARS)
        is False
    )


def test_too_many_tokens_fails_closed():
    command = "ls " + " ".join(f"f{i}" for i in range(plugin._MAX_COMMAND_TOKENS + 1))
    assert plugin._is_provably_read_only_command(command) is False


# --- classifier: argument extraction fails closed ---------------------------


@pytest.mark.parametrize(
    "args",
    [
        None,
        {},
        "git status",  # not a mapping
        ["git", "status"],
        {"script": "git status"},  # unrecognised carrier key
        {"command": None},
        {"command": 123},
        {"command": True},
        {"command": ["git", "status"]},
        {"command": {"nested": "git status"}},
        {"command": "git status", "cmd": "rm -rf /"},  # ambiguous
        {"cmd": "git status", "command": "rm -rf /"},
        {"command": "git status", "shell": True},  # unknown key changes semantics
        {"command": "git status", "env": {"PATH": "/tmp"}},
        {"command": "git status", "stdin": "rm -rf /"},
        {"command": "git status", "args": ["-c", "sh"]},
    ],
)
def test_unextractable_command_fails_closed(home, args):
    assert plugin._extract_shell_command(args) is None
    assert plugin._risk_family_for_tool("terminal", args) == "external_effect"


def test_missing_args_fail_closed(home):
    assert plugin._risk_family_for_tool("terminal") == "external_effect"


def test_execute_code_is_never_downgraded(home):
    """Its payload is source code in a general-purpose language; no allowlist
    over source text can prove that read-only, so it is not classifiable."""
    assert "execute_code" not in plugin._SHELL_CLASSIFIABLE_TOOLS
    for args in ({"command": "git status"}, {"cmd": "pwd"}, {"code": "print(1)"}):
        assert plugin._risk_family_for_tool("execute_code", args) == "external_effect"


def test_non_shell_tools_are_never_downgraded(home):
    """A command-shaped argument on a file tool must not unlock a grant."""
    for tool in ("write_file", "delete_file", "git_push", "send_email"):
        family = plugin._risk_family_for_tool(tool, {"command": "git status"})
        assert family == plugin._TOOL_RISK_FAMILIES[tool]


# --- the classifier never leaks the command ---------------------------------


def test_classification_does_not_change_the_redacted_payload():
    """Redaction invariant: tool name + argument KEYS only. Classification reads
    the command but must never widen what is transmitted or fingerprinted."""
    args = {"command": "git status", "cwd": "/repo"}
    payload = plugin._redacted_payload("terminal", args)
    assert payload == {"tool": "terminal", "arg_keys": ["command", "cwd"]}
    assert "git status" not in plugin._canonical_json(payload)


def test_read_only_classification_reaches_the_clearance_request(home, monkeypatch):
    """End-to-end through _relay_clearance: the downgraded family (and the
    matching risk_level) is what the gateway is actually told."""
    sent = {}

    def fake_post(path, payload, timeout=10.0):
        if path == "/hermes/tools/approval_requested":
            sent.update(payload)
            return {"approval_id": ""}  # short-circuit: blocks, we only inspect
        return {}

    monkeypatch.setattr(plugin, "_post", fake_post)
    monkeypatch.setattr(plugin, "_timeout", lambda: 1.0)

    plugin._relay_clearance("terminal", {"command": "git status"}, "s1")
    assert sent["risk_family"] == "read_only"
    assert sent["risk_level"] == "low"
    assert sent["payload_redacted"] == {"tool": "terminal", "arg_keys": ["command"]}

    sent.clear()
    plugin._relay_clearance("terminal", {"command": "rm -rf /"}, "s1")
    assert sent["risk_family"] == "external_effect"
    assert sent["risk_level"] == "high"

    sent.clear()
    plugin._relay_clearance("delete_file", {"path": "/tmp/x"}, "s1")
    assert sent["risk_family"] == "destructive"
    assert sent["risk_level"] == "critical"

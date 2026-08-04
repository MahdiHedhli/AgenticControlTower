# act-clearance — Hermes ↔ ACT control-plane bridge

An in-process Hermes plugin that makes the operator's paired Secure-Enclave phone a
first-class control surface for the real Hermes agent. Three planes:

- **Monitoring** — session/tool lifecycle hooks upsert the real agent / session / mission
  into ACT (`POST /v1/runtime/context`) so the app's dashboard / agents / task-visibility
  show the **real** agent live.
- **Clearance** — risky tools raise an ACT clearance via `pre_tool_call` and **block**
  until approved on the phone (fail-closed on deny/expiry/timeout/gateway error).
- **Interactive questions** — designated "ask" tools (`clarify`) raise an ACT TUA request
  and block until the operator answers on the phone; the operator's typed reply is
  returned to the agent.

Default-OFF: every hook is a no-op unless `ACT_CLEARANCE_ENABLED=1` or the ACT
config enables it (and the plugin is in Hermes `plugins.enabled`), so installing
the files alone cannot disrupt a live agent.

See [docs/implementation/act-010-hermes-control-bridge.md](../../../docs/implementation/act-010-hermes-control-bridge.md)
(bridge) and [act-009](../../../docs/implementation/act-009-hermes-clearance-plugin.md)
(clearance) for design + verification.

## Install and update

```sh
act install
act plugin-check
```

`act install` copies the bundled plugin into `~/.hermes/plugins/act-clearance`,
writes an owner-only SHA-256 release manifest, and enables the plugin. Restart
Hermes after an update so its in-memory module matches the installed release.
`act plugin-check` is read-only; `act doctor` runs the same version and integrity
check. The ACT mobile Settings screen also compares the managed, installed, and
Hermes-loaded versions and alerts when an install or restart is recommended.

Risky tool calls fail closed when the managed manifest is missing, a plugin file
has drifted, or Hermes still has an older plugin version loaded.

## Risk classification (what the operator can actually grant)

Each gated tool is classified by its **capability ceiling**, not its typical use:

| Tools | Risk family |
| --- | --- |
| `delete_file`, `write_file`, `edit_file`, `apply_patch` | `destructive` |
| `git_push`, `send_email`, `browser_submit` | `external_effect` |
| `terminal`, `bash`, `shell`, `execute_command`, `run_command`, `execute_code` | `external_effect` (**floor** — the ceiling is unbounded) |
| anything else gated | `external_effect` |

All of those are mobile-mandatory, so the tower will never satisfy them from a
standing grant — approving "for this session" on the phone correctly yields
nothing but a single-use clearance.

### Shell commands are deliberately NOT content-classified

**The command string is never inspected.** `terminal`, `bash`, `shell`,
`execute_command`, `run_command`, and `execute_code` sit at their `external_effect`
floor unconditionally, whatever the arguments look like. `{"command": "ls -la"}`
and `{"command": "rm -rf /"}` are classified identically.

**What the operator loses, stated plainly: standing grants are unreachable for
terminal work.** Every shell call needs a tap on the phone, every time. There is
no "approve `git status` for this session".

An earlier version did downgrade "provably read-only" commands to `read_only` —
an allowlist of characters, of programs, and of flags per program, with operands
resolved against the call's `cwd`. Three independent adversarial reviews broke
it, each time at whichever layer had just been added, while the token parser
itself held:

1. **Round 1 — proven arbitrary code execution at `read_only`.** `git` runs
   helper programs named by the *repository's own* `.git/config` and
   `.gitattributes`: `core.fsmonitor` fires on `git status`, a
   `diff.<name>.command` driver fires on `git diff`. None of it appears on the
   command line the classifier is shown, and one prior approved write inside a
   repo (or cloning a hostile one) arms it. Same review: `cwd` was validated by
   key *name* only, so `{"command": "cat config", "cwd": ".../.ssh"}` read a
   private key while naming no secret anywhere.
2. **Round 2 — path normalisation defeated three ways**, after `git` was dropped
   and `cwd` resolution was added. POSIX permits an implementation-defined
   meaning for a leading `//`, so `posixpath.normpath` preserves exactly two
   leading slashes and `//dev/urandom` walked past the `/dev` prefix check while
   still opening the device; a relative operand with *no* `cwd` returned "safe"
   before the device check ran at all; and `cwd: "//dev"` passed validation for
   the same reason as the first. `//dev/ptmx` allocates a pty pair on open and
   `//dev/tty` steals the operator's terminal input.
3. **Round 3 — the cost/benefit stopped holding.** Round 2 had already removed
   the feature's real use case (`git status`, `git log`). What was left was a
   handful of commands on non-device paths, guarding a feature whose failure mode
   is unattended code execution with no human in the loop.

The structural problem is not any one of those bugs: **this plugin labels a
string that somebody else then executes.** It does not control the environment,
the shell, `PATH`, the config files the program will read, or the filesystem
between the check and the run. Every "proof" it can offer is a claim about text,
while what actually happens is decided by state the text never mentions.

**If this capability is wanted later, the correct design is for the tower to
execute the command itself** in a hardened, config-neutralised environment it
owns — scrubbed environment, no user or repo config honoured, no device or
pseudo-filesystem paths reachable, resource- and time-bounded, output captured —
and report the result. Then "read-only" is a property of a sandbox the tower
controls rather than an assertion about a string another party will run. That is a
different component, not a bigger allowlist.

The exploit fixtures are kept as permanent tests
(`tests/test_risk_classification.py`) and now assert that those inputs land at the
floor, so any future attempt to reintroduce a downgrade trips them.

Overrides (ENV > `act.toml`) may **tighten only**:

- `ACT_CLEARANCE_RISK_FAMILY_<TOOL>` / `[tool_risk_families]` — per tool;
- `ACT_CLEARANCE_MIN_RISK_FAMILY` / `min_risk_family` — blanket floor;
- `ACT_CLEARANCE_RISK_FAMILY` / `clearance_risk_family` — floor for **unclassified**
  tools only. It is not a blanket: `act install` stamps it with the historical
  value, and honouring that as a blanket would silently restore the original bug.

A family name that is unknown, or that would lower a tool's family, is ignored.

## Pair a phone from Hermes

```sh
hermes act-pair
```

This operator-only command requires a directly attached interactive terminal,
warns that the QR grants clearance authority, requires typing `PAIR`, and then
renders ACT's one-time 10-minute QR locally. It intentionally offers no JSON or
redirection mode.

Pairing is **not** registered as an agent tool or `/slash` command. Hermes makes
plugin slash commands available to gateway sessions such as Discord and Slack;
returning a device-enrollment secret through those surfaces would cross the
local-operator trust boundary and could expose it to chat history, logs, or an
untrusted prompt.

## Run (default-off until you set the env gate)

```sh
ACT_CLEARANCE_ENABLED=1 \
ACT_GATEWAY_URL=http://127.0.0.1:8788/v1 \
ACT_CLEARANCE_AGENT_ID=colpanic_m2 \
ACT_CLEARANCE_AGENT_NAME=ColPanicM2 \
ACT_QUESTION_TOOLS=clarify \
hermes ...
```

Without `ACT_CLEARANCE_ENABLED=1` the hook is a no-op, so the plugin cannot affect an
agent that has not opted in. See the doc for all config env vars.

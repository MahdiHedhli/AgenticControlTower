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

**The exception that makes standing grants usable:** when a shell tool's command
is *provably* read-only it is classified `read_only` for that call, which is
grant-eligible. "Provably" is a fail-closed allowlist, not a filter:

- an allowlist of characters — any shell metacharacter, escape, newline, control
  character, or non-ASCII codepoint rejects the command outright, so a pipeline
  or `;`-chain can never be classified read-only even if every element is safe;
- an allowlist of programs (`ls`, `cat`, `head`, `tail`, `wc`, `du`, `pwd`,
  `which`, `stat`) and **flags per program** — a flag nobody allowlisted is
  simply not classifiable;
- operands that look like credential paths (`.env`, `.ssh`, `id_rsa`, `.pem`,
  `token`, `secret`, …) fall back to the floor, and the check is applied to the
  operand **resolved against the call's `cwd`**, not to the text as written —
  `{"command": "cat config", "cwd": ".../.ssh"}` names no secret anywhere but
  reads one, so a `cwd` that cannot be pinned to an exact absolute path (missing
  is fine; relative, `~`, non-string, or two `cwd`-ish keys at once are not)
  fails the whole classification closed;
- operands resolving under `/dev`, `/proc`, or `/sys` fall back to the floor:
  consuming from a FIFO or character device is a side effect, and several such
  reads never return;
- `execute_code` is never classified: no allowlist over source text can prove a
  program read-only.

Anything the classifier does not positively recognise — including an unparsable,
missing, non-string, or ambiguous command argument — stays at the floor.

**`git` is deliberately NOT classifiable, and neither is `file`.** `git` executes
helper programs named by the *repository's own* `.git/config` and
`.gitattributes` — `core.fsmonitor` fires on `git status`, a `diff.<name>.command`
driver fires on `git diff` — none of which appear on the command line. One prior
approved write inside a repo, or cloning a hostile one, turns a read-shaped git
command into arbitrary code execution. Because this plugin only *classifies* and
never *executes*, it cannot inject hardening flags; and the set of config keys git
will run a program from is open-ended (driver names come from `.gitattributes`)
and grows between releases, so no allowlist of them can be proven complete. An
incomplete one here is an RCE, so `git` falls to `external_effect` and always
needs a human tap. `file` is out for the same class of reason: libmagic honours
`$MAGIC` and `~/.magic`. **This is a real cost — `git status` and `git log` were
the main day-to-day use of the downgrade.**

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

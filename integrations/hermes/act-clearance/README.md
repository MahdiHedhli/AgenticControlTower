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

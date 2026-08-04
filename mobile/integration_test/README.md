# ACT mobile — end-to-end simulator smoke

The regression net for the incidents in
[`docs/implementation/ios-recurring-failure-modes.md`](../../docs/implementation/ios-recurring-failure-modes.md).

Every one of those shipped, and every one was caught only by a human staring at
a phone. Each scenario here reproduces one of them automatically: the **real
app**, on the **iOS Simulator**, against a **real gateway built from this
repo**, with widget-level assertions.

## Run it

```bash
mobile/scripts/e2e-smoke.sh
```

That is the whole thing. It boots (or reuses) the simulator, starts a scratch
gateway on a private port with a throw-away database, seeds fixtures over the
gateway's own HTTP API, runs every scenario, answers the Face ID prompts, tears
the gateway down, prints a pass/skip/fail table and exits non-zero if anything
failed.

One manual prerequisite: **Simulator > Features > Face ID > Enrolled** — see
below.

```bash
mobile/scripts/e2e-smoke.sh --verbose              # stream flutter output
mobile/scripts/e2e-smoke.sh --scenario app_boot    # one scenario
mobile/scripts/e2e-smoke.sh --keep-gateway         # leave the gateway up to poke at
mobile/scripts/e2e-smoke.sh --udid <UDID>          # a different simulator
mobile/scripts/e2e-smoke.sh --strict               # CI: a SKIP is a failure
```

Overrides: `ACT_E2E_UDID`, `FLUTTER_BIN`, `ACT_E2E_PYTHON`,
`ACT_E2E_SCENARIO_TIMEOUT` (seconds; a scenario that exceeds it is killed and
reported as a failure rather than stalling the run).

### One-time simulator setup: enrol Face ID

**Simulator > Features > Face ID > Enrolled**, once per booted device.

This cannot be scripted. Biometric enrolment on a simulator is in-memory state
owned by Simulator.app; `notifyutil -s com.apple.BiometricKit_Sim.pearl.enroll 1`
is silently refused, and `simctl` has no biometric subcommand. **It is lost
whenever the device reboots or is erased.**

Without it, `evaluatePolicy(.deviceOwnerAuthentication)` falls back to a
passcode field no test can fill. Rather than hang on it, the suite adapts:

- `pairing` — reports **SKIP** with that reason. It is the one scenario that
  genuinely needs the biometric prompt.
- `approvals`, `standing_grants` — pair over the app's software-Ed25519 path
  instead. Real signed transport and real signed decisions against a real
  gateway are still exercised; the enclave/Face ID pairing path is not.

A SKIP is never counted as green.

Running `flutter test integration_test/...` by hand works too, but scenarios
that need a gateway will report themselves **skipped** with the reason in the
test name — they never silently pass.

### What the driver owns

| Concern | How |
|---|---|
| Port | first free port in **8950–8968**; **8969 is deliberately left closed** as the unreachable endpoint for the degradation scenarios |
| Database | fresh SQLite under a `TemporaryDirectory`, deleted on exit |
| Gateway process | `uvicorn` from `gateway/.venv` (provisioned with `uv sync --frozen` if missing) |
| Face ID | posts `pearl.match` every 400 ms for the whole run (see the enrolment caveat below) |
| Stale app | terminates a leftover `Runner` before each scenario |
| iCloud detritus | `xattr -cr mobile` before building |

It never touches `~/.hermes`, ports 8787/8788, `tailscale serve`, or a physical
device.

## Scenarios

| File | Incident it guards | Assertion in one line |
|---|---|---|
| `app_boot_test.dart` | **A3 black screen** — `runApp()` behind `await _registerPushToken()` | a first frame arrives within budget even when the push channel *never answers*, and the app still navigates |
| `pairing_test.dart` | **B1 contract drift**, mock-masquerading-as-live, **C1 lying capability probe** | real pairing succeeds, the Inbox shows a gateway-minted fixture and none of the mock's strings, and Settings reports `software_p256_dev` — not `secure_enclave_p256` |
| `approvals_test.dart` | **A1 unsettled biometric futures**, **D2 protocol tokens as prose** | a server-minted approval appears, its options read as sentences, Approve settles, and the **gateway** records `approved` |
| `standing_grants_test.dart` | standing grants not consumed | after `scope=session`, a byte-identical repeat is `approved` with `approved_by=standing_grant`, and no second prompt reaches the Inbox |
| `resilience_test.dart` | **D1 raw errors as UI**, infinite spinner, black screen | a dead port degrades to a human sentence with Retry / Open Settings — no spinner, no dump |

`support/e2e_support.dart` holds the shared assertions. The three that encode
the failure modes directly:

- `expectRenderedFrame` — something is on screen (not LaunchScreen forever)
- `expectNoSpinner` — nothing is still loading that never will
- `expectNoRawExceptionText` — no `PlatformException` / `Exception:` /
  `SocketException` / `#0 ` in any rendered `Text`

## Proving the net actually catches things

A suite that cannot fail is the thing this exists to prevent. To verify the
black-screen guard, reintroduce the bug in `mobile/lib/main.dart`:

```dart
Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  final runtime = await HermesAppRuntime.create();   // ← the bug
  runApp(HermesMobileApp(runtime: runtime));
}
```

`mobile/scripts/e2e-smoke.sh --scenario app_boot` then fails with

```
BLACK SCREEN REGRESSION: the push-token provider never answered and the first
frame never arrived. runApp() must not be gated on push registration, a
platform channel, or the network.
```

Revert and it goes green again.

## Flakiness, and what the harness does about it

The simulator is a shared, stateful machine, and two failure shapes here are
*stalls* rather than failures — the test framework's own timeout cannot fire,
because `tester.pump()` never returns when the app stops producing frames.
Observed roughly once in eight scenario runs, always in the launch/build phase.

Mitigations, in order of how much they matter:

1. **`SCENARIO_TIMEOUT_SECONDS` (default 420, `ACT_E2E_SCENARIO_TIMEOUT`).**
   The driver kills a scenario that exceeds it and reports `TIMED OUT`. A
   harness that can stall forever is not a harness.
2. **Per-scenario log files, not pipes.** `flutter` block-buffers into a pipe,
   so a killed scenario used to come back with three lines of output. The tail
   printed on failure is now the real tail.
3. **Stale `Runner` killed before every scenario**, and `flutter pub get` run
   once up front rather than per scenario.
4. **A gateway per scenario**, each with an empty database, so no fixture from
   one scenario can decide another's assertions.

If a run does stall, `xcrun simctl uninstall <UDID> app.act.agenticControlTower`
followed by a re-run clears it. A stuck system alert is the usual cause.

## What this CANNOT cover

State it plainly, because a green run here is **not** a green run on a device:

- **Secure Enclave / hardware attestation.** There is no enclave on a
  simulator. The native signer takes its honest `software_p256_dev` path, so
  the suite validates the *flow* — key generation, possession proof, signed
  transport, signed decisions — and never the hardware-binding guarantee.
  `pairing_test` asserts the app *says so*; it cannot assert the real thing.
- **Real APNs.** Push registration does not exist on a simulator;
  `simctl push` only simulates *handling* a payload, never the registration
  round-trip. The black-screen scenario therefore *simulates* the hostile push
  provider with a method-channel handler that never answers. That reproduces the
  incident's shape exactly, but the real APNs path needs a device.
- **Real biometrics.** Face ID is answered by a Darwin notification, not a face.
  Prompt *policy* (fresh evaluation for clearance decisions, reuse window for
  routine reads) is exercised; user-presence enforcement is not.
- **Device-only divergences.** The simulator ignores
  `touchIDAuthenticationAllowableReuseDuration`, and codesigning, provisioning
  profiles and entitlements are not exercised at all.
- **Release-mode behaviour.** These run a debug build. Debug-only assertions
  fire here (which is useful — one of them found a real defect) and tree-shaking
  or release-only timing differences do not.
- **The physical phone, production gateway, and `tailscale serve`.** Out of
  scope by construction.

Anything touching biometrics, the Secure Enclave, or push still has to be
verified on a device before it counts as verified.

## Simulator techniques used here

Recorded so they are not rediscovered:

```bash
# answer a Face ID prompt (enrolment is a Simulator.app menu item — see above;
# the notifyutil -s form does NOT work, it is silently refused)
xcrun simctl spawn <UDID> notifyutil -p com.apple.BiometricKit_Sim.pearl.match

# clear a stuck system alert / a wedged install
xcrun simctl uninstall <UDID> app.act.agenticControlTower

# app stdout
xcrun simctl launch --console <UDID> app.act.agenticControlTower
```

- **Text entry.** Synthetic keystrokes open the iOS accent picker. The suite
  sets the gateway URL through the app's own configuration store
  (`presetGatewayUrl`) and asserts the field renders it. Use
  `xcrun simctl pbcopy <UDID>` + paste if a scenario ever truly needs typing.
- **iCloud detritus.** The repo lives under `~/Documents`, so `codesign` fails
  with "resource fork, Finder information, or similar detritus not allowed".
  The driver runs `xattr -cr mobile` before every build.
- **`pumpAndSettle` is unusable here.** A `CircularProgressIndicator` animates
  forever, so settling times out on exactly the screens under test. Use
  `pumpUntil`, which measures wall-clock.
- **Stale `Runner` processes** make `flutter test` report "No tests ran." — the
  driver kills them first.
- **System alerts freeze the app, and therefore the test.** The notification
  permission prompt (`UNUserNotificationCenter.requestAuthorization`, called
  from `AppDelegate` at launch) is SpringBoard UI: nothing inside the process
  can dismiss it, so `tester.pump()` never returns and the run stalls instead of
  failing. Reinstalling resets the authorization, so it reappears at
  unpredictable points. The driver exports
  `SIMCTL_CHILD_ACT_SUPPRESS_PUSH_PROMPT=1`, which CoreSimulator forwards to the
  app as `ACT_SUPPRESS_PUSH_PROMPT`; `AppDelegate` skips the request when it is
  set. Nothing outside this harness sets it. If a prompt does get stuck on the
  device, `xcrun simctl uninstall` + reboot clears it.
- **Lazy `ListView`s.** Every screen is a long list, so a widget below the fold
  is not in the tree at all — `find` reports nothing and `ensureVisible` throws
  "Bad state: No element". Scroll first (`scrollUntilFound`,
  `pumpUntilVisible`), and assert about a whole screen with
  `renderedTextWhileScrolling`.
- **`tester.allWidgets` sees offstage routes.** A `pushNamed` leaves the
  previous screen in the tree, so "the mock strings are gone" would fail on a
  screen nobody can see. `renderedText` uses `find.byType`, which skips
  offstage.
- **The Claude Code iOS Simulator MCP is unusable on this machine** (it reports
  Xcode is not selected). Drive the simulator with `xcrun simctl`.
- **macOS has no `timeout(1)`.**

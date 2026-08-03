/// Shared plumbing for the ACT end-to-end simulator suite.
///
/// Everything here is test-only. The scenarios drive the *real* app widget tree
/// against a *real* gateway process started by `scripts/e2e_smoke.py`, so the
/// helpers deliberately avoid faking anything the incidents actually involved:
/// no fake signer, no fake HTTP, no fake key store. The one exception is
/// `app_boot_test`, which fakes a *hostile* platform on purpose.
library;

import 'dart:async';
import 'dart:convert';

import 'package:agentic_control_tower/src/security/device_request_signer.dart';
import 'package:agentic_control_tower/src/security/secure_enclave_channel.dart';
import 'package:flutter/material.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:meta/meta.dart';
import 'package:shared_preferences/shared_preferences.dart';

/// Values injected by the driver script via `--dart-define`.
class E2EConfig {
  /// Base URL of the scratch gateway, e.g. `http://127.0.0.1:8951/v1`.
  /// Empty when the suite is run without the driver.
  static const gatewayBaseUrl = String.fromEnvironment('ACT_E2E_GATEWAY');

  /// Wall-clock ceiling for "the app rendered something".
  static const firstFrameBudget = Duration(
    milliseconds: int.fromEnvironment(
      'ACT_E2E_FIRST_FRAME_MS',
      defaultValue: 10000,
    ),
  );

  /// Wall-clock ceiling for a screen to leave its loading state.
  static const loadBudget = Duration(
    milliseconds: int.fromEnvironment(
      'ACT_E2E_LOAD_MS',
      defaultValue: 45000,
    ),
  );

  /// A port the driver deliberately leaves closed, for the degradation
  /// scenarios. Never served by anything.
  static const deadGatewayBaseUrl = String.fromEnvironment(
    'ACT_E2E_DEAD_GATEWAY',
    defaultValue: 'http://127.0.0.1:8969/v1',
  );

  /// Ceiling for a step that waits on the out-of-process Face ID answerer.
  static const biometricBudget = Duration(
    milliseconds: int.fromEnvironment(
      'ACT_E2E_BIOMETRIC_MS',
      defaultValue: 60000,
    ),
  );

  static bool get hasGateway => gatewayBaseUrl.isNotEmpty;

  /// Reason string used when a scenario is skipped for want of a gateway.
  static const noGatewayReason =
      'no gateway: run via mobile/scripts/e2e-smoke.sh (sets ACT_E2E_GATEWAY)';
}

/// A scenario that needs the scratch gateway.
///
/// Without one it is registered as skipped *with the reason in the test name*,
/// so `flutter test` reports it explicitly instead of silently not running.
/// A skipped scenario is never a green scenario.
@isTest
void scenario(
  String description,
  WidgetTesterCallback body, {
  bool requiresGateway = true,
  Duration timeout = const Duration(minutes: 5),
}) {
  final skip = requiresGateway && !E2EConfig.hasGateway;
  testWidgets(
    skip ? '$description [SKIPPED: ${E2EConfig.noGatewayReason}]' : description,
    body,
    skip: skip,
    timeout: Timeout(timeout),
  );
}

/// Pump real frames until [predicate] holds or [timeout] elapses.
///
/// `pumpAndSettle` is unusable across this suite: a `CircularProgressIndicator`
/// animates forever, so settling times out on exactly the screens whose loading
/// behaviour is under test. This loop measures wall-clock instead.
Future<bool> pumpUntil(
  WidgetTester tester,
  bool Function() predicate, {
  Duration timeout = const Duration(seconds: 30),
  Duration step = const Duration(milliseconds: 120),
}) async {
  final clock = Stopwatch()..start();
  while (clock.elapsed < timeout) {
    if (predicate()) {
      return true;
    }
    await tester.pump(step);
  }
  return predicate();
}

/// Every string currently **visible** to the operator.
///
/// Deliberately not `tester.allWidgets`: that walks offstage routes too. A
/// `pushNamed` leaves the previous screen in the tree, so an app that had shown
/// mock data before pairing would still "contain" those strings afterwards and
/// the mock-masquerading-as-live assertion would fire on a screen nobody can
/// see. `find.byType` skips offstage by default; that is what a human sees.
List<String> renderedText(WidgetTester tester) {
  final out = <String>[];
  for (final widget in tester.widgetList<Text>(find.byType(Text))) {
    final value = widget.data ?? widget.textSpan?.toPlainText();
    if (value != null && value.isNotEmpty) {
      out.add(value);
    }
  }
  for (final widget
      in tester.widgetList<SelectableText>(find.byType(SelectableText))) {
    final value = widget.data ?? widget.textSpan?.toPlainText();
    if (value != null && value.isNotEmpty) {
      out.add(value);
    }
  }
  return out;
}

bool textMatching(WidgetTester tester, Pattern pattern) =>
    renderedText(tester).any((line) => line.contains(pattern));

bool anyMatching(List<String> lines, Pattern pattern) =>
    lines.any((line) => line.contains(pattern));

/// Everything the operator would see on a screen if they scrolled it end to end.
///
/// A lazy `ListView` builds only what is on screen, so one snapshot of
/// [renderedText] can neither prove a string is present nor prove it is absent.
/// Assertions about a whole screen — "the options read as sentences", "no raw
/// wire token anywhere" — have to walk it.
Future<List<String>> renderedTextWhileScrolling(
  WidgetTester tester, {
  Finder? within,
  int maxScrolls = 25,
}) async {
  final seen = <String>{...renderedText(tester)};
  final candidates = within ?? find.byType(Scrollable);
  if (candidates.evaluate().isEmpty) {
    return seen.toList();
  }
  final scrollable = candidates.first;
  for (var i = 0; i < 10; i++) {
    await tester.drag(scrollable, const Offset(0, 400));
    await tester.pump(const Duration(milliseconds: 60));
    seen.addAll(renderedText(tester));
  }
  for (var i = 0; i < maxScrolls; i++) {
    await tester.drag(scrollable, const Offset(0, -220));
    await tester.pump(const Duration(milliseconds: 60));
    seen.addAll(renderedText(tester));
  }
  return seen.toList();
}

/// Failure mode D1: a caught exception's `toString()` rendered as operator copy.
final rawExceptionPattern = RegExp(
  r'PlatformException|Exception:|SocketException|ClientException|#0\s',
);

void expectNoRawExceptionText(WidgetTester tester, {String? where}) {
  final offenders = renderedText(tester)
      .where((line) => rawExceptionPattern.hasMatch(line))
      .toList();
  expect(
    offenders,
    isEmpty,
    reason: 'raw exception text rendered as operator-facing UI'
        '${where == null ? '' : ' on $where'}: $offenders',
  );
}

/// Failure mode A: a spinner that never resolves.
void expectNoSpinner(WidgetTester tester, {String? where}) {
  expect(
    find.byType(CircularProgressIndicator),
    findsNothing,
    reason: 'screen is still spinning'
        '${where == null ? '' : ' on $where'} — nothing will ever settle it. '
        'Rendered: ${renderedText(tester)}',
  );
}

/// Failure mode A3: nothing rendered at all (LaunchScreen forever).
void expectRenderedFrame(WidgetTester tester, {String? where}) {
  expect(
    find.byType(MaterialApp),
    findsOneWidget,
    reason: 'no app frame was rendered'
        '${where == null ? '' : ' ($where)'} — runApp() was never reached',
  );
  expect(
    renderedText(tester),
    isNotEmpty,
    reason: 'app frame rendered but is blank'
        '${where == null ? '' : ' ($where)'}',
  );
}

/// Thin client for the gateway's Hermes-facing (unsigned, local-caller)
/// endpoints. The scenarios use it to mint and inspect server state, so the
/// assertions are about a real gateway rather than about the app's own beliefs.
class GatewayProbe {
  GatewayProbe(this.baseUrl);

  final String baseUrl;
  final _client = http.Client();

  void close() => _client.close();

  Future<Map<String, dynamic>> health() async => _get('/health');

  /// Mint an approval exactly as Hermes would. Byte-identical calls (same tool,
  /// payload, agent, session) share a `params_fingerprint`, which is what a
  /// session-scoped standing grant matches on.
  Future<Map<String, dynamic>> createApproval({
    required String actionId,
    String agentId = 'agent_e2e',
    String sessionId = 'sess_e2e',
    String requestedTool = 'git_status',
    String riskLevel = 'medium',
    String riskFamily = 'routine',
    required String summary,
    Map<String, dynamic> payload = const {'command': 'redacted'},
    List<String> suggestedScopes = const ['once', 'session'],
    String expiresAt = '2099-01-01T00:00:00Z',
  }) async {
    return _post('/approvals', {
      'action_id': actionId,
      'agent_id': agentId,
      'session_id': sessionId,
      'requested_tool': requestedTool,
      'risk_level': riskLevel,
      'risk_family': riskFamily,
      'summary': summary,
      'full_payload_redacted': payload,
      'resource_scope': 'repo',
      'expires_at': expiresAt,
      'options': [
        for (final scope in suggestedScopes)
          if (scope == 'once')
            'approve_once'
          else if (scope == 'session')
            'approve_for_session'
          else if (scope == 'agent')
            'approve_for_agent'
          else
            'approve_permanent',
        'deny',
      ],
    });
  }

  /// Server-side truth for an approval, via the Hermes status tool.
  Future<Map<String, dynamic>> approvalStatus(String approvalId) =>
      _post('/hermes/tools/approval_status', {'approval_id': approvalId});

  /// Enrol a software Ed25519 device the way the app's non-enclave path does.
  ///
  /// Used by the boot scenarios so they run against a *genuinely* paired
  /// device: the dashboard then loads real gateway data instead of failing,
  /// and the scenario measures the boot path rather than network noise. The
  /// enclave/biometric path is exercised by `pairing_test` instead.
  Future<Map<String, dynamic>> pairEd25519Device({
    required String devicePublicKeyBase64,
    String deviceName = 'ACT E2E Boot Device',
  }) async {
    final session = await _post('/pairing/start', {
      'display_name': deviceName,
      'clearance_channel': 'mobile_signed',
      'requested_permissions': ['read_state', 'approve', 'intervene'],
    });
    return _post('/pairing/complete', {
      'pairing_id': session['pairing_id'],
      'challenge_response': session['pairing_token'],
      'device_public_key': devicePublicKeyBase64,
      'device': {
        'device_name': deviceName,
        'platform': 'ios',
        'app_instance_id': 'act-e2e-boot',
        'app_version': '0.2.0',
      },
    });
  }

  Future<Map<String, dynamic>> registerNode({
    required String nodeId,
    required String displayName,
    required String fingerprint,
  }) =>
      _post('/nodes/register', {
        'node_id': nodeId,
        'display_name': displayName,
        'environment': 'homelab',
        'gateway_base_url': baseUrl,
        'node_fingerprint': fingerprint,
        'gateway_version': '0.1.0',
        'hermes_version': 'e2e',
        'tags': ['e2e'],
      });

  Future<Map<String, dynamic>> _get(String path) async {
    final response = await _client.get(Uri.parse('$baseUrl$path'));
    return _decode(response, 'GET $path');
  }

  Future<Map<String, dynamic>> _post(
    String path,
    Map<String, dynamic> body,
  ) async {
    final response = await _client.post(
      Uri.parse('$baseUrl$path'),
      headers: const {'Content-Type': 'application/json'},
      body: jsonEncode(body),
    );
    return _decode(response, 'POST $path');
  }

  Map<String, dynamic> _decode(http.Response response, String label) {
    if (response.statusCode >= 400) {
      throw StateError(
        'gateway $label failed ${response.statusCode}: ${response.body}',
      );
    }
    return jsonDecode(response.body) as Map<String, dynamic>;
  }
}

// ---------------------------------------------------------------------------
// Device state on the simulator
//
// These touch the REAL preference store and the REAL keychain, because a fake
// store would not reproduce the boot path that hangs. Every scenario clears
// state on entry: `flutter test` runs the suite files in one long-lived app
// install, so pairing leaks between files otherwise.
// ---------------------------------------------------------------------------

const _deviceStateKeys = <String>[
  'hmcp.device.id',
  'hmcp.device.access_token',
  'hmcp.device.refresh_token',
  'hmcp.device.private_key',
  'hmcp.device.public_key',
  'hmcp.device.key_algorithm',
  'hmcp.tower.public_key',
];

const _gatewayUrlKey = 'hmcp.gateway.base_url';

Future<void> clearDeviceState() async {
  final preferences = await SharedPreferences.getInstance();
  await preferences.reload();
  for (final key in [..._deviceStateKeys, _gatewayUrlKey]) {
    await preferences.remove(key);
  }
  const storage = FlutterSecureStorage();
  for (final key in _deviceStateKeys) {
    try {
      await storage.delete(key: key);
    } on Object {
      // best-effort
    }
  }
}

/// Put the app in a genuinely paired state without spending a Face ID prompt.
///
/// The boot scenarios need `initialize()` to take its paired branch — the one
/// that ends in `_registerPushToken()` — because an unpaired app never calls it
/// and the black-screen guard would pass vacuously.
///
/// When [gateway] is given, the device is really enrolled with that gateway
/// over the app's own software-Ed25519 pairing path, so the dashboard load that
/// follows succeeds and the scenario measures the boot path and nothing else.
/// Without it the session is local-only.
Future<void> seedPairedDeviceState({
  required String gatewayBaseUrl,
  GatewayProbe? gateway,
  String deviceId = 'dev_e2e_boot',
  String accessToken = 'e2e-access-token',
  String refreshToken = 'e2e-refresh-token',
}) async {
  final keyPair = await DeviceKeyPair.generate();
  var resolvedDeviceId = deviceId;
  var resolvedAccess = accessToken;
  var resolvedRefresh = refreshToken;

  if (gateway != null) {
    final completion = await gateway.pairEd25519Device(
      devicePublicKeyBase64: keyPair.publicKeyBase64,
    );
    final device = Map<String, dynamic>.from(completion['device'] as Map);
    final tokens = Map<String, dynamic>.from(completion['tokens'] as Map);
    resolvedDeviceId = device['device_id'] as String;
    resolvedAccess = tokens['access_token'] as String;
    resolvedRefresh = tokens['refresh_token'] as String;
  }

  final preferences = await SharedPreferences.getInstance();
  await preferences.setString(_gatewayUrlKey, gatewayBaseUrl);
  await preferences.setString('hmcp.device.id', resolvedDeviceId);
  await preferences.setString('hmcp.device.access_token', resolvedAccess);
  await preferences.setString('hmcp.device.refresh_token', resolvedRefresh);
  await preferences.setString(
      'hmcp.device.private_key', keyPair.privateKeyBase64);
  await preferences.setString('hmcp.device.public_key', keyPair.publicKeyBase64);

  const storage = FlutterSecureStorage();
  await storage.write(key: 'hmcp.device.access_token', value: resolvedAccess);
  await storage.write(key: 'hmcp.device.refresh_token', value: resolvedRefresh);
  await storage.write(
      key: 'hmcp.device.private_key', value: keyPair.privateKeyBase64);
  await storage.write(
      key: 'hmcp.device.public_key', value: keyPair.publicKeyBase64);
}

/// Point a fresh install at a gateway without typing into the URL field.
///
/// Synthetic keystrokes open the iOS accent picker on this simulator, so the
/// suite sets the value through the app's own configuration store instead. The
/// Settings text field is still exercised — it renders what this wrote.
Future<void> presetGatewayUrl(String gatewayBaseUrl) async {
  final preferences = await SharedPreferences.getInstance();
  await preferences.setString(_gatewayUrlKey, gatewayBaseUrl);
}

/// Unmount the app at the end of a scenario.
///
/// `runApp` inside a test leaves a live widget tree attached to the binding.
/// Left in place it keeps rebuilding into the next test, whose first `pump`
/// then collides with frames it did not schedule ("pump called before the
/// previous pump completed"). Replacing the tree ends that cleanly.
Future<void> unmountApp(WidgetTester tester) async {
  await tester.pumpWidget(const SizedBox.shrink());
  await tester.pump(const Duration(milliseconds: 200));
}

/// Let a deliberately-hung platform call finish before the test body ends.
///
/// A future still pending when the test completes leaks into the next test in
/// the file — `flutter_test` then reports it against whichever test happens to
/// be running. Releasing it here keeps failures attributable.
Future<void> releaseHungCall(
  WidgetTester tester,
  Completer<Object?> completer,
) async {
  if (!completer.isCompleted) {
    completer.complete(null);
  }
  for (var i = 0; i < 4; i++) {
    await tester.pump(const Duration(milliseconds: 200));
  }
}

/// Scroll until [finder] matches, or give up.
///
/// A `ListView` builds lazily: a widget below the fold does not exist in the
/// tree at all, so `find` reports nothing and `ensureVisible` throws
/// "Bad state: No element". Every screen in this app is a long `ListView`, so
/// scrolling has to come *before* finding, not after.
Future<bool> scrollUntilFound(
  WidgetTester tester,
  Finder finder, {
  Finder? within,
  int maxScrolls = 30,
}) async {
  if (finder.evaluate().isNotEmpty) {
    return true;
  }
  // Resolve lazily and defensively: `.first` on a finder that matches nothing
  // throws "Bad state: No element" the moment it is evaluated, and a screen
  // that is still loading has no Scrollable at all.
  final candidates = within ?? find.byType(Scrollable);
  if (candidates.evaluate().isEmpty) {
    return false;
  }
  final scrollable = candidates.first;
  // Rewind first: the caller may have left the list part-way down.
  for (var i = 0; i < 8; i++) {
    await tester.drag(scrollable, const Offset(0, 400));
    await tester.pump(const Duration(milliseconds: 80));
    if (finder.evaluate().isNotEmpty) {
      return true;
    }
  }
  for (var i = 0; i < maxScrolls; i++) {
    await tester.drag(scrollable, const Offset(0, -220));
    await tester.pump(const Duration(milliseconds: 80));
    if (finder.evaluate().isNotEmpty) {
      return true;
    }
  }
  return false;
}

/// Tap a widget that may sit below the fold, scrolling to it first.
Future<void> tapWhenVisible(
  WidgetTester tester,
  Finder finder, {
  Finder? scrollable,
}) async {
  final found = await scrollUntilFound(tester, finder, within: scrollable);
  expect(
    found,
    isTrue,
    reason: 'nothing to tap for $finder. Rendered: ${renderedText(tester)}',
  );
  await tester.ensureVisible(finder.first);
  await tester.pump(const Duration(milliseconds: 120));
  await tester.tap(finder.first, warnIfMissed: false);
  await tester.pump(const Duration(milliseconds: 250));
}

/// True once [pattern] is on screen, scrolling the list to look for it.
Future<bool> pumpUntilVisible(
  WidgetTester tester,
  Pattern pattern, {
  Duration? timeout,
}) async {
  final clock = Stopwatch()..start();
  final budget = timeout ?? E2EConfig.loadBudget;
  while (clock.elapsed < budget) {
    if (textMatching(tester, pattern)) {
      return true;
    }
    if (await scrollUntilFound(tester, find.textContaining(pattern),
        maxScrolls: 12)) {
      return true;
    }
    await tester.pump(const Duration(milliseconds: 200));
  }
  return textMatching(tester, pattern);
}

/// Poll the gateway until an approval reaches [state], pumping meanwhile.
///
/// The decision is submitted by the app; the gateway is the authority on
/// whether it landed. Polling here rather than trusting the UI is the point:
/// a screen that says "approved" while the server still says "pending" is the
/// failure this catches.
Future<Map<String, dynamic>> waitForApprovalState(
  WidgetTester tester,
  GatewayProbe gateway,
  String approvalId,
  String state, {
  Duration? timeout,
}) async {
  final deadline = DateTime.now().add(timeout ?? E2EConfig.biometricBudget);
  var status = await gateway.approvalStatus(approvalId);
  while (status['state'] != state && DateTime.now().isBefore(deadline)) {
    await tester.pump(const Duration(milliseconds: 400));
    status = await gateway.approvalStatus(approvalId);
  }
  expect(
    status['state'],
    state,
    reason: 'gateway never recorded state "$state" for $approvalId '
        '(server state: $status)',
  );
  return status;
}

// ---------------------------------------------------------------------------
// navigation
// ---------------------------------------------------------------------------

/// Boot the real app and wait for the dashboard shell.
Future<void> launchApp(WidgetTester tester, Future<void> Function() entry) async {
  unawaited(entry());
  final booted = await pumpUntil(
    tester,
    () => find.text('ACT Tower').evaluate().isNotEmpty,
    timeout: E2EConfig.firstFrameBudget,
  );
  expect(booted, isTrue,
      reason: 'app never reached the dashboard. '
          'Rendered: ${renderedText(tester)}');
}

Future<void> openSettings(WidgetTester tester) async {
  await tapWhenVisible(tester, find.byTooltip('Settings'));
  final open = await pumpUntil(
    tester,
    () => find.text('Gateway base URL').evaluate().isNotEmpty,
    timeout: E2EConfig.loadBudget,
  );
  expect(open, isTrue,
      reason: 'Settings never opened. Rendered: ${renderedText(tester)}');
}

/// Switch bottom-navigation tab by its label ('Home', 'Inbox', …).
Future<void> openTab(WidgetTester tester, String label) async {
  await tapWhenVisible(tester, find.text(label).last);
  await tester.pump(const Duration(milliseconds: 400));
}

/// Opt a scenario out, loudly.
///
/// `markTestSkipped`'s reason does not survive into the reporter's output, so
/// the driver would print "1 skipped" and nothing else. This marker is what
/// `scripts/e2e_smoke.py` greps to put the reason in the summary table — a
/// silent skip is indistinguishable from a scenario that was never written.
void skipScenario(String reason) {
  debugPrint('[e2e] SKIP: $reason');
  markTestSkipped(reason);
}

/// Whether this simulator can actually answer a biometric prompt.
///
/// Biometric enrolment on a simulator is in-memory state owned by
/// Simulator.app (Features > Face ID > Enrolled). It does not survive a device
/// reboot and **cannot be set from the command line** — `notifyutil -s` on
/// `com.apple.BiometricKit_Sim.pearl.enroll` is silently refused.
///
/// Without it, `evaluatePolicy(.deviceOwnerAuthentication)` falls back to a
/// passcode field that no test can fill, and the app freezes behind a system
/// prompt — a hang, not a failure. So the suite asks first, and adapts.
Future<bool> biometryAvailable() async {
  try {
    final status = await const SecureEnclaveChannel().status();
    return status?.biometryAvailable ?? false;
  } on Object {
    return false;
  }
}

/// Get the app to a paired state by whichever route this machine supports.
///
/// * biometry enrolled → the real pairing UI, Face ID and all (the enclave
///   P-256 channel, signed decisions with a fresh presence evaluation);
/// * otherwise → enrol over the app's software-Ed25519 pairing path before
///   launch, so the scenario still exercises real signed transport and real
///   signed decisions against a real gateway, minus the biometric gate.
///
/// The degraded route is announced in the log and returned, so a scenario that
/// wants to assert something biometric can skip itself instead of lying.
Future<bool> pairForScenario(
  WidgetTester tester,
  GatewayProbe gateway, {
  required String gatewayBaseUrl,
  required Future<void> Function() entry,
}) async {
  if (await biometryAvailable()) {
    await launchApp(tester, entry);
    await pairThroughUi(tester);
    return true;
  }
  debugPrint(
    '[e2e] biometry is NOT enrolled on this simulator — pairing over the '
    'software Ed25519 path instead. Signed transport and signed decisions are '
    'still exercised; the enclave/biometric pairing path is not. '
    'Enrol via Simulator > Features > Face ID > Enrolled to restore it.',
  );
  await seedPairedDeviceState(
    gatewayBaseUrl: gatewayBaseUrl,
    gateway: gateway,
  );
  await launchApp(tester, entry);
  return false;
}

/// Drive the app's own pairing UI to completion, Face ID included.
///
/// Deliberately goes through the real buttons rather than seeding storage: the
/// signed-request contract (failure mode B1) is only exercised if the app
/// actually enrols.
Future<void> pairThroughUi(WidgetTester tester) async {
  await openSettings(tester);
  await tapWhenVisible(tester, find.widgetWithText(FilledButton, 'Start'),
      scrollable: find.byType(Scrollable).first);
  final started = await pumpUntil(
    tester,
    () => find.text('Pairing ID').evaluate().isNotEmpty,
    timeout: E2EConfig.loadBudget,
  );
  expect(started, isTrue,
      reason: 'pairing session never started. '
          'Rendered: ${renderedText(tester)}');

  await tapWhenVisible(tester, find.widgetWithText(FilledButton, 'Complete'),
      scrollable: find.byType(Scrollable).first);
  final paired = await pumpUntil(
    tester,
    () => textMatching(tester, 'Signed gateway access'),
    timeout: E2EConfig.biometricBudget,
  );
  expect(
    paired,
    isTrue,
    reason: 'pairing never completed. Either the signed-request contract '
        'drifted from the gateway, or the Face ID prompt went unanswered. '
        'Rendered: ${renderedText(tester)}',
  );
  expectNoRawExceptionText(tester, where: 'pairing');
}

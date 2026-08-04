/// THE BLACK-SCREEN GUARD — the most important scenario in this suite.
///
/// Incident (failure mode A3): `main()` was
///
/// ```dart
/// final runtime = await HermesAppRuntime.create();   // ← awaited BEFORE runApp
/// runApp(HermesMobileApp(runtime: runtime));
/// ```
///
/// and `create()` ended in `await _registerPushToken()`, which waits on the iOS
/// APNs device-token callback. On a dev-signed build that callback never
/// arrived, so `runApp()` was never reached and iOS showed the LaunchScreen
/// storyboard — a totally black screen — forever. Networking started inside
/// `initialize()` kept running, so the gateway logged healthy signed 200s from
/// an app that looked dead. Force-quitting did not help.
///
/// The second test reproduces that environment exactly — the push channel never
/// answers — and demands a rendered, navigable app anyway.
library;

import 'dart:async';

import 'package:agentic_control_tower/main.dart' as app;
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';

import 'support/e2e_support.dart';

const _pushChannel = MethodChannel('act/push');

void main() {
  final binding = IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  tearDown(() async {
    binding.defaultBinaryMessenger.setMockMethodCallHandler(_pushChannel, null);
    await clearDeviceState();
  });

  testWidgets(
    'cold boot reaches a rendered first frame',
    (tester) async {
      await clearDeviceState();

      final clock = Stopwatch()..start();
      unawaited(app.main());

      final rendered = await pumpUntil(
        tester,
        () => find.byType(MaterialApp).evaluate().isNotEmpty,
        timeout: E2EConfig.firstFrameBudget,
      );
      clock.stop();

      expect(
        rendered,
        isTrue,
        reason:
            'no first frame within ${E2EConfig.firstFrameBudget.inSeconds}s. '
            'This is the black-screen signature: runApp() was never reached. '
            'Look for an await before runApp() in main.dart / bootstrap.dart.',
      );
      debugPrint('[e2e] first frame after ${clock.elapsedMilliseconds}ms');

      // A frame is not enough — it must be the app, with content on it.
      final ready = await pumpUntil(
        tester,
        () => find.text('ACT Tower').evaluate().isNotEmpty,
        timeout: E2EConfig.loadBudget,
      );
      expect(ready, isTrue,
          reason: 'app shell never appeared. Rendered: ${renderedText(tester)}');
      expectNoRawExceptionText(tester, where: 'cold boot');

      await unmountApp(tester);
    },
    timeout: const Timeout(Duration(minutes: 3)),
  );

  testWidgets(
    'hostile push provider never resolves — the app still renders and navigates',
    (tester) async {
      await clearDeviceState();
      // A paired session is required to reach the branch of initialize() that
      // registers for push; an unpaired app never calls it and the scenario
      // would pass vacuously. Pair for real against the live gateway so the
      // only thing wrong with this environment is the push provider.
      final gateway =
          E2EConfig.hasGateway ? GatewayProbe(E2EConfig.gatewayBaseUrl) : null;
      addTearDown(() => gateway?.close());
      await seedPairedDeviceState(
        gatewayBaseUrl: E2EConfig.hasGateway
            ? E2EConfig.gatewayBaseUrl
            : E2EConfig.deadGatewayBaseUrl,
        gateway: gateway,
      );

      // The incident, reproduced exactly: APNs never calls back.
      final neverAnswers = Completer<Object?>();
      binding.defaultBinaryMessenger.setMockMethodCallHandler(
        _pushChannel,
        (call) => neverAnswers.future,
      );

      final clock = Stopwatch()..start();
      unawaited(app.main());

      final rendered = await pumpUntil(
        tester,
        () => find.byType(MaterialApp).evaluate().isNotEmpty,
        timeout: E2EConfig.firstFrameBudget,
      );
      clock.stop();

      expect(
        rendered,
        isTrue,
        reason: 'BLACK SCREEN REGRESSION: the push-token provider never '
            'answered and the first frame never arrived. runApp() must not be '
            'gated on push registration, a platform channel, or the network.',
      );
      debugPrint(
        '[e2e] first frame under hostile push after '
        '${clock.elapsedMilliseconds}ms',
      );
      expectRenderedFrame(tester, where: 'hostile push provider');
      expectNoRawExceptionText(tester, where: 'hostile push provider');

      // A rendered-but-frozen frame is still a broken app: prove it navigates
      // while push registration is *still* outstanding.
      final settings = find.byTooltip('Settings');
      final reachable = await pumpUntil(
        tester,
        () => settings.evaluate().isNotEmpty,
        timeout: E2EConfig.loadBudget,
      );
      expect(reachable, isTrue,
          reason: 'Settings affordance never rendered. '
              'Rendered: ${renderedText(tester)}');

      await tester.tap(settings, warnIfMissed: false);
      final onSettings = await pumpUntil(
        tester,
        () => find.text('Gateway base URL').evaluate().isNotEmpty,
        timeout: E2EConfig.loadBudget,
      );
      expect(onSettings, isTrue,
          reason: 'navigation is blocked while push registration hangs. '
              'Rendered: ${renderedText(tester)}');
      expect(neverAnswers.isCompleted, isFalse,
          reason: 'the scenario is only meaningful while push is still hung');
      expectNoRawExceptionText(tester, where: 'settings under hostile push');

      await releaseHungCall(tester, neverAnswers);
      await unmountApp(tester);
    },
    timeout: const Timeout(Duration(minutes: 3)),
  );
}

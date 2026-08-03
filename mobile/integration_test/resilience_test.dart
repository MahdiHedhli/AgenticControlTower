/// A gateway that is not there must degrade honestly.
///
/// Three of the week's incidents share one shape: the app hit a condition it
/// had no story for, and the operator got no usable information — a black
/// screen, a spinner that would never resolve, or a `PlatformException` dump
/// rendered as the interface. On a security product the last one is the worst:
/// unreadable at the exact moment a decision is needed.
///
/// This scenario points a paired app at a closed port and demands:
///   * a rendered app (not a black screen),
///   * a settled screen (not a spinner nothing will ever resolve),
///   * one human-readable sentence naming what to do about it,
///   * no raw exception text anywhere,
///   * and a way back — Settings must still be reachable.
library;

import 'package:agentic_control_tower/main.dart' as app;
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';

import 'support/e2e_support.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  tearDown(clearDeviceState);

  scenario(
    'a dead gateway degrades to a readable message, not a spinner or a dump',
    requiresGateway: false,
    (tester) async {
      await clearDeviceState();
      // Paired, so the app uses the gateway repository rather than falling back
      // to mock data — the failure has to be visible, not papered over.
      await seedPairedDeviceState(
        gatewayBaseUrl: E2EConfig.deadGatewayBaseUrl,
      );

      await launchApp(tester, app.main);

      // 1. The app rendered at all.
      expectRenderedFrame(tester, where: 'dead gateway');

      // 2. It settles. A screen still spinning here is the infinite-spinner
      //    failure: the load will never succeed and nothing will ever say so.
      final settled = await pumpUntil(
        tester,
        () => !tester.any(find.byType(CircularProgressIndicator)),
        timeout: E2EConfig.loadBudget,
      );
      expect(
        settled,
        isTrue,
        reason: 'INFINITE SPINNER: the dashboard is still loading against a '
            'gateway that is not listening. A failed load must render a '
            'failure, not a spinner. Rendered: ${renderedText(tester)}',
      );

      // 3. A human sentence, and a way to act on it.
      expect(
        textMatching(tester, "Can't reach the control tower"),
        isTrue,
        reason: 'no operator-readable explanation of the outage. '
            'Rendered: ${renderedText(tester)}',
      );
      expect(find.text('Open Settings'), findsWidgets,
          reason: 'the failure state offers no way to fix the gateway URL');
      expect(find.text('Retry'), findsWidgets,
          reason: 'the failure state offers no way to try again');

      // 4. No exception dumps as copy.
      expectNoRawExceptionText(tester, where: 'dashboard, dead gateway');

      // --- the same on the Inbox -------------------------------------------
      await openTab(tester, 'Inbox');
      final inboxSettled = await pumpUntil(
        tester,
        () => !tester.any(find.byType(CircularProgressIndicator)),
        timeout: E2EConfig.loadBudget,
      );
      expect(inboxSettled, isTrue,
          reason: 'INFINITE SPINNER on the Inbox against a dead gateway. '
              'Rendered: ${renderedText(tester)}');
      expect(textMatching(tester, "Can't reach the control tower"), isTrue,
          reason: 'the Inbox does not explain the outage. '
              'Rendered: ${renderedText(tester)}');
      expectNoRawExceptionText(tester, where: 'inbox, dead gateway');

      // --- and the operator can still reach the fix -------------------------
      await openSettings(tester);
      expectNoRawExceptionText(tester, where: 'settings, dead gateway');
      await tapWhenVisible(tester, find.text('Check'));
      final checked = await pumpUntil(
        tester,
        () => textMatching(tester, 'Connection failed'),
        timeout: E2EConfig.loadBudget,
      );
      expect(checked, isTrue,
          reason: 'the connection check gave the operator no verdict. '
              'Rendered: ${renderedText(tester)}');
      expect(textMatching(tester, "Can't reach the control tower"), isTrue,
          reason: 'the connection check must say what to do, not just fail');
      expectNoRawExceptionText(tester, where: 'settings check, dead gateway');

      await unmountApp(tester);
    },
  );
}

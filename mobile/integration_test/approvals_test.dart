/// An approval minted server-side must be visible, readable and decidable.
///
/// Guards:
///
///  * **A1 concurrent biometric sign requests** — the Inbox fires several
///    signed reads at once (approvals, notifications, assistance). Overlapping
///    `LAContext.evaluatePolicy` calls used to cancel each other with LAError
///    -4, leaving futures unsettled: infinite spinner, and Approve taps that
///    silently did nothing. Every `expectNoSpinner` below is that guard.
///  * **D2 protocol tokens shown as prose** — the detail screen listed the
///    gateway's raw option tokens (`approve_once`, `approve_for_session`) as if
///    they were the operator's own constraints.
///  * **D1 raw errors as UI**, everywhere.
///
/// The decision is asserted against the *gateway's* record, not the app's, so a
/// UI that says "approved" while the server disagrees fails here.
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
    'a server-minted approval reaches the inbox and can be approved',
    (tester) async {
      final gateway = GatewayProbe(E2EConfig.gatewayBaseUrl);
      addTearDown(gateway.close);

      await clearDeviceState();
      await presetGatewayUrl(E2EConfig.gatewayBaseUrl);

      final marker = 'e2e-approval-${DateTime.now().microsecondsSinceEpoch}';
      final approval = await gateway.createApproval(
        actionId: 'act_$marker',
        requestedTool: 'e2e_deploy_probe',
        summary: marker,
        suggestedScopes: const ['once', 'session'],
      );
      final approvalId = approval['approval_id'] as String;
      expect(approval['state'], 'pending');

      // Pair by whichever route this simulator supports. With biometry
      // enrolled that is the real enclave/Face ID flow; without it, the app's
      // software-Ed25519 path — still real signed transport and real signed
      // decisions against a real gateway.
      await pairForScenario(
        tester,
        gateway,
        gatewayBaseUrl: E2EConfig.gatewayBaseUrl,
        entry: app.main,
      );

      // --- inbox ------------------------------------------------------------
      await openTab(tester, 'Inbox');
      final listed = await pumpUntilVisible(tester, marker);
      expect(listed, isTrue,
          reason: 'the approval never appeared in the Inbox. '
              'Rendered: ${renderedText(tester)}');
      expectNoSpinner(tester, where: 'inbox');
      expectNoRawExceptionText(tester, where: 'inbox');

      // --- detail -----------------------------------------------------------
      await tapWhenVisible(tester, find.text(marker));
      final onDetail =
          await pumpUntilVisible(tester, 'Offered Decision Options');
      expect(onDetail, isTrue,
          reason: 'approval detail never loaded. '
              'Rendered: ${renderedText(tester)}');
      expectNoSpinner(tester, where: 'approval detail');
      expectNoRawExceptionText(tester, where: 'approval detail');

      // Humanized, not wire tokens. Walk the whole screen: the options sit
      // below the fold in a lazily-built ListView, so a snapshot proves nothing.
      final detail = await renderedTextWhileScrolling(tester);
      expect(anyMatching(detail, 'Approve for this session'), isTrue,
          reason: 'the offered options must read as sentences. '
              'Screen text: $detail');
      for (final token in const [
        'approve_once',
        'approve_for_session',
        'approve_for_agent',
        'approve_permanent',
      ]) {
        expect(anyMatching(detail, token), isFalse,
            reason: 'RAW PROTOCOL TOKEN "$token" rendered as operator copy');
      }
      expect(
        detail.where((line) => rawExceptionPattern.hasMatch(line)),
        isEmpty,
        reason: 'raw exception text on the approval detail screen',
      );

      // The bottom sheet's decision list must be humanized too.
      await tapWhenVisible(tester, find.widgetWithText(OutlinedButton, 'More'),
          scrollable: find.byType(Scrollable));
      final sheet = await pumpUntil(
        tester,
        () => find.text('Decision Options').evaluate().isNotEmpty,
        timeout: E2EConfig.loadBudget,
      );
      expect(sheet, isTrue, reason: 'decision-options sheet never opened');
      for (final label in const [
        'Approve Once',
        'Approve For Session',
        'Deny',
      ]) {
        expect(find.text(label), findsWidgets,
            reason: 'humanized decision option "$label" is missing');
      }
      Navigator.of(tester.element(find.text('Decision Options'))).pop();
      await tester.pump(const Duration(milliseconds: 400));

      // --- decide -----------------------------------------------------------
      await tapWhenVisible(
        tester,
        find.widgetWithText(FilledButton, 'Approve'),
        scrollable: find.byType(Scrollable),
      );

      // Clearance decisions always take a fresh presence evaluation, so this
      // step waits on the out-of-process Face ID answerer.
      final settled = await pumpUntil(
        tester,
        () => !tester.any(find.byType(CircularProgressIndicator)),
        timeout: E2EConfig.biometricBudget,
      );
      expect(settled, isTrue,
          reason: 'the decision never settled — this is the unsettled-future '
              'signature (concurrent biometric sign requests cancelling each '
              'other). Rendered: ${renderedText(tester)}');
      expectNoRawExceptionText(tester, where: 'after approve');

      // --- server-side truth ------------------------------------------------
      var status = await gateway.approvalStatus(approvalId);
      final deadline = DateTime.now().add(E2EConfig.biometricBudget);
      while (status['state'] != 'approved' && DateTime.now().isBefore(deadline)) {
        await tester.pump(const Duration(milliseconds: 400));
        status = await gateway.approvalStatus(approvalId);
      }
      expect(
        status['state'],
        'approved',
        reason: 'the app reported a decision the gateway never recorded '
            '(server state: $status)',
      );
      expect(status['selected_scope'], 'once');

      await unmountApp(tester);
    },
  );
}

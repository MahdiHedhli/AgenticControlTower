/// "Approve for this session" must actually stop asking.
///
/// The feature that just shipped: a decision carrying a scope other than
/// `once` mints an explicit, hard-expiring, revocable standing grant, and a
/// byte-identical later request is auto-satisfied by it instead of prompting
/// again.
///
/// The regression this guards is the pre-feature behaviour: the scope was
/// recorded on the approval row and nothing ever consumed it, so the operator
/// was asked again, and again, for a decision they had already made. That looks
/// like a working app — which is exactly why it needs a test.
///
/// Both halves are asserted:
///   * server-side — the repeat request comes back `approved` with
///     `approved_by == standing_grant`, and the record still exists (an
///     auto-satisfied action is still an attempted action and must be audited);
///   * operator-side — no second prompt reaches the Inbox.
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
    'approve-for-session auto-satisfies a byte-identical repeat request',
    (tester) async {
      final gateway = GatewayProbe(E2EConfig.gatewayBaseUrl);
      addTearDown(gateway.close);

      await clearDeviceState();
      await presetGatewayUrl(E2EConfig.gatewayBaseUrl);

      // A grantable (low-risk) family: the mobile-mandatory families
      // (external_effect, destructive, …) can never be auto-satisfied, by
      // design, and would make this scenario prove the opposite of the feature.
      final run = DateTime.now().microsecondsSinceEpoch;
      final firstSummary = 'e2e-grant-first-$run';
      final tool = 'e2e_git_status_$run';

      final first = await gateway.createApproval(
        actionId: 'act_grant_first_$run',
        requestedTool: tool,
        riskFamily: 'routine',
        summary: firstSummary,
        suggestedScopes: const ['once', 'session'],
      );
      expect(first['state'], 'pending');

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

      await openTab(tester, 'Inbox');
      expect(
        await pumpUntilVisible(tester, firstSummary),
        isTrue,
        reason: 'the first approval never reached the Inbox. '
            'Rendered: ${renderedText(tester)}',
      );

      await tapWhenVisible(tester, find.text(firstSummary));
      expect(
        await pumpUntilVisible(tester, 'Offered Decision Options'),
        isTrue,
        reason: 'approval detail never loaded. '
            'Rendered: ${renderedText(tester)}',
      );

      // --- decide with scope=session ---------------------------------------
      await tapWhenVisible(tester, find.widgetWithText(OutlinedButton, 'More'),
          scrollable: find.byType(Scrollable));
      expect(
        await pumpUntilVisible(tester, 'Approve For Session'),
        isTrue,
        reason: '"Approve For Session" is not offered for this approval',
      );
      await tapWhenVisible(tester, find.text('Approve For Session'));

      final settled = await pumpUntil(
        tester,
        () => !tester.any(find.byType(CircularProgressIndicator)),
        timeout: E2EConfig.biometricBudget,
      );
      expect(settled, isTrue,
          reason: 'the scoped decision never settled. '
              'Rendered: ${renderedText(tester)}');
      expectNoRawExceptionText(tester, where: 'approve for session');

      final firstStatus = await waitForApprovalState(
        tester,
        gateway,
        first['approval_id'] as String,
        'approved',
      );
      expect(firstStatus['selected_scope'], 'session',
          reason: 'the decision did not carry scope=session, so no standing '
              'grant can have been minted (server state: $firstStatus)');

      // --- the repeat request ----------------------------------------------
      // Byte-identical: same tool, agent, session and payload, therefore the
      // same params_fingerprint — which is what a session-scoped grant matches.
      final secondSummary = 'e2e-grant-second-$run';
      final second = await gateway.createApproval(
        actionId: 'act_grant_second_$run',
        requestedTool: tool,
        riskFamily: 'routine',
        summary: secondSummary,
        suggestedScopes: const ['once', 'session'],
      );

      expect(
        second['params_fingerprint'],
        first['params_fingerprint'],
        reason: 'the repeat request is not byte-identical, so this scenario '
            'would prove nothing about standing grants',
      );
      expect(
        second['state'],
        'approved',
        reason: 'STANDING GRANT NOT CONSUMED: a byte-identical repeat after '
            '"approve for this session" came back ${second['state']}. The '
            'operator is being asked again for a decision they already made.',
      );
      expect(
        second['approved_by'],
        'standing_grant',
        reason: 'the repeat was approved by ${second['approved_by']} rather '
            'than the standing grant',
      );
      expect(second['human_approved'], isFalse,
          reason: 'an auto-satisfied request must not be recorded as a human '
              'decision');

      // Auto-satisfying may never mean "no record".
      final secondStatus =
          await gateway.approvalStatus(second['approval_id'] as String);
      expect(secondStatus['state'], 'approved',
          reason: 'the auto-satisfied request left no server-side record');

      // --- and no second prompt reaches the operator ------------------------
      await openTab(tester, 'Home');
      await openTab(tester, 'Inbox');
      final refreshed = await pumpUntil(
        tester,
        () => !tester.any(find.byType(CircularProgressIndicator)),
        timeout: E2EConfig.loadBudget,
      );
      expect(refreshed, isTrue, reason: 'the Inbox never finished reloading');
      expect(
        textMatching(tester, secondSummary),
        isFalse,
        reason: 'AUTO-SATISFIED REQUEST PROMPTED ANYWAY: "$secondSummary" is '
            'in the operator queue even though a standing grant cleared it. '
            'Rendered: ${renderedText(tester)}',
      );
      expectNoRawExceptionText(tester, where: 'inbox after auto-satisfaction');

      await unmountApp(tester);
    },
  );
}

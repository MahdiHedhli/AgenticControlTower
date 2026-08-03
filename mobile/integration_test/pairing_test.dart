/// Pair a fresh install with a real gateway and prove the data is LIVE.
///
/// Guards three incidents at once:
///
///  * **B1 contract drift** — the app bearer-authenticated its reads while the
///    gateway required signed device requests, so every endpoint 401'd. Real
///    pairing here fails if the signing contract has drifted, because the
///    dashboard load that follows is signed end to end.
///  * **Mock masquerading as live** — the app silently falls back to
///    `MockAlphaRepository` when unpaired. A screenful of plausible fake data
///    looks exactly like a working app. This asserts a fixture that only the
///    gateway could have produced, and asserts the mock's own strings are gone.
///  * **C1 a capability probe that lied** — `SecureEnclave.isAvailable` returns
///    true on the Simulator, so Settings once claimed `secure_enclave_p256` /
///    hardware-backed on a machine with no enclave. Settings must say
///    `software_p256_dev` here, and must not claim hardware backing.
///
/// The Face ID prompt raised by the possession-proof signature is answered by
/// the driver script (`notifyutil -p …pearl.match`), not from inside the app.
library;

import 'package:agentic_control_tower/main.dart' as app;
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';

import 'support/e2e_support.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  tearDown(clearDeviceState);

  scenario(
    'pairs with the gateway and then shows live data, not mock data',
    (tester) async {
      // This is the one scenario that genuinely needs a biometric prompt: it
      // asserts the enclave/Face ID pairing path and the honest key-backend
      // label that comes with it. Enrolment is Simulator.app state that no
      // command line can set, so say so and skip rather than hang on a
      // passcode field nothing can fill.
      if (!await biometryAvailable()) {
        skipScenario(
          'Face ID is not enrolled on this simulator, so the pairing prompt '
          'falls back to a passcode field the harness cannot answer. Enrol via '
          'Simulator > Features > Face ID > Enrolled and re-run. '
          '(Enrolment is in-memory and is lost when the device reboots.)',
        );
        return;
      }

      final gateway = GatewayProbe(E2EConfig.gatewayBaseUrl);
      addTearDown(gateway.close);

      await clearDeviceState();
      await presetGatewayUrl(E2EConfig.gatewayBaseUrl);

      // A fixture with a signature no bundled mock could ever produce.
      final marker = 'e2e-live-marker-${DateTime.now().microsecondsSinceEpoch}';
      await gateway.createApproval(
        actionId: 'act_$marker',
        requestedTool: 'e2e_live_probe',
        summary: marker,
      );

      await launchApp(tester, app.main);

      // Unpaired: the app is honest about being on mock data.
      expect(
        await pumpUntilVisible(tester, 'Mock alpha data'),
        isTrue,
        reason: 'an unpaired app must say it is on mock data. '
            'Rendered: ${renderedText(tester)}',
      );

      await pairThroughUi(tester);
      expectNoSpinner(tester, where: 'settings after pairing');

      // --- honest key backend on a simulator --------------------------------
      expect(textMatching(tester, 'software_p256_dev'), isTrue,
          reason: 'Settings must report the honest software key backend on a '
              'simulator. Rendered: ${renderedText(tester)}');
      expect(textMatching(tester, 'secure_enclave_p256'), isFalse,
          reason: 'CLAIMED HARDWARE BACKING ON A SIMULATOR: there is no Secure '
              'Enclave here. SecureEnclave.isAvailable lies on the Simulator; '
              'the probe must be compile-time gated.');
      expect(textMatching(tester, 'DEV BUILD: software P-256 key'), isTrue,
          reason: 'the not-production-ready warning must be visible');

      // --- live data, not mock ---------------------------------------------
      await openTab(tester, 'Inbox');
      final live = await pumpUntil(
        tester,
        () => textMatching(tester, marker),
        timeout: E2EConfig.loadBudget,
      );
      expect(
        live,
        isTrue,
        reason: 'the gateway fixture never reached the Inbox. A paired app '
            'showing plausible data that is not this fixture is the '
            'mock-masquerading-as-live failure. Rendered: '
            '${renderedText(tester)}',
      );
      for (final mockOnly in const [
        'Run migration cleanup command',
        'Agent needs help',
        'Nightly backup audit',
      ]) {
        expect(textMatching(tester, mockOnly), isFalse,
            reason: 'MOCK DATA IS STILL ON SCREEN after pairing ("$mockOnly")');
      }
      expectNoSpinner(tester, where: 'inbox after pairing');
      expectNoRawExceptionText(tester, where: 'inbox after pairing');

      await unmountApp(tester);
    },
  );
}

/// Browser Assist actions must report their verdict, not vanish.
///
/// Why this is a widget test and not an `integration_test` scenario: against a
/// dead gateway the *list* load fails first, so `LoadFailurePanel` replaces the
/// session cards and the Record Note / Return buttons are never rendered. The
/// escape only exists when the list succeeded and the action does not — a state
/// the resilience scenario (one closed port for everything) cannot produce.
/// So the seam is here: a real repository over a real `GatewayApiClient` with a
/// real signer, whose socket serves the list and then refuses the POST.
///
/// The bug: both handlers were `try { await …; setState(_refresh); } finally {
/// _busy = false; }` — a `finally` with no `catch` — wired to `onPressed`, a
/// `VoidCallback`. The rejected future was discarded, the throw escaped as an
/// unhandled async error, and the operator saw nothing at all.
library;

import 'dart:convert';

import 'package:agentic_control_tower/src/api/gateway_api_client.dart';
import 'package:agentic_control_tower/src/app_runtime.dart';
import 'package:agentic_control_tower/src/config/gateway_config.dart';
import 'package:agentic_control_tower/src/repositories/browser_assistance_repository.dart';
import 'package:agentic_control_tower/src/screens/browser_assistance_screen.dart';
import 'package:agentic_control_tower/src/security/device_request_signer.dart';
import 'package:agentic_control_tower/src/security/secure_key_store.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';

void main() {
  testWidgets(
    'a failed Record Note tells the operator, and does not escape',
    (tester) async {
      var posts = 0;
      final runtime = _RuntimeWith(
        await _repository((request) async {
          if (request.method == 'POST') {
            posts += 1;
            // What an unreachable gateway actually produces underneath
            // `postJson`. `operator_error` maps this to the "can't reach"
            // sentence.
            throw http.ClientException('Connection refused', request.url);
          }
          return http.Response(jsonEncode(_sessionsPayload), 200);
        }),
      );

      await _pumpScreen(tester, runtime);
      expect(find.text('Record Note'), findsOneWidget,
          reason: 'the session card did not render, so the action under test '
              'was never reachable');

      await tester.tap(find.text('Record Note'));
      await tester.pumpAndSettle();

      expect(posts, 1, reason: 'the action never reached the repository');

      // 1. The operator is told. This is the whole point: before the fix the
      //    button simply re-enabled itself as though the note was recorded.
      expect(
        find.textContaining("Can't reach the control tower"),
        findsOneWidget,
        reason: 'a failed Record Note gave the operator no verdict at all',
      );

      // 2. Not as an exception dump.
      expect(find.textContaining('ClientException'), findsNothing);

      // 3. Nothing escaped. `testWidgets` fails the test outright on an
      //    unhandled async error in its zone, which is what the un-caught
      //    handler produced; this asserts the framework channel too.
      expect(tester.takeException(), isNull);

      // 4. The button is usable again.
      final button = tester.widget<OutlinedButton>(
        find.ancestor(
          of: find.text('Record Note'),
          matching: find.byType(OutlinedButton),
        ),
      );
      expect(button.onPressed, isNotNull,
          reason: '_busy never reset after the failure');
    },
  );

  testWidgets(
    'a successful Return still refreshes the session list',
    (tester) async {
      var gets = 0;
      final runtime = _RuntimeWith(
        await _repository((request) async {
          if (request.method == 'POST') {
            return http.Response(jsonEncode(_sessionJson), 200);
          }
          gets += 1;
          return http.Response(jsonEncode(_sessionsPayload), 200);
        }),
      );

      await _pumpScreen(tester, runtime);
      expect(gets, 1);

      await tester.tap(find.text('Return'));
      await tester.pumpAndSettle();

      // The old code refreshed inside the `try`; the wrapper must keep that
      // for the success path while adding the failure path.
      expect(gets, 2,
          reason: 'a successful action no longer re-reads the session list');
      expect(tester.takeException(), isNull);
    },
  );
}

Future<void> _pumpScreen(WidgetTester tester, HermesAppRuntime runtime) async {
  await tester.pumpWidget(
    MaterialApp(home: BrowserAssistanceScreen(runtime: runtime)),
  );
  await tester.pumpAndSettle();
}

Future<BrowserAssistanceRepository> _repository(MockClientHandler handler) async {
  final keyPair = await DeviceKeyPair.generate();
  return BrowserAssistanceRepository(
    GatewayApiClient(
      config: GatewayConfig.loopback,
      signer: Ed25519DeviceRequestSigner(deviceId: 'dev_test', keyPair: keyPair),
      httpClient: MockClient(handler),
    ),
  );
}

/// A runtime that reports as paired and hands out the repository under test.
/// Only the two members the screen reads are overridden — everything else is
/// the real `HermesAppRuntime`.
class _RuntimeWith extends HermesAppRuntime {
  _RuntimeWith(this._repository)
      : super(
          configStore: InMemoryGatewayConfigStore(),
          keyStore: InMemorySecureKeyStore(),
        );

  final BrowserAssistanceRepository _repository;

  @override
  bool get isPaired => true;

  @override
  BrowserAssistanceRepository? get browserAssistanceRepository => _repository;
}

final _sessionJson = <String, dynamic>{
  'browser_session_id': 'bs_1',
  'node_id': 'node_1',
  'agent_id': 'agent_1',
  'session_id': 'sess_1',
  'reason': 'Operator review needed on the checkout page.',
  'state': 'waiting_on_user',
  'created_at': '2026-07-31T10:00:00Z',
  'updated_at': '2026-07-31T10:00:00Z',
};

final _sessionsPayload = <String, dynamic>{
  'sessions': [_sessionJson],
};

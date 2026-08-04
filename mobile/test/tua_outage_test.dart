/// TUA must not report an outage as an empty room.
///
/// `_loadSession` used to end both of its lookups in a bare
/// `on Object { return; }`. Against a gateway that was not listening, TUA fell
/// through to "Assistance session unavailable" — the screen said *there is
/// nothing here* when the truth was *we could not reach the tower*, and the
/// `hasError` branch could never fire. Only a 404 answered *by* the tower is a
/// legitimate empty.
library;

import 'dart:convert';

import 'package:agentic_control_tower/src/api/gateway_api_client.dart';
import 'package:agentic_control_tower/src/app_runtime.dart';
import 'package:agentic_control_tower/src/config/gateway_config.dart';
import 'package:agentic_control_tower/src/repositories/alpha_repository.dart';
import 'package:agentic_control_tower/src/repositories/mock_alpha_repository.dart';
import 'package:agentic_control_tower/src/repositories/tua_repository.dart';
import 'package:agentic_control_tower/src/screens/tua_screen.dart';
import 'package:agentic_control_tower/src/security/device_request_signer.dart';
import 'package:agentic_control_tower/src/security/secure_key_store.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';

void main() {
  testWidgets('an unreachable tower renders a failure, not an empty state',
      (tester) async {
    final runtime = _RuntimeWith(
      await _tuaRepository((request) async {
        throw http.ClientException('Connection refused', request.url);
      }),
    );

    await _pumpTua(tester, runtime);

    expect(
      find.textContaining("Can't reach the control tower"),
      findsOneWidget,
      reason: 'a dead gateway was reported to the operator as an empty session',
    );
    expect(
      find.text('Assistance session unavailable'),
      findsNothing,
      reason: 'an outage must never read as "nothing here"',
    );
    expect(find.text('Retry'), findsOneWidget);
    expect(find.textContaining('ClientException'), findsNothing);
    expect(tester.takeException(), isNull);
  });

  // Isolates the *first* lookup's guard specifically. The session lookup fails
  // with a 500 while the request list answers cleanly and is empty. With the
  // old bare swallow the 500 disappeared into the fallback path and the screen
  // reported "nothing here"; only a 404 may fall through.
  testWidgets('a 500 on the session lookup is not swallowed by the fallback',
      (tester) async {
    final runtime = _RuntimeWith(
      await _tuaRepository((request) async {
        if (request.url.path.contains('/tua/requests')) {
          return http.Response(jsonEncode({'requests': <dynamic>[]}), 200);
        }
        return http.Response('{"detail":"boom"}', 500);
      }),
    );

    await _pumpTua(tester, runtime);

    expect(find.textContaining('internal error (500)'), findsOneWidget);
    expect(find.text('Assistance session unavailable'), findsNothing);
    expect(tester.takeException(), isNull);
  });

  // Isolates the *second* lookup's guard: the session lookup 404s legitimately,
  // then the request list cannot be reached at all.
  testWidgets('an outage on the fallback lookup is not swallowed either',
      (tester) async {
    final runtime = _RuntimeWith(
      await _tuaRepository((request) async {
        if (request.url.path.contains('/tua/requests')) {
          throw http.ClientException('Connection refused', request.url);
        }
        return http.Response('{"detail":"not found"}', 404);
      }),
    );

    await _pumpTua(tester, runtime);

    expect(find.textContaining("Can't reach the control tower"), findsOneWidget);
    expect(find.text('Assistance session unavailable'), findsNothing);
    expect(tester.takeException(), isNull);
  });

  testWidgets('a real 404 from the tower is still a legitimate empty state',
      (tester) async {
    final runtime = _RuntimeWith(
      await _tuaRepository((request) async {
        // The tower is up and answering. It has no session under this id
        // (approval routes pass an approval id) and no matching request.
        if (request.url.path.contains('/tua/requests')) {
          return http.Response(jsonEncode({'requests': <dynamic>[]}), 200);
        }
        return http.Response('{"detail":"not found"}', 404);
      }),
    );

    await _pumpTua(tester, runtime);

    expect(
      find.text('Assistance session unavailable'),
      findsOneWidget,
      reason: 'a genuine not-found must stay an empty state, not a failure',
    );
    expect(find.textContaining("Can't reach the control tower"), findsNothing);
    expect(tester.takeException(), isNull);
  });
}

Future<void> _pumpTua(WidgetTester tester, HermesAppRuntime runtime) async {
  await tester.pumpWidget(
    MaterialApp(
      onGenerateRoute: (_) => MaterialPageRoute<void>(
        settings: const RouteSettings(name: '/tua', arguments: 'ctx_1'),
        builder: (_) => TuaScreen(
          repository: const MockAlphaRepository(),
          runtime: runtime,
        ),
      ),
    ),
  );
  await tester.pumpAndSettle();
}

Future<TuaRepository> _tuaRepository(MockClientHandler handler) async {
  final keyPair = await DeviceKeyPair.generate();
  return TuaRepository(
    GatewayApiClient(
      config: GatewayConfig.loopback,
      signer: Ed25519DeviceRequestSigner(deviceId: 'dev_test', keyPair: keyPair),
      httpClient: MockClient(handler),
    ),
  );
}

class _RuntimeWith extends HermesAppRuntime {
  _RuntimeWith(this._tua)
      : super(
          configStore: InMemoryGatewayConfigStore(),
          keyStore: InMemorySecureKeyStore(),
        );

  final TuaRepository _tua;

  @override
  bool get isPaired => true;

  @override
  TuaRepository? get tuaRepository => _tua;

  @override
  AlphaRepository get alphaRepository => const MockAlphaRepository();
}

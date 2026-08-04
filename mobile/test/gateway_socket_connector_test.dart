@TestOn('vm')
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:agentic_control_tower/src/api/gateway_socket_connector.dart';
import 'package:agentic_control_tower/src/api/gateway_stream_errors.dart';

void main() {
  test('a refused upgrade reports the HTTP status', () async {
    // The gateway closes the WebSocket before accepting when the access token
    // does not verify, which uvicorn serves as a 403 on the upgrade. This is
    // the exact wire behaviour a paired iPhone hit on /v1/events/stream.
    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    addTearDown(() => server.close(force: true));
    unawaited(server.forEach((request) {
      request.response.statusCode = HttpStatus.forbidden;
      request.response.close();
    }));

    final error = await connectGatewayWebSocket(
      Uri.parse('ws://127.0.0.1:${server.port}/v1/events/stream'
          '?access_token=expired'),
    ).first.then<Object?>((_) => null, onError: (Object e) => e);

    expect(error, isA<GatewayStreamUpgradeException>());
    expect((error! as GatewayStreamUpgradeException).statusCode, 403);
    expect(GatewayStreamConnectError.from(error).isAuthFailure, isTrue);
  });

  test('the reported error never carries the access token', () async {
    // dart:io builds its message from the full request URL. The runtime logs
    // connect errors, so the token must not ride along into the debug log.
    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    addTearDown(() => server.close(force: true));
    unawaited(server.forEach((request) {
      request.response.statusCode = HttpStatus.forbidden;
      request.response.close();
    }));

    final error = await connectGatewayWebSocket(
      Uri.parse('ws://127.0.0.1:${server.port}/v1/events/stream'
          '?access_token=super-secret-token'),
    ).first.then<Object?>((_) => null, onError: (Object e) => e);

    expect(error.toString(), isNot(contains('super-secret-token')));
  });

  test('an accepted upgrade delivers gateway events', () async {
    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    addTearDown(() => server.close(force: true));
    unawaited(server.forEach((request) async {
      final socket = await WebSocketTransformer.upgrade(request);
      socket.add(jsonEncode({'cursor': 'evt_1', 'type': 'system.health'}));
    }));

    final raw = await connectGatewayWebSocket(
      Uri.parse('ws://127.0.0.1:${server.port}/v1/events/stream'
          '?access_token=valid'),
    ).first;

    expect(jsonDecode(raw as String), containsPair('cursor', 'evt_1'));
  });

  test('cancel completes without waiting on the handshake', () async {
    // Preserves the property the reconnect loop depends on: a listener that
    // walks away mid-connect is never left hanging on the network.
    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    addTearDown(() => server.close(force: true));
    // Never answer, so the handshake is still in flight when we cancel.
    unawaited(server.forEach((request) {}));

    final subscription = connectGatewayWebSocket(
      Uri.parse('ws://127.0.0.1:${server.port}/v1/events/stream'
          '?access_token=valid'),
    ).listen((_) {});

    await subscription.cancel().timeout(
          const Duration(seconds: 5),
          onTimeout: () => fail('cancel() waited on the handshake'),
        );
  });
}

import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:agentic_control_tower/src/api/gateway_event_stream_client.dart';
import 'package:agentic_control_tower/src/config/gateway_config.dart';

void main() {
  test('stream uri uses websocket scheme and access token', () {
    final client = GatewayEventStreamClient(
      config: GatewayConfig.fromInput('http://127.0.0.1:8787/v1'),
      accessToken: 'access-test',
    );

    final uri = client.streamUri(after: 'cursor-1');

    expect(uri.scheme, 'ws');
    expect(uri.path, '/v1/events/stream');
    expect(uri.queryParameters['access_token'], 'access-test');
    expect(uri.queryParameters['after'], 'cursor-1');
  });

  test('parses gateway event json string', () {
    final event = GatewayEventStreamClient.parseGatewayEvent(
      jsonEncode(_eventJson(cursor: 'evt_1', type: 'approval.requested')),
    );

    expect(event.cursor, 'evt_1');
    expect(event.type, 'approval.requested');
    expect(event.payload['approval_id'], 'appr_test');
  });

  test('reconnects using latest cursor', () async {
    final seenUris = <Uri>[];
    var connectCount = 0;
    final client = GatewayEventStreamClient(
      config: GatewayConfig.fromInput('http://127.0.0.1:8787/v1'),
      accessToken: 'access-test',
      initialBackoff: Duration.zero,
      maxReconnects: 1,
      socketConnector: (uri) {
        seenUris.add(uri);
        connectCount += 1;
        if (connectCount == 1) {
          return Stream<dynamic>.value(
            jsonEncode(_eventJson(cursor: 'cursor-1')),
          );
        }
        return Stream<dynamic>.value(
          jsonEncode(_eventJson(cursor: 'cursor-2')),
        );
      },
    );

    final events = await client.connect().take(2).toList();

    expect(events.map((event) => event.cursor), ['cursor-1', 'cursor-2']);
    expect(seenUris[1].queryParameters['after'], 'cursor-1');
  });

  test('surfaces connection errors via onConnectError (for token refresh)',
      () async {
    final errors = <Object>[];
    final client = GatewayEventStreamClient(
      config: GatewayConfig.fromInput('http://127.0.0.1:8787/v1'),
      accessToken: 'stale-token',
      initialBackoff: Duration.zero,
      maxReconnects: 0,
      onConnectError: errors.add,
      socketConnector: (uri) => Stream<dynamic>.error(
        StateError('WebSocket handshake failed: 403 Forbidden'),
      ),
    );

    await client.connect().toList();

    expect(errors, isNotEmpty);
    expect(errors.first.toString(), contains('403'));
  });

  test('cancel completes promptly while stuck in the reconnect loop', () async {
    // Regression: connect() was an async* generator, which only observes the
    // listener's cancel() at a `yield`. A stream that never connects (dead
    // gateway / revoked token) never yields, so cancel() never completed and
    // clearPairing hung forever awaiting it.
    var connects = 0;
    final client = GatewayEventStreamClient(
      config: GatewayConfig.fromInput('http://127.0.0.1:8787/v1'),
      accessToken: 'revoked-token',
      // Long backoff so the loop is asleep when we cancel — the exact state
      // the operator hits.
      initialBackoff: const Duration(minutes: 5),
      socketConnector: (uri) {
        connects += 1;
        return Stream<dynamic>.error(
          StateError('WebSocket handshake failed: 403 Forbidden'),
        );
      },
    );

    final subscription = client.connect().listen((_) {});
    // Let the first connect attempt fail and the backoff sleep begin.
    await Future<void>.delayed(const Duration(milliseconds: 50));
    expect(connects, greaterThanOrEqualTo(1));

    await subscription
        .cancel()
        .timeout(const Duration(seconds: 5), onTimeout: () {
      fail('cancel() did not complete while the stream was reconnecting');
    });

    // The reconnect task must stop: no further connection attempts after the
    // cancel has been observed.
    final connectsAtCancel = connects;
    await Future<void>.delayed(const Duration(milliseconds: 100));
    expect(connects, connectsAtCancel);
  });
}

Map<String, dynamic> _eventJson({
  required String cursor,
  String type = 'system.health',
}) {
  return {
    'event_id': 'evt_$cursor',
    'cursor': cursor,
    'node_id': 'node_test',
    'type': type,
    'occurred_at': '2026-06-05T12:00:00Z',
    'payload': {'approval_id': 'appr_test'},
  };
}

import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:agentic_control_tower/src/api/gateway_api_client.dart';
import 'package:agentic_control_tower/src/config/gateway_config.dart';
import 'package:agentic_control_tower/src/repositories/tui_repository.dart';
import 'package:agentic_control_tower/src/security/device_request_signer.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';

void main() {
  test('create session posts signed gateway request', () async {
    late http.Request captured;
    final client = GatewayApiClient(
      config: GatewayConfig.fromInput('http://127.0.0.1:8787/v1'),
      signer: const _StaticSigner(),
      httpClient: MockClient((request) async {
        captured = request;
        return http.Response(jsonEncode(_sessionJson()), 201);
      }),
    );

    final session = await TuiRepository(client).createSession(
      agentId: 'agent_mock',
      sessionContextId: 'sess_mock',
    );

    final body = jsonDecode(captured.body) as Map<String, dynamic>;
    expect(captured.method, 'POST');
    expect(captured.url.path, '/v1/tui/sessions');
    expect(captured.headers['X-HMCP-Device-Id'], 'dev_test');
    expect(body['agent_id'], 'agent_mock');
    expect(body['session_context_id'], 'sess_mock');
    expect(session.sessionId, 'tui_1');
    expect(session.state, 'active');
  });

  test('listSessions reads with token auth, not a device signature', () async {
    late http.Request captured;
    final client = GatewayApiClient(
      config: GatewayConfig.fromInput('http://127.0.0.1:8787/v1'),
      signer: const _StaticSigner(),
      accessToken: 'tok_abc',
      httpClient: MockClient((request) async {
        captured = request;
        return http.Response(
          jsonEncode({
            'sessions': [_sessionJson()],
          }),
          200,
        );
      }),
    );

    final sessions = await TuiRepository(client).listSessions();

    // Token auth: bearer header present, no device-signature headers (so no
    // biometric prompt just to VIEW the terminal mirror).
    expect(captured.method, 'GET');
    expect(captured.url.path, '/v1/tui/sessions');
    expect(captured.headers['Authorization'], 'Bearer tok_abc');
    expect(captured.headers.containsKey('X-HMCP-Signature'), isFalse);
    expect(captured.headers.containsKey('X-HMCP-Device-Id'), isFalse);
    expect(sessions.single.sessionId, 'tui_1');
  });

  test('getSession reads with token auth, not a device signature', () async {
    late http.Request captured;
    final client = GatewayApiClient(
      config: GatewayConfig.fromInput('http://127.0.0.1:8787/v1'),
      signer: const _StaticSigner(),
      accessToken: 'tok_abc',
      httpClient: MockClient((request) async {
        captured = request;
        return http.Response(jsonEncode(_sessionJson()), 200);
      }),
    );

    await TuiRepository(client).getSession('tui_1');

    expect(captured.method, 'GET');
    expect(captured.url.path, '/v1/tui/sessions/tui_1');
    expect(captured.headers['Authorization'], 'Bearer tok_abc');
    expect(captured.headers.containsKey('X-HMCP-Signature'), isFalse);
  });

  test('close session unwraps control response', () async {
    final client = GatewayApiClient(
      config: GatewayConfig.fromInput('http://127.0.0.1:8787/v1'),
      signer: const _StaticSigner(),
      httpClient: MockClient((request) async {
        return http.Response(
          jsonEncode({'session': _sessionJson(state: 'closed')}),
          200,
        );
      }),
    );

    final session = await TuiRepository(client).close('tui_1');

    expect(session.state, 'closed');
  });
}

class _StaticSigner implements DeviceRequestSigner {
  const _StaticSigner();

  @override
  ClearanceKeyProtection get protection =>
      ClearanceKeyProtection.developmentExportableEd25519;

  @override
  Future<SignedRequestHeaders> sign({
    required String method,
    required String pathWithQuery,
    required Uint8List body,
  }) async {
    return const SignedRequestHeaders({
      'X-HMCP-Device-Id': 'dev_test',
      'X-HMCP-Timestamp': '1',
      'X-HMCP-Nonce': 'nonce-test',
      'X-HMCP-Signature': 'signature-test',
    });
  }
}

Map<String, dynamic> _sessionJson({String state = 'active'}) {
  return {
    'session_id': 'tui_1',
    'agent_id': 'agent_mock',
    'node_id': 'node_test',
    'user_device_id': 'dev_test',
    'state': state,
    'command': '/bin/cat',
    'working_directory': '/tmp',
    'created_at': '2026-06-05T12:00:00Z',
    'last_activity_at': '2026-06-05T12:00:01Z',
    'closed_at': state == 'closed' ? '2026-06-05T12:00:02Z' : null,
    'risk_level': 'high',
    'audit_refs': ['aud_1'],
  };
}

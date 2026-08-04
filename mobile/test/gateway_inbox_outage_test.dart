/// The repository layer must not render an outage as an empty room.
///
/// `GatewayAlphaRepository._loadOpenAssistanceInbox()` ended in a bare
/// `on Object { return const []; }`. It feeds both `loadInbox()` and
/// `loadHome()`, so every refusal — a 500, an expired token, a gateway that is
/// not listening at all — arrived at the screen as a *successful* load holding
/// no assistance items. That is worse than the screen-level bug the TUA fix
/// addressed: down here the future resolves, so `snapshot.hasError` can never
/// fire and the screens' `LoadFailurePanel` is unreachable no matter how well
/// the screen is written.
///
/// The discriminator is the TUA fix's: a `GatewayApiException` proves the tower
/// answered, and only its 404 (an older gateway with no `/tua/requests` route
/// at all) is a genuine empty.
library;

import 'dart:convert';
import 'dart:io';

import 'package:agentic_control_tower/src/api/gateway_api_client.dart';
import 'package:agentic_control_tower/src/config/gateway_config.dart';
import 'package:agentic_control_tower/src/repositories/agents_repository.dart';
import 'package:agentic_control_tower/src/repositories/approvals_repository.dart';
import 'package:agentic_control_tower/src/repositories/dashboard_repository.dart';
import 'package:agentic_control_tower/src/repositories/gateway_alpha_repository.dart';
import 'package:agentic_control_tower/src/repositories/missions_repository.dart';
import 'package:agentic_control_tower/src/repositories/notifications_repository.dart';
import 'package:agentic_control_tower/src/repositories/tua_repository.dart';
import 'package:agentic_control_tower/src/security/device_request_signer.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';

void main() {
  // ISOLATES the transport half. Everything else the inbox needs answers
  // cleanly and non-empty, so the ONLY way this can pass is the assistance
  // lookup propagating. With the old bare swallow it returned an inbox of one
  // approval and no error at all.
  test('loadInbox propagates an unreachable tower instead of dropping items',
      () async {
    final repository = _repository((request) {
      if (request.url.path.contains('/tua/requests')) {
        throw http.ClientException('Connection refused', request.url);
      }
      return _ok(request);
    });

    await expectLater(
      repository.loadInbox(),
      throwsA(isA<http.ClientException>()),
      reason: 'an outage reported as "no assistance items" is a lie the '
          'screen cannot detect',
    );
  });

  // ISOLATES a SocketException specifically — the other transport shape, which
  // is not an http.ClientException and would need its own clause if anyone
  // reintroduced a type-listing catch instead of letting it propagate.
  test('loadInbox propagates a SocketException too', () async {
    final repository = _repository((request) {
      if (request.url.path.contains('/tua/requests')) {
        throw const SocketException('Network is unreachable');
      }
      return _ok(request);
    });

    await expectLater(
      repository.loadInbox(),
      throwsA(isA<SocketException>()),
    );
  });

  // ISOLATES the "the tower answered, but not with a 404" half.
  test('loadInbox propagates a 500 from the assistance route', () async {
    final repository = _repository((request) {
      if (request.url.path.contains('/tua/requests')) {
        return http.Response('{"detail":"boom"}', 500);
      }
      return _ok(request);
    });

    await expectLater(
      repository.loadInbox(),
      throwsA(isA<GatewayApiException>()
          .having((e) => e.statusCode, 'statusCode', 500)),
    );
  });

  // ISOLATES the auth case: a 401 is a pairing problem the operator must be
  // told about, not an absence of work.
  test('loadInbox propagates a 401 from the assistance route', () async {
    final repository = _repository((request) {
      if (request.url.path.contains('/tua/requests')) {
        return http.Response('{"detail":"expired"}', 401);
      }
      return _ok(request);
    });

    await expectLater(
      repository.loadInbox(),
      throwsA(isA<GatewayApiException>()
          .having((e) => e.statusCode, 'statusCode', 401)),
    );
  });

  // loadHome() shares the same helper and had the same hole — the dashboard's
  // Notifications and Security stat tiles were silently undercounted.
  test('loadHome propagates an unreachable tower', () async {
    final repository = _repository((request) {
      if (request.url.path.contains('/tua/requests')) {
        throw http.ClientException('Connection refused', request.url);
      }
      return _ok(request);
    });

    await expectLater(
      repository.loadHome(),
      throwsA(isA<http.ClientException>()),
    );
  });

  // THE NEGATIVE HALF of the discriminator. A blanket rethrow would break this:
  // a gateway with no /tua/requests route at all is a genuine "no assistance
  // items", and the rest of the inbox must still load.
  test('a 404 on the assistance route stays a legitimate empty', () async {
    final repository = _repository((request) {
      if (request.url.path.contains('/tua/requests')) {
        return http.Response('{"detail":"not found"}', 404);
      }
      return _ok(request);
    });

    final inbox = await repository.loadInbox();

    expect(inbox, hasLength(1), reason: 'the pending approval must survive');
    expect(inbox.single.id, 'appr_1');
  });

  // And a tower that answers with an empty list is still empty, not an error.
  test('an empty assistance list is still an empty inbox section', () async {
    final repository = _repository(_ok);

    final inbox = await repository.loadInbox();

    expect(inbox.map((item) => item.id), ['appr_1']);
  });
}

GatewayAlphaRepository _repository(
  Object? Function(http.Request request) handler,
) {
  final client = GatewayApiClient(
    config: GatewayConfig.fromInput('http://127.0.0.1:8787/v1'),
    signer: const _StaticSigner(),
    httpClient: MockClient((request) async {
      final result = handler(request);
      return result as http.Response;
    }),
  );
  return GatewayAlphaRepository(
    dashboardRepository: DashboardRepository(client),
    agentsRepository: AgentsRepository(client),
    approvalsRepository: ApprovalsRepository(client),
    missionsRepository: MissionsRepository(client),
    notificationsRepository: NotificationsRepository(client),
    tuaRepository: TuaRepository(client),
  );
}

/// A healthy gateway: one pending approval, nothing else outstanding.
http.Response _ok(http.Request request) {
  final path = request.url.path;
  if (path.endsWith('/approvals')) {
    return http.Response(jsonEncode({'approvals': [_approvalJson()]}), 200);
  }
  if (path.contains('/tua/requests')) {
    return http.Response(jsonEncode({'requests': <dynamic>[]}), 200);
  }
  if (path.endsWith('/notifications')) {
    return http.Response(jsonEncode({'notifications': <dynamic>[]}), 200);
  }
  if (path.endsWith('/agents')) {
    return http.Response(jsonEncode({'agents': <dynamic>[]}), 200);
  }
  if (path.endsWith('/missions')) {
    return http.Response(jsonEncode({'missions': <dynamic>[]}), 200);
  }
  if (path.endsWith('/inventory')) {
    return http.Response(jsonEncode({'nodes': <dynamic>[]}), 200);
  }
  return http.Response('{}', 200);
}

Map<String, dynamic> _approvalJson() {
  return {
    'approval_id': 'appr_1',
    'action_id': 'act_1',
    'params_fingerprint': 'fp_1',
    'session_id': 'sess_1',
    'agent_id': 'agent_1',
    'node_id': 'node_1',
    'requested_tool': 'shell',
    'summary': 'Run a migration',
    'risk_level': 'high',
    'state': 'pending',
    'expires_at': '2099-01-01T00:00:00Z',
    'full_payload_redacted': <String, dynamic>{},
    'options': <dynamic>[],
    'decision_scope': 'once',
  };
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
    required List<int> body,
  }) async {
    return const SignedRequestHeaders({
      'X-HMCP-Device-Id': 'dev_test',
      'X-HMCP-Timestamp': '1',
      'X-HMCP-Nonce': 'nonce-test',
      'X-HMCP-Signature': 'signature-test',
    });
  }
}

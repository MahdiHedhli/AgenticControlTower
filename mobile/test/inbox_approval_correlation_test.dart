/// An inbox row must carry the id the approval route can actually resolve.
///
/// `_inboxFromNotification` built every notification-derived `InboxItem` with
/// `id: notification.notificationId` — a `ntf_…` — and `inbox_screen._openItem`
/// pushed the approval detail route with that id for both `approval` and
/// `security` kinds. `GET /v1/approvals/ntf_…` answers 404, so tapping a real,
/// current alert showed the operator a load-failure panel.
///
/// The tower's actual link is `action_id`: `store.create_notification` and
/// `store.create_approval` write the same value. `NotificationRecord` dropped
/// it entirely, so the client had no id it could legally follow — the wrong id
/// was the only id available.
library;

import 'dart:convert';

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
  test('a notification announcing an approval carries that approval id',
      () async {
    final inbox = await _repository().loadInbox();
    final row = inbox.firstWhere((item) => item.id == 'ntf_1');

    expect(
      row.approvalId,
      'appr_1',
      reason: 'the row must carry the approval id correlated by action_id; '
          'following row.id would GET /v1/approvals/ntf_1 -> 404',
    );
    expect(row.approvalId, isNot(row.id),
        reason: 'a notification id is not an approval id');
  });

  test('a notification announcing no action has nothing to open', () async {
    final inbox = await _repository().loadInbox();
    final row = inbox.firstWhere((item) => item.id == 'ntf_alert');

    expect(
      row.approvalId,
      isNull,
      reason: 'every live security_alert has action_id null; a non-null value '
          'here would send the operator to a screen that can only fail',
    );
  });

  test('an approval-derived row still points at itself', () async {
    final inbox = await _repository().loadInbox();
    final row = inbox.firstWhere((item) => item.id == 'appr_1');
    expect(row.approvalId, 'appr_1');
  });
}

GatewayAlphaRepository _repository() {
  final client = GatewayApiClient(
    config: GatewayConfig.fromInput('http://127.0.0.1:8787/v1'),
    signer: const _StaticSigner(),
    httpClient: MockClient((request) async => _ok(request)),
  );
  return GatewayAlphaRepository(
    approvalsRepository: ApprovalsRepository(client),
    agentsRepository: AgentsRepository(client),
    notificationsRepository: NotificationsRepository(client),
    missionsRepository: MissionsRepository(client),
    dashboardRepository: DashboardRepository(client),
    tuaRepository: TuaRepository(client),
  );
}

http.Response _ok(http.Request request) {
  final path = request.url.path;
  if (path.endsWith('/approvals')) {
    return http.Response(jsonEncode({
      'approvals': [_approvalJson()]
    }), 200);
  }
  if (path.contains('/tua/requests')) {
    return http.Response(jsonEncode({'requests': <dynamic>[]}), 200);
  }
  if (path.endsWith('/notifications')) {
    return http.Response(
        jsonEncode({
          'notifications': [
            {
              'notification_id': 'ntf_1',
              'category': 'approval_required',
              'urgency': 'high',
              'state': 'delivered',
              'created_at': '2026-01-01T00:00:00Z',
              'title_safe': 'Approval required',
              'action_id': 'act_1',
            },
            {
              'notification_id': 'ntf_alert',
              'category': 'security_alert',
              'urgency': 'high',
              'state': 'delivered',
              'created_at': '2026-01-01T00:00:00Z',
              'title_safe': 'Security alert',
            },
          ]
        }),
        200);
  }
  return http.Response(
      jsonEncode({
        'agents': <dynamic>[],
        'missions': <dynamic>[],
        'nodes': <dynamic>[],
      }),
      200);
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

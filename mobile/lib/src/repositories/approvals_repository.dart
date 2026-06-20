import 'dart:convert';
import 'dart:typed_data';

import '../api/gateway_api_client.dart';
import '../clearance/canonical_json.dart';
import '../models/core_models.dart';
import '../security/secure_enclave_signer.dart';

class ApprovalsRepository {
  const ApprovalsRepository(this.apiClient);

  final GatewayApiClient apiClient;

  Future<List<ApprovalRequestModel>> listPending() async {
    final response = await apiClient.getJson(
      '/approvals',
      query: {'state': 'pending'},
    );
    return _approvals(response);
  }

  Future<ApprovalRequestModel> getApproval(String approvalId) async {
    final response = await apiClient.getJson('/approvals/$approvalId');
    return ApprovalRequestModel.fromJson(response);
  }

  Future<ApprovalRequestModel> approveOnce(String approvalId) async {
    await apiClient.postJson('/approvals/$approvalId/approve_once');
    return getApproval(approvalId);
  }

  Future<ApprovalRequestModel> approveForSession(String approvalId) async {
    await decide(
      approvalId,
      decision: 'approve',
      scope: 'session',
    );
    return getApproval(approvalId);
  }

  Future<ApprovalRequestModel> approveForAgent(String approvalId) async {
    await decide(
      approvalId,
      decision: 'approve',
      scope: 'agent',
    );
    return getApproval(approvalId);
  }

  Future<ApprovalRequestModel> deny(String approvalId) async {
    await apiClient.postJson('/approvals/$approvalId/deny');
    return getApproval(approvalId);
  }

  Future<Map<String, dynamic>> decide(
    String approvalId, {
    required String decision,
    required String scope,
  }) async {
    final approval = await getApproval(approvalId);
    final decisionId = 'dec_${DateTime.now().microsecondsSinceEpoch}';
    final signedPayload = {
      'approval_id': approvalId,
      'decision': decision,
      'scope': scope,
      'decision_id': decisionId,
      'params_fingerprint': approval.paramsFingerprint,
    };
    final signature = await _signDecision(signedPayload, approvalId);
    return await apiClient.postJson(
      '/approvals/$approvalId/decisions',
      body: {
        'decision_id': decisionId,
        'decision': decision,
        'scope': scope,
        'signed_payload': signedPayload,
        'signature': signature,
      },
    );
  }

  /// Produce a real per-decision signature over the canonical signed_payload when
  /// the device key is enclave-backed (gated by user presence). The gateway does
  /// not yet independently verify this field — the authoritative, server-verified
  /// signature is the HMCP transport signature on this request — but this is
  /// honest crypto rather than a placeholder.
  Future<String> _signDecision(
    Map<String, dynamic> signedPayload,
    String approvalId, {
    String? reason,
  }) async {
    final signer = apiClient.signer;
    if (signer is SecureEnclaveDeviceRequestSigner) {
      final bytes = Uint8List.fromList(utf8.encode(canonicalJson(signedPayload)));
      return signer.signPayload(
        bytes,
        reason: reason ?? 'Approve clearance $approvalId',
      );
    }
    // Legacy/dev (web) signer cannot produce a non-exportable per-decision
    // signature; the transport signature still authenticates the request.
    return 'hmcp-device-request-signature';
  }

  /// Send a signed operator intervention (pause / steer / stop) for a session.
  /// The plugin drains it and applies it at the agent's next tool boundary.
  Future<void> intervene(
    String sessionId, {
    required String type,
    required String reason,
    required String agentId,
    String? instruction,
    String? faceIdReason,
  }) async {
    final interventionId = 'intv_${DateTime.now().microsecondsSinceEpoch}';
    final signedPayload = <String, dynamic>{
      'type': type,
      'agent_id': agentId,
      'intervention_id': interventionId,
    };
    final signature = await _signDecision(
      signedPayload,
      interventionId,
      reason: faceIdReason ?? reason,
    );
    await apiClient.postJson(
      '/sessions/$sessionId/interventions',
      body: {
        'intervention_id': interventionId,
        'type': type,
        'reason': reason,
        if (instruction != null) 'instruction': instruction,
        'signed_payload': signedPayload,
        'signature': signature,
      },
    );
  }

  Future<void> pauseAgent(String sessionId, String agentId) => intervene(
        sessionId,
        type: 'pause',
        reason: 'Operator paused the agent',
        agentId: agentId,
        faceIdReason: 'Pause agent',
      );

  Future<void> stopTask(String sessionId, String agentId) => intervene(
        sessionId,
        type: 'cancel_task',
        reason: 'Operator stopped the current task',
        agentId: agentId,
        faceIdReason: 'Stop task',
      );

  Future<void> stopAgent(String sessionId, String agentId) => intervene(
        sessionId,
        type: 'kill_agent',
        reason: 'Operator stopped the agent',
        agentId: agentId,
        faceIdReason: 'Stop agent',
      );
}

List<ApprovalRequestModel> _approvals(Map<String, dynamic> response) {
  return (response['approvals'] as List<dynamic>? ?? const [])
      .map((item) =>
          ApprovalRequestModel.fromJson(Map<String, dynamic>.from(item as Map)))
      .toList();
}

import '../api/gateway_api_client.dart';
import '../models/core_models.dart';

class TuiRepository {
  const TuiRepository(this._apiClient);

  final GatewayApiClient _apiClient;

  Future<TuiSessionModel> createSession({
    String agentId = 'agent_mock',
    String? nodeId,
    String? sessionContextId,
    String? command,
    String? workingDirectory,
    String riskLevel = 'high',
  }) async {
    final json = await _apiClient.postJson(
      '/tui/sessions',
      body: {
        'agent_id': agentId,
        'node_id': nodeId,
        'session_context_id': sessionContextId,
        'command': command,
        'working_directory': workingDirectory,
        'risk_level': riskLevel,
      },
    );
    return TuiSessionModel.fromJson(json);
  }

  Future<TuiAttachTokenModel> createAttachToken(String sessionId) async {
    final json = await _apiClient.postJson(
      '/tui/sessions/$sessionId/attach-token',
    );
    return TuiAttachTokenModel.fromJson(json);
  }

  Future<List<TuiSessionModel>> listSessions({String? state}) async {
    // Read-only: token auth (signed: false) — no device signature, no biometric
    // prompt just to VIEW the terminal mirror.
    final json = await _apiClient.getJson(
      '/tui/sessions',
      query: {'state': state},
      signed: false,
    );
    return (json['sessions'] as List<dynamic>)
        .map((item) => TuiSessionModel.fromJson(
              Map<String, dynamic>.from(item as Map),
            ))
        .toList();
  }

  /// Node-owned, read-only relay sessions that mirror a live agent's terminal
  /// (created by the Hermes bridge). Any tui-capable device may watch them.
  Future<List<TuiSessionModel>> listRelaySessions() async {
    final sessions = await listSessions();
    return sessions
        .where((session) =>
            session.userDeviceId == '__relay__' && session.state != 'closed')
        .toList();
  }

  Future<TuiSessionModel> getSession(String sessionId) async {
    // Read-only: token auth (signed: false), same as listSessions.
    final json = await _apiClient.getJson(
      '/tui/sessions/$sessionId',
      signed: false,
    );
    return TuiSessionModel.fromJson(json);
  }

  Future<TuiSessionModel> detach(String sessionId) async {
    final json = await _apiClient.postJson('/tui/sessions/$sessionId/detach');
    return _sessionFromControlResponse(json);
  }

  Future<TuiSessionModel> close(String sessionId) async {
    final json = await _apiClient.postJson('/tui/sessions/$sessionId/close');
    return _sessionFromControlResponse(json);
  }

  TuiSessionModel _sessionFromControlResponse(Map<String, dynamic> json) {
    return TuiSessionModel.fromJson(
      Map<String, dynamic>.from(json['session'] as Map),
    );
  }
}

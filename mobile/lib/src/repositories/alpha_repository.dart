import '../models/alpha_models.dart';

/// The tower answered, and the record the operator asked for is not in the
/// fleet it returned.
///
/// This is the third state in the vocabulary the rest of the app already
/// speaks, and it exists because the first two could not say it:
///
///  * a transport failure (`ClientException` / `SocketException`) means we
///    never reached the tower — "can't reach the control tower";
///  * a [GatewayApiException] means the tower answered and refused, and its
///    `statusCode` is what separates a genuine empty from an outage (see
///    `GatewayAlphaRepository._loadOpenAssistanceInbox` and
///    `TuaScreen._isNotFound`);
///  * this means the tower answered *successfully* and the record simply is
///    not there.
///
/// Nothing about that third case is an error condition on the wire, so there
/// is no HTTP status to carry it — which is exactly why the lookup that
/// produced it used to substitute a mock record instead. Screens surface it
/// through the same `hasError` -> [LoadFailurePanel] path as the other two,
/// and [operatorErrorMessage] gives it its own line so an operator can tell
/// "this agent is no longer in the fleet" from "we cannot reach the tower".
class FleetRecordNotFoundException implements Exception {
  const FleetRecordNotFoundException({required this.kind, required this.id});

  /// What was looked up: `'agent'`, `'approval'`, …
  final String kind;

  /// The id the operator's navigation asked for.
  final String id;

  @override
  String toString() => 'FleetRecordNotFoundException($kind "$id" not in fleet)';
}

/// This surface has no live source on the control tower, so there is nothing
/// honest to return.
///
/// Distinct from [FleetRecordNotFoundException]: the record is not "absent from
/// the fleet", we simply never asked the tower anything. The paired app serves
/// these surfaces from their own dedicated repositories (`TuaRepository`,
/// `TuiRepository`); the [AlphaRepository] members exist for the unpaired demo
/// repository. A live repository reaching one of them means a screen took the
/// demo path while paired — a bug, and one that must not be paid for with
/// fabricated conversation or terminal output.
class LiveDataUnavailableException implements Exception {
  const LiveDataUnavailableException(this.surface);

  final String surface;

  @override
  String toString() => 'LiveDataUnavailableException($surface)';
}

abstract class AlphaRepository {
  Future<HomeAlphaSnapshot> loadHome();
  Future<List<FleetAgent>> loadAgents();
  Future<FleetAgent> loadAgent(String agentId);
  Future<List<MissionSummary>> loadMissions();
  Future<List<InboxItem>> loadInbox();
  Future<ApprovalAlpha> loadApproval(String approvalId);
  Future<ApprovalAlpha> approveOnce(String approvalId);
  Future<ApprovalAlpha> approveForSession(String approvalId);
  Future<ApprovalAlpha> approveForAgent(String approvalId);
  Future<ApprovalAlpha> deny(String approvalId);
  Future<void> pauseAgent(String sessionId, String agentId);
  Future<void> stopTask(String sessionId, String agentId);
  Future<void> stopAgent(String sessionId, String agentId);
  Future<AssistanceSessionAlpha> loadAssistanceSession(String sessionId);
  Future<TerminalSessionAlpha> loadTerminalSession(String sessionId);
}

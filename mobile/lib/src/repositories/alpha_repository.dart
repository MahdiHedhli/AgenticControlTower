import '../models/alpha_models.dart';

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

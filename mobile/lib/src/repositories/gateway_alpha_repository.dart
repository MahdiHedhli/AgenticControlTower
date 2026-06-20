import 'dart:convert';

import '../models/alpha_models.dart';
import '../models/core_models.dart';
import 'agents_repository.dart';
import 'alpha_repository.dart';
import 'approvals_repository.dart';
import 'dashboard_repository.dart';
import 'mock_alpha_repository.dart';
import 'missions_repository.dart';
import 'notifications_repository.dart';
import 'tua_repository.dart';

class GatewayAlphaRepository implements AlphaRepository {
  const GatewayAlphaRepository({
    required this.dashboardRepository,
    required this.agentsRepository,
    required this.approvalsRepository,
    required this.missionsRepository,
    required this.notificationsRepository,
    required this.tuaRepository,
    this.fallback = const MockAlphaRepository(),
  });

  final DashboardRepository dashboardRepository;
  final AgentsRepository agentsRepository;
  final ApprovalsRepository approvalsRepository;
  final MissionsRepository missionsRepository;
  final NotificationsRepository notificationsRepository;
  final TuaRepository tuaRepository;
  final AlphaRepository fallback;

  @override
  Future<HomeAlphaSnapshot> loadHome() async {
    final snapshot = await dashboardRepository.loadSnapshot();
    final fallbackHome = await fallback.loadHome();
    final assistance = await _loadOpenAssistanceInbox();
    final agents = snapshot.agents.map(_agentFromGateway).toList();
    final approvals =
        snapshot.pendingApprovals.map(_approvalFromGateway).toList();
    // Real agent questions (TUA) replace the notification-derived assistance
    // rows so each carries its true requestId for the answer flow.
    final notifications = [
      ...snapshot.notifications
          .where((notification) =>
              _kindFromNotification(notification.category) !=
              InboxKind.assistance)
          .map(_inboxFromNotification),
      ...assistance,
    ];
    final missions =
        snapshot.missions.map((mission) => _missionFromGateway(mission)).toList();
    final activeMissions =
        missions.where((mission) => mission.state != MissionState.complete).toList();
    final onlineAgents = agents
        .where((agent) => agent.status != AgentRunStatus.offline)
        .length
        .toString();

    return HomeAlphaSnapshot(
      stats: [
        DashboardStat(
          label: 'Agents',
          value: agents.length.toString(),
          trend: '$onlineAgents online',
          intent: 'neutral',
        ),
        DashboardStat(
          label: 'Online',
          value: onlineAgents,
          trend: '${snapshot.nodes.length} nodes registered',
          intent: 'good',
        ),
        DashboardStat(
          label: 'Missions',
          value: missions.length.toString(),
          trend: '${activeMissions.length} active',
          intent: 'active',
        ),
        DashboardStat(
          label: 'Approvals',
          value: approvals.length.toString(),
          trend: 'pending review',
          intent: approvals.isEmpty ? 'neutral' : 'warn',
        ),
        DashboardStat(
          label: 'Notifications',
          value: notifications.length.toString(),
          trend: 'recent gateway records',
          intent: 'active',
        ),
        DashboardStat(
          label: 'Security',
          value: notifications
              .where((item) => item.kind == InboxKind.security)
              .length
              .toString(),
          trend: 'security alerts',
          intent: 'critical',
        ),
      ],
      pendingApprovals: approvals,
      activeMissions: activeMissions,
      agents: agents,
      activity: fallbackHome.activity,
      notifications: notifications,
    );
  }

  @override
  Future<List<FleetAgent>> loadAgents() async {
    final agents = await agentsRepository.listAgents();
    return agents.map(_agentFromGateway).toList();
  }

  @override
  Future<FleetAgent> loadAgent(String agentId) async {
    final agents = await loadAgents();
    for (final agent in agents) {
      if (agent.id == agentId) {
        return agent;
      }
    }
    return fallback.loadAgent(agentId);
  }

  @override
  Future<List<MissionSummary>> loadMissions() async {
    final missions = await missionsRepository.listMissions();
    return missions.map(_missionFromGateway).toList();
  }

  @override
  Future<List<InboxItem>> loadInbox() async {
    final approvals = await approvalsRepository.listPending();
    final notifications = await notificationsRepository.listRecent();
    final assistance = await _loadOpenAssistanceInbox();
    return [
      ...approvals.map(_inboxFromApproval),
      ...notifications
          .where((notification) =>
              _kindFromNotification(notification.category) !=
              InboxKind.assistance)
          .map(_inboxFromNotification),
      ...assistance,
    ];
  }

  /// Real, operator-actionable TUA assistance requests as inbox items, each
  /// carrying its true requestId so the TUA screen can open a real session.
  /// Best-effort: a gateway without /tua/requests degrades to no items rather
  /// than failing the whole inbox.
  Future<List<InboxItem>> _loadOpenAssistanceInbox() async {
    try {
      final requests = await tuaRepository.listRequests();
      return requests
          .where((request) => _isOpenAssistance(request.state))
          .map(_inboxFromAssistanceRequest)
          .toList();
    } on Object {
      return const [];
    }
  }

  @override
  Future<ApprovalAlpha> loadApproval(String approvalId) async {
    final approval = await approvalsRepository.getApproval(approvalId);
    return _approvalFromGateway(approval);
  }

  @override
  Future<ApprovalAlpha> approveOnce(String approvalId) async {
    final approval = await approvalsRepository.approveOnce(approvalId);
    return _approvalFromGateway(approval);
  }

  @override
  Future<ApprovalAlpha> approveForSession(String approvalId) async {
    final approval = await approvalsRepository.approveForSession(approvalId);
    return _approvalFromGateway(approval);
  }

  @override
  Future<ApprovalAlpha> approveForAgent(String approvalId) async {
    final approval = await approvalsRepository.approveForAgent(approvalId);
    return _approvalFromGateway(approval);
  }

  @override
  Future<ApprovalAlpha> deny(String approvalId) async {
    final approval = await approvalsRepository.deny(approvalId);
    return _approvalFromGateway(approval);
  }

  @override
  Future<void> pauseAgent(String sessionId, String agentId) =>
      approvalsRepository.pauseAgent(sessionId, agentId);

  @override
  Future<void> stopTask(String sessionId, String agentId) =>
      approvalsRepository.stopTask(sessionId, agentId);

  @override
  Future<void> stopAgent(String sessionId, String agentId) =>
      approvalsRepository.stopAgent(sessionId, agentId);

  @override
  Future<AssistanceSessionAlpha> loadAssistanceSession(String sessionId) {
    return fallback.loadAssistanceSession(sessionId);
  }

  @override
  Future<TerminalSessionAlpha> loadTerminalSession(String sessionId) {
    return fallback.loadTerminalSession(sessionId);
  }
}

FleetAgent _agentFromGateway(GatewayAgent agent) {
  return FleetAgent(
    id: agent.agentId,
    name: agent.displayName,
    team: agent.nodeId,
    status: _statusFromGateway(agent.status),
    node: agent.nodeId,
    currentMission:
        agent.currentTarget ?? agent.currentTool ?? 'No active mission',
    lastActivity: agent.activeSessionId == null
        ? 'idle'
        : 'session ${agent.activeSessionId}',
    capabilities: [
      if (agent.currentTool != null) agent.currentTool!,
      if (agent.currentTarget != null) 'targeted',
    ],
    notificationCount: 0,
    approvalCount: 0,
  );
}

ApprovalAlpha _approvalFromGateway(ApprovalRequestModel approval) {
  return ApprovalAlpha(
    id: approval.approvalId,
    title: '${approval.requestedTool} approval requested',
    agentName: approval.agentId,
    node: approval.nodeId,
    session: approval.sessionId,
    risk: approval.riskLevel,
    state: approval.state,
    requestedTool: approval.requestedTool,
    summary: approval.summary,
    payloadPreview: jsonEncode(approval.fullPayloadRedacted),
    expiresIn: _timeUntil(approval.expiresAt),
    constraints: approval.options,
    decisionScope: approval.decisionScope,
  );
}

MissionSummary _missionFromGateway(MissionRecord mission) {
  return MissionSummary(
    id: mission.missionId,
    title: mission.title ?? mission.missionId,
    agentName: mission.agentId,
    team: mission.nodeId,
    state: _missionStateFromGateway(mission.state),
    progressLabel: mission.summary ?? mission.state,
    lastEvent: _timeAgo(mission.updatedAt),
  );
}

InboxItem _inboxFromApproval(ApprovalRequestModel approval) {
  return InboxItem(
    id: approval.approvalId,
    kind: InboxKind.approval,
    title: 'Approval required',
    subtitle: approval.summary,
    agentName: approval.agentId,
    timeLabel: _timeUntil(approval.expiresAt),
    unread: true,
    priority: approval.riskLevel,
  );
}

InboxItem _inboxFromNotification(NotificationRecord notification) {
  return InboxItem(
    id: notification.notificationId,
    kind: _kindFromNotification(notification.category),
    title: notification.title ?? notification.category,
    subtitle: notification.body ?? notification.state,
    agentName: notification.agentId ?? 'Hermes Gateway',
    timeLabel: _timeAgo(notification.createdAt),
    unread: notification.state != 'read',
    priority: notification.urgency,
  );
}

InboxItem _inboxFromAssistanceRequest(AssistanceRequestModel request) {
  return InboxItem(
    id: request.requestId,
    kind: InboxKind.assistance,
    title: 'Agent needs your input',
    subtitle: request.reason,
    agentName: request.agentId,
    timeLabel: _timeAgo(request.updatedAt),
    unread: true,
    priority: 'high',
  );
}

/// Assistance states that still need an operator. Terminal states
/// (returned_to_agent / closed / cancelled) are not actionable.
bool _isOpenAssistance(String state) {
  return switch (state) {
    'requested' || 'active' || 'waiting_on_user' || 'user_controlling' => true,
    _ => false,
  };
}

AgentRunStatus _statusFromGateway(String status) {
  return switch (status) {
    'running' => AgentRunStatus.running,
    'blocked' => AgentRunStatus.blocked,
    'waiting_approval' => AgentRunStatus.waitingApproval,
    'waiting_assistance' => AgentRunStatus.waitingAssistance,
    'user_controlling' => AgentRunStatus.userControlling,
    'paused' => AgentRunStatus.paused,
    'offline' => AgentRunStatus.offline,
    'failed' => AgentRunStatus.failed,
    'completed' => AgentRunStatus.completed,
    'warning' => AgentRunStatus.warning,
    'error' => AgentRunStatus.warning,
    'idle' => AgentRunStatus.idle,
    _ => AgentRunStatus.online,
  };
}

MissionState _missionStateFromGateway(String state) {
  return switch (state) {
    'queued' => MissionState.queued,
    'running' => MissionState.running,
    'waiting_approval' => MissionState.waitingApproval,
    'waiting_assistance' => MissionState.waitingAssistance,
    'user_controlling' => MissionState.userControlling,
    'completed' => MissionState.complete,
    'failed' => MissionState.failed,
    'cancelled' => MissionState.cancelled,
    _ => MissionState.running,
  };
}

InboxKind _kindFromNotification(String category) {
  return switch (category) {
    'approval_required' => InboxKind.approval,
    'security_alert' => InboxKind.security,
    'agent_blocked' => InboxKind.assistance,
    'voice_callback' => InboxKind.assistance,
    _ => InboxKind.notification,
  };
}

String _timeUntil(DateTime time) {
  final diff = time.difference(DateTime.now());
  if (diff.isNegative) {
    return 'expired';
  }
  final minutes = diff.inMinutes;
  if (minutes < 60) {
    return '${minutes}m';
  }
  return '${diff.inHours}h';
}

String _timeAgo(DateTime time) {
  final diff = DateTime.now().difference(time);
  if (diff.inMinutes < 1) {
    return 'now';
  }
  if (diff.inMinutes < 60) {
    return '${diff.inMinutes}m';
  }
  return '${diff.inHours}h';
}

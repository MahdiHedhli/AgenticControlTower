import 'dart:convert';

import '../api/gateway_api_client.dart';
import '../models/alpha_models.dart';
import '../models/core_models.dart';
import 'agents_repository.dart';
import 'alpha_repository.dart';
import 'approvals_repository.dart';
import 'dashboard_repository.dart';
import 'missions_repository.dart';
import 'notifications_repository.dart';
import 'tua_repository.dart';

/// The paired device's view of the fleet: every answer here comes from the
/// control tower, or is an honest refusal.
///
/// This class used to hold a `MockAlphaRepository fallback`, default-constructed
/// into the constructor so `app_runtime` got one whether it asked or not, and
/// four members read from it. A paired operator therefore saw invented fleet
/// state — an agent that does not exist, a "security alert" nobody raised,
/// terminal output nobody ran — with no mock indicator, no error, and no empty
/// state. On a control plane that is worse than an outage: an outage is visible,
/// and fabricated state is not.
///
/// The field is gone rather than merely unused. A live repository that *can*
/// reach demo fixtures will eventually reach them again; one that cannot hold a
/// reference to them cannot. Absence is now said with
/// [FleetRecordNotFoundException] / [LiveDataUnavailableException], and every
/// other failure propagates.
class GatewayAlphaRepository implements AlphaRepository {
  const GatewayAlphaRepository({
    required this.dashboardRepository,
    required this.agentsRepository,
    required this.approvalsRepository,
    required this.missionsRepository,
    required this.notificationsRepository,
    required this.tuaRepository,
  });

  final DashboardRepository dashboardRepository;
  final AgentsRepository agentsRepository;
  final ApprovalsRepository approvalsRepository;
  final MissionsRepository missionsRepository;
  final NotificationsRepository notificationsRepository;
  final TuaRepository tuaRepository;

  @override
  Future<HomeAlphaSnapshot> loadHome() async {
    final snapshot = await dashboardRepository.loadSnapshot();
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
    // "Online" counts agents the tower positively reported as up. An agent whose
    // status this build cannot read is not evidence of an online agent, so it is
    // not counted as one.
    final onlineAgents = agents
        .where((agent) =>
            agent.status != AgentRunStatus.offline &&
            agent.status != AgentRunStatus.unknown)
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
      activity: _activityFromNotifications(snapshot.notifications),
      notifications: notifications,
    );
  }

  @override
  Future<List<FleetAgent>> loadAgents() async {
    final agents = await agentsRepository.listAgents();
    return agents.map(_agentFromGateway).toList();
  }

  /// One agent from the live fleet, or an honest "it is not in the fleet".
  ///
  /// This used to end in `return fallback.loadAgent(agentId)`. The mock it
  /// delegated to is `firstWhere(..., orElse: () => _agents.first)`, which can
  /// never decline — so a stale notification, an expired deep link, or an agent
  /// that was retired mid-session rendered a **fully populated running agent**
  /// ("Repo Sentinel" on node "work-vm-02", three notifications, one approval)
  /// on a paired device talking to a healthy tower. No mock indicator, no error,
  /// no empty state; the operator had no way to tell it was invented.
  ///
  /// The list load above already carries the other two states: a transport
  /// failure propagates ("can't reach the tower"), and a [GatewayApiException]
  /// propagates with the tower's own status. Reaching the end of the loop means
  /// the tower answered and this id is simply not in what it returned — the one
  /// state neither of those can express, so it gets its own.
  @override
  Future<FleetAgent> loadAgent(String agentId) async {
    final agents = await loadAgents();
    for (final agent in agents) {
      if (agent.id == agentId) {
        return agent;
      }
    }
    throw FleetRecordNotFoundException(kind: 'agent', id: agentId);
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
  ///
  /// This used to end in a bare `on Object { return const []; }`. Because it
  /// feeds both [loadInbox] and [loadHome], **every** refusal — a 500, an
  /// expired token, a gateway that is not listening at all — was rendered to the
  /// operator as "you have no items". That is the same dishonesty the TUA screen
  /// fix addressed, one layer down, and down here it silently defeats the
  /// screen-level guard: the future resolves successfully, so `hasError` can
  /// never fire and `LoadFailurePanel` can never render.
  ///
  /// The discriminator is the one the TUA fix uses. A [GatewayApiException]
  /// exists only because a response came back, so it already proves the tower
  /// answered; a 404 on this route is an older gateway that has no
  /// `/tua/requests` at all, which is a genuine "no assistance items" and stays
  /// empty. Everything else — 5xx, auth, and any transport failure
  /// (`ClientException` / `SocketException`, which never reach this catch
  /// clause) — propagates so the screens can say what actually happened.
  Future<List<InboxItem>> _loadOpenAssistanceInbox() async {
    final List<AssistanceRequestModel> requests;
    try {
      requests = await tuaRepository.listRequests();
    } on GatewayApiException catch (error) {
      if (error.statusCode == 404) {
        return const [];
      }
      rethrow;
    }
    return requests
        .where((request) => _isOpenAssistance(request.state))
        .map(_inboxFromAssistanceRequest)
        .toList();
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

  /// Not served from here. The paired app reads assistance sessions through
  /// [TuaRepository] (see `TuaScreen._loadSession`); this member exists for the
  /// unpaired demo repository.
  ///
  /// It used to `return fallback.loadAssistanceSession(sessionId)`, handing back
  /// a hand-written conversation between "Repo Sentinel" and the operator with
  /// the *caller's real session id* stamped on it, so it read as specific to
  /// whatever the operator had just opened. Refusing is the only honest answer:
  /// reaching this on a paired device means a screen took the demo path, and the
  /// operator must see that rather than a plausible transcript.
  // `async` so the refusal arrives as a rejected future rather than a
  // synchronous throw at the call site — callers treat these as loads and hand
  // them to `FutureBuilder`/`claimLoadErrors`, which can only see the former.
  @override
  Future<AssistanceSessionAlpha> loadAssistanceSession(String sessionId) async {
    throw const LiveDataUnavailableException('assistance session');
  }

  /// Not served from here — [TuiRepository] and `TuiStreamClient` carry the live
  /// relay. Same history as [loadAssistanceSession], and worse content: the
  /// fixture is a fabricated shell transcript (`git status`, `39 passed`, real-
  /// looking commit hashes) under a `hermes@work-vm-02` prompt. Terminal output
  /// an operator reads as evidence must never be invented.
  @override
  Future<TerminalSessionAlpha> loadTerminalSession(String sessionId) async {
    throw const LiveDataUnavailableException('terminal session');
  }
}

/// Recent activity, from the tower's own notification records.
///
/// This used to be `(await fallback.loadHome()).activity` — unconditionally, on
/// the success path, for every paired operator. The home screen's "Recent
/// Activity" list was therefore always the mock's four hardcoded rows, including
/// a fabricated **"Security alert — PromptFence Guard flagged a route
/// advertisement"**, rendered directly beneath genuinely live stats and agents
/// and indistinguishable from them.
///
/// The tower exposes no separate activity feed, so the honest source is the
/// notification records `loadHome` has already fetched. When there are none the
/// section is genuinely empty — which is a true statement about the fleet, and
/// the only kind worth showing.
List<ActivityEvent> _activityFromNotifications(
  List<NotificationRecord> notifications,
) {
  return notifications
      .map(
        (notification) => ActivityEvent(
          title: notification.title ?? notification.category,
          detail: notification.body ?? notification.state,
          timeLabel: _timeAgo(notification.createdAt),
          severity: _severityFromNotification(notification),
        ),
      )
      .toList();
}

/// Severity straight from what the tower said, never guessed upward or downward.
String _severityFromNotification(NotificationRecord notification) {
  if (notification.category == 'security_alert') {
    return 'critical';
  }
  return switch (notification.urgency) {
    'critical' => 'critical',
    'high' || 'warn' || 'warning' => 'warn',
    _ => 'info',
  };
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
    // Was `_ => AgentRunStatus.online`. A status this build does not know —
    // from a newer gateway, or an older one — was painted healthy green and
    // counted in the dashboard's "Online" tile. That is an invented claim about
    // fleet health, made in the optimistic direction, which is the direction
    // that hides trouble.
    _ => AgentRunStatus.unknown,
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
    // Was `_ => MissionState.running`, asserting progress with no evidence.
    _ => MissionState.unknown,
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

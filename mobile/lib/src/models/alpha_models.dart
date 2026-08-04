enum AgentRunStatus {
  idle,
  online,
  running,
  blocked,
  waitingApproval,
  waitingAssistance,
  userControlling,
  paused,
  offline,
  warning,
  failed,
  completed,

  /// The tower reported a status this build does not recognise.
  ///
  /// Exists because the wire mapper's fallback used to be
  /// `_ => AgentRunStatus.online` — a newer or older gateway's unfamiliar status
  /// rendered as a healthy green agent *and* was counted in the dashboard's
  /// "Online" tile. Not knowing is not the same as being fine, and guessing
  /// upward is the direction that hides trouble.
  unknown,
}

enum MissionState {
  queued,
  running,
  waitingApproval,
  waitingAssistance,
  userControlling,
  complete,
  failed,
  cancelled,

  /// Same reason as [AgentRunStatus.unknown]: the mapper defaulted to
  /// `MissionState.running`, asserting progress it had no evidence of.
  unknown,
}

enum InboxKind {
  approval,
  notification,
  assistance,
  security,
}

enum AssistanceState {
  requested,
  active,
  waitingOnUser,
  userControlling,
  returnedToAgent,
  closed,
}

enum TerminalKeyPage {
  controls,
  symbols,
  brackets,
  functions,
}

class FleetAgent {
  const FleetAgent({
    required this.id,
    required this.name,
    required this.team,
    required this.status,
    required this.node,
    required this.currentMission,
    required this.lastActivity,
    required this.capabilities,
    required this.notificationCount,
    required this.approvalCount,
  });

  final String id;
  final String name;
  final String team;
  final AgentRunStatus status;
  final String node;
  final String currentMission;
  final String lastActivity;
  final List<String> capabilities;
  final int notificationCount;
  final int approvalCount;
}

class MissionSummary {
  const MissionSummary({
    required this.id,
    required this.title,
    required this.agentName,
    required this.team,
    required this.state,
    required this.progressLabel,
    required this.lastEvent,
  });

  final String id;
  final String title;
  final String agentName;
  final String team;
  final MissionState state;
  final String progressLabel;
  final String lastEvent;
}

class InboxItem {
  const InboxItem({
    required this.id,
    required this.kind,
    required this.title,
    required this.subtitle,
    required this.agentName,
    required this.timeLabel,
    required this.unread,
    required this.priority,
  });

  final String id;
  final InboxKind kind;
  final String title;
  final String subtitle;
  final String agentName;
  final String timeLabel;
  final bool unread;
  final String priority;
}

class ActivityEvent {
  const ActivityEvent({
    required this.title,
    required this.detail,
    required this.timeLabel,
    required this.severity,
  });

  final String title;
  final String detail;
  final String timeLabel;
  final String severity;
}

class ApprovalAlpha {
  const ApprovalAlpha({
    required this.id,
    required this.title,
    required this.agentName,
    required this.node,
    required this.session,
    required this.risk,
    required this.state,
    required this.requestedTool,
    required this.summary,
    required this.payloadPreview,
    required this.expiresIn,
    required this.constraints,
    this.decisionScope,
  });

  final String id;
  final String title;
  final String agentName;
  final String node;
  final String session;
  final String risk;
  final String state;
  final String requestedTool;
  final String summary;
  final String payloadPreview;
  final String expiresIn;
  final List<String> constraints;
  final String? decisionScope;

  ApprovalAlpha copyWith({
    String? state,
    String? decisionScope,
  }) {
    return ApprovalAlpha(
      id: id,
      title: title,
      agentName: agentName,
      node: node,
      session: session,
      risk: risk,
      state: state ?? this.state,
      requestedTool: requestedTool,
      summary: summary,
      payloadPreview: payloadPreview,
      expiresIn: expiresIn,
      constraints: constraints,
      decisionScope: decisionScope ?? this.decisionScope,
    );
  }
}

class AssistanceMessageAlpha {
  const AssistanceMessageAlpha({
    required this.sender,
    required this.body,
    required this.timeLabel,
    required this.fromUser,
  });

  final String sender;
  final String body;
  final String timeLabel;
  final bool fromUser;
}

class AssistanceSessionAlpha {
  const AssistanceSessionAlpha({
    required this.id,
    required this.agentName,
    required this.node,
    required this.mission,
    required this.state,
    required this.reason,
    required this.messages,
  });

  final String id;
  final String agentName;
  final String node;
  final String mission;
  final AssistanceState state;
  final String reason;
  final List<AssistanceMessageAlpha> messages;
}

class TerminalSessionAlpha {
  const TerminalSessionAlpha({
    required this.id,
    required this.agentName,
    required this.node,
    required this.mission,
    required this.prompt,
    required this.scrollback,
  });

  final String id;
  final String agentName;
  final String node;
  final String mission;
  final String prompt;
  final List<String> scrollback;
}

class DashboardStat {
  const DashboardStat({
    required this.label,
    required this.value,
    required this.trend,
    required this.intent,
  });

  final String label;
  final String value;
  final String trend;
  final String intent;
}

class HomeAlphaSnapshot {
  const HomeAlphaSnapshot({
    required this.stats,
    required this.pendingApprovals,
    required this.activeMissions,
    required this.agents,
    required this.activity,
    required this.notifications,
  });

  final List<DashboardStat> stats;
  final List<ApprovalAlpha> pendingApprovals;
  final List<MissionSummary> activeMissions;
  final List<FleetAgent> agents;
  final List<ActivityEvent> activity;
  final List<InboxItem> notifications;
}

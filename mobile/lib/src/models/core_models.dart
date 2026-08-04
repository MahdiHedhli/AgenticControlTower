class PairingSessionModel {
  const PairingSessionModel({
    required this.pairingId,
    required this.challenge,
    required this.status,
    required this.nodeId,
    required this.nodeFingerprint,
    required this.expiresAt,
    this.pairingToken,
  });

  final String pairingId;
  final String? pairingToken;
  final String challenge;
  final String status;
  final String nodeId;
  final String nodeFingerprint;
  final DateTime expiresAt;

  factory PairingSessionModel.fromJson(Map<String, dynamic> json) {
    return PairingSessionModel(
      pairingId: json['pairing_id'] as String,
      pairingToken: json['pairing_token'] as String?,
      challenge: json['challenge'] as String,
      status: json['status'] as String,
      nodeId: json['node_id'] as String,
      nodeFingerprint: json['node_fingerprint'] as String,
      expiresAt: DateTime.parse(json['expires_at'] as String),
    );
  }
}

class PairingCompletionModel {
  const PairingCompletionModel({
    required this.node,
    required this.deviceId,
    required this.accessToken,
    required this.refreshToken,
    required this.accessTokenExpiresAt,
  });

  final GatewayNode node;
  final String deviceId;
  final String accessToken;
  final String refreshToken;

  /// When [accessToken] stops being accepted by the event stream. Null only
  /// against a gateway that omits it; the runtime then falls back to
  /// refreshing reactively once the stream upgrade is refused.
  final DateTime? accessTokenExpiresAt;

  factory PairingCompletionModel.fromJson(Map<String, dynamic> json) {
    final device = Map<String, dynamic>.from(json['device'] as Map);
    final tokens = Map<String, dynamic>.from(json['tokens'] as Map);
    return PairingCompletionModel(
      node:
          GatewayNode.fromJson(Map<String, dynamic>.from(json['node'] as Map)),
      deviceId: device['device_id'] as String,
      accessToken: tokens['access_token'] as String,
      refreshToken: tokens['refresh_token'] as String,
      accessTokenExpiresAt: parseTokenExpiry(tokens['expires_at']),
    );
  }
}

/// Read an `expires_at` from a token payload as UTC, tolerating a gateway that
/// omits or malforms it — a session that cannot be scheduled is still usable,
/// and the reactive refresh remains the backstop.
DateTime? parseTokenExpiry(Object? value) {
  if (value is! String) {
    return null;
  }
  return DateTime.tryParse(value)?.toUtc();
}

class GatewayNode {
  const GatewayNode({
    required this.nodeId,
    required this.displayName,
    required this.environment,
    required this.health,
    this.tags = const [],
  });

  final String nodeId;
  final String displayName;
  final String environment;
  final String health;
  final List<String> tags;

  factory GatewayNode.fromJson(Map<String, dynamic> json) {
    return GatewayNode(
      nodeId: json['node_id'] as String,
      displayName: json['display_name'] as String,
      environment: json['environment'] as String,
      health: json['health'] as String,
      tags: _stringList(json['tags']),
    );
  }
}

class GatewayAgent {
  const GatewayAgent({
    required this.agentId,
    required this.nodeId,
    required this.displayName,
    required this.status,
    this.activeSessionId,
    this.currentTool,
    this.currentTarget,
  });

  final String agentId;
  final String nodeId;
  final String displayName;
  final String status;
  final String? activeSessionId;
  final String? currentTool;
  final String? currentTarget;

  factory GatewayAgent.fromJson(Map<String, dynamic> json) {
    return GatewayAgent(
      agentId: json['agent_id'] as String,
      nodeId: json['node_id'] as String,
      displayName: json['display_name'] as String,
      status: json['status'] as String,
      activeSessionId: json['active_session_id'] as String?,
      currentTool: json['current_tool'] as String?,
      currentTarget: json['current_target'] as String?,
    );
  }
}

class ApprovalRequestModel {
  const ApprovalRequestModel({
    required this.approvalId,
    required this.actionId,
    required this.nodeId,
    required this.agentId,
    required this.sessionId,
    required this.requestedTool,
    required this.riskLevel,
    required this.paramsFingerprint,
    required this.summary,
    required this.fullPayloadRedacted,
    required this.state,
    required this.expiresAt,
    required this.options,
    this.decisionScope,
  });

  final String approvalId;
  final String actionId;
  final String nodeId;
  final String agentId;
  final String sessionId;
  final String requestedTool;
  final String riskLevel;
  final String paramsFingerprint;
  final String summary;
  final Map<String, dynamic> fullPayloadRedacted;
  final String state;
  final DateTime expiresAt;
  final List<String> options;
  final String? decisionScope;

  factory ApprovalRequestModel.fromJson(Map<String, dynamic> json) {
    return ApprovalRequestModel(
      approvalId: json['approval_id'] as String,
      actionId: json['action_id'] as String,
      nodeId: json['node_id'] as String,
      agentId: json['agent_id'] as String,
      sessionId: json['session_id'] as String,
      requestedTool: json['requested_tool'] as String,
      riskLevel: json['risk_level'] as String,
      paramsFingerprint: json['params_fingerprint'] as String? ?? '',
      summary: json['summary'] as String,
      fullPayloadRedacted:
          Map<String, dynamic>.from(json['full_payload_redacted'] as Map),
      state: json['state'] as String,
      expiresAt: DateTime.parse(json['expires_at'] as String),
      options: _stringList(json['options']),
      decisionScope: json['decision_scope'] as String?,
    );
  }
}

class NotificationRecord {
  const NotificationRecord({
    required this.notificationId,
    required this.category,
    required this.urgency,
    required this.state,
    required this.createdAt,
    this.title,
    this.body,
    this.agentId,
    this.sessionId,
  });

  final String notificationId;
  final String category;
  final String urgency;
  final String state;
  final DateTime createdAt;
  final String? title;
  final String? body;
  final String? agentId;
  final String? sessionId;

  factory NotificationRecord.fromJson(Map<String, dynamic> json) {
    return NotificationRecord(
      notificationId: json['notification_id'] as String,
      category: json['category'] as String,
      urgency: json['urgency'] as String,
      state: json['state'] as String,
      createdAt: DateTime.parse(json['created_at'] as String),
      title: json['title_safe'] as String?,
      body: json['body_safe'] as String?,
      agentId: json['agent_id'] as String?,
      sessionId: json['session_id'] as String?,
    );
  }
}

class MissionRecord {
  const MissionRecord({
    required this.missionId,
    required this.nodeId,
    required this.agentId,
    required this.state,
    required this.updatedAt,
    this.sessionId,
    this.title,
    this.summary,
  });

  final String missionId;
  final String nodeId;
  final String agentId;
  final String? sessionId;
  final String state;
  final String? title;
  final String? summary;
  final DateTime updatedAt;

  factory MissionRecord.fromJson(Map<String, dynamic> json) {
    return MissionRecord(
      missionId: json['mission_id'] as String,
      nodeId: json['node_id'] as String,
      agentId: json['agent_id'] as String,
      sessionId: json['session_id'] as String?,
      state: json['state'] as String,
      title: json['title'] as String?,
      summary: json['summary'] as String?,
      updatedAt: DateTime.parse(json['updated_at'] as String),
    );
  }
}

class GatewayEvent {
  const GatewayEvent({
    required this.eventId,
    required this.cursor,
    required this.nodeId,
    required this.type,
    required this.occurredAt,
    required this.payload,
    this.agentId,
    this.sessionId,
  });

  final String eventId;
  final String cursor;
  final String nodeId;
  final String type;
  final DateTime occurredAt;
  final Map<String, dynamic> payload;
  final String? agentId;
  final String? sessionId;

  factory GatewayEvent.fromJson(Map<String, dynamic> json) {
    return GatewayEvent(
      eventId: json['event_id'] as String,
      cursor: json['cursor'] as String,
      nodeId: json['node_id'] as String,
      type: json['type'] as String,
      occurredAt: DateTime.parse(json['occurred_at'] as String),
      payload: Map<String, dynamic>.from(json['payload'] as Map),
      agentId: json['agent_id'] as String?,
      sessionId: json['session_id'] as String?,
    );
  }
}

class TuiSessionModel {
  const TuiSessionModel({
    required this.sessionId,
    required this.agentId,
    required this.nodeId,
    required this.userDeviceId,
    required this.state,
    required this.command,
    required this.workingDirectory,
    required this.createdAt,
    required this.lastActivityAt,
    required this.riskLevel,
    required this.riskLabel,
    required this.outputRetentionEnabled,
    this.closedAt,
    this.auditRefs = const [],
  });

  final String sessionId;
  final String agentId;
  final String nodeId;
  final String userDeviceId;
  final String state;
  final String command;
  final String workingDirectory;
  final DateTime createdAt;
  final DateTime lastActivityAt;
  final DateTime? closedAt;
  final String riskLevel;
  final String riskLabel;
  final bool outputRetentionEnabled;
  final List<String> auditRefs;

  factory TuiSessionModel.fromJson(Map<String, dynamic> json) {
    return TuiSessionModel(
      sessionId: json['session_id'] as String,
      agentId: json['agent_id'] as String,
      nodeId: json['node_id'] as String,
      userDeviceId: json['user_device_id'] as String,
      state: json['state'] as String,
      command: json['command'] as String,
      workingDirectory: json['working_directory'] as String,
      createdAt: DateTime.parse(json['created_at'] as String),
      lastActivityAt: DateTime.parse(json['last_activity_at'] as String),
      closedAt: json['closed_at'] == null
          ? null
          : DateTime.parse(json['closed_at'] as String),
      riskLevel: json['risk_level'] as String,
      riskLabel: json['risk_label'] as String? ?? 'operator terminal',
      outputRetentionEnabled:
          json['output_retention_enabled'] as bool? ?? false,
      auditRefs: _stringList(json['audit_refs']),
    );
  }
}

class TuiAttachTokenModel {
  const TuiAttachTokenModel({
    required this.attachToken,
    required this.expiresAt,
  });

  final String attachToken;
  final DateTime expiresAt;

  factory TuiAttachTokenModel.fromJson(Map<String, dynamic> json) {
    return TuiAttachTokenModel(
      attachToken: json['attach_token'] as String,
      expiresAt: DateTime.parse(json['expires_at'] as String),
    );
  }
}

class AssistanceRequestModel {
  const AssistanceRequestModel({
    required this.requestId,
    required this.nodeId,
    required this.agentId,
    required this.sessionId,
    required this.reason,
    required this.state,
    required this.createdAt,
    required this.updatedAt,
    this.approvalId,
  });

  final String requestId;
  final String nodeId;
  final String agentId;
  final String sessionId;
  final String reason;
  final String state;
  final DateTime createdAt;
  final DateTime updatedAt;
  final String? approvalId;

  factory AssistanceRequestModel.fromJson(Map<String, dynamic> json) {
    return AssistanceRequestModel(
      requestId: json['request_id'] as String,
      nodeId: json['node_id'] as String,
      agentId: json['agent_id'] as String,
      sessionId: json['session_id'] as String,
      reason: json['reason'] as String,
      state: json['state'] as String,
      createdAt: DateTime.parse(json['created_at'] as String),
      updatedAt: DateTime.parse(json['updated_at'] as String),
      approvalId: json['approval_id'] as String?,
    );
  }
}

class AssistanceSessionModel {
  const AssistanceSessionModel({
    required this.assistanceSessionId,
    required this.requestId,
    required this.nodeId,
    required this.agentId,
    required this.sessionId,
    required this.state,
    required this.createdAt,
    required this.updatedAt,
    this.returnSummary,
    this.messages = const [],
  });

  final String assistanceSessionId;
  final String requestId;
  final String nodeId;
  final String agentId;
  final String sessionId;
  final String state;
  final DateTime createdAt;
  final DateTime updatedAt;
  final String? returnSummary;
  final List<AssistanceMessageModel> messages;

  factory AssistanceSessionModel.fromJson(Map<String, dynamic> json) {
    return AssistanceSessionModel(
      assistanceSessionId: json['assistance_session_id'] as String,
      requestId: json['request_id'] as String,
      nodeId: json['node_id'] as String,
      agentId: json['agent_id'] as String,
      sessionId: json['session_id'] as String,
      state: json['state'] as String,
      createdAt: DateTime.parse(json['created_at'] as String),
      updatedAt: DateTime.parse(json['updated_at'] as String),
      returnSummary: json['return_summary'] as String?,
      messages: (json['messages'] as List<dynamic>? ?? const [])
          .map((item) => AssistanceMessageModel.fromJson(
              Map<String, dynamic>.from(item as Map)))
          .toList(),
    );
  }
}

class AssistanceMessageModel {
  const AssistanceMessageModel({
    required this.messageId,
    required this.assistanceSessionId,
    required this.senderType,
    required this.senderId,
    required this.body,
    required this.createdAt,
  });

  final String messageId;
  final String assistanceSessionId;
  final String senderType;
  final String senderId;
  final String body;
  final DateTime createdAt;

  factory AssistanceMessageModel.fromJson(Map<String, dynamic> json) {
    return AssistanceMessageModel(
      messageId: json['message_id'] as String,
      assistanceSessionId: json['assistance_session_id'] as String,
      senderType: json['sender_type'] as String,
      senderId: json['sender_id'] as String,
      body: json['body'] as String,
      createdAt: DateTime.parse(json['created_at'] as String),
    );
  }
}

class BrowserAssistanceSessionModel {
  const BrowserAssistanceSessionModel({
    required this.browserSessionId,
    required this.nodeId,
    required this.agentId,
    required this.sessionId,
    required this.reason,
    required this.state,
    required this.createdAt,
    required this.updatedAt,
    this.returnSummary,
    this.userActionNotes = const [],
  });

  final String browserSessionId;
  final String nodeId;
  final String agentId;
  final String sessionId;
  final String reason;
  final String state;
  final DateTime createdAt;
  final DateTime updatedAt;
  final String? returnSummary;
  final List<String> userActionNotes;

  factory BrowserAssistanceSessionModel.fromJson(Map<String, dynamic> json) {
    return BrowserAssistanceSessionModel(
      browserSessionId: json['browser_session_id'] as String,
      nodeId: json['node_id'] as String,
      agentId: json['agent_id'] as String,
      sessionId: json['session_id'] as String,
      reason: json['reason'] as String,
      state: json['state'] as String,
      createdAt: DateTime.parse(json['created_at'] as String),
      updatedAt: DateTime.parse(json['updated_at'] as String),
      returnSummary: json['return_summary'] as String?,
      userActionNotes: _stringList(json['user_action_notes']),
    );
  }
}

class ApprovalResponseModel {
  const ApprovalResponseModel({
    required this.approvalResponseId,
    required this.approvalId,
    required this.decisionType,
    required this.createdAt,
    this.userMessage,
    this.alternateDirective,
    this.policyProposalId,
  });

  final String approvalResponseId;
  final String approvalId;
  final String decisionType;
  final DateTime createdAt;
  final String? userMessage;
  final String? alternateDirective;
  final String? policyProposalId;

  factory ApprovalResponseModel.fromJson(Map<String, dynamic> json) {
    return ApprovalResponseModel(
      approvalResponseId: json['approval_response_id'] as String,
      approvalId: json['approval_id'] as String,
      decisionType: json['decision_type'] as String,
      createdAt: DateTime.parse(json['created_at'] as String),
      userMessage: json['user_message'] as String?,
      alternateDirective: json['alternate_directive'] as String?,
      policyProposalId: json['policy_proposal_id'] as String?,
    );
  }
}

class VoiceSessionModel {
  const VoiceSessionModel({
    required this.voiceSessionId,
    required this.nodeId,
    required this.agentId,
    required this.mode,
    required this.state,
    required this.createdAt,
    this.sessionId,
    this.messages = const [],
  });

  final String voiceSessionId;
  final String nodeId;
  final String agentId;
  final String? sessionId;
  final String mode;
  final String state;
  final DateTime createdAt;
  final List<VoiceMessageModel> messages;

  factory VoiceSessionModel.fromJson(Map<String, dynamic> json) {
    return VoiceSessionModel(
      voiceSessionId: json['voice_session_id'] as String,
      nodeId: json['node_id'] as String,
      agentId: json['agent_id'] as String,
      sessionId: json['session_id'] as String?,
      mode: json['mode'] as String,
      state: json['state'] as String,
      createdAt: DateTime.parse(json['created_at'] as String),
      messages: (json['messages'] as List<dynamic>? ?? const [])
          .map((item) =>
              VoiceMessageModel.fromJson(Map<String, dynamic>.from(item as Map)))
          .toList(),
    );
  }
}

class VoiceMessageModel {
  const VoiceMessageModel({
    required this.voiceMessageId,
    required this.voiceSessionId,
    required this.senderType,
    required this.body,
    required this.inputMode,
    required this.createdAt,
  });

  final String voiceMessageId;
  final String voiceSessionId;
  final String senderType;
  final String body;
  final String inputMode;
  final DateTime createdAt;

  factory VoiceMessageModel.fromJson(Map<String, dynamic> json) {
    return VoiceMessageModel(
      voiceMessageId: json['voice_message_id'] as String,
      voiceSessionId: json['voice_session_id'] as String,
      senderType: json['sender_type'] as String,
      body: json['body'] as String,
      inputMode: json['input_mode'] as String,
      createdAt: DateTime.parse(json['created_at'] as String),
    );
  }
}

class DashboardSnapshot {
  const DashboardSnapshot({
    required this.nodes,
    required this.agents,
    required this.missions,
    required this.pendingApprovals,
    required this.notifications,
  });

  final List<GatewayNode> nodes;
  final List<GatewayAgent> agents;
  final List<MissionRecord> missions;
  final List<ApprovalRequestModel> pendingApprovals;
  final List<NotificationRecord> notifications;
}

List<String> _stringList(Object? value) {
  return (value as List<dynamic>? ?? const [])
      .map((item) => item as String)
      .toList();
}

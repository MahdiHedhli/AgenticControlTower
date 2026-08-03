import 'package:flutter/foundation.dart';

import '../models/alpha_models.dart';
import '../repositories/alpha_repository.dart';

class HomeViewModel {
  HomeViewModel(this.repository);

  final AlphaRepository repository;

  Future<HomeAlphaSnapshot> load() => repository.loadHome();
}

class AgentsViewModel {
  AgentsViewModel(this.repository);

  final AlphaRepository repository;
  String searchQuery = '';
  String teamFilter = 'All';
  bool groupByTeam = true;

  Future<List<FleetAgent>> loadAgents() => repository.loadAgents();

  List<String> teams(List<FleetAgent> agents) {
    final values = agents.map((agent) => agent.team).toSet().toList()..sort();
    return ['All', ...values];
  }

  List<FleetAgent> visibleAgents(List<FleetAgent> agents) {
    final query = searchQuery.trim().toLowerCase();
    return agents.where((agent) {
      final matchesTeam = teamFilter == 'All' || agent.team == teamFilter;
      final matchesSearch = query.isEmpty ||
          agent.name.toLowerCase().contains(query) ||
          agent.team.toLowerCase().contains(query) ||
          agent.node.toLowerCase().contains(query) ||
          agent.currentMission.toLowerCase().contains(query);
      return matchesTeam && matchesSearch;
    }).toList();
  }

  Map<String, List<FleetAgent>> groupedAgents(List<FleetAgent> agents) {
    final grouped = <String, List<FleetAgent>>{};
    for (final agent in visibleAgents(agents)) {
      grouped.putIfAbsent(agent.team, () => []).add(agent);
    }
    return grouped;
  }
}

class InboxViewModel {
  InboxViewModel(this.repository);

  final AlphaRepository repository;
  InboxKind? filter;

  Future<List<InboxItem>> loadInbox() => repository.loadInbox();

  List<InboxItem> visibleItems(List<InboxItem> items) {
    if (filter == null) {
      return items;
    }
    return items.where((item) => item.kind == filter).toList();
  }
}

class MissionsViewModel {
  MissionsViewModel(this.repository);

  final AlphaRepository repository;

  Future<List<MissionSummary>> loadMissions() => repository.loadMissions();
}

class ApprovalDetailViewModel {
  ApprovalDetailViewModel(this.repository);

  final AlphaRepository repository;

  Future<ApprovalAlpha> load(String approvalId) =>
      repository.loadApproval(approvalId);

  Future<ApprovalAlpha> approveOnce(String approvalId) =>
      repository.approveOnce(approvalId);

  Future<ApprovalAlpha> approveForSession(String approvalId) =>
      repository.approveForSession(approvalId);

  Future<ApprovalAlpha> approveForAgent(String approvalId) =>
      repository.approveForAgent(approvalId);

  Future<ApprovalAlpha> deny(String approvalId) => repository.deny(approvalId);

  Future<void> pauseAgent(String sessionId, String agentId) =>
      repository.pauseAgent(sessionId, agentId);

  Future<void> stopTask(String sessionId, String agentId) =>
      repository.stopTask(sessionId, agentId);

  Future<void> stopAgent(String sessionId, String agentId) =>
      repository.stopAgent(sessionId, agentId);

  List<ApprovalMoreAction> moreActionsFor(ApprovalAlpha approval) {
    final pending = approval.state == 'pending';
    return [
      ApprovalMoreAction(
        kind: ApprovalMoreActionKind.approveOnce,
        label: 'Approve Once',
        description: 'Signed decision for this single action.',
        enabled: pending && _hasOption(approval, 'approve_once'),
      ),
      ApprovalMoreAction(
        kind: ApprovalMoreActionKind.deny,
        label: 'Deny',
        description: 'Signed denial for this request.',
        enabled: pending,
      ),
      ApprovalMoreAction(
        kind: ApprovalMoreActionKind.approveForSession,
        label: 'Approve For Session',
        description: 'Signed approval scoped to this Hermes session.',
        enabled: pending && _hasOption(approval, 'approve_for_session'),
      ),
      ApprovalMoreAction(
        kind: ApprovalMoreActionKind.approveForAgent,
        label: 'Approve For Agent',
        description: 'Signed approval scoped to this agent.',
        enabled: pending && _hasOption(approval, 'approve_for_agent'),
      ),
      ApprovalMoreAction(
        kind: ApprovalMoreActionKind.approveForever,
        label: 'Approve Forever',
        description: 'Create a policy proposal only; no permanent allow is activated.',
        enabled: pending,
      ),
      ApprovalMoreAction(
        kind: ApprovalMoreActionKind.other,
        label: 'Other',
        description: 'Send an alternate directive or constraint.',
        enabled: pending,
      ),
      const ApprovalMoreAction(
        kind: ApprovalMoreActionKind.moreInfo,
        label: 'More Info',
        description: 'Inspect request metadata and redacted payload.',
        enabled: true,
      ),
      const ApprovalMoreAction(
        kind: ApprovalMoreActionKind.openTua,
        label: 'Open TUA Session',
        description: 'Open the assistance workflow with this context.',
        enabled: true,
      ),
      const ApprovalMoreAction(
        kind: ApprovalMoreActionKind.openTui,
        label: 'Open TUI Session',
        description: 'Open the terminal prototype for this context.',
        enabled: true,
      ),
      const ApprovalMoreAction(
        kind: ApprovalMoreActionKind.browserAssistance,
        label: 'Browser Assistance',
        description: 'Open the browser assistance operator surface.',
        enabled: true,
      ),
      const ApprovalMoreAction(
        kind: ApprovalMoreActionKind.pauseAgent,
        label: 'Pause Agent',
        description: 'Pause the agent at its next tool boundary.',
        enabled: true,
      ),
      const ApprovalMoreAction(
        kind: ApprovalMoreActionKind.stopTask,
        label: 'Stop Task',
        description: 'Stop the agent\'s current task.',
        enabled: true,
      ),
      const ApprovalMoreAction(
        kind: ApprovalMoreActionKind.stopAgent,
        label: 'Stop Agent',
        description: 'Stop the agent.',
        enabled: true,
      ),
    ];
  }

  /// Whether the tower offered this decision scope, and nothing else.
  ///
  /// This used to fall back to `{'work-vm-02', 'laptop', 'vps-prod'}.contains
  /// (approval.node)` so the demo approvals stayed clickable. The guard was on
  /// the *node name*, not on the data source — and `laptop` is a name a real
  /// host has. A live approval from an agent running on a machine called
  /// `laptop` therefore had Approve-Once / Approve-For-Session /
  /// Approve-For-Agent enabled regardless of the scopes the tower actually
  /// offered: an invented authority, presented to the operator as the tower's.
  ///
  /// The demo data now declares its own options like the gateway does, so there
  /// is nothing left to guess.
  bool _hasOption(ApprovalAlpha approval, String option) {
    return approval.constraints.contains(option);
  }
}

enum ApprovalMoreActionKind {
  approveOnce,
  deny,
  approveForSession,
  approveForAgent,
  approveForever,
  other,
  moreInfo,
  openTua,
  openTui,
  browserAssistance,
  pauseAgent,
  stopTask,
  stopAgent,
}

class ApprovalMoreAction {
  const ApprovalMoreAction({
    required this.kind,
    required this.label,
    required this.description,
    required this.enabled,
    this.planned = false,
  });

  final ApprovalMoreActionKind kind;
  final String label;
  final String description;
  final bool enabled;
  final bool planned;
}

class TuaViewModel extends ChangeNotifier {
  TuaViewModel(this.repository);

  final AlphaRepository repository;
  AssistanceSessionAlpha? _session;
  final _draftReplies = <AssistanceMessageAlpha>[];
  bool returnedToAgent = false;

  AssistanceSessionAlpha? get session => _session;

  List<AssistanceMessageAlpha> get messages => [
        ...?_session?.messages,
        ..._draftReplies,
      ];

  Future<void> load(String sessionId) async {
    _session = await repository.loadAssistanceSession(sessionId);
    notifyListeners();
  }

  void sendReply(String body) {
    final trimmed = body.trim();
    if (trimmed.isEmpty) {
      return;
    }
    _draftReplies.add(
      AssistanceMessageAlpha(
        sender: 'You',
        body: trimmed,
        timeLabel: 'now',
        fromUser: true,
      ),
    );
    notifyListeners();
  }

  void returnToAgent() {
    returnedToAgent = true;
    _draftReplies.add(
      const AssistanceMessageAlpha(
        sender: 'You',
        body:
            'Return control with the current constraints and summarize before writing.',
        timeLabel: 'now',
        fromUser: true,
      ),
    );
    notifyListeners();
  }
}

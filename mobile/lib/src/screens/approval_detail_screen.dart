import 'package:flutter/material.dart';

import '../acs_tokens.dart';
import '../app_runtime.dart';
import '../models/alpha_models.dart';
import '../operator_error.dart';
import '../repositories/alpha_repository.dart';
import '../routes.dart';
import '../viewmodels/alpha_viewmodels.dart';
import '../widgets/alpha_components.dart';
import '../widgets/screen_shell.dart';

class ApprovalDetailScreen extends StatefulWidget {
  const ApprovalDetailScreen({
    required this.repository,
    this.runtime,
    super.key,
  });

  final AlphaRepository repository;
  final HermesAppRuntime? runtime;

  @override
  State<ApprovalDetailScreen> createState() => _ApprovalDetailScreenState();
}

class _ApprovalDetailScreenState extends State<ApprovalDetailScreen> {
  late Future<ApprovalAlpha> _approval;
  String _approvalId = 'appr-shell';
  String? _draftResponse;
  bool _busy = false;
  bool _loadedRoute = false;
  int _seenEventRevision = -1;

  AlphaRepository get _repository =>
      widget.runtime?.alphaRepository ?? widget.repository;

  ApprovalDetailViewModel get _viewModel =>
      ApprovalDetailViewModel(_repository);

  @override
  void initState() {
    super.initState();
    widget.runtime?.addListener(_runtimeChanged);
  }

  @override
  void dispose() {
    widget.runtime?.removeListener(_runtimeChanged);
    super.dispose();
  }

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    final argument = ModalRoute.of(context)?.settings.arguments;
    final approvalId = argument is String ? argument : 'appr-shell';
    if (!_loadedRoute || approvalId != _approvalId) {
      _approvalId = approvalId;
      _approval = _viewModel.load(_approvalId);
      _loadedRoute = true;
    }
  }

  void _runtimeChanged() {
    final runtime = widget.runtime;
    if (!_loadedRoute || runtime == null) {
      return;
    }
    if (_seenEventRevision == runtime.eventRevision) {
      setState(() {});
      return;
    }
    _seenEventRevision = runtime.eventRevision;
    final lastEvent = runtime.lastEvent;
    final eventApprovalId = lastEvent?.payload['approval_id'] as String?;
    if (lastEvent == null ||
        eventApprovalId == _approvalId ||
        lastEvent.type == 'approval.requested' ||
        lastEvent.type == 'approval.resolved') {
      setState(() {
        _approval = _viewModel.load(_approvalId);
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return ScreenShell(
      title: 'Approval',
      selectedRoute: HermesRoutes.inbox,
      body: FutureBuilder<ApprovalAlpha>(
        future: _approval,
        builder: (context, snapshot) {
          if (snapshot.hasError) {
            return _ApprovalError(
                error: operatorErrorMessage(snapshot.error!,
                    context: 'approval-detail'));
          }
          final approval = snapshot.data;
          if (approval == null) {
            return const Center(child: CircularProgressIndicator());
          }
          return ListView(
            padding: const EdgeInsets.fromLTRB(16, 8, 16, 24),
            children: [
              _ApprovalHeader(approval: approval),
              const SectionHeader(title: 'Request Summary'),
              AlphaPanel(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(approval.summary,
                        style: Theme.of(context).textTheme.bodyLarge),
                    const SizedBox(height: 14),
                    DetailRow(label: 'State', value: approval.state),
                    DetailRow(
                        label: 'Tool',
                        value: approval.requestedTool,
                        mono: true),
                    DetailRow(label: 'Agent', value: approval.agentName),
                    DetailRow(label: 'Node', value: approval.node, mono: true),
                    DetailRow(
                        label: 'Session', value: approval.session, mono: true),
                    DetailRow(label: 'Expires', value: approval.expiresIn),
                    if (approval.decisionScope != null)
                      DetailRow(
                        label: 'Scope',
                        value: approval.decisionScope!,
                      ),
                    if (_draftResponse != null)
                      DetailRow(label: 'Draft', value: _draftResponse!),
                  ],
                ),
              ),
              const SectionHeader(title: 'Redacted Payload'),
              AlphaPanel(
                child: SelectableText(
                  approval.payloadPreview,
                  style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                        fontFamily: AcsTokens.fontMono,
                      ),
                ),
              ),
              const SectionHeader(title: 'Available Decisions'),
              AlphaPanel(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: approval.constraints
                      .map(
                        (option) => Padding(
                          padding: const EdgeInsets.only(bottom: 8),
                          child: Row(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              Icon(
                                Icons.check_circle_outline,
                                color: Theme.of(context).colorScheme.primary,
                                size: 18,
                              ),
                              const SizedBox(width: 8),
                              Expanded(
                                  child: Text(_humanizeDecisionOption(option))),
                            ],
                          ),
                        ),
                      )
                      .toList(),
                ),
              ),
              const SizedBox(height: 22),
              _ApprovalActions(
                viewModel: _viewModel,
                approval: approval,
                busy: _busy,
                onDecision: _submitDecision,
                onModifiedResponse: _submitModifiedResponse,
                onPolicyProposal: _submitPolicyProposal,
                onNeedsInfo: _requestMoreInfo,
              ),
            ],
          );
        },
      ),
    );
  }

  Future<void> _submitDecision(
      String action, Future<ApprovalAlpha> Function() submit) async {
    setState(() => _busy = true);
    try {
      final updated = await submit();
      setState(() {
        _approval = Future.value(updated);
      });
      if (!mounted) {
        return;
      }
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('$action submitted')),
      );
    } on Object catch (error) {
      if (!mounted) {
        return;
      }
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(operatorErrorMessage(error, context: 'approval')),
        ),
      );
    } finally {
      if (mounted) {
        setState(() => _busy = false);
      }
    }
  }

  void _saveDraftResponse(String value) {
    final trimmed = value.trim();
    if (trimmed.isEmpty) {
      return;
    }
    setState(() {
      _draftResponse = trimmed;
    });
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(content: Text('Draft response saved locally')),
    );
  }

  Future<void> _submitModifiedResponse(String value) async {
    final trimmed = value.trim();
    if (trimmed.isEmpty) {
      return;
    }
    final repository = widget.runtime?.approvalResponsesRepository;
    if (repository == null) {
      _saveDraftResponse(trimmed);
      return;
    }
    setState(() => _busy = true);
    try {
      await repository.modified(
        _approvalId,
        alternateDirective: trimmed,
        constraints: [
          {
            'constraint_type': 'operator_directive',
            'value_redacted': {'source': 'mobile'},
          }
        ],
      );
      setState(() => _draftResponse = trimmed);
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Modified response submitted')),
        );
      }
    } on Object catch (error) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(operatorErrorMessage(error, context: 'approval')),
          ),
        );
      }
    } finally {
      if (mounted) {
        setState(() => _busy = false);
      }
    }
  }

  Future<void> _submitPolicyProposal() async {
    final repository = widget.runtime?.approvalResponsesRepository;
    if (repository == null) {
      _saveDraftResponse('Policy proposal drafted locally');
      return;
    }
    setState(() => _busy = true);
    try {
      await repository.proposePolicy(
        _approvalId,
        confirmationPhrase: 'PROPOSE POLICY',
        constraints: [
          {
            'constraint_type': 'requires_future_review',
            'value_redacted': {'source': 'mobile_approve_forever'},
          }
        ],
      );
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Policy proposal created')),
        );
      }
    } on Object catch (error) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(operatorErrorMessage(error, context: 'approval')),
          ),
        );
      }
    } finally {
      if (mounted) {
        setState(() => _busy = false);
      }
    }
  }

  Future<void> _requestMoreInfo() async {
    final repository = widget.runtime?.approvalResponsesRepository;
    if (repository == null) {
      return;
    }
    setState(() => _busy = true);
    try {
      await repository.needsInfo(
        _approvalId,
        userMessage: 'Please provide more detail before the mobile decision.',
      );
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('More info requested')),
        );
      }
    } on Object catch (error) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(operatorErrorMessage(error, context: 'approval')),
          ),
        );
      }
    } finally {
      if (mounted) {
        setState(() => _busy = false);
      }
    }
  }
}

class _ApprovalError extends StatelessWidget {
  const _ApprovalError({required this.error});

  final String error;

  @override
  Widget build(BuildContext context) {
    return ListView(
      padding: const EdgeInsets.fromLTRB(16, 16, 16, 24),
      children: [
        AlphaPanel(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              StatusPill(
                  label: 'gateway error',
                  color: Theme.of(context).colorScheme.error),
              const SizedBox(height: 12),
              Text(error),
              const SizedBox(height: 14),
              OutlinedButton.icon(
                onPressed: () =>
                    Navigator.of(context).pushNamed(HermesRoutes.settings),
                icon: const Icon(Icons.settings_outlined),
                label: const Text('Open Settings'),
              ),
            ],
          ),
        ),
      ],
    );
  }
}

class _ApprovalHeader extends StatelessWidget {
  const _ApprovalHeader({required this.approval});

  final ApprovalAlpha approval;

  @override
  Widget build(BuildContext context) {
    return AlphaPanel(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              StatusPill(
                  label: approval.risk,
                  color: riskColor(context, approval.risk)),
              const SizedBox(width: 8),
              StatusPill(
                  label: approval.state,
                  color: _stateColor(context, approval.state)),
              const Spacer(),
              Text(
                approval.expiresIn,
                style: Theme.of(context).textTheme.titleMedium?.copyWith(
                      color: Theme.of(context).colorScheme.secondary,
                      fontWeight: FontWeight.w700,
                    ),
              ),
            ],
          ),
          const SizedBox(height: 16),
          Text(
            approval.title,
            style: Theme.of(context).textTheme.headlineSmall?.copyWith(
                  fontWeight: FontWeight.w800,
                ),
          ),
          const SizedBox(height: 8),
          Text(
            '${approval.agentName} wants permission to use ${approval.requestedTool}.',
            style: Theme.of(context).textTheme.bodyLarge,
          ),
        ],
      ),
    );
  }
}

class _ApprovalActions extends StatelessWidget {
  const _ApprovalActions({
    required this.viewModel,
    required this.approval,
    required this.busy,
    required this.onDecision,
    required this.onModifiedResponse,
    required this.onPolicyProposal,
    required this.onNeedsInfo,
  });

  final ApprovalDetailViewModel viewModel;
  final ApprovalAlpha approval;
  final bool busy;
  final Future<void> Function(
      String action, Future<ApprovalAlpha> Function() submit) onDecision;
  final Future<void> Function(String value) onModifiedResponse;
  final Future<void> Function() onPolicyProposal;
  final Future<void> Function() onNeedsInfo;

  @override
  Widget build(BuildContext context) {
    final pending = approval.state == 'pending';
    return Column(
      children: [
        Row(
          children: [
            Expanded(
              child: CommandButton(
                label: 'Approve',
                icon: Icons.verified_outlined,
                primary: true,
                onPressed: busy || !pending
                    ? () {}
                    : () => onDecision(
                          'Approve Once',
                          () => viewModel.approveOnce(approval.id),
                        ),
              ),
            ),
            const SizedBox(width: 10),
            Expanded(
              child: CommandButton(
                label: 'Deny',
                icon: Icons.block_outlined,
                destructive: true,
                onPressed: busy || !pending
                    ? () {}
                    : () => onDecision(
                          'Deny',
                          () => viewModel.deny(approval.id),
                        ),
              ),
            ),
          ],
        ),
        const SizedBox(height: 10),
        SizedBox(
          width: double.infinity,
          child: OutlinedButton.icon(
            onPressed: () => _showMore(context),
            icon: const Icon(Icons.more_horiz),
            label: const Text('More'),
          ),
        ),
      ],
    );
  }

  void _showMore(BuildContext context) {
    showModalBottomSheet<void>(
      context: context,
      showDragHandle: true,
      builder: (context) {
        return SafeArea(
          child: ListView(
            shrinkWrap: true,
            padding: const EdgeInsets.fromLTRB(16, 4, 16, 16),
            children: [
              Text(
                'Decision Options',
                style: Theme.of(context)
                    .textTheme
                    .titleLarge
                    ?.copyWith(fontWeight: FontWeight.w800),
              ),
              const SizedBox(height: 8),
              ...viewModel.moreActionsFor(approval).map(
                    (action) => ListTile(
                      enabled: action.enabled,
                      leading: Icon(_actionIcon(action.kind)),
                      title: Text(action.label),
                      subtitle: Text(action.description),
                      trailing: action.planned
                          ? StatusPill(
                              label: 'planned',
                              color: Theme.of(context).colorScheme.outline,
                            )
                          : action.enabled
                              ? null
                              : StatusPill(
                                  label: 'disabled',
                                  color: Theme.of(context).colorScheme.outline,
                                ),
                      onTap: action.enabled
                          ? () {
                              Navigator.of(context).pop();
                              _handleMoreAction(context, action);
                            }
                          : null,
                    ),
                  ),
            ],
          ),
        );
      },
    );
  }

  void _handleMoreAction(BuildContext context, ApprovalMoreAction action) {
    switch (action.kind) {
      case ApprovalMoreActionKind.approveOnce:
        onDecision(
          'Approve Once',
          () => viewModel.approveOnce(approval.id),
        );
        return;
      case ApprovalMoreActionKind.deny:
        onDecision(
          'Deny',
          () => viewModel.deny(approval.id),
        );
        return;
      case ApprovalMoreActionKind.approveForSession:
        onDecision(
          'Approve For Session',
          () => viewModel.approveForSession(approval.id),
        );
        return;
      case ApprovalMoreActionKind.approveForAgent:
        onDecision(
          'Approve For Agent',
          () => viewModel.approveForAgent(approval.id),
        );
        return;
      case ApprovalMoreActionKind.other:
        _showDraftResponse(context);
        return;
      case ApprovalMoreActionKind.moreInfo:
        _showMoreInfo(context);
        return;
      case ApprovalMoreActionKind.openTua:
        Navigator.of(context)
            .pushNamed(HermesRoutes.tua, arguments: approval.id);
        return;
      case ApprovalMoreActionKind.openTui:
        Navigator.of(context)
            .pushNamed(HermesRoutes.tui, arguments: approval.id);
        return;
      case ApprovalMoreActionKind.browserAssistance:
        Navigator.of(context)
            .pushNamed(HermesRoutes.browserAssistance, arguments: approval.id);
        return;
      case ApprovalMoreActionKind.approveForever:
        _showPolicyProposal(context);
        return;
      case ApprovalMoreActionKind.pauseAgent:
        onDecision('Pause agent', () async {
          await viewModel.pauseAgent(approval.session, approval.agentName);
          return approval;
        });
        return;
      case ApprovalMoreActionKind.stopTask:
        onDecision('Stop task', () async {
          await viewModel.stopTask(approval.session, approval.agentName);
          return approval;
        });
        return;
      case ApprovalMoreActionKind.stopAgent:
        onDecision('Stop agent', () async {
          await viewModel.stopAgent(approval.session, approval.agentName);
          return approval;
        });
        return;
    }
  }

  void _showDraftResponse(BuildContext context) {
    final controller = TextEditingController();
    showModalBottomSheet<void>(
      context: context,
      showDragHandle: true,
      builder: (context) {
        return SafeArea(
          child: Padding(
            padding: const EdgeInsets.fromLTRB(16, 4, 16, 16),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  'Draft Modified Response',
                  style: Theme.of(context)
                      .textTheme
                      .titleLarge
                      ?.copyWith(fontWeight: FontWeight.w800),
                ),
                const SizedBox(height: 8),
                Text(
                  'When paired, this sends a signed modified response to the gateway. Otherwise it is saved locally.',
                  style: Theme.of(context).textTheme.bodySmall,
                ),
                const SizedBox(height: 12),
                TextField(
                  controller: controller,
                  minLines: 3,
                  maxLines: 5,
                  decoration: const InputDecoration(
                    hintText: 'Describe constraints or alternate instruction',
                    prefixIcon: Icon(Icons.edit_note_outlined),
                  ),
                ),
                const SizedBox(height: 12),
                SizedBox(
                  width: double.infinity,
                  child: FilledButton.icon(
                    onPressed: () async {
                      await onModifiedResponse(controller.text);
                      if (context.mounted) {
                        Navigator.of(context).pop();
                      }
                    },
                    icon: const Icon(Icons.save_outlined),
                    label: const Text('Submit Modified Response'),
                  ),
                ),
              ],
            ),
          ),
        );
      },
    );
  }

  void _showMoreInfo(BuildContext context) {
    showDialog<void>(
      context: context,
      builder: (context) {
        return AlertDialog(
          title: const Text('Approval Details'),
          content: SingleChildScrollView(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                DetailRow(label: 'Approval', value: approval.id, mono: true),
                DetailRow(label: 'Risk', value: approval.risk),
                DetailRow(
                    label: 'Tool', value: approval.requestedTool, mono: true),
                DetailRow(label: 'Agent', value: approval.agentName),
                DetailRow(label: 'Node', value: approval.node, mono: true),
                DetailRow(
                    label: 'Session', value: approval.session, mono: true),
                DetailRow(label: 'State', value: approval.state),
                if (approval.decisionScope != null)
                  DetailRow(label: 'Scope', value: approval.decisionScope!),
                const SizedBox(height: 10),
                SelectableText(
                  approval.payloadPreview,
                  style: Theme.of(context).textTheme.bodySmall?.copyWith(
                        fontFamily: AcsTokens.fontMono,
                      ),
                ),
              ],
            ),
          ),
          actions: [
            TextButton(
              onPressed: () {
                Navigator.of(context).pop();
                onNeedsInfo();
              },
              child: const Text('Request More Info'),
            ),
            TextButton(
              onPressed: () => Navigator.of(context).pop(),
              child: const Text('Close'),
            ),
          ],
        );
      },
    );
  }

  void _showPolicyProposal(BuildContext context) {
    showDialog<void>(
      context: context,
      builder: (context) {
        return AlertDialog(
          title: const Text('Create Policy Proposal'),
          content: const Text(
            'Approve Forever creates a proposal only. It does not activate a permanent allow policy.',
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.of(context).pop(),
              child: const Text('Cancel'),
            ),
            FilledButton(
              onPressed: () async {
                await onPolicyProposal();
                if (context.mounted) {
                  Navigator.of(context).pop();
                }
              },
              child: const Text('Create Proposal'),
            ),
          ],
        );
      },
    );
  }
}

IconData _actionIcon(ApprovalMoreActionKind action) {
  return switch (action) {
    ApprovalMoreActionKind.approveOnce => Icons.verified_outlined,
    ApprovalMoreActionKind.approveForSession => Icons.verified_user_outlined,
    ApprovalMoreActionKind.approveForAgent => Icons.admin_panel_settings,
    ApprovalMoreActionKind.approveForever => Icons.all_inclusive,
    ApprovalMoreActionKind.deny => Icons.block_outlined,
    ApprovalMoreActionKind.other => Icons.edit_note_outlined,
    ApprovalMoreActionKind.moreInfo => Icons.info_outline,
    ApprovalMoreActionKind.openTua => Icons.support_agent_outlined,
    ApprovalMoreActionKind.openTui => Icons.terminal_outlined,
    ApprovalMoreActionKind.browserAssistance => Icons.travel_explore_outlined,
    ApprovalMoreActionKind.pauseAgent => Icons.pause_circle_outline,
    ApprovalMoreActionKind.stopTask => Icons.stop_circle_outlined,
    ApprovalMoreActionKind.stopAgent => Icons.power_settings_new,
  };
}

Color _stateColor(BuildContext context, String state) {
  return switch (state) {
    'approved' => AcsTokens.go,
    'denied' => AcsTokens.alert,
    'expired' => Theme.of(context).colorScheme.outline,
    'cancelled' => Theme.of(context).colorScheme.outline,
    _ => AcsTokens.attention,
  };
}

/// The gateway sends decision-option tokens (`approve_once`,
/// `approve_for_session`, ...). Humanize the known ones; pass anything
/// else through with underscores softened.
String _humanizeDecisionOption(String option) {
  return switch (option) {
    'approve_once' => 'Approve once',
    'approve_for_session' => 'Approve for session',
    'approve_for_agent' => 'Approve for agent',
    'approve_forever' => 'Approve forever (policy proposal)',
    'deny' => 'Deny',
    'needs_info' => 'Request more info',
    'modified' => 'Modified response',
    _ => option.replaceAll('_', ' '),
  };
}

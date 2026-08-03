import 'package:flutter/material.dart';

import '../app_runtime.dart';
import '../models/alpha_models.dart';
import '../models/core_models.dart';
import '../operator_error.dart';
import '../repositories/alpha_repository.dart';
import '../routes.dart';
import '../viewmodels/alpha_viewmodels.dart';
import '../widgets/alpha_components.dart';
import '../widgets/load_failure.dart';
import '../widgets/screen_shell.dart';

class TuaScreen extends StatefulWidget {
  const TuaScreen({
    required this.repository,
    this.runtime,
    super.key,
  });

  final AlphaRepository repository;
  final HermesAppRuntime? runtime;

  @override
  State<TuaScreen> createState() => _TuaScreenState();
}

class _TuaScreenState extends State<TuaScreen> {
  late final TuaViewModel _viewModel;
  late Future<void> _load;
  String? _contextId;
  final _replyController = TextEditingController();
  bool _loadedRoute = false;
  AssistanceSessionModel? _gatewaySession;
  bool _gatewayMode = false;
  bool _busy = false;

  @override
  void initState() {
    super.initState();
    _viewModel = TuaViewModel(widget.repository);
  }

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    if (_loadedRoute) {
      return;
    }
    _contextId = ModalRoute.of(context)?.settings.arguments as String?;
    _load = _startLoad();
    _loadedRoute = true;
  }

  Future<void> _startLoad() {
    final contextId = _contextId;
    if (contextId == null || contextId.isEmpty) {
      return Future<void>.value();
    }
    return claimLoadErrors(_loadSession(contextId), context: 'tua');
  }

  @override
  void dispose() {
    _replyController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return ScreenShell(
      title: 'TUA',
      selectedRoute: HermesRoutes.inbox,
      body: FutureBuilder<void>(
        future: _load,
        builder: (context, snapshot) {
          if (snapshot.hasError) {
            return LoadFailurePanel(
              error: snapshot.error!,
              context_: 'tua',
              onRetry: () => setState(() => _load = _startLoad()),
            );
          }
          if (snapshot.connectionState != ConnectionState.done) {
            return const Center(child: CircularProgressIndicator());
          }
          return AnimatedBuilder(
            animation: _viewModel,
            builder: (context, _) {
              final session = _currentSession;
              if (session == null) {
                return const Center(
                    child: Text('Assistance session unavailable'));
              }
              final messages = _gatewayMode
                  ? _gatewayMessages(_gatewaySession)
                  : _viewModel.messages;
              return Column(
                children: [
                  _SessionHeader(
                      session: session,
                      returnedToAgent:
                          _viewModel.returnedToAgent || _isReturned(session)),
                  Expanded(
                    child: ListView.builder(
                      padding: const EdgeInsets.fromLTRB(16, 8, 16, 16),
                      itemCount: messages.length,
                      itemBuilder: (context, index) {
                        return _MessageBubble(message: messages[index]);
                      },
                    ),
                  ),
                  _ReplyBar(
                    controller: _replyController,
                    busy: _busy,
                    onSend: _sendReply,
                    onReturn: _returnToAgent,
                  ),
                ],
              );
            },
          );
        },
      ),
    );
  }

  AssistanceSessionAlpha? get _currentSession {
    final gateway = _gatewaySession;
    if (_gatewayMode && gateway != null) {
      return AssistanceSessionAlpha(
        id: gateway.assistanceSessionId,
        agentName: gateway.agentId,
        node: gateway.nodeId,
        mission: gateway.sessionId,
        state: _assistanceState(gateway.state),
        reason: 'Gateway assistance session',
        messages: _gatewayMessages(gateway),
      );
    }
    return _viewModel.session;
  }

  Future<void> _loadSession(String contextId) async {
    final repository = widget.runtime?.tuaRepository;
    if (repository == null) {
      await _viewModel.load(contextId);
      return;
    }
    try {
      _gatewaySession = await repository.getSession(contextId);
      _gatewayMode = true;
      return;
    } on Object {
      // Approval routes pass an approval id, not an assistance session id.
    }
    try {
      final requests = await repository.listRequests();
      AssistanceRequestModel? matched;
      for (final request in requests) {
        if (request.requestId == contextId || request.approvalId == contextId) {
          matched = request;
          break;
        }
      }
      if (matched == null) {
        // Paired but no real request matches this id — show an explicit empty
        // state rather than leaking mock assistance data.
        return;
      }
      _gatewaySession = await repository.createSession(
        matched.requestId,
        initialMessage: 'Opened from Agentic Control Tower.',
      );
      _gatewayMode = true;
    } on Object {
      // Paired but the gateway call failed — surface empty/error, never mock.
      return;
    }
  }

  void _sendReply() {
    final body = _replyController.text.trim();
    if (body.isEmpty) {
      return;
    }
    _replyController.clear();
    if (!_gatewayMode || _gatewaySession == null) {
      _viewModel.sendReply(body);
      return;
    }
    _runGatewayAction(() async {
      final repository = widget.runtime?.tuaRepository;
      if (repository == null) {
        return;
      }
      await repository.sendMessage(
        _gatewaySession!.assistanceSessionId,
        body: body,
      );
      _gatewaySession =
          await repository.getSession(_gatewaySession!.assistanceSessionId);
    });
  }

  void _returnToAgent() {
    if (!_gatewayMode || _gatewaySession == null) {
      _viewModel.returnToAgent();
      return;
    }
    _runGatewayAction(() async {
      final repository = widget.runtime?.tuaRepository;
      if (repository == null) {
        return;
      }
      _gatewaySession = await repository.returnControl(
        _gatewaySession!.assistanceSessionId,
        summary: 'Operator returned control from mobile.',
      );
    });
  }

  Future<void> _runGatewayAction(Future<void> Function() action) async {
    setState(() => _busy = true);
    try {
      await action();
      if (mounted) {
        setState(() {});
      }
    } on Object catch (error) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(operatorErrorMessage(error, context: 'tui')),
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

class _SessionHeader extends StatelessWidget {
  const _SessionHeader({
    required this.session,
    required this.returnedToAgent,
  });

  final AssistanceSessionAlpha session;
  final bool returnedToAgent;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.fromLTRB(16, 8, 16, 6),
      child: AlphaPanel(
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                StatusPill(
                  label:
                      returnedToAgent ? 'returned' : _stateLabel(session.state),
                  color: returnedToAgent
                      ? Theme.of(context).colorScheme.primary
                      : Theme.of(context).colorScheme.secondary,
                ),
                const Spacer(),
                Text(session.node,
                    style: Theme.of(context).textTheme.labelMedium),
              ],
            ),
            const SizedBox(height: 12),
            Text(session.agentName,
                style: Theme.of(context).textTheme.titleLarge),
            const SizedBox(height: 4),
            Text(session.mission),
            const SizedBox(height: 10),
            Text(session.reason, style: Theme.of(context).textTheme.bodySmall),
          ],
        ),
      ),
    );
  }
}

class _MessageBubble extends StatelessWidget {
  const _MessageBubble({required this.message});

  final AssistanceMessageAlpha message;

  @override
  Widget build(BuildContext context) {
    final bubbleColor = message.fromUser
        ? Theme.of(context).colorScheme.primary.withValues(alpha: 0.18)
        : Theme.of(context).colorScheme.surface;
    final borderColor = message.fromUser
        ? Theme.of(context).colorScheme.primary.withValues(alpha: 0.55)
        : Theme.of(context).colorScheme.outlineVariant;
    return Align(
      alignment:
          message.fromUser ? Alignment.centerRight : Alignment.centerLeft,
      child: ConstrainedBox(
        constraints: const BoxConstraints(maxWidth: 320),
        child: Padding(
          padding: const EdgeInsets.only(bottom: 10),
          child: DecoratedBox(
            decoration: BoxDecoration(
              color: bubbleColor,
              border: Border.all(color: borderColor),
              borderRadius: BorderRadius.circular(8),
            ),
            child: Padding(
              padding: const EdgeInsets.all(12),
              child: Column(
                crossAxisAlignment: message.fromUser
                    ? CrossAxisAlignment.end
                    : CrossAxisAlignment.start,
                children: [
                  Text(
                    '${message.sender} - ${message.timeLabel}',
                    style: Theme.of(context).textTheme.labelSmall,
                  ),
                  const SizedBox(height: 6),
                  Text(message.body),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}

class _ReplyBar extends StatelessWidget {
  const _ReplyBar({
    required this.controller,
    required this.busy,
    required this.onSend,
    required this.onReturn,
  });

  final TextEditingController controller;
  final bool busy;
  final VoidCallback onSend;
  final VoidCallback onReturn;

  @override
  Widget build(BuildContext context) {
    return SafeArea(
      top: false,
      child: DecoratedBox(
        decoration: BoxDecoration(
          color: Theme.of(context).colorScheme.surface,
          border: Border(
              top: BorderSide(
                  color: Theme.of(context).colorScheme.outlineVariant)),
        ),
        child: Padding(
          padding: const EdgeInsets.fromLTRB(12, 10, 12, 10),
          child: Column(
            children: [
              Row(
                children: [
                  Expanded(
                    child: TextField(
                      controller: controller,
                      minLines: 1,
                      maxLines: 3,
                      decoration: const InputDecoration(
                        hintText: 'Send operator instruction',
                        prefixIcon: Icon(Icons.edit_note_outlined),
                      ),
                    ),
                  ),
                  const SizedBox(width: 8),
                  IconButton.filled(
                    onPressed: busy ? null : onSend,
                    icon: const Icon(Icons.send_outlined),
                    tooltip: 'Send',
                  ),
                ],
              ),
              const SizedBox(height: 8),
              SizedBox(
                width: double.infinity,
                child: OutlinedButton.icon(
                  onPressed: busy ? null : onReturn,
                  icon: const Icon(Icons.keyboard_return_outlined),
                  label: const Text('Return To Agent'),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

List<AssistanceMessageAlpha> _gatewayMessages(AssistanceSessionModel? session) {
  return (session?.messages ?? const [])
      .map(
        (message) => AssistanceMessageAlpha(
          sender: message.senderType == 'user' ? 'You' : message.senderId,
          body: message.body,
          timeLabel: 'gateway',
          fromUser: message.senderType == 'user',
        ),
      )
      .toList();
}

AssistanceState _assistanceState(String state) {
  return switch (state) {
    'requested' => AssistanceState.requested,
    'waiting_on_user' => AssistanceState.waitingOnUser,
    'user_controlling' => AssistanceState.userControlling,
    'returned_to_agent' => AssistanceState.returnedToAgent,
    'closed' => AssistanceState.closed,
    _ => AssistanceState.active,
  };
}

bool _isReturned(AssistanceSessionAlpha session) {
  return session.state == AssistanceState.returnedToAgent ||
      session.state == AssistanceState.closed;
}

String _stateLabel(AssistanceState state) {
  return switch (state) {
    AssistanceState.requested => 'requested',
    AssistanceState.active => 'active',
    AssistanceState.waitingOnUser => 'waiting',
    AssistanceState.userControlling => 'controlling',
    AssistanceState.returnedToAgent => 'returned',
    AssistanceState.closed => 'closed',
  };
}

import 'package:flutter/material.dart';

import '../app_runtime.dart';
import '../models/core_models.dart';
import '../operator_error.dart';
import '../repositories/alpha_repository.dart';
import '../routes.dart';
import '../widgets/alpha_components.dart';
import '../widgets/screen_shell.dart';

class VoiceScreen extends StatefulWidget {
  const VoiceScreen({
    required this.repository,
    this.runtime,
    super.key,
  });

  final AlphaRepository repository;
  final HermesAppRuntime? runtime;

  @override
  State<VoiceScreen> createState() => _VoiceScreenState();
}

class _VoiceScreenState extends State<VoiceScreen> {
  final _messageController = TextEditingController();
  VoiceSessionModel? _session;
  bool _busy = false;
  String _status = 'Ready for text-backed voice MVP.';

  @override
  void dispose() {
    _messageController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return ScreenShell(
      title: 'Voice',
      selectedRoute: HermesRoutes.voice,
      body: ListView(
        padding: const EdgeInsets.fromLTRB(16, 8, 16, 24),
        children: [
          AlphaPanel(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    Icon(Icons.mic_none_outlined,
                        color: Theme.of(context).colorScheme.primary),
                    const SizedBox(width: 10),
                    Expanded(
                      child: Text(
                        'Push To Talk MVP',
                        style: Theme.of(context).textTheme.titleLarge?.copyWith(
                              fontWeight: FontWeight.w800,
                            ),
                      ),
                    ),
                    StatusPill(
                      label: widget.runtime?.isPaired == true
                          ? 'gateway'
                          : 'fallback',
                      color: Theme.of(context).colorScheme.primary,
                    ),
                  ],
                ),
                const SizedBox(height: 12),
                Text(
                  'Audio capture is not enabled on this target. This MVP records a signed voice session and text-backed operator messages.',
                  style: Theme.of(context).textTheme.bodyLarge,
                ),
                const SizedBox(height: 14),
                DetailRow(
                  label: 'State',
                  value: _session?.state ?? 'not started',
                ),
                DetailRow(label: 'Status', value: _status),
              ],
            ),
          ),
          const SectionHeader(title: 'Session'),
          AlphaPanel(
            child: Column(
              children: [
                Row(
                  children: [
                    Expanded(
                      child: FilledButton.icon(
                        onPressed:
                            _busy || _session != null ? null : _createSession,
                        icon: const Icon(Icons.radio_button_checked),
                        label: const Text('Start Voice Session'),
                      ),
                    ),
                    const SizedBox(width: 10),
                    Expanded(
                      child: OutlinedButton.icon(
                        onPressed:
                            _busy || _session == null ? null : _closeSession,
                        icon: const Icon(Icons.stop_circle_outlined),
                        label: const Text('Close'),
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 12),
                TextField(
                  controller: _messageController,
                  minLines: 1,
                  maxLines: 3,
                  decoration: const InputDecoration(
                    hintText: 'Speak or type fallback instruction',
                    prefixIcon: Icon(Icons.graphic_eq_outlined),
                  ),
                ),
                const SizedBox(height: 10),
                SizedBox(
                  width: double.infinity,
                  child: OutlinedButton.icon(
                    onPressed: _busy || _session == null ? null : _sendMessage,
                    icon: const Icon(Icons.send_outlined),
                    label: const Text('Send Voice Message'),
                  ),
                ),
              ],
            ),
          ),
          const SectionHeader(title: 'Messages'),
          if ((_session?.messages ?? const []).isEmpty)
            const AlphaPanel(child: Text('No voice messages yet.'))
          else
            ..._session!.messages.map(_messageRow),
          const SectionHeader(title: 'Future Audio'),
          const AlphaPanel(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                DetailRow(
                    label: 'Audio',
                    value:
                        'Live capture and streaming are intentionally deferred.'),
                DetailRow(
                    label: 'Approvals',
                    value: 'Voice approval will require confirmation phrase.'),
                DetailRow(
                    label: 'Providers',
                    value: 'No external STT/TTS provider is used in this MVP.'),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _messageRow(VoiceMessageModel message) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 10),
      child: AlphaPanel(
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            StatusPill(
              label: message.inputMode,
              color: Theme.of(context).colorScheme.secondary,
            ),
            const SizedBox(height: 8),
            Text(message.body),
          ],
        ),
      ),
    );
  }

  void _createSession() {
    _runGatewayAction(() async {
      final repository = widget.runtime?.voiceRepository;
      if (repository == null) {
        _status = 'Voice gateway repository unavailable on this target.';
        return;
      }
      _session = await repository.createSession(
        agentId: 'agent_mock',
        sessionId: 'sess_mock',
        mode: 'text_fallback',
      );
      _status = 'Voice session created.';
    });
  }

  void _sendMessage() {
    final body = _messageController.text.trim();
    if (body.isEmpty || _session == null) {
      return;
    }
    _messageController.clear();
    _runGatewayAction(() async {
      final repository = widget.runtime?.voiceRepository;
      if (repository == null) {
        return;
      }
      await repository.sendMessage(
        _session!.voiceSessionId,
        body: body,
        inputMode: 'text_fallback',
      );
      _session = await repository.getSession(_session!.voiceSessionId);
      _status = 'Voice message sent.';
    });
  }

  void _closeSession() {
    if (_session == null) {
      return;
    }
    _runGatewayAction(() async {
      final repository = widget.runtime?.voiceRepository;
      if (repository == null) {
        return;
      }
      _session = await repository.closeSession(_session!.voiceSessionId);
      _status = 'Voice session closed.';
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
        setState(() => _status = operatorErrorMessage(error, context: 'voice'));
      }
    } finally {
      if (mounted) {
        setState(() => _busy = false);
      }
    }
  }
}

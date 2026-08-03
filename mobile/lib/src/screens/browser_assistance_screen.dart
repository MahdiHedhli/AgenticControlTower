import 'package:flutter/material.dart';

import '../app_runtime.dart';
import '../models/core_models.dart';
import '../operator_error.dart';
import '../routes.dart';
import '../widgets/alpha_components.dart';
import '../widgets/load_failure.dart';
import '../widgets/screen_shell.dart';

class BrowserAssistanceScreen extends StatefulWidget {
  const BrowserAssistanceScreen({
    required this.runtime,
    super.key,
  });

  final HermesAppRuntime runtime;

  @override
  State<BrowserAssistanceScreen> createState() =>
      _BrowserAssistanceScreenState();
}

class _BrowserAssistanceScreenState extends State<BrowserAssistanceScreen> {
  Future<List<BrowserAssistanceSessionModel>>? _sessions;
  bool _busy = false;

  @override
  void initState() {
    super.initState();
    _refresh();
  }

  void _refresh() {
    final repository = widget.runtime.browserAssistanceRepository;
    if (repository == null) {
      _sessions = Future.value(const []);
      return;
    }
    _sessions = claimLoadErrors(
      repository.listSessions(),
      context: 'browser-assistance',
    );
  }

  @override
  Widget build(BuildContext context) {
    return ScreenShell(
      title: 'Browser Assist',
      selectedRoute: HermesRoutes.inbox,
      body: FutureBuilder<List<BrowserAssistanceSessionModel>>(
        future: _sessions,
        builder: (context, snapshot) {
          final sessions = snapshot.data ?? const [];
          return ListView(
            padding: const EdgeInsets.fromLTRB(16, 8, 16, 24),
            children: [
              AlphaPanel(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    StatusPill(
                      label: widget.runtime.isPaired
                          ? 'gateway-backed'
                          : 'mock fallback',
                      color: Theme.of(context).colorScheme.primary,
                    ),
                    const SizedBox(height: 12),
                    Text(
                      'Human review surface',
                      style: Theme.of(context).textTheme.titleLarge?.copyWith(
                            fontWeight: FontWeight.w800,
                          ),
                    ),
                    const SizedBox(height: 8),
                    Text(
                      'Mobile can view requested browser help, record operator notes, and return control. Live browser streaming remains future work.',
                      style: Theme.of(context).textTheme.bodyMedium,
                    ),
                  ],
                ),
              ),
              const SectionHeader(title: 'Sessions'),
              if (snapshot.hasError)
                LoadFailurePanel(
                  error: snapshot.error!,
                  context_: 'browser-assistance',
                  onRetry: () => setState(_refresh),
                )
              else if (snapshot.connectionState == ConnectionState.waiting)
                const Center(child: CircularProgressIndicator())
              else if (sessions.isEmpty)
                const AlphaPanel(
                  child: Text(
                    'No browser assistance sessions are waiting on this gateway.',
                  ),
                )
              else
                ...sessions.map(_sessionCard),
            ],
          );
        },
      ),
    );
  }

  Widget _sessionCard(BrowserAssistanceSessionModel session) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 12),
      child: AlphaPanel(
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                StatusPill(
                  label: session.state,
                  color: Theme.of(context).colorScheme.secondary,
                ),
                const Spacer(),
                Text(session.agentId),
              ],
            ),
            const SizedBox(height: 12),
            Text(
              session.reason,
              style: Theme.of(context).textTheme.titleMedium?.copyWith(
                    fontWeight: FontWeight.w700,
                  ),
            ),
            const SizedBox(height: 8),
            DetailRow(label: 'Session', value: session.sessionId),
            DetailRow(label: 'Node', value: session.nodeId),
            if (session.userActionNotes.isNotEmpty)
              DetailRow(
                label: 'Last note',
                value: session.userActionNotes.last,
              ),
            const SizedBox(height: 12),
            Row(
              children: [
                Expanded(
                  child: OutlinedButton.icon(
                    onPressed: _busy ? null : () => _recordNote(session),
                    icon: const Icon(Icons.note_add_outlined),
                    label: const Text('Record Note'),
                  ),
                ),
                const SizedBox(width: 10),
                Expanded(
                  child: FilledButton.icon(
                    onPressed: _busy ? null : () => _returnControl(session),
                    icon: const Icon(Icons.keyboard_return),
                    label: const Text('Return'),
                  ),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }

  void _recordNote(BrowserAssistanceSessionModel session) {
    final repository = widget.runtime.browserAssistanceRepository;
    if (repository == null) {
      return;
    }
    _runGatewayAction(
      () => repository.recordEvent(
        session.browserSessionId,
        note: 'Operator reviewed browser context from mobile.',
      ),
    );
  }

  void _returnControl(BrowserAssistanceSessionModel session) {
    final repository = widget.runtime.browserAssistanceRepository;
    if (repository == null) {
      return;
    }
    _runGatewayAction(
      () => repository.returnControl(
        session.browserSessionId,
        summary: 'Operator reviewed browser context and returned control.',
      ),
    );
  }

  /// Run one operator action against the gateway and always report the verdict.
  ///
  /// Failure mode this closes: both handlers used to be `try { await …; }
  /// finally { _busy = false; }` — a `finally` with no `catch`. They are wired
  /// to `onPressed`, a `VoidCallback`, so the returned future is discarded and
  /// a POST to an unreachable gateway escaped as an *unhandled async error*.
  /// The operator saw nothing at all: no message, no panel, just a button that
  /// re-enabled itself as though the note had been recorded.
  ///
  /// Same shape as `tua_screen`/`voice_screen` `_runGatewayAction`: success
  /// refreshes, failure says one readable sentence, `_busy` always resets.
  Future<void> _runGatewayAction(Future<void> Function() action) async {
    setState(() => _busy = true);
    try {
      await action();
      if (mounted) {
        // Inside the try in the old code, so a failure skipped it silently.
        // Only a *successful* action refreshes — and it still does.
        setState(_refresh);
      }
    } on Object catch (error) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(
              operatorErrorMessage(error, context: 'browser-assistance'),
            ),
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

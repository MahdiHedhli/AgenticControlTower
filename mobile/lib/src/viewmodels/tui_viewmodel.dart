import 'dart:async';

import 'package:flutter/foundation.dart';

import '../api/gateway_api_client.dart';
import '../api/tui_protocol.dart';
import '../api/tui_stream_client.dart';
import '../models/alpha_models.dart';
import '../models/core_models.dart';
import '../operator_error.dart';
import '../repositories/alpha_repository.dart';
import '../repositories/tui_repository.dart';

class TuiViewModel extends ChangeNotifier {
  TuiViewModel({
    required AlphaRepository fallbackRepository,
    TuiRepository? tuiRepository,
    TuiStreamClient? streamClient,
  })  : _fallbackRepository = fallbackRepository,
        _tuiRepository = tuiRepository,
        _streamClient = streamClient;

  final AlphaRepository _fallbackRepository;
  final TuiRepository? _tuiRepository;
  final TuiStreamClient? _streamClient;

  TerminalSessionAlpha? _fallbackSession;
  TuiSessionModel? _gatewaySession;
  TuiStreamConnection? _connection;
  StreamSubscription<TuiServerFrame>? _subscription;
  final List<String> _gatewayScrollback = [];
  bool _loading = false;
  bool _gatewayMode = false;
  bool _connected = false;
  bool _isRelay = false;
  final List<TuiSessionModel> _relaySessions = [];
  String _statusLabel = 'Terminal idle';
  String? _errorLabel;

  bool get loading => _loading;
  bool get gatewayMode => _gatewayMode;
  bool get connected => _connected;
  // True when watching a read-only agent terminal mirror (relay) session.
  bool get isRelay => _isRelay;
  List<TuiSessionModel> get relaySessions => List.unmodifiable(_relaySessions);
  String get statusLabel => _statusLabel;
  String? get errorLabel => _errorLabel;
  TuiSessionModel? get gatewaySession => _gatewaySession;

  String get agentName =>
      _gatewaySession?.agentId ?? _fallbackSession?.agentName ?? 'Hermes Agent';
  String get node => _gatewaySession?.nodeId ?? _fallbackSession?.node ?? 'local';
  String get mission =>
      _gatewayMode ? _gatewaySession?.command ?? 'Terminal' : _fallbackSession?.mission ?? 'Terminal';
  String get prompt => _gatewayMode ? r'$' : _fallbackSession?.prompt ?? r'$';

  String get scrollbackText {
    if (_gatewayMode) {
      return _gatewayScrollback.join();
    }
    return [
      if (_fallbackSession != null) _fallbackSession!.scrollback.join('\n'),
      ..._gatewayScrollback,
    ].where((chunk) => chunk.isNotEmpty).join('\n');
  }

  Future<void> start(String routeContext) async {
    _loading = true;
    _statusLabel = 'Starting terminal';
    _errorLabel = null;
    notifyListeners();

    final repository = _tuiRepository;
    final streamClient = _streamClient;
    if (repository == null || streamClient == null) {
      await _loadMock(routeContext, 'Mock terminal; pair with gateway for live TUI');
      return;
    }

    try {
      // Watch the live agent terminal mirror (read-only relay), not a PTY.
      final relays = await repository.listRelaySessions();
      _relaySessions
        ..clear()
        ..addAll(relays);
      if (relays.isEmpty) {
        await _loadMock(
          routeContext,
          'No live agent terminal to mirror yet',
        );
        return;
      }
      await _attachRelay(relays.first, repository, streamClient);
    } on GatewayApiException catch (error) {
      await _loadMock(routeContext, 'Mock terminal; gateway rejected TUI (${error.statusCode})');
    } on Object catch (error) {
      await _loadMock(routeContext, 'Mock terminal; TUI unavailable');
      // Never the raw toString(): this label is operator-facing copy.
      _errorLabel = operatorErrorMessage(error, context: 'tui-start');
    } finally {
      _loading = false;
      notifyListeners();
    }
  }

  /// Attach (read-only) to a relay session's output stream.
  Future<void> _attachRelay(
    TuiSessionModel session,
    TuiRepository repository,
    TuiStreamClient streamClient,
  ) async {
    await _subscription?.cancel();
    _connection?.close();
    _gatewaySession = session;
    _gatewayMode = true;
    _isRelay = true;
    _connected = false;
    _gatewayScrollback.clear();
    _statusLabel = 'Connecting to ${session.agentId} terminal';
    notifyListeners();

    final attach = await repository.createAttachToken(session.sessionId);
    _connection = streamClient.connect(
      session.sessionId,
      attachToken: attach.attachToken,
    );
    _subscription = _connection!.frames.listen(
      _handleFrame,
      onError: (Object error) {
        _connected = false;
        _errorLabel = operatorErrorMessage(error, context: 'tui-stream');
        _statusLabel = 'Terminal stream error';
        notifyListeners();
      },
      onDone: () {
        _connected = false;
        _statusLabel = 'Terminal stream detached';
        notifyListeners();
      },
    );
  }

  /// Switch which relay session is being watched.
  Future<void> selectRelaySession(String sessionId) async {
    final repository = _tuiRepository;
    final streamClient = _streamClient;
    if (repository == null || streamClient == null) {
      return;
    }
    final session = _relaySessions.firstWhere(
      (s) => s.sessionId == sessionId,
      orElse: () => _relaySessions.first,
    );
    _loading = true;
    notifyListeners();
    try {
      await _attachRelay(session, repository, streamClient);
    } on Object catch (error) {
      _errorLabel = operatorErrorMessage(error, context: 'tui-relay');
    } finally {
      _loading = false;
      notifyListeners();
    }
  }

  Future<void> sendText(String text) async {
    if (text.isEmpty) {
      return;
    }
    if (_isRelay) {
      _statusLabel = 'Read-only: agent terminal mirror';
      notifyListeners();
      return;
    }
    if (_gatewayMode && _connection != null) {
      _connection!.send(TuiClientFrame.input(text));
      return;
    }
    _gatewayScrollback.add('${_fallbackSession?.prompt ?? r'$'} $text\n');
    notifyListeners();
  }

  Future<void> sendPaste(String text) async {
    if (text.isEmpty) {
      return;
    }
    if (_isRelay) {
      _statusLabel = 'Read-only: agent terminal mirror';
      notifyListeners();
      return;
    }
    if (_gatewayMode && _connection != null) {
      _connection!.send(TuiClientFrame.paste(text));
      return;
    }
    _gatewayScrollback.add(text.endsWith('\n') ? text : '$text\n');
    notifyListeners();
  }

  Future<void> sendSpecialKey(String label) async {
    final sequence = terminalSequenceForLabel(label);
    if (sequence == null) {
      _statusLabel = '$label is planned';
      notifyListeners();
      return;
    }
    await sendText(sequence);
  }

  Future<void> detach() async {
    if (_gatewayMode && _connection != null) {
      _connection!.send(TuiClientFrame.detach());
    }
    _connected = false;
    _statusLabel = 'Terminal detached';
    notifyListeners();
  }

  Future<void> close() async {
    if (_gatewayMode && _connection != null) {
      _connection!.send(TuiClientFrame.close());
    }
    _connected = false;
    _statusLabel = 'Terminal closing';
    notifyListeners();
  }

  List<String> keysForPage(TerminalKeyPage page) {
    return switch (page) {
      TerminalKeyPage.controls => [
          'ESC',
          'TAB',
          'CTRL+C',
          'ALT',
          'CMD',
          'Left',
          'Up',
          'Down',
          'Right'
        ],
      TerminalKeyPage.symbols => ['/', '~', '|', '&', r'$', ';', ':'],
      TerminalKeyPage.brackets => ['{}', '[]', '()', '<>'],
      TerminalKeyPage.functions => [
          'F1',
          'F2',
          'F3',
          'F4',
          'F5',
          'F6',
          'F7',
          'F8',
          'F9',
          'F10',
          'F11',
          'F12',
          'Home',
          'End',
          'PgUp',
          'PgDn',
        ],
    };
  }

  @override
  void dispose() {
    _subscription?.cancel();
    _connection?.close();
    super.dispose();
  }

  Future<void> _loadMock(String routeContext, String statusLabel) async {
    _fallbackSession = await _fallbackRepository.loadTerminalSession(routeContext);
    _gatewaySession = null;
    _gatewayMode = false;
    _connected = false;
    _statusLabel = statusLabel;
    _loading = false;
    notifyListeners();
  }

  void _handleFrame(TuiServerFrame frame) {
    if (frame.type == 'output') {
      _gatewayScrollback.add(frame.data ?? '');
      _statusLabel = 'Receiving terminal output';
    } else if (frame.type == 'state') {
      _connected = frame.state == 'active';
      _statusLabel = 'Terminal ${frame.state ?? 'state updated'}';
    } else if (frame.type == 'audit_notice') {
      _statusLabel = frame.message ?? 'Terminal audit active';
    } else if (frame.type == 'error') {
      _errorLabel = frame.message ?? 'Terminal stream error';
      _statusLabel = 'Terminal stream error';
    } else if (frame.type == 'pong') {
      _statusLabel = 'Terminal alive';
    }
    notifyListeners();
  }
}

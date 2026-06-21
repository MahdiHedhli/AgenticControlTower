import 'dart:async';

import 'package:flutter/foundation.dart';

import '../api/gateway_api_client.dart';
import '../api/tui_protocol.dart';
import '../api/tui_stream_client.dart';
import '../models/alpha_models.dart';
import '../models/core_models.dart';
import '../repositories/tui_repository.dart';

class TuiViewModel extends ChangeNotifier {
  TuiViewModel({
    TuiRepository? tuiRepository,
    TuiStreamClient? streamClient,
  })  : _tuiRepository = tuiRepository,
        _streamClient = streamClient;

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
  bool _empty = false;
  final List<TuiSessionModel> _relaySessions = [];
  String _statusLabel = 'Terminal idle';
  String? _errorLabel;

  /// Shown when there is no live agent terminal to mirror, instead of loading
  /// fabricated mock terminal data.
  static const noLiveTerminalMessage =
      'No live agent terminal — run a Hermes task with the ACT bridge to '
      'mirror it here.';

  bool get loading => _loading;
  bool get gatewayMode => _gatewayMode;
  bool get connected => _connected;
  // True when watching a read-only agent terminal mirror (relay) session.
  bool get isRelay => _isRelay;
  // True when there is no live terminal to show (honest empty state, no mock).
  bool get empty => _empty;
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
      // Honest empty state for an unpaired/unconfigured app — never fabricate a
      // mock terminal, so a paired user can never see fake "work-vm-02" data
      // even if the stream-client and repository guards ever diverge.
      _setEmpty('Pair this device with a gateway to mirror agent terminals here.');
      return;
    }

    try {
      // Watch the live agent terminal mirror (read-only relay), not a PTY.
      final relays = await repository.listRelaySessions();
      _relaySessions
        ..clear()
        ..addAll(relays);
      if (relays.isEmpty) {
        // Honest empty state — paired users never see fabricated terminal data.
        _setEmpty(noLiveTerminalMessage);
        return;
      }
      await _attachRelay(relays.first, repository, streamClient);
    } on GatewayApiException catch (error) {
      // Real failure talking to the gateway: surface it, do not fake a terminal.
      _setEmpty('Terminal mirror unavailable (gateway error ${error.statusCode})');
      _errorLabel = '$error';
    } on Object catch (error) {
      _setEmpty('Terminal mirror unavailable');
      _errorLabel = '$error';
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
    _empty = false;
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
        _errorLabel = 'TUI stream error: $error';
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
      _errorLabel = '$error';
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

  /// Honest empty state: there is no live terminal to mirror. We clear any
  /// gateway/fallback session so the UI shows [message] rather than fabricated
  /// terminal data.
  void _setEmpty(String message) {
    _fallbackSession = null;
    _gatewaySession = null;
    _gatewayScrollback.clear();
    _gatewayMode = false;
    _isRelay = false;
    _connected = false;
    _empty = true;
    _statusLabel = message;
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

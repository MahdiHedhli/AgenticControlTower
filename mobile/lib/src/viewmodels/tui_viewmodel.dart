import 'dart:async';

import 'package:flutter/foundation.dart';

import '../api/gateway_api_client.dart';
import '../api/tui_protocol.dart';
import '../api/tui_stream_client.dart';
import '../async_guard.dart';
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

  /// True when nothing is attached and no demo session is loaded — the state a
  /// paired device lands in when the tower has no terminal to mirror. The header
  /// must not name an agent or a node here: it used to read "Hermes Agent" on
  /// "local", a confident identity for a session that does not exist.
  bool get hasSession => _gatewaySession != null || _fallbackSession != null;

  String get agentName =>
      _gatewaySession?.agentId ?? _fallbackSession?.agentName ?? 'No terminal';
  String get node => _gatewaySession?.nodeId ?? _fallbackSession?.node ?? '--';
  String get mission => _gatewayMode
      ? _gatewaySession?.command ?? 'Terminal'
      : _fallbackSession?.mission ?? 'nothing attached';
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

  /// Attach to the live agent terminal mirror, or say why there is none.
  ///
  /// **Every** absence and failure path here used to end in `_loadMock(...)`,
  /// which loads `AlphaRepository.loadTerminalSession` — and on a paired device
  /// that repository is `GatewayAlphaRepository`, which used to hand back the
  /// demo fixture. So an empty relay list, a 500, an expired token or a dead
  /// socket all painted the terminal pane with a fabricated shell transcript
  /// (`git status`, `39 passed, 1 warning in 1.92s`, invented commit hashes)
  /// under a `hermes@work-vm-02` prompt, attributed to "Repo Sentinel".
  ///
  /// Terminal output is evidence; an operator reads it to decide what an agent
  /// actually did. Inventing it is the worst version of this bug in the app, and
  /// on the `relays.isEmpty` branch the status label did not even say "mock".
  ///
  /// The demo terminal now has exactly one entrance: no [TuiRepository] at all,
  /// which happens only when the device is unpaired (`HermesAppRuntime`
  /// returns null for it whenever `isPaired` is false) and the app is already
  /// announcing "Mock alpha data" in Settings. Paired, every other outcome is a
  /// named empty state with an empty pane.
  Future<void> start(String routeContext) async {
    _loading = true;
    _statusLabel = 'Starting terminal';
    _errorLabel = null;
    notifyListeners();

    final repository = _tuiRepository;
    final streamClient = _streamClient;
    if (repository == null) {
      // Unpaired: the sanctioned demo terminal, labelled as such.
      await _loadMock(routeContext, 'Mock terminal; pair with gateway for live TUI');
      return;
    }
    if (streamClient == null) {
      // Paired but with no usable access token — a pairing problem, not a
      // reason to show a fake terminal.
      _detachedState('Terminal unavailable: pair this device again');
      _loading = false;
      notifyListeners();
      return;
    }

    try {
      // Watch the live agent terminal mirror (read-only relay), not a PTY.
      final relays = await repository.listRelaySessions();
      _relaySessions
        ..clear()
        ..addAll(relays);
      if (relays.isEmpty) {
        _detachedState('No live agent terminal to mirror yet');
        return;
      }
      await _attachRelay(relays.first, repository, streamClient);
    } on GatewayApiException catch (error) {
      _detachedState('Gateway rejected TUI (${error.statusCode})');
      _errorLabel = operatorErrorMessage(error, context: 'tui-start');
    } on Object catch (error) {
      _detachedState('Terminal unavailable');
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
    // Re-attaching tears down the previous socket. Neither teardown may fail
    // the attach that follows it, and neither may escape: `close()` is
    // deliberately not awaited (the old socket's drain must not delay the new
    // relay), which is only safe because `TuiStreamConnection.close()` now
    // always completes and never throws.
    await cancelQuietly(_subscription);
    unawaited(_connection?.close() ?? Future<void>.value());
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
  ///
  /// The lookup used to be `orElse: () => _relaySessions.first`. Asking for a
  /// session that had ended between the list load and the tap therefore
  /// attached to **a different agent's terminal** and reported success: the
  /// operator watches one agent believing they are watching another. (It also
  /// threw a bare `StateError` when the list was empty.) A vanished session is
  /// an absence, and it says so.
  Future<void> selectRelaySession(String sessionId) async {
    final repository = _tuiRepository;
    final streamClient = _streamClient;
    if (repository == null || streamClient == null) {
      return;
    }
    TuiSessionModel? session;
    for (final candidate in _relaySessions) {
      if (candidate.sessionId == sessionId) {
        session = candidate;
        break;
      }
    }
    if (session == null) {
      _detachedState('That terminal session is no longer open');
      notifyListeners();
      return;
    }
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
    // The local echo below is the demo terminal's only behaviour. With nothing
    // attached it would paint the operator's own keystrokes into an empty pane
    // as though a shell had accepted them, on a paired device, with no shell
    // anywhere. Refuse and say why.
    if (!hasSession) {
      _statusLabel = 'No terminal attached';
      notifyListeners();
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
    if (!hasSession) {
      _statusLabel = 'No terminal attached';
      notifyListeners();
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
    // Both futures are discarded by a synchronous `dispose()`, so both must be
    // incapable of rejecting: `cancel()` is wrapped, and `close()` claims its
    // own errors and cannot hang on a socket that never connected.
    unawaited(cancelQuietly(_subscription));
    unawaited(_connection?.close() ?? Future<void>.value());
    _subscription = null;
    _connection = null;
    super.dispose();
  }

  /// The unpaired demo terminal. Only [start] may call this, and only when there
  /// is no [TuiRepository] at all — see the note on [start].
  Future<void> _loadMock(String routeContext, String statusLabel) async {
    _fallbackSession = await _fallbackRepository.loadTerminalSession(routeContext);
    _gatewaySession = null;
    _gatewayMode = false;
    _connected = false;
    _statusLabel = statusLabel;
    _loading = false;
    notifyListeners();
  }

  /// Paired, but nothing to mirror: an empty pane and a reason.
  ///
  /// This is what replaced `_loadMock` on the paired paths. It clears every
  /// session field rather than leaving a stale one behind, so `scrollbackText`
  /// is empty and the header reports no agent — the screen shows that there is
  /// no terminal, which is the truth.
  void _detachedState(String statusLabel) {
    _fallbackSession = null;
    _gatewaySession = null;
    _gatewayScrollback.clear();
    _gatewayMode = false;
    _isRelay = false;
    _connected = false;
    _statusLabel = statusLabel;
  }

  void _handleFrame(TuiServerFrame frame) {
    if (frame.type == 'output') {
      _gatewayScrollback.add(frame.data ?? '');
      _statusLabel = 'Receiving terminal output';
    } else if (frame.type == 'state') {
      _connected = frame.state == 'active';
      _statusLabel = 'Terminal ${frame.state ?? 'state updated'}';
    } else if (frame.type == 'audit_notice') {
      // Was `?? 'Terminal audit active'`. A notice frame that carried no message
      // is not evidence that auditing is on; asserting it is the app inventing a
      // guarantee on the tower's behalf.
      _statusLabel = frame.message ?? 'Terminal audit notice received';
    } else if (frame.type == 'error') {
      _errorLabel = frame.message ?? 'Terminal stream error';
      _statusLabel = 'Terminal stream error';
    } else if (frame.type == 'pong') {
      _statusLabel = 'Terminal alive';
    }
    notifyListeners();
  }
}

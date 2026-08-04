import 'dart:async';

import 'package:web_socket_channel/web_socket_channel.dart';

import '../config/gateway_config.dart';
import 'tui_protocol.dart';

typedef TuiSocketConnector = WebSocketChannel Function(Uri uri);

/// How long a teardown may wait on the socket before giving up on it.
///
/// Teardown is best-effort by nature: nothing downstream can act on the result.
const kTuiCloseTimeout = Duration(seconds: 2);

class TuiStreamClient {
  const TuiStreamClient({
    required this.config,
    TuiSocketConnector? socketConnector,
    this.closeTimeout = kTuiCloseTimeout,
  }) : _socketConnector = socketConnector;

  final GatewayConfig config;
  final TuiSocketConnector? _socketConnector;

  /// Passed to every [TuiStreamConnection] this client opens. Injectable so a
  /// test can assert the teardown bound without waiting on the real one.
  final Duration closeTimeout;

  Uri streamUri(String sessionId, {required String attachToken}) {
    final httpUri = config.resolve('/tui/sessions/$sessionId/stream', {
      'attach_token': attachToken,
    });
    final scheme = switch (httpUri.scheme) {
      'https' => 'wss',
      'http' => 'ws',
      _ => httpUri.scheme,
    };
    return httpUri.replace(scheme: scheme);
  }

  TuiStreamConnection connect(String sessionId, {required String attachToken}) {
    final connector = _socketConnector;
    final channel = connector == null
        ? WebSocketChannel.connect(
            streamUri(sessionId, attachToken: attachToken))
        : connector(streamUri(sessionId, attachToken: attachToken));
    // Identical treatment to `GatewayEventStreamClient._connectRaw`, for an
    // identical defect: `WebSocketChannel.connect()` reports a failed connection
    // through TWO independent paths — `ready` completing with an error, and the
    // error arriving on `stream`. The only subscriber here is
    // `TuiViewModel._attachRelay`, which claims the second (`frames.listen`'s
    // onError) and nothing at all claims the first. Against a gateway that will
    // not upgrade the socket the `ready` rejection therefore escaped as an
    // UNHANDLED async error on every relay attach: a zone-level crash on device
    // and a failed test here, for a condition the stream path already reports.
    // Claim it and drop it; `stream` remains the single error path.
    unawaited(channel.ready.catchError((Object _) {}));
    return TuiStreamConnection(channel, closeTimeout: closeTimeout);
  }
}

class TuiStreamConnection {
  TuiStreamConnection(this._channel, {this.closeTimeout = kTuiCloseTimeout});

  final WebSocketChannel _channel;
  final Duration closeTimeout;

  Stream<TuiServerFrame> get frames =>
      _channel.stream.map((raw) => TuiServerFrame.parse(raw));

  void send(TuiClientFrame frame) {
    _channel.sink.add(frame.encode());
  }

  /// Tear the socket down. Always completes promptly, never throws.
  ///
  /// `WebSocketChannel.sink.close()` on a channel that never connected does not
  /// complete — the sink waits on a socket that will never exist — and this was
  /// observed as a 30s test timeout. `close()` is only ever called from
  /// teardown (`TuiViewModel._attachRelay` before re-attaching, and
  /// `TuiViewModel.dispose`), where the future is discarded, so a hang leaks the
  /// connection forever and a throw escapes as an unhandled async error. A
  /// dispose path that can hang or throw is its own defect class regardless of
  /// what caused it.
  ///
  /// Both halves matter. The `onError` handler claims the sink's rejection even
  /// when the timeout is the one that wins the race — dropping the timed-out
  /// future without a handler would simply move the escape rather than close it.
  Future<void> close() {
    final Future<void> drained;
    try {
      drained = _channel.sink.close().then<void>(
            (_) {},
            onError: (Object _, StackTrace __) {},
          );
    } on Object {
      // A sink that throws synchronously is already gone.
      return Future<void>.value();
    }
    return drained.timeout(closeTimeout, onTimeout: () {});
  }
}

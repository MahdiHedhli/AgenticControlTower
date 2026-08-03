/// The TUI relay socket must not leak an async error, and must not hang on
/// teardown.
///
/// `WebSocketChannel.connect()` reports a failed connection through TWO
/// independent paths: `ready` completing with an error, and the error arriving
/// on `stream`. `TuiViewModel._attachRelay` claims only the second
/// (`frames.listen(onError:)`), so against a gateway that will not upgrade the
/// socket the `ready` rejection escaped unclaimed on every relay attach.
/// `GatewayEventStreamClient` already carried the fix; this file pins the
/// ported one, and the separate teardown guard next to it.
library;

import 'dart:async';

import 'package:agentic_control_tower/src/api/tui_stream_client.dart';
import 'package:agentic_control_tower/src/config/gateway_config.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:web_socket_channel/web_socket_channel.dart';

void main() {
  // ISOLATES the `ready` claim in `TuiStreamClient.connect` and nothing else.
  // The channel's `stream` is left alone (a live relay subscribes to it and
  // handles its errors), so the ONLY thing that can fail this test is an
  // unclaimed `ready` rejection reaching the test zone as an unhandled async
  // error. Nothing here awaits `close()`, so the teardown guard cannot mask it.
  test('a socket the gateway will not upgrade does not escape via ready',
      () async {
    final channel = _FakeWebSocketChannel(
      ready: Future<void>.error(
        WebSocketChannelException('Connection refused'),
      ),
    );
    final client = TuiStreamClient(
      config: GatewayConfig.loopback,
      socketConnector: (_) => channel,
    );

    client.connect('tui_1', attachToken: 'attach_1');

    // Let the rejection land. Unclaimed, it is reported to the enclosing zone
    // here and the test fails with "Unhandled error ... Connection refused".
    await _settle();
  });

  // ISOLATES the teardown guard. The socket never connected, so the sink's
  // close() never completes — the exact 30s-timeout hang that was observed.
  // Only a close() that bounds its own wait can satisfy this.
  test('close() completes even when the socket never connected', () async {
    final channel = _FakeWebSocketChannel(
      // Pre-claimed here: this test builds the connection directly rather than
      // through `TuiStreamClient.connect`, so the ready-claim under test above
      // is not in play and must not be what this case measures.
      ready: _claimed(WebSocketChannelException('Connection refused')),
      sinkClose: Completer<void>().future, // never completes, as in the wild
    );
    final connection = TuiStreamConnection(
      channel,
      closeTimeout: const Duration(milliseconds: 50),
    );

    await expectLater(
      connection.close().timeout(const Duration(seconds: 5)),
      completes,
      reason: 'a dispose path that can hang is a permanent connection leak',
    );
    await _settle();
  });

  // ISOLATES the "never throws" half of the teardown guard, which the hang test
  // above cannot reach: here the sink close *rejects* rather than hanging.
  // `TuiViewModel.dispose()` discards this future, so a rejection would escape.
  test('close() neither throws nor escapes when the sink close rejects',
      () async {
    final channel = _FakeWebSocketChannel(
      ready: Future<void>.value(),
      sinkClose: Future<void>.error(StateError('socket already gone')),
    );
    final connection = TuiStreamConnection(
      channel,
      closeTimeout: const Duration(milliseconds: 50),
    );

    await expectLater(connection.close(), completes);
    await _settle();
  });

  // A healthy socket must still be drained properly — the guard must not have
  // turned close() into a no-op.
  test('close() still closes a live sink', () async {
    final channel = _FakeWebSocketChannel(ready: Future<void>.value());
    final connection = TuiStreamConnection(channel);

    await connection.close();

    expect(channel.sink.closeCalls, 1);
  });

  test('frames still surface stream errors to the subscriber', () async {
    final controller = StreamController<dynamic>();
    final channel = _FakeWebSocketChannel(
      ready: Future<void>.error(
        WebSocketChannelException('Connection refused'),
      ),
      stream: controller.stream,
    );
    final client = TuiStreamClient(
      config: GatewayConfig.loopback,
      socketConnector: (_) => channel,
    );

    final connection = client.connect('tui_1', attachToken: 'attach_1');
    Object? seen;
    connection.frames.listen((_) {}, onError: (Object error) => seen = error);
    controller.addError(WebSocketChannelException('Connection refused'));
    await _settle();

    expect(
      seen,
      isNotNull,
      reason: 'claiming `ready` must not disturb the real error path',
    );
    await controller.close();
  });
}

/// Drain microtasks and one timer turn so a pending rejection is reported.
Future<void> _settle() => Future<void>.delayed(const Duration(milliseconds: 80));

/// A rejected future whose error is already claimed, so it cannot be mistaken
/// for the escape a test is trying to detect.
Future<void> _claimed(Object error) {
  final future = Future<void>.error(error);
  future.ignore();
  return future;
}

class _FakeWebSocketChannel implements WebSocketChannel {
  _FakeWebSocketChannel({
    required Future<void> ready,
    Future<void>? sinkClose,
    Stream<dynamic>? stream,
  })  : _ready = ready,
        _stream = stream ?? const Stream<dynamic>.empty(),
        sink = _FakeWebSocketSink(sinkClose ?? Future<void>.value());

  final Future<void> _ready;
  final Stream<dynamic> _stream;

  @override
  final _FakeWebSocketSink sink;

  @override
  Future<void> get ready => _ready;

  @override
  Stream<dynamic> get stream => _stream;

  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

class _FakeWebSocketSink implements WebSocketSink {
  _FakeWebSocketSink(this._closeResult);

  final Future<void> _closeResult;
  int closeCalls = 0;

  @override
  Future<void> close([int? closeCode, String? closeReason]) {
    closeCalls += 1;
    return _closeResult;
  }

  @override
  void add(dynamic data) {}

  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

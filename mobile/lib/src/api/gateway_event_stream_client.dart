import 'dart:async';
import 'dart:convert';

import 'package:web_socket_channel/web_socket_channel.dart';

import '../config/gateway_config.dart';
import '../models/core_models.dart';

typedef GatewayEventSocketConnector = Stream<dynamic> Function(Uri uri);

class GatewayEventStreamClient {
  const GatewayEventStreamClient({
    required this.config,
    required this.accessToken,
    GatewayEventSocketConnector? socketConnector,
    this.initialBackoff = const Duration(seconds: 1),
    this.maxBackoff = const Duration(seconds: 20),
    this.maxReconnects,
    this.onConnectError,
  }) : _socketConnector = socketConnector;

  final GatewayConfig config;
  final String accessToken;
  final GatewayEventSocketConnector? _socketConnector;
  final Duration initialBackoff;
  final Duration maxBackoff;
  final int? maxReconnects;

  /// Called on each failed connection attempt with the raw error. Lets the
  /// caller distinguish an auth failure (expired access token -> HTTP 403/401 in
  /// the error) from a transient network drop and refresh the token if needed.
  final void Function(Object error)? onConnectError;

  Uri streamUri({String? after}) {
    final httpUri = config.resolve('/events/stream', {
      'access_token': accessToken,
      'after': after,
    });
    final scheme = switch (httpUri.scheme) {
      'https' => 'wss',
      'http' => 'ws',
      _ => httpUri.scheme,
    };
    return httpUri.replace(scheme: scheme);
  }

  /// Connect and emit gateway events, reconnecting with exponential backoff.
  ///
  /// Implemented on a [StreamController] rather than as an `async*` generator.
  /// A generator only observes the listener's cancel() at a `yield`, and a
  /// stream that cannot connect (gateway down, token revoked — exactly the
  /// state in which an operator reaches for Clear Pairing) never yields, so
  /// cancel() never completed and every caller awaiting it hung forever.
  /// Here cancel() completes immediately, wakes any backoff sleep, and the
  /// reconnect task shuts itself down at its next checkpoint.
  Stream<GatewayEvent> connect({String? after}) {
    final controller = StreamController<GatewayEvent>();
    var cancelled = false;
    Completer<void>? wake;

    Future<void> run() async {
      var cursor = after;
      var reconnects = 0;
      while (!cancelled &&
          (maxReconnects == null || reconnects <= maxReconnects!)) {
        try {
          await for (final raw in _connectRaw(streamUri(after: cursor))) {
            if (cancelled) {
              break;
            }
            final event = parseGatewayEvent(raw);
            cursor = event.cursor;
            reconnects = 0;
            controller.add(event);
          }
        } on Object catch (error) {
          // The caller observes liveness through missing events and the next
          // successful event. Requests remain fail-closed because approvals
          // still require signed HTTP decisions. Surface the error so the
          // caller can refresh an expired access token and reconnect.
          if (!cancelled) {
            onConnectError?.call(error);
          }
        }

        if (cancelled) {
          break;
        }
        reconnects += 1;
        if (maxReconnects != null && reconnects > maxReconnects!) {
          break;
        }
        final sleep = wake = Completer<void>();
        await Future.any(<Future<void>>[
          Future<void>.delayed(_backoffFor(reconnects)),
          sleep.future,
        ]);
        wake = null;
      }
      await controller.close();
    }

    controller.onListen = () {
      unawaited(run());
    };
    controller.onCancel = () {
      cancelled = true;
      final sleep = wake;
      if (sleep != null && !sleep.isCompleted) {
        sleep.complete();
      }
    };
    return controller.stream;
  }

  Stream<dynamic> _connectRaw(Uri uri) {
    final connector = _socketConnector;
    if (connector != null) {
      return connector(uri);
    }
    return WebSocketChannel.connect(uri).stream;
  }

  Duration _backoffFor(int attempt) {
    if (initialBackoff == Duration.zero) {
      return Duration.zero;
    }
    final exponent = (attempt - 1).clamp(0, 6).toInt();
    final factor = 1 << exponent;
    final milliseconds = initialBackoff.inMilliseconds * factor;
    if (milliseconds > maxBackoff.inMilliseconds) {
      return maxBackoff;
    }
    return Duration(milliseconds: milliseconds);
  }

  static GatewayEvent parseGatewayEvent(Object raw) {
    if (raw is String) {
      return GatewayEvent.fromJson(jsonDecode(raw) as Map<String, dynamic>);
    }
    if (raw is Map<String, dynamic>) {
      return GatewayEvent.fromJson(raw);
    }
    if (raw is Map) {
      return GatewayEvent.fromJson(Map<String, dynamic>.from(raw));
    }
    throw FormatException('Unsupported gateway event payload: $raw');
  }
}

class GatewayEventStreamStatus {
  const GatewayEventStreamStatus({
    required this.label,
    required this.connected,
  });

  final String label;
  final bool connected;
}

import 'dart:async';
import 'dart:convert';

import '../config/gateway_config.dart';
import '../models/core_models.dart';
import 'gateway_socket_connector.dart';
import 'gateway_stream_errors.dart';

export 'gateway_stream_errors.dart';

typedef GatewayEventSocketConnector = Stream<dynamic> Function(Uri uri);

/// Supplies the access token for the next connection attempt.
///
/// Read per attempt rather than captured once: the paired-device access token
/// has a 15 minute TTL, so a stream that outlives one token has to reconnect
/// with the token the runtime holds *now*, not the one it held at construction.
typedef GatewayAccessTokenProvider = FutureOr<String?> Function();

/// Re-authenticates after the gateway refuses the upgrade with 401/403.
///
/// Returns true when a fresh access token is available, which reconnects
/// immediately instead of waiting out a backoff window.
typedef GatewayStreamReauthenticator = Future<bool> Function();

class GatewayEventStreamClient {
  const GatewayEventStreamClient({
    required this.config,
    required this.accessToken,
    GatewayEventSocketConnector? socketConnector,
    this.initialBackoff = const Duration(seconds: 1),
    this.maxBackoff = const Duration(seconds: 20),
    this.maxReconnects,
    this.onConnectError,
    this.onAuthFailure,
  }) : _socketConnector = socketConnector;

  final GatewayConfig config;
  final GatewayAccessTokenProvider accessToken;
  final GatewayEventSocketConnector? _socketConnector;
  final Duration initialBackoff;
  final Duration maxBackoff;
  final int? maxReconnects;

  /// Called on each failed connection attempt, with the HTTP status of the
  /// refused upgrade when the platform reports one.
  final void Function(GatewayStreamConnectError error)? onConnectError;

  /// Called when a failed attempt was an auth rejection. Refresh the access
  /// token here; returning true retries at once with whatever
  /// [accessToken] now yields.
  final GatewayStreamReauthenticator? onAuthFailure;

  Uri streamUri({required String accessToken, String? after}) {
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
      // At most one immediate re-auth retry per backoff window, so a token the
      // gateway keeps rejecting cannot spin this loop.
      var reauthenticated = false;
      var retryNow = false;
      while (!cancelled &&
          (maxReconnects == null || reconnects <= maxReconnects!)) {
        retryNow = false;
        try {
          final token = await accessToken();
          if (cancelled) {
            break;
          }
          if (token == null || token.isEmpty) {
            throw const GatewayStreamUpgradeException(
              'no access token for the event stream',
              statusCode: 401,
            );
          }
          await for (final raw
              in _connectRaw(streamUri(accessToken: token, after: cursor))) {
            if (cancelled) {
              break;
            }
            final event = parseGatewayEvent(raw);
            cursor = event.cursor;
            reconnects = 0;
            reauthenticated = false;
            controller.add(event);
          }
        } on Object catch (error) {
          // The caller observes liveness through missing events and the next
          // successful event. Requests remain fail-closed because approvals
          // still require signed HTTP decisions.
          if (!cancelled) {
            final failure = GatewayStreamConnectError.from(error);
            // Guarded on its own: this is *inside* the catch clause, so a throw
            // from either callback is not caught by the `try` above. It would
            // escape `run()` — which nothing awaits — into the root zone as an
            // unhandled async error, and skip `controller.close()`, leaving
            // every listener waiting on a stream that can never end.
            try {
              onConnectError?.call(failure);
              final reauthenticate = onAuthFailure;
              if (failure.isAuthFailure &&
                  !reauthenticated &&
                  reauthenticate != null) {
                reauthenticated = true;
                retryNow = await reauthenticate();
              }
            } on Object {
              // A reporting/re-auth callback that fails tells us nothing more
              // than the connection failure we are already handling. Keep
              // reconnecting.
              retryNow = false;
            }
          }
        }

        if (cancelled) {
          break;
        }
        if (retryNow) {
          // Credentials just changed. Reconnect now rather than leaving the
          // operator on a stale dashboard for a failure already fixed.
          continue;
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
        reauthenticated = false;
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
    // The `WebSocketChannel.ready` unhandled-rejection guard that used to live
    // here moved into the connectors: the io connector no longer uses
    // `WebSocketChannel` at all (it opens `dart:io`'s socket so a refused
    // upgrade keeps its HTTP status), and the web connector claims `ready`
    // itself. See `gateway_socket_connector_web.dart`.
    return connectGatewayWebSocket(uri);
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

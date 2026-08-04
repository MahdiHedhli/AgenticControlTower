/// The gateway refused the WebSocket upgrade for `/v1/events/stream`.
///
/// Carries the HTTP status of the rejected handshake so a caller can tell an
/// expired access token (401/403) from an unreachable gateway.
///
/// The status is only available because the event stream opens its own socket.
/// `WebSocketChannel.connect` routes through `package:web_socket`, which
/// catches `dart:io`'s `WebSocketException` and rethrows its own carrying only
/// `message` — `httpStatusCode` is dropped there. What reaches the caller is
/// "Connection to '...' was not upgraded to websocket", which names no status
/// at all.
class GatewayStreamUpgradeException implements Exception {
  const GatewayStreamUpgradeException(this.message, {this.statusCode});

  final String message;

  /// HTTP status of the refused upgrade, or null on platforms that do not
  /// expose one (browsers hide it by spec).
  final int? statusCode;

  @override
  String toString() => statusCode == null
      ? 'GatewayStreamUpgradeException: $message'
      : 'GatewayStreamUpgradeException: $message (HTTP $statusCode)';
}

/// One failed attempt to open the gateway event stream.
class GatewayStreamConnectError {
  const GatewayStreamConnectError(this.error, {this.statusCode});

  factory GatewayStreamConnectError.from(Object error) {
    return GatewayStreamConnectError(
      error,
      statusCode:
          error is GatewayStreamUpgradeException ? error.statusCode : null,
    );
  }

  final Object error;

  /// HTTP status of the refused upgrade when the platform reported one.
  final int? statusCode;

  /// Whether the gateway rejected this attempt for auth reasons — the signal
  /// that the access token needs refreshing before reconnecting.
  ///
  /// The reported status is authoritative. The string fallback applies only
  /// when no status is available, and is deliberately not the primary check:
  /// matching "403"/"forbidden" against the message was the original bug. The
  /// message for a rejected upgrade contains neither, so an expired token left
  /// the stream reconnecting forever with the dead token and the dashboard on
  /// "Live stream connecting".
  bool get isAuthFailure {
    final status = statusCode;
    if (status != null) {
      return status == 401 || status == 403;
    }
    final text = error.toString().toLowerCase();
    return text.contains('403') ||
        text.contains('401') ||
        text.contains('forbidden') ||
        text.contains('unauthor');
  }
}

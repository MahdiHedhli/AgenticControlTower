import 'dart:async';

import 'package:web_socket_channel/web_socket_channel.dart';

import 'gateway_stream_request.dart';

/// Browser fallback for the gateway event stream.
///
/// Browsers never expose the handshake status to script, so a refused upgrade
/// arrives with no status to report and [GatewayStreamConnectError] falls back
/// to inspecting the message.
Stream<dynamic> connectGatewayWebSocket(GatewayStreamRequest request) {
  // Browsers cannot set headers on a WebSocket handshake, so this platform has
  // no way to avoid the query form. The gateway still accepts it (and logs it
  // as deprecated), and redacts the parameter at its log sink -- which is the
  // only mitigation that covers a client that cannot be fixed.
  final channel = WebSocketChannel.connect(request.uriWithQueryToken);
  // `ready` completes with an error of its own when the socket cannot be
  // established (gateway down, wrong port). Nothing awaits it — the reconnect
  // loop learns the same thing from `stream`, which it does handle — so its
  // rejection escapes as an UNHANDLED async error: a zone-level crash for a
  // condition the client recovers from. Claim it and drop it; `stream` remains
  // the single error path.
  unawaited(channel.ready.catchError((Object _) {}));
  return channel.stream;
}

import 'package:web_socket_channel/web_socket_channel.dart';

/// Browser fallback for the gateway event stream.
///
/// Browsers never expose the handshake status to script, so a refused upgrade
/// arrives with no status to report and [GatewayStreamConnectError] falls back
/// to inspecting the message.
Stream<dynamic> connectGatewayWebSocket(Uri uri) =>
    WebSocketChannel.connect(uri).stream;

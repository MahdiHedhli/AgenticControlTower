import 'dart:async';
import 'dart:io' as io;

import 'gateway_stream_errors.dart';

/// Open the gateway event stream over `dart:io`'s WebSocket.
///
/// Deliberately not `WebSocketChannel.connect`: that path runs through
/// `package:web_socket`, which catches `dart:io`'s `WebSocketException` and
/// rethrows its own with only `message`, discarding `httpStatusCode`. Opening
/// the socket here keeps the status of a refused upgrade, which is the only
/// reliable way to tell an expired access token from a dead gateway.
Stream<dynamic> connectGatewayWebSocket(Uri uri) {
  late final StreamController<dynamic> controller;
  io.WebSocket? socket;
  var cancelled = false;

  Future<void> open() async {
    try {
      final opened = await io.WebSocket.connect(uri.toString());
      if (cancelled) {
        await opened.close();
        return;
      }
      socket = opened;
      await controller.addStream(opened);
    } on io.WebSocketException catch (error) {
      // dart:io builds this message out of the full request URL — access token
      // and all — and the caller logs errors. Report the status, not the URL.
      controller.addError(
        GatewayStreamUpgradeException(
          'gateway refused the event stream upgrade',
          statusCode: error.httpStatusCode,
        ),
      );
    } on Object catch (error) {
      controller.addError(error);
    } finally {
      await controller.close();
    }
  }

  controller = StreamController<dynamic>(
    onListen: () => unawaited(open()),
    onCancel: () async {
      cancelled = true;
      // Closing ends the forwarded socket stream, which completes `addStream`.
      // A handshake still in flight is picked up by the `cancelled` check
      // above instead, so cancel() never waits on the network.
      await socket?.close();
    },
  );
  return controller.stream;
}

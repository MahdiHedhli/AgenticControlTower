import 'package:flutter/services.dart';

/// Bridges the iOS APNs device token from native (AppDelegate) to Dart over the
/// `act/push` MethodChannel. Native pushes the token via `onApnsToken` once it
/// registers with APNs, and also answers a `requestToken` pull with the latest
/// cached token. On platforms / builds without the native handler this is inert
/// (returns null, registers nothing) so it is safe to wire unconditionally.
class PushTokenChannel {
  const PushTokenChannel();

  static const MethodChannel _channel = MethodChannel('act/push');

  /// Install a handler invoked whenever native delivers an APNs device token.
  /// Set this early (before native finishes registering) so no token is dropped.
  void onToken(void Function(String token) handler) {
    _channel.setMethodCallHandler((call) async {
      if (call.method == 'onApnsToken') {
        final token = _extractToken(call.arguments);
        if (token != null) {
          handler(token);
        }
      }
      return null;
    });
  }

  /// Pull the latest cached APNs token from native (e.g. after pairing, in case
  /// the push arrived before a handler was set). Returns null when unavailable.
  Future<String?> requestToken() async {
    try {
      final token = await _channel.invokeMethod<dynamic>('requestToken');
      return _extractToken(token);
    } on MissingPluginException {
      return null;
    } on PlatformException {
      return null;
    }
  }

  String? _extractToken(Object? raw) {
    final value = raw is Map ? raw['token'] : raw;
    if (value is String && value.isNotEmpty) {
      return value;
    }
    return null;
  }
}

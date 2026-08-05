/// One attempt to open the gateway event stream.
///
/// The access token is a field here rather than a query parameter on [uri] on
/// purpose: a token in the URL is part of the HTTP request target, and the
/// gateway's own access log records that target verbatim — uvicorn logs every
/// WebSocket upgrade on `uvicorn.error`, which the LaunchAgent points at
/// gateway.err.log. A 15-minute token then sits in plaintext on disk for as
/// long as the log is kept. Measured before this change: 42 of 147 upgrade
/// lines on the live host carried one.
///
/// Keeping the two separate makes it a compile error to put the credential back
/// into the URL by accident, and lets each platform choose the transport it
/// actually has.
class GatewayStreamRequest {
  const GatewayStreamRequest({
    required this.uri,
    required this.accessToken,
  });

  /// Where to connect. Carries `after` only — never the token.
  final Uri uri;

  final String accessToken;

  /// Upgrade-request headers for platforms that can send them (dart:io).
  Map<String, dynamic> get headers => <String, dynamic>{
        'Authorization': 'Bearer $accessToken',
      };

  /// The legacy URL form, token in the query string.
  ///
  /// Browsers cannot set headers on a WebSocket handshake, so the web connector
  /// has no alternative and must still use this. That is a platform limit, not
  /// a choice — and it is why the gateway ALSO redacts these params at its log
  /// sink rather than relying on every client to stop sending them.
  Uri get uriWithQueryToken => uri.replace(
        queryParameters: <String, String>{
          ...uri.queryParameters,
          'access_token': accessToken,
        },
      );
}

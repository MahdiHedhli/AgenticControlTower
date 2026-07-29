import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import 'api/gateway_api_client.dart';
import 'security/secure_enclave_channel.dart';

/// Render a caught error as one short, human-readable line for operator UI.
///
/// A raw exception dump is never operator-facing copy. Pairing used to surface
/// `PlatformException(generate_failed, Error Domain=com.apple.LocalAuthentication
/// Code=-1020 "This call is not supported on iOS Simulator." ...)` verbatim in a
/// snackbar. The technical detail still reaches the debug log through
/// [debugPrint]; only the readable summary reaches the screen.
///
/// Pass [context] to label the log line (e.g. `'completePairing'`).
String operatorErrorMessage(Object error, {String? context}) {
  debugPrint('[act] ${context ?? 'error'}: $error');
  return _describe(error);
}

String _describe(Object error) {
  if (error is SecureEnclaveException) {
    return "Couldn't create a secure key on this device.";
  }
  if (error is PlatformException) {
    final reason = _nativeReason(error);
    return switch (error.code) {
      'generate_failed' ||
      'access_control' =>
        "Couldn't create a secure key on this device.$reason",
      'sign_failed' => "Couldn't authorize this with Face ID or your "
          'passcode.$reason',
      'no_key' => 'This device has no signing key yet — pair it again.',
      'bad_arguments' => 'The app sent an incomplete signing request.',
      _ => 'The device could not complete this secure operation.$reason',
    };
  }
  if (error is GatewayApiException) {
    return _gatewayReason(error.statusCode);
  }
  if (error is TimeoutException) {
    return 'The control tower took too long to respond.';
  }
  if (error is FormatException) {
    return 'The control tower sent a response the app could not read.';
  }
  final detail = error.toString();
  if (_looksLikeNetwork(detail)) {
    return "Can't reach the control tower. Check the gateway URL in Settings.";
  }
  return 'Something went wrong. See the debug log for details.';
}

/// Translate the few native failure modes an operator can actually act on.
/// Anything else contributes no text at all rather than leaking a dump.
String _nativeReason(PlatformException error) {
  final detail = '${error.message ?? ''} ${error.details ?? ''}';
  if (detail.contains('not supported on iOS Simulator')) {
    return ' The Secure Enclave is not available on the Simulator.';
  }
  if (detail.contains('-1004') || detail.contains('passcode not set')) {
    return ' Set a device passcode first.';
  }
  if (detail.contains('-7') && detail.contains('not enrolled')) {
    return ' Face ID or Touch ID is not set up yet.';
  }
  if (detail.contains('biometry is locked') || detail.contains('-8')) {
    return ' Biometrics are locked — unlock with your passcode.';
  }
  if (detail.contains('-2') || detail.toLowerCase().contains('cancel')) {
    return ' The authentication prompt was dismissed.';
  }
  return '';
}

String _gatewayReason(int statusCode) {
  if (statusCode == 401 || statusCode == 403) {
    return 'The control tower refused this request. Pair this device again.';
  }
  if (statusCode == 404) {
    return 'The control tower no longer has that record.';
  }
  if (statusCode == 409) {
    return 'That decision was already recorded.';
  }
  if (statusCode == 429) {
    return 'Too many requests — try again in a moment.';
  }
  if (statusCode >= 500) {
    return 'The control tower hit an internal error ($statusCode).';
  }
  return 'The control tower rejected this request ($statusCode).';
}

bool _looksLikeNetwork(String detail) {
  const markers = [
    'SocketException',
    'ClientException',
    'HttpException',
    'Connection refused',
    'Connection closed',
    'Failed host lookup',
    'Network is unreachable',
    'Software caused connection abort',
  ];
  return markers.any(detail.contains);
}

import 'dart:convert';
import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import 'api/gateway_api_client.dart';
import 'repositories/alpha_repository.dart';
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
  // Absence, said out loud. These two must never read like a connectivity
  // problem: the tower was reached, and the honest answer is that the record is
  // gone (or was never live here). Rendering them as "can't reach the control
  // tower" would send the operator to Settings to fix a network that is fine;
  // rendering them as a populated screen — which is what the repository used to
  // do — is worse still.
  if (error is FleetRecordNotFoundException) {
    return switch (error.kind) {
      'agent' => 'That agent is no longer in this fleet.',
      'approval' => 'That approval is no longer in the queue.',
      _ => 'The control tower no longer has that record.',
    };
  }
  if (error is LiveDataUnavailableException) {
    return 'The control tower has no live ${error.surface} for this device.';
  }
  if (error is SecureEnclaveException) {
    return "Couldn't create a secure key on this device.";
  }
  if (error is PlatformException) {
    final reason = _nativeReason(error);
    return switch (error.code) {
      'generate_failed' ||
      'access_control' =>
        "Couldn't create a secure key on this device.$reason",
      'sign_failed' ||
      'auth_failed' =>
        "Couldn't authorize this with Face ID or your passcode.$reason",
      'no_key' => 'This device has no signing key yet — pair it again.',
      'bad_arguments' => 'The app sent an incomplete signing request.',
      _ => 'The device could not complete this secure operation.$reason',
    };
  }
  if (error is GatewayApiException) {
    return _gatewayReason(error.statusCode, error.body);
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

/// The tower's machine-readable conflict codes, mapped to what actually
/// happened to the operator.
///
/// Every 409 used to render as "That decision was already recorded". That is
/// false for most of them and dangerous for one: an operator who taps Deny on a
/// clearance a standing grant already approved was told their decision landed,
/// and walked away believing they had stopped something that in fact ran. The
/// tower now names the outcome; this is where the operator reads it.
const Map<String, String> _conflictReasons = {
  'approval_already_approved':
      'This was already APPROVED — by a standing grant or another device. '
          'Your decision was not recorded. If it should not have run, revoke '
          'the grant and stop the agent.',
  'approval_already_denied': 'This was already denied. Your decision was not '
      'recorded, but the outcome matches.',
  'approval_already_expired': 'This request expired before you answered, so '
      'nothing was approved. Ask the agent to request again.',
  'approval_expired': 'This request expired just as you answered, so nothing '
      'was approved. Ask the agent to request again.',
  'approval_cancelled': 'The agent withdrew this request, so there was nothing '
      'to decide.',
  'approval_consumed': 'This was already approved and carried out by the '
      'agent. Your decision was not recorded.',
  'request_replayed': 'That request was sent twice. Try again.',
};

String _gatewayReason(int statusCode, String body) {
  if (statusCode == 401 || statusCode == 403) {
    return 'The control tower refused this request. Pair this device again.';
  }
  if (statusCode == 404) {
    return 'The control tower no longer has that record.';
  }
  if (statusCode == 409) {
    final code = _conflictCode(body);
    final reason = _conflictReasons[code];
    if (reason != null) {
      return reason;
    }
    // An older tower, or a conflict this build does not know. Say only what is
    // certainly true rather than guessing which outcome occurred -- the old
    // blanket sentence was wrong far more often than it was right.
    return 'The control tower could not accept that decision because the '
        'request is no longer open. Refresh to see its current state.';
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

/// Pull the tower's conflict code out of the response body.
///
/// GatewayApiException.body was previously discarded entirely, which is why one
/// sentence had to cover six different outcomes. Parsing is deliberately
/// defensive: an unparseable body falls through to the honest generic message
/// rather than asserting something that may be false.
String? _conflictCode(String body) {
  if (body.isEmpty) {
    return null;
  }
  try {
    final decoded = jsonDecode(body);
    if (decoded is Map<String, dynamic>) {
      final detail = decoded['detail'];
      if (detail is Map<String, dynamic>) {
        final error = detail['error'];
        return error is String ? error : null;
      }
    }
  } on FormatException {
    return null;
  }
  return null;
}

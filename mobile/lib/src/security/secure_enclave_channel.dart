import 'dart:convert';

import 'package:flutter/services.dart';

import 'device_request_signer.dart';

/// Honest, native-sourced description of the device signing key's protection.
class SecureEnclaveStatus {
  const SecureEnclaveStatus({
    required this.secureEnclaveAvailable,
    required this.hasKey,
    required this.backend,
    required this.hardwareBacked,
    required this.userPresenceRequired,
    required this.privateKeyExportable,
    required this.biometryAvailable,
    required this.biometryType,
  });

  final bool secureEnclaveAvailable;
  final bool hasKey;
  final String backend;
  final bool hardwareBacked;
  final bool userPresenceRequired;
  final bool privateKeyExportable;
  final bool biometryAvailable;
  final String biometryType;

  factory SecureEnclaveStatus.fromMap(Map<String, dynamic> map) {
    return SecureEnclaveStatus(
      secureEnclaveAvailable: (map['secureEnclaveAvailable'] as bool?) ?? false,
      hasKey: (map['hasKey'] as bool?) ?? false,
      backend: (map['backend'] as String?) ?? 'unknown',
      hardwareBacked: (map['hardwareBacked'] as bool?) ?? false,
      userPresenceRequired: (map['userPresenceRequired'] as bool?) ?? false,
      privateKeyExportable: (map['privateKeyExportable'] as bool?) ?? true,
      biometryAvailable: (map['biometryAvailable'] as bool?) ?? false,
      biometryType: (map['biometryType'] as String?) ?? 'none',
    );
  }

  /// Map the native status to the UI-facing protection record, truthfully.
  ClearanceKeyProtection toProtection() {
    final warning = hardwareBacked
        ? 'Signing key is generated inside the Secure Enclave, non-exportable, '
            'and every signature requires user presence ($biometryType).'
        : 'DEV BUILD: software P-256 key (no Secure Enclave on this device). '
            'Not hardware-backed; do not use for production clearances.';
    return ClearanceKeyProtection(
      backend: backend,
      hardwareBacked: hardwareBacked,
      userPresenceRequired: userPresenceRequired,
      privateKeyExportable: privateKeyExportable,
      productionReady: hardwareBacked,
      warning: warning,
    );
  }
}

class SecureEnclaveKey {
  const SecureEnclaveKey({
    required this.publicKeyBase64,
    required this.backend,
    required this.hardwareBacked,
  });

  final String publicKeyBase64;
  final String backend;
  final bool hardwareBacked;

  /// Device key algorithm class registered with the gateway.
  String get algorithm => 'p256';
}

class SecureEnclaveException implements Exception {
  const SecureEnclaveException(this.message);
  final String message;
  @override
  String toString() => 'SecureEnclaveException: $message';
}

/// Dart bridge to the native `SecureEnclaveSigner` (iOS) over a MethodChannel.
///
/// The private key never crosses this channel — only the public key, signatures
/// (DER, base64url), and protection metadata. Signing is performed inside the
/// Secure Enclave behind a user-presence prompt.
class SecureEnclaveChannel {
  const SecureEnclaveChannel([
    this._channel = const MethodChannel('act/secure_enclave'),
  ]);

  final MethodChannel _channel;

  /// True only where a real Secure Enclave is present (physical iOS device).
  ///
  /// Deliberately false on the Simulator: the native side gates this on a
  /// compile-time `targetEnvironment(simulator)` check, because Apple's
  /// `SecureEnclave.isAvailable` reports true there even though no enclave
  /// exists. Use this for *hardware* claims, never to decide whether the native
  /// signer can be used — that is [isSupported].
  Future<bool> isAvailable() async {
    try {
      return (await _channel.invokeMethod<bool>('isAvailable')) ?? false;
    } on MissingPluginException {
      return false;
    } on PlatformException {
      return false;
    }
  }

  /// True where the native P-256 signer module exists at all (iOS device *and*
  /// Simulator), regardless of hardware backing. This is the routing predicate
  /// for pairing: on a device it yields an enclave-backed key, on the Simulator
  /// an honestly-labelled `software_p256_dev` key, and on platforms without the
  /// native module (web/Android) it is false so the caller falls back to the
  /// software Ed25519 path.
  Future<bool> isSupported() async {
    try {
      return (await _channel.invokeMethod<bool>('isSupported')) ?? false;
    } on MissingPluginException {
      return false;
    } on PlatformException {
      return false;
    }
  }

  Future<SecureEnclaveStatus?> status() async {
    try {
      final map = await _channel.invokeMapMethod<String, dynamic>('status');
      if (map == null) return null;
      return SecureEnclaveStatus.fromMap(map);
    } on MissingPluginException {
      return null;
    }
  }

  /// Generate a non-exportable signing key (Secure Enclave when available).
  Future<SecureEnclaveKey> generateKey({bool requireBiometry = true}) async {
    final map = await _channel.invokeMapMethod<String, dynamic>(
      'generateKey',
      {'requireBiometry': requireBiometry},
    );
    if (map == null) {
      throw const SecureEnclaveException('generateKey returned null');
    }
    return SecureEnclaveKey(
      publicKeyBase64: map['publicKey'] as String,
      backend: (map['backend'] as String?) ?? 'unknown',
      hardwareBacked: (map['hardwareBacked'] as bool?) ?? false,
    );
  }

  /// Sign [data] inside the enclave. [allowReuseSeconds] lets a short burst of
  /// routine signed requests reuse one user-presence authentication; pass 0 to
  /// force a fresh prompt (used for clearance decisions).
  Future<String> sign({
    required Uint8List data,
    required String reason,
    double allowReuseSeconds = 0,
  }) async {
    final signature = await _channel.invokeMethod<String>('sign', {
      'data': base64Encode(data),
      'reason': reason,
      'allowReuseSeconds': allowReuseSeconds,
    });
    if (signature == null) {
      throw const SecureEnclaveException('sign returned null');
    }
    return signature;
  }

  Future<void> clearKey() async {
    try {
      await _channel.invokeMethod<void>('clearKey');
    } on MissingPluginException {
      // No native key store on this platform; nothing to clear.
    }
  }
}

import 'package:flutter/foundation.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'device_request_signer.dart';

abstract class SecureKeyStore {
  Future<String?> readDeviceId();
  Future<String?> readAccessToken();
  Future<String?> readRefreshToken();

  /// When the stored access token expires, as UTC, or null if unknown — an
  /// install that paired before the expiry was persisted, or a gateway that
  /// omitted it. The runtime then refreshes reactively instead of ahead.
  Future<DateTime?> readAccessTokenExpiry();

  Future<String?> readDevicePrivateKey();
  Future<String?> readDevicePublicKey();
  Future<String> storageWarning();
  Future<ClearanceKeyProtection> clearanceKeyProtection();
  Future<void> saveDeviceKeyPair({
    required String privateKey,
    required String publicKey,
  });

  /// Persist a Secure-Enclave (or software-P256) enrolment. No private key is
  /// stored — the private key never leaves the enclave. [publicKey], [algorithm]
  /// and [towerPublicKey] are all non-secret.
  Future<void> saveDeviceEnrollment({
    required String publicKey,
    required String algorithm,
    required String towerPublicKey,
  });

  Future<String?> readDeviceKeyAlgorithm();
  Future<String?> readTowerPublicKey();

  Future<void> saveDeviceSession({
    required String deviceId,
    required String accessToken,
    required String refreshToken,
    required DateTime? accessTokenExpiresAt,
  });
  Future<void> clear();
}

class PlatformAwareSecureKeyStore implements SecureKeyStore {
  PlatformAwareSecureKeyStore(this.preferences)
      : _fallback = SharedPreferencesSecureKeyStore(preferences);

  final SharedPreferences preferences;
  final SharedPreferencesSecureKeyStore _fallback;
  final FlutterSecureStorage _secureStorage = const FlutterSecureStorage();

  bool get _useFallback => kIsWeb;

  @override
  Future<String?> readAccessToken() => _read(_accessTokenKey);

  @override
  Future<String?> readDeviceId() => _fallback.readDeviceId();

  @override
  Future<String?> readDevicePrivateKey() => _read(_devicePrivateKeyKey);

  @override
  Future<String?> readDevicePublicKey() => _read(_devicePublicKeyKey);

  @override
  Future<String?> readRefreshToken() => _read(_refreshTokenKey);

  @override
  Future<DateTime?> readAccessTokenExpiry() async =>
      _parseExpiry(await _read(_accessTokenExpiresAtKey));

  @override
  Future<String> storageWarning() async {
    if (_useFallback) {
      return 'Web/dev fallback storage active; private key is not in native secure storage.';
    }
    return 'Native secure storage enabled for device secrets.';
  }

  @override
  Future<ClearanceKeyProtection> clearanceKeyProtection() async {
    if (_useFallback) {
      return ClearanceKeyProtection.developmentExportableEd25519;
    }
    return const ClearanceKeyProtection(
      backend: 'flutter_secure_storage_exportable_ed25519',
      hardwareBacked: null,
      userPresenceRequired: false,
      privateKeyExportable: true,
      productionReady: false,
      warning:
          'Native secure storage protects bytes at rest, but signing is not yet non-exportable or user-presence gated.',
    );
  }

  @override
  Future<void> saveDeviceKeyPair({
    required String privateKey,
    required String publicKey,
  }) async {
    await _write(_devicePrivateKeyKey, privateKey);
    await _write(_devicePublicKeyKey, publicKey);
  }

  @override
  Future<void> saveDeviceEnrollment({
    required String publicKey,
    required String algorithm,
    required String towerPublicKey,
  }) async {
    // No private key is persisted for an enclave enrolment; clear any stale one.
    await _fallback.preferences.remove(_devicePrivateKeyKey);
    if (!_useFallback) {
      try {
        await _secureStorage.delete(key: _devicePrivateKeyKey);
      } on Object {
        // best-effort
      }
    }
    await _write(_devicePublicKeyKey, publicKey);
    await _write(_deviceKeyAlgorithmKey, algorithm);
    await _write(_towerPublicKeyKey, towerPublicKey);
  }

  @override
  Future<String?> readDeviceKeyAlgorithm() => _read(_deviceKeyAlgorithmKey);

  @override
  Future<String?> readTowerPublicKey() => _read(_towerPublicKeyKey);

  @override
  Future<void> saveDeviceSession({
    required String deviceId,
    required String accessToken,
    required String refreshToken,
    required DateTime? accessTokenExpiresAt,
  }) async {
    await _fallback.saveDeviceSession(
      deviceId: deviceId,
      accessToken: accessToken,
      refreshToken: refreshToken,
      accessTokenExpiresAt: accessTokenExpiresAt,
    );
    await _write(_accessTokenKey, accessToken);
    await _write(_refreshTokenKey, refreshToken);
    // A stale expiry is worse than none: it would schedule a refresh for a
    // token that is already gone, or skip one that is about to expire.
    if (accessTokenExpiresAt == null) {
      await _delete(_accessTokenExpiresAtKey);
    } else {
      await _write(
        _accessTokenExpiresAtKey,
        accessTokenExpiresAt.toUtc().toIso8601String(),
      );
    }
  }

  @override
  Future<void> clear() async {
    await _fallback.clear();
    await _fallback.preferences.remove(_deviceKeyAlgorithmKey);
    await _fallback.preferences.remove(_towerPublicKeyKey);
    if (_useFallback) {
      return;
    }
    await _secureStorage.delete(key: _accessTokenKey);
    await _secureStorage.delete(key: _accessTokenExpiresAtKey);
    await _secureStorage.delete(key: _refreshTokenKey);
    await _secureStorage.delete(key: _devicePrivateKeyKey);
    await _secureStorage.delete(key: _devicePublicKeyKey);
    await _secureStorage.delete(key: _deviceKeyAlgorithmKey);
    await _secureStorage.delete(key: _towerPublicKeyKey);
  }

  Future<String?> _read(String key) async {
    if (_useFallback) {
      return _fallback.preferences.getString(key);
    }
    try {
      return await _secureStorage.read(key: key);
    } on Object {
      return _fallback.preferences.getString(key);
    }
  }

  Future<void> _write(String key, String value) async {
    await _fallback.preferences.setString(key, value);
    if (_useFallback) {
      return;
    }
    try {
      await _secureStorage.write(key: key, value: value);
    } on Object {
      // SharedPreferences remains the explicit development fallback.
    }
  }

  Future<void> _delete(String key) async {
    await _fallback.preferences.remove(key);
    if (_useFallback) {
      return;
    }
    try {
      await _secureStorage.delete(key: key);
    } on Object {
      // best-effort
    }
  }
}

class SharedPreferencesSecureKeyStore implements SecureKeyStore {
  const SharedPreferencesSecureKeyStore(this.preferences);

  final SharedPreferences preferences;

  @override
  Future<String?> readAccessToken() async =>
      preferences.getString(_accessTokenKey);

  @override
  Future<String?> readDeviceId() async => preferences.getString(_deviceIdKey);

  @override
  Future<String?> readDevicePrivateKey() async =>
      preferences.getString(_devicePrivateKeyKey);

  @override
  Future<String?> readDevicePublicKey() async =>
      preferences.getString(_devicePublicKeyKey);

  @override
  Future<String> storageWarning() async =>
      'Development fallback storage active; private key is not in native secure storage.';

  @override
  Future<ClearanceKeyProtection> clearanceKeyProtection() async =>
      ClearanceKeyProtection.developmentExportableEd25519;

  @override
  Future<String?> readRefreshToken() async =>
      preferences.getString(_refreshTokenKey);

  @override
  Future<DateTime?> readAccessTokenExpiry() async =>
      _parseExpiry(preferences.getString(_accessTokenExpiresAtKey));

  @override
  Future<void> saveDeviceKeyPair({
    required String privateKey,
    required String publicKey,
  }) async {
    await preferences.setString(_devicePrivateKeyKey, privateKey);
    await preferences.setString(_devicePublicKeyKey, publicKey);
  }

  @override
  Future<void> saveDeviceEnrollment({
    required String publicKey,
    required String algorithm,
    required String towerPublicKey,
  }) async {
    await preferences.remove(_devicePrivateKeyKey);
    await preferences.setString(_devicePublicKeyKey, publicKey);
    await preferences.setString(_deviceKeyAlgorithmKey, algorithm);
    await preferences.setString(_towerPublicKeyKey, towerPublicKey);
  }

  @override
  Future<String?> readDeviceKeyAlgorithm() async =>
      preferences.getString(_deviceKeyAlgorithmKey);

  @override
  Future<String?> readTowerPublicKey() async =>
      preferences.getString(_towerPublicKeyKey);

  @override
  Future<void> saveDeviceSession({
    required String deviceId,
    required String accessToken,
    required String refreshToken,
    required DateTime? accessTokenExpiresAt,
  }) async {
    await preferences.setString(_deviceIdKey, deviceId);
    await preferences.setString(_accessTokenKey, accessToken);
    await preferences.setString(_refreshTokenKey, refreshToken);
    if (accessTokenExpiresAt == null) {
      await preferences.remove(_accessTokenExpiresAtKey);
    } else {
      await preferences.setString(
        _accessTokenExpiresAtKey,
        accessTokenExpiresAt.toUtc().toIso8601String(),
      );
    }
  }

  @override
  Future<void> clear() async {
    await preferences.remove(_deviceIdKey);
    await preferences.remove(_accessTokenKey);
    await preferences.remove(_accessTokenExpiresAtKey);
    await preferences.remove(_refreshTokenKey);
    await preferences.remove(_devicePrivateKeyKey);
    await preferences.remove(_devicePublicKeyKey);
    await preferences.remove(_deviceKeyAlgorithmKey);
    await preferences.remove(_towerPublicKeyKey);
  }
}

class InMemorySecureKeyStore implements SecureKeyStore {
  String? _deviceId;
  String? _accessToken;
  DateTime? _accessTokenExpiresAt;
  String? _refreshToken;
  String? _devicePrivateKey;
  String? _devicePublicKey;
  String? _keyAlgorithm;
  String? _towerPublicKey;

  @override
  Future<String?> readAccessToken() async => _accessToken;

  @override
  Future<String?> readDeviceId() async => _deviceId;

  @override
  Future<String?> readDevicePrivateKey() async => _devicePrivateKey;

  @override
  Future<String?> readDevicePublicKey() async => _devicePublicKey;

  @override
  Future<String> storageWarning() async => 'In-memory test storage active.';

  @override
  Future<ClearanceKeyProtection> clearanceKeyProtection() async =>
      ClearanceKeyProtection.developmentExportableEd25519;

  @override
  Future<String?> readRefreshToken() async => _refreshToken;

  @override
  Future<DateTime?> readAccessTokenExpiry() async => _accessTokenExpiresAt;

  @override
  Future<void> saveDeviceKeyPair({
    required String privateKey,
    required String publicKey,
  }) async {
    _devicePrivateKey = privateKey;
    _devicePublicKey = publicKey;
  }

  @override
  Future<void> saveDeviceEnrollment({
    required String publicKey,
    required String algorithm,
    required String towerPublicKey,
  }) async {
    _devicePrivateKey = null;
    _devicePublicKey = publicKey;
    _keyAlgorithm = algorithm;
    _towerPublicKey = towerPublicKey;
  }

  @override
  Future<String?> readDeviceKeyAlgorithm() async => _keyAlgorithm;

  @override
  Future<String?> readTowerPublicKey() async => _towerPublicKey;

  @override
  Future<void> saveDeviceSession({
    required String deviceId,
    required String accessToken,
    required String refreshToken,
    required DateTime? accessTokenExpiresAt,
  }) async {
    _deviceId = deviceId;
    _accessToken = accessToken;
    _accessTokenExpiresAt = accessTokenExpiresAt?.toUtc();
    _refreshToken = refreshToken;
  }

  @override
  Future<void> clear() async {
    _deviceId = null;
    _accessToken = null;
    _accessTokenExpiresAt = null;
    _refreshToken = null;
    _devicePrivateKey = null;
    _devicePublicKey = null;
    _keyAlgorithm = null;
    _towerPublicKey = null;
  }
}

/// A malformed or absent stored expiry reads as "unknown", which downgrades to
/// reactive refresh rather than failing the whole session read.
DateTime? _parseExpiry(String? value) =>
    value == null ? null : DateTime.tryParse(value)?.toUtc();

const _deviceIdKey = 'hmcp.device.id';
const _accessTokenKey = 'hmcp.device.access_token';
const _accessTokenExpiresAtKey = 'hmcp.device.access_token_expires_at';
const _refreshTokenKey = 'hmcp.device.refresh_token';
const _devicePrivateKeyKey = 'hmcp.device.private_key';
const _devicePublicKeyKey = 'hmcp.device.public_key';
const _deviceKeyAlgorithmKey = 'hmcp.device.key_algorithm';
const _towerPublicKeyKey = 'hmcp.tower.public_key';

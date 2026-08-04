import 'package:flutter_test/flutter_test.dart';
import 'package:agentic_control_tower/src/security/secure_key_store.dart';

void main() {
  test('in-memory secure store persists and clears pairing material', () async {
    final store = InMemorySecureKeyStore();

    await store.saveDeviceKeyPair(
      privateKey: 'private',
      publicKey: 'public',
    );
    final expiry = DateTime.utc(2026, 8, 3, 14, 32, 40);
    await store.saveDeviceSession(
      deviceId: 'dev_1',
      accessToken: 'access',
      refreshToken: 'refresh',
      accessTokenExpiresAt: expiry,
    );

    expect(await store.readDeviceId(), 'dev_1');
    expect(await store.readDevicePrivateKey(), 'private');
    expect(await store.readAccessTokenExpiry(), expiry);
    expect(await store.storageWarning(), contains('In-memory'));
    final protection = await store.clearanceKeyProtection();
    expect(protection.backend, 'development_exportable_ed25519');
    expect(protection.hardwareBacked, isFalse);
    expect(protection.userPresenceRequired, isFalse);
    expect(protection.productionReady, isFalse);

    await store.clear();

    expect(await store.readDeviceId(), isNull);
    expect(await store.readDevicePrivateKey(), isNull);
    expect(await store.readAccessTokenExpiry(), isNull);
  });

  test('a session saved without an expiry reads back as unknown', () async {
    // A gateway that omits expires_at must not leave a stale expiry behind
    // from the previous token: that would schedule a refresh for a token that
    // is already gone, or skip one that is about to expire.
    final store = InMemorySecureKeyStore();
    await store.saveDeviceSession(
      deviceId: 'dev_1',
      accessToken: 'access',
      refreshToken: 'refresh',
      accessTokenExpiresAt: DateTime.utc(2026, 8, 3, 14, 32, 40),
    );

    await store.saveDeviceSession(
      deviceId: 'dev_1',
      accessToken: 'access-2',
      refreshToken: 'refresh-2',
      accessTokenExpiresAt: null,
    );

    expect(await store.readAccessTokenExpiry(), isNull);
  });
}

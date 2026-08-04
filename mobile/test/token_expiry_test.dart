import 'package:flutter_test/flutter_test.dart';
import 'package:agentic_control_tower/src/models/core_models.dart';

void main() {
  test('parses the expires_at the gateway actually emits', () {
    // Captured from the running gateway: UTC with six fractional digits and a
    // trailing Z. The whole pre-expiry refresh hangs off reading this, and a
    // value that fails to parse degrades silently to reactive-only refresh.
    final expiry = parseTokenExpiry('2026-08-04T01:09:49.044111Z');

    expect(expiry, isNotNull);
    expect(expiry!.isUtc, isTrue);
    expect(expiry, DateTime.utc(2026, 8, 4, 1, 9, 49, 44, 111));
  });

  test('an offset-form expires_at is normalised to UTC', () {
    final expiry = parseTokenExpiry('2026-08-04T03:09:49+02:00');

    expect(expiry!.isUtc, isTrue);
    expect(expiry, DateTime.utc(2026, 8, 4, 1, 9, 49));
  });

  test('a missing or unparseable expires_at reads as unknown', () {
    expect(parseTokenExpiry(null), isNull);
    expect(parseTokenExpiry(12345), isNull);
    expect(parseTokenExpiry('not-a-timestamp'), isNull);
  });

  test('pairing carries the access token expiry through to the runtime', () {
    final completion = PairingCompletionModel.fromJson({
      'node': {
        'node_id': 'node_test',
        'display_name': 'Test Hermes',
        'environment': 'local',
        'health': 'healthy',
      },
      'device': {'device_id': 'dev_1'},
      'tokens': {
        'access_token': 'access',
        'refresh_token': 'refresh',
        'expires_at': '2026-08-04T01:09:49.044111Z',
      },
    });

    expect(completion.accessTokenExpiresAt,
        DateTime.utc(2026, 8, 4, 1, 9, 49, 44, 111));
  });
}

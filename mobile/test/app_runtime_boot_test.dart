import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:agentic_control_tower/src/app_runtime.dart';
import 'package:agentic_control_tower/src/config/gateway_config.dart';
import 'package:agentic_control_tower/src/security/device_request_signer.dart';
import 'package:agentic_control_tower/src/security/push_token_channel.dart';
import 'package:agentic_control_tower/src/security/secure_key_store.dart';
import 'package:flutter_test/flutter_test.dart';

/// An APNs bridge that never answers — exactly what a dev-signed build does
/// when its provisioning profile has no usable aps-environment, and what the
/// Simulator does always.
class _SilentPushTokenChannel extends PushTokenChannel {
  const _SilentPushTokenChannel();

  @override
  void onToken(void Function(String token) handler) {
    // Native never delivers a token.
  }

  @override
  Future<String?> requestToken() => Completer<String?>().future;
}

Future<InMemorySecureKeyStore> _pairedKeyStore({
  DateTime? accessTokenExpiresAt,
}) async {
  final store = InMemorySecureKeyStore();
  final keyPair = await DeviceKeyPair.generate();
  await store.saveDeviceKeyPair(
    privateKey: keyPair.privateKeyBase64,
    publicKey: keyPair.publicKeyBase64,
  );
  await store.saveDeviceSession(
    deviceId: 'dev_boot_test',
    accessToken: 'access-token',
    refreshToken: 'refresh-token',
    accessTokenExpiresAt:
        accessTokenExpiresAt ?? DateTime.now().toUtc().add(_farFuture),
  );
  return store;
}

const _farFuture = Duration(days: 365);

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  // The black-screen regression: HermesAppRuntime.create() used to await
  // _registerPushToken() before runApp(), so an APNs token that never arrived
  // meant runApp() was never called and iOS held the launch storyboard
  // forever. Startup must not depend on APNs at all.
  test('runtime startup completes when the APNs token never arrives', () async {
    final runtime = HermesAppRuntime(
      configStore: InMemoryGatewayConfigStore(),
      keyStore: await _pairedKeyStore(),
      pushToken: const _SilentPushTokenChannel(),
    );

    await expectLater(
      runtime.initialize().timeout(const Duration(seconds: 5)),
      completes,
      reason: 'the first frame must never wait on the APNs device token',
    );

    expect(runtime.isPaired, isTrue,
        reason: 'startup must not discard an existing pairing');
    runtime.dispose();
  });

  test('bounded startup renders even if local setup stalls', () async {
    final runtime = HermesAppRuntime(
      configStore: _StalledConfigStore(),
      keyStore: await _pairedKeyStore(),
      pushToken: const _SilentPushTokenChannel(),
      bootTimeout: const Duration(milliseconds: 100),
    );

    // initializeBounded() fails open: it always completes, so main() always
    // reaches runApp().
    await expectLater(
      runtime.initializeBounded().timeout(const Duration(seconds: 5)),
      completes,
    );
    expect(runtime.connectionStatus, contains('Startup slow'));
    runtime.dispose();
  });

  test('background bootstrap survives a push token that never resolves',
      () async {
    final runtime = HermesAppRuntime(
      configStore: InMemoryGatewayConfigStore(),
      keyStore: await _pairedKeyStore(),
      pushToken: const _SilentPushTokenChannel(),
      pushTokenTimeout: const Duration(milliseconds: 50),
      socketConnector: (_) => const Stream<dynamic>.empty(),
    );
    await runtime.initialize();

    await expectLater(
      runtime.startBackgroundBootstrap().timeout(const Duration(seconds: 5)),
      completes,
    );
    expect(runtime.pushStatus, contains('timed out'));
    expect(runtime.isPaired, isTrue);
    runtime.dispose();
  });

  // The pre-expiry refresh must not walk back the black-screen fix. A token
  // that expired while the app was closed is the ordinary case after a night
  // on the charger, and it schedules a zero-delay refresh — but initialize()
  // runs before runApp(), so nothing may be armed until the UI is up.
  test('an expired access token is refreshed by the bootstrap, not by startup',
      () async {
    // TestWidgetsFlutterBinding stubs HttpClient so every request 400s without
    // touching a socket. This test is about what does and does not reach the
    // gateway, so it needs the real one back.
    final stubbedOverrides = HttpOverrides.current;
    HttpOverrides.global = null;
    addTearDown(() => HttpOverrides.global = stubbedOverrides);

    final gateway = await _FakeGateway.start();

    final runtime = HermesAppRuntime(
      configStore: InMemoryGatewayConfigStore(initial: gateway.config),
      keyStore: await _pairedKeyStore(
        accessTokenExpiresAt:
            DateTime.now().toUtc().subtract(const Duration(hours: 12)),
      ),
      pushToken: const _SilentPushTokenChannel(),
      pushTokenTimeout: const Duration(milliseconds: 50),
      socketConnector: (_) => const Stream<dynamic>.empty(),
    );

    await expectLater(
      runtime.initialize().timeout(const Duration(seconds: 5)),
      completes,
    );
    // A turn of the event loop is long enough for a zero-delay timer to have
    // fired, had startup armed one.
    await Future<void>.delayed(Duration.zero);
    expect(gateway.requests, isEmpty,
        reason: 'the first frame must never wait on the network');
    expect(runtime.accessToken, 'access-token');

    await runtime.startBackgroundBootstrap();
    await Future<void>.delayed(const Duration(milliseconds: 100));

    expect(runtime.accessToken, 'fresh-access-token-1');
    // The proactive timer and the stream's pre-connect check both wanted a
    // fresh token; every refresh rotates the refresh token, so they must have
    // shared one request rather than racing to invalidate each other's.
    expect(gateway.refreshCount, 1);
    runtime.dispose();
  });

  test('the token is refreshed ahead of expiry without dropping the stream',
      () async {
    final stubbedOverrides = HttpOverrides.current;
    HttpOverrides.global = null;
    addTearDown(() => HttpOverrides.global = stubbedOverrides);

    final gateway = await _FakeGateway.start();
    var connects = 0;

    final runtime = HermesAppRuntime(
      configStore: InMemoryGatewayConfigStore(initial: gateway.config),
      keyStore: await _pairedKeyStore(
        // Due 1s from now, with enough headroom that test-setup jitter cannot
        // make it due before the socket opens — that would exercise the
        // pre-connect check instead of the timer this test is about.
        accessTokenExpiresAt:
            DateTime.now().toUtc().add(const Duration(seconds: 5)),
      ),
      pushToken: const _SilentPushTokenChannel(),
      pushTokenTimeout: const Duration(milliseconds: 10),
      accessTokenRefreshSkew: const Duration(seconds: 4),
      socketConnector: (_) {
        connects += 1;
        // A live connection: it neither ends nor errors, so the only thing that
        // can refresh the token here is the scheduled pre-expiry refresh.
        return StreamController<dynamic>().stream;
      },
    );

    await runtime.initialize();
    await runtime.startBackgroundBootstrap();
    await Future<void>.delayed(const Duration(milliseconds: 50));
    // The token was not yet due at connect time, so the socket opened on the
    // original token and the scheduled refresh is still pending.
    expect(connects, 1);
    expect(runtime.accessToken, 'access-token');
    expect(gateway.refreshCount, 0);

    await Future<void>.delayed(const Duration(milliseconds: 1500));

    expect(runtime.accessToken, 'fresh-access-token-1');
    expect(gateway.refreshCount, 1);
    expect(connects, 1,
        reason: 'a pre-expiry refresh must not cost the operator a reconnect');
    runtime.dispose();
  });

  test('a scheduled refresh that fails retries while the token is still live',
      () async {
    final stubbedOverrides = HttpOverrides.current;
    HttpOverrides.global = null;
    addTearDown(() => HttpOverrides.global = stubbedOverrides);

    // Offline or gateway down for the first attempt, back for the retry.
    final gateway = await _FakeGateway.start(failFirst: 1);

    final runtime = HermesAppRuntime(
      configStore: InMemoryGatewayConfigStore(initial: gateway.config),
      keyStore: await _pairedKeyStore(
        accessTokenExpiresAt:
            DateTime.now().toUtc().add(const Duration(seconds: 30)),
      ),
      pushToken: const _SilentPushTokenChannel(),
      pushTokenTimeout: const Duration(milliseconds: 10),
      // Due immediately, so the first attempt lands as soon as the UI is up.
      accessTokenRefreshSkew: const Duration(seconds: 60),
      accessTokenRefreshRetry: const Duration(milliseconds: 100),
      socketConnector: (_) => StreamController<dynamic>().stream,
    );

    await runtime.initialize();
    await runtime.startBackgroundBootstrap();
    await Future<void>.delayed(const Duration(milliseconds: 400));

    expect(gateway.refreshCount, greaterThanOrEqualTo(2));
    expect(runtime.accessToken, startsWith('fresh-access-token'));
    runtime.dispose();
  });
}

/// A gateway that answers `/auth/token/refresh` and records what it was asked.
class _FakeGateway {
  _FakeGateway(this._server);

  static Future<_FakeGateway> start({int failFirst = 0}) async {
    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    final gateway = _FakeGateway(server);
    addTearDown(() => server.close(force: true));
    unawaited(server.forEach((request) async {
      gateway.requests.add('${request.method} ${request.uri.path}');
      if (gateway.refreshCount <= failFirst) {
        request.response.statusCode = HttpStatus.internalServerError;
        await request.response.close();
        return;
      }
      request.response.headers.contentType = ContentType.json;
      request.response.write(jsonEncode({
        'access_token': 'fresh-access-token-${gateway.refreshCount}',
        'refresh_token': 'fresh-refresh-token-${gateway.refreshCount}',
        'expires_at': DateTime.now()
            .toUtc()
            .add(const Duration(minutes: 15))
            .toIso8601String(),
      }));
      await request.response.close();
    }));
    return gateway;
  }

  final HttpServer _server;
  final List<String> requests = <String>[];

  GatewayConfig get config =>
      GatewayConfig.fromInput('http://127.0.0.1:${_server.port}/v1');

  int get refreshCount =>
      requests.where((r) => r == 'POST /v1/auth/token/refresh').length;
}

class _StalledConfigStore implements GatewayConfigStore {
  @override
  Future<GatewayConfig> read() => Completer<GatewayConfig>().future;

  @override
  Future<void> save(GatewayConfig config) async {}
}

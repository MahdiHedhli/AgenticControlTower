import 'dart:async';

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

Future<InMemorySecureKeyStore> _pairedKeyStore() async {
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
  );
  return store;
}

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
}

class _StalledConfigStore implements GatewayConfigStore {
  @override
  Future<GatewayConfig> read() => Completer<GatewayConfig>().future;

  @override
  Future<void> save(GatewayConfig config) async {}
}

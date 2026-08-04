/// The re-authentication path is driven from the stream client's own error
/// handler, on a task started with `unawaited`, so nothing downstream can catch
/// it and nothing downstream can see it stall. Two failure shapes lived there:
///
///  1. No `catch` around it — any throw (a rejected `cancel()`, a
///     `notifyListeners()` on a runtime disposed while the refresh was in
///     flight) went straight past the discarded future into the root zone as an
///     unhandled async error.
///  2. When the refresh failed, the method simply stopped, leaving the status
///     pinned at "Live stream re-authenticating" — a permanent misleading state
///     with no way for the operator to learn the pairing needs redoing.
///
/// The function those fixes lived in (`_refreshTokenAndRestartStream`) no longer
/// exists: retry and auth ownership moved into `GatewayEventStreamClient`, which
/// calls back into `_refreshAccessTokenForStream`. Both escapes are the same
/// shape in the new arrangement — worse, in fact, because the callback runs
/// inside the client's own `catch` clause, where a throw also skips
/// `controller.close()` — so both guards are tested here against the new entry
/// point.
library;

import 'dart:async';

import 'package:agentic_control_tower/src/api/gateway_event_stream_client.dart';
import 'package:agentic_control_tower/src/app_runtime.dart';
import 'package:agentic_control_tower/src/config/gateway_config.dart';
import 'package:agentic_control_tower/src/security/secure_key_store.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  // ISOLATES the failure branch. The runtime is alive, so nothing throws and
  // the catch clause is never entered; the refresh cannot succeed (no stored
  // refresh token), so the ONLY thing that can move the status off
  // "re-authenticating" is the explicit failure branch.
  test('a failed refresh reports a signed-out stream, not a stuck one',
      () async {
    final runtime = _runtime();

    await runtime.debugRefreshAccessTokenForStream();

    expect(
      runtime.eventStreamStatus,
      isNot(contains('re-authenticating')),
      reason: 'the operator was left staring at a status that never resolves',
    );
    expect(runtime.eventStreamStatus, contains('Pair this device again'));
    expect(runtime.eventStreamConnected, isFalse);
    runtime.dispose();
  });

  // The terminal state must also be terminal. The client keeps reconnecting
  // after a rejected refresh, and every further attempt is an auth failure, so
  // an unlatched `_onStreamConnectError` would flip the dashboard back to
  // "re-authenticating" on each backoff window — the same never-resolving
  // status, just blinking.
  test('a later auth failure does not overwrite the signed-out state',
      () async {
    final runtime = _runtime();

    await runtime.debugRefreshAccessTokenForStream();
    runtime.debugReportStreamConnectError(
      GatewayStreamConnectError.from(
        const GatewayStreamUpgradeException('refused', statusCode: 403),
      ),
    );

    expect(runtime.eventStreamStatus, contains('Pair this device again'));
    expect(runtime.eventStreamStatus, isNot(contains('re-authenticating')));
    runtime.dispose();
  });

  // ISOLATES the catch clause. Disposing first makes `notifyListeners()` throw,
  // which is the commonest real path in: the operator leaves the screen while a
  // refresh is in flight. Without the guards this future rejects and — being
  // driven from an `unawaited` task in production — escapes.
  test('a refresh that outlives the runtime does not escape', () async {
    final runtime = _runtime();
    runtime.dispose();

    await expectLater(
      runtime.debugRefreshAccessTokenForStream(),
      completes,
      reason: 'an unawaited refresh that throws is an unhandled async error',
    );
  });

  // Same escape, same disposed runtime, the other callback: the client invokes
  // `onConnectError` from inside its catch clause too.
  test('reporting a connect error on a disposed runtime does not escape',
      () async {
    final runtime = _runtime();
    runtime.dispose();

    expect(
      () => runtime.debugReportStreamConnectError(
        GatewayStreamConnectError.from(Exception('gateway down')),
      ),
      returnsNormally,
    );
  });

  // The in-flight coalescing latch must be released whichever way an attempt
  // ends; if it were not, every later refresh would return the dead future and
  // the stream could never recover.
  test('the in-flight latch is released so later attempts still run', () async {
    final runtime = _runtime();
    runtime.dispose();

    await runtime.debugRefreshAccessTokenForStream();
    await expectLater(
      runtime.debugRefreshAccessTokenForStream(),
      completes,
    );
    expect(runtime.eventStreamStatus, contains('Pair this device again'));
  });

  // The structural half of guard (1), at the boundary that actually needs it: a
  // re-authenticator that throws must not escape the client's reconnect task or
  // strand the stream controller.
  test('a reauthenticator that throws neither escapes nor strands the stream',
      () async {
    var attempts = 0;
    final client = GatewayEventStreamClient(
      config: GatewayConfig.fromInput('http://127.0.0.1:8787/v1'),
      accessToken: () => 'access-test',
      initialBackoff: Duration.zero,
      maxReconnects: 2,
      socketConnector: (_) {
        attempts += 1;
        return Stream<dynamic>.error(
          const GatewayStreamUpgradeException('refused', statusCode: 403),
        );
      },
      onAuthFailure: () async => throw StateError('disposed mid-refresh'),
    );

    // `toList()` only completes when the controller closes — which the throw
    // used to skip entirely.
    await expectLater(
      client.connect().toList().timeout(const Duration(seconds: 5)),
      completion(isEmpty),
    );
    expect(attempts, greaterThan(1),
        reason: 'the loop must keep reconnecting after a failed re-auth');
  });
}

HermesAppRuntime _runtime() {
  return HermesAppRuntime(
    configStore: InMemoryGatewayConfigStore(),
    keyStore: InMemorySecureKeyStore(),
  );
}

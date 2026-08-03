/// The re-authentication path is fired with `unawaited` from a stream error
/// callback, so nothing downstream can catch it and nothing downstream can see
/// it stall. Two failure shapes lived there:
///
///  1. `try { … } finally { … }` with **no catch** — any throw (a rejected
///     `cancel()`, a `notifyListeners()` on a runtime disposed while the
///     refresh was in flight) went straight past the discarded future into the
///     root zone as an unhandled async error.
///  2. When the refresh failed, the method simply stopped, leaving the status
///     pinned at "Live stream re-authenticating" — a permanent misleading state
///     with no way for the operator to learn the pairing needs redoing.
library;

import 'package:agentic_control_tower/src/app_runtime.dart';
import 'package:agentic_control_tower/src/config/gateway_config.dart';
import 'package:agentic_control_tower/src/security/secure_key_store.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  // ISOLATES the `else` branch. The runtime is alive, so nothing throws and the
  // catch clause is never entered; the refresh cannot succeed (no stored refresh
  // token), so the ONLY thing that can move the status off "re-authenticating"
  // is the explicit failure branch.
  test('a failed refresh reports a signed-out stream, not a stuck one',
      () async {
    final runtime = _runtime();

    await runtime.debugRefreshTokenAndRestartStream();

    expect(
      runtime.eventStreamStatus,
      isNot(contains('re-authenticating')),
      reason: 'the operator was left staring at a status that never resolves',
    );
    expect(runtime.eventStreamStatus, contains('Pair this device again'));
    expect(runtime.eventStreamConnected, isFalse);
    runtime.dispose();
  });

  // ISOLATES the catch clause. Disposing first makes the very first
  // `notifyListeners()` inside the try throw, which is the commonest real path
  // in: the operator leaves the screen while a refresh is in flight. Without
  // the catch this future rejects and — being `unawaited` in production —
  // escapes. The `else` branch is never reached here, so it cannot mask this.
  test('a refresh that outlives the runtime does not escape', () async {
    final runtime = _runtime();
    runtime.dispose();

    await expectLater(
      runtime.debugRefreshTokenAndRestartStream(),
      completes,
      reason: 'an unawaited refresh that throws is an unhandled async error',
    );
  });

  // The `finally` must still release the in-flight flag when the attempt ends
  // in the catch clause; if it did not, every later refresh would return early
  // and the stream could never recover. Disposing makes the first attempt throw,
  // so this only passes if `_refreshingToken` was reset on the exception path.
  test('the in-flight flag is released on the exception path', () async {
    final runtime = _runtime();
    runtime.dispose();

    await runtime.debugRefreshTokenAndRestartStream();
    // A second attempt must run rather than short-circuit on a stuck flag.
    await expectLater(
      runtime.debugRefreshTokenAndRestartStream(),
      completes,
    );
    expect(runtime.eventStreamStatus, contains('re-authentication failed'));
  });
}

HermesAppRuntime _runtime() {
  return HermesAppRuntime(
    configStore: InMemoryGatewayConfigStore(),
    keyStore: InMemorySecureKeyStore(),
  );
}

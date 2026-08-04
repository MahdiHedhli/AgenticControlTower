/// Teardown paths must always complete and must never throw.
///
/// `dispose()` is synchronous, so every future it starts is discarded.
/// `StreamSubscription.cancel()` returns a future that can complete with an
/// error, and an unclaimed rejection is an unhandled async error — a zone-level
/// crash on device blamed on whatever ran next. Both `HermesAppRuntime.dispose`
/// and `TuiViewModel.dispose` route through [cancelQuietly] for exactly this.
library;

import 'dart:async';

import 'package:agentic_control_tower/src/async_guard.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  // ISOLATES cancelQuietly. A plain `subscription.cancel()` in a dispose path
  // rejects here and escapes to the zone; only the guard turns that into a
  // completed future. `expectLater(..., completes)` alone is not enough — an
  // escape is reported to the zone, not to the awaiter — so the test also
  // settles the event loop afterwards, which is where an unclaimed rejection
  // would surface and fail this test.
  test('cancelQuietly claims a cancel that rejects', () async {
    final controller = StreamController<int>(
      onCancel: () => Future<void>.error(StateError('teardown blew up')),
    );
    final subscription = controller.stream.listen((_) {});

    await expectLater(cancelQuietly(subscription), completes);
    await _settle();
  });

  test('cancelQuietly claims a cancel that throws synchronously', () async {
    final controller = StreamController<int>(
      onCancel: () => throw StateError('teardown blew up'),
    );
    final subscription = controller.stream.listen((_) {});

    await expectLater(cancelQuietly(subscription), completes);
    await _settle();
  });

  test('cancelQuietly tolerates a null subscription', () async {
    await expectLater(cancelQuietly(null), completes);
  });

  // The guard must still actually cancel — a swallow that also stops doing the
  // work would be a worse bug than the one it replaced.
  test('cancelQuietly really cancels a healthy subscription', () async {
    var cancelled = false;
    final controller = StreamController<int>(onCancel: () => cancelled = true);
    final subscription = controller.stream.listen((_) {});

    await cancelQuietly(subscription);

    expect(cancelled, isTrue);
    await controller.close();
  });
}

Future<void> _settle() => Future<void>.delayed(const Duration(milliseconds: 50));

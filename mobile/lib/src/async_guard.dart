import 'dart:async';

/// Teardown guards for the async paths that nothing is left to catch.
///
/// Two shapes recur across this app and both end as an **unhandled async
/// error** — a zone-level crash on device, blamed on whatever ran next:
///
/// 1. `dispose()` is synchronous, so every future it starts is discarded.
///    `StreamSubscription.cancel()` returns a future that can complete with an
///    error (the stream's `onCancel` runs arbitrary teardown), and that
///    rejection has no owner.
/// 2. A teardown that fails is not operator-actionable. There is no screen to
///    show it on and no decision it can change — the object is being discarded
///    either way — so the honest handling is to claim it and drop it, not to
///    propagate it into a dispose path that cannot respond.
///
/// This is deliberately *not* a general "swallow errors" helper. It is only for
/// teardown. Anywhere a failure could still change what the operator sees, the
/// error must propagate instead — see `GatewayAlphaRepository`, where swallowing
/// turned an outage into an empty inbox.

/// Cancel [subscription] (if any), always completing and never throwing.
Future<void> cancelQuietly(StreamSubscription<Object?>? subscription) async {
  try {
    await subscription?.cancel();
  } on Object {
    // Deliberate: see the library comment. A failed cancel cannot be acted on.
  }
}

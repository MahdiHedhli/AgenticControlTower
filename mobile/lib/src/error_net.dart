import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';

import 'operator_error.dart';

/// The net under everything else.
///
/// Every screen-level handler in this app claims its own failures. This file
/// exists for the ones that get away anyway: an async error raised outside any
/// `await` we own — a stray `unawaited`, a stream that errors after its
/// subscriber is gone, a plugin callback — lands in the root zone. With no
/// `PlatformDispatcher.onError` installed it is *silently dropped* in a release
/// build. The bug then does not exist as far as anyone can tell.
///
/// The one rule here: **this net never swallows.** The handler records the
/// error, shows it where a surface exists, and returns `false` — "not handled"
/// — so the framework's own reporting still runs exactly as it would have.
/// `runZonedGuarded` is deliberately *not* used: its handler is terminal (the
/// error stops there), and wrapping `main` in a custom zone is also what breaks
/// `integration_test`, which owns its own zone. Returning `false` from
/// `PlatformDispatcher.onError` gives us the record without taking the report.
///
/// In `flutter test` and `integration_test` this handler is never reached at
/// all: the test binding runs the body in a guarded zone, so uncaught async
/// errors go to the test framework's zone handler and fail the test. Nothing
/// here can hide a test failure.

/// Attached to `MaterialApp.scaffoldMessengerKey` so an escaped error can still
/// reach the operator when the app is on screen.
final GlobalKey<ScaffoldMessengerState> operatorMessengerKey =
    GlobalKey<ScaffoldMessengerState>();

/// Escapes seen this run, oldest first, capped. Diagnostics — an escape that is
/// only printed to a console nobody is attached to is barely better than lost.
List<Object> get escapedErrors => List.unmodifiable(_escapedErrors);
final List<Object> _escapedErrors = <Object>[];
const _maxRecordedEscapes = 20;

bool _installed = false;

/// Install the last-resort handler. Idempotent.
void installLastResortErrorNet() {
  if (_installed) {
    return;
  }
  _installed = true;
  PlatformDispatcher.instance.onError = recordEscapedError;
}

/// Record one escaped async error and surface it if a surface exists.
///
/// Always returns `false`: the error is *not* consumed here. Exposed directly
/// so the behaviour can be tested without mutating global dispatcher state.
bool recordEscapedError(Object error, StackTrace stack) {
  if (_escapedErrors.length >= _maxRecordedEscapes) {
    _escapedErrors.removeAt(0);
  }
  _escapedErrors.add(error);
  final message = operatorErrorMessage(error, context: 'unhandled');
  debugPrintStack(stackTrace: stack, label: '[act] unhandled async error');
  try {
    operatorMessengerKey.currentState?.showSnackBar(
      SnackBar(content: Text(message)),
    );
  } on Object catch (surfaceError) {
    // A net that can itself throw is not a net.
    debugPrint('[act] could not surface unhandled error: $surfaceError');
  }
  return false;
}

@visibleForTesting
void resetLastResortErrorNet() {
  _escapedErrors.clear();
  _installed = false;
  PlatformDispatcher.instance.onError = null;
}

/// The last-resort net records escapes without ever swallowing one.
///
/// A net that consumed the error would be worse than no net: the crash report
/// would stop arriving and the bug would look fixed. Both properties are
/// asserted here — it records, *and* it reports "not handled".
library;

import 'dart:ui';

import 'package:agentic_control_tower/src/error_net.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  tearDown(resetLastResortErrorNet);

  test('an escaped error is recorded and explicitly not handled', () {
    final handled = recordEscapedError(
      StateError('gateway sink closed'),
      StackTrace.current,
    );

    expect(handled, isFalse,
        reason: 'returning true would suppress the framework report — the '
            'error would vanish exactly as it does today, but silently');
    expect(escapedErrors, hasLength(1));
    expect(escapedErrors.single, isA<StateError>());
  });

  test('the record is bounded so a crash loop cannot grow without limit', () {
    for (var i = 0; i < 50; i++) {
      recordEscapedError(StateError('escape $i'), StackTrace.current);
    }
    expect(escapedErrors.length, lessThanOrEqualTo(20));
    expect(escapedErrors.last.toString(), contains('escape 49'));
  });

  test('installing is idempotent and leaves the dispatcher hook in place', () {
    installLastResortErrorNet();
    final first = PlatformDispatcher.instance.onError;
    installLastResortErrorNet();

    expect(first, isNotNull);
    expect(PlatformDispatcher.instance.onError, same(first));
  });

  testWidgets('with no surface mounted the net still records, never throws',
      (tester) async {
    // currentState is null before any MaterialApp is pumped.
    expect(operatorMessengerKey.currentState, isNull);

    expect(
      () => recordEscapedError(StateError('no surface'), StackTrace.current),
      returnsNormally,
    );
    expect(escapedErrors, hasLength(1));
  });

  testWidgets('with the app on screen the escape reaches the operator',
      (tester) async {
    await tester.pumpWidget(
      MaterialApp(
        scaffoldMessengerKey: operatorMessengerKey,
        home: const Scaffold(body: Text('anything')),
      ),
    );

    recordEscapedError(
      const FormatException('truncated frame'),
      StackTrace.current,
    );
    await tester.pump();

    expect(
      find.textContaining('sent a response the app could not read'),
      findsOneWidget,
    );
    // Never the raw dump.
    expect(find.textContaining('FormatException'), findsNothing);
  });
}

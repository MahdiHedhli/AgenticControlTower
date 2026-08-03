import 'dart:async';

import 'package:flutter/material.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'app.dart';
import 'app_runtime.dart';
import 'config/gateway_config.dart';
import 'security/secure_key_store.dart';

/// Hard ceiling on everything that happens before the first frame.
///
/// The black-screen incident (failure mode A3) was `runApp()` sitting behind
/// `await HermesAppRuntime.create()`, whose `initialize()` ended in
/// `await _registerPushToken()` — a wait on the iOS APNs device-token callback
/// that never fires on a dev-signed build. iOS kept showing the LaunchScreen
/// storyboard forever while the gateway happily served signed requests from the
/// same process.
///
/// The rule this constant enforces: **no platform channel, push registration or
/// network call may gate the first frame.** Bootstrap still runs — it is simply
/// no longer allowed to hold the frame hostage. When it finishes late,
/// `notifyListeners()` brings the UI up as things arrive.
const kFirstFrameBudget = Duration(milliseconds: 2000);

/// Build the app runtime without ever letting bootstrap block the first frame.
///
/// Local reads (preferences, key store) normally complete in a few milliseconds
/// and the returned runtime is fully initialised. If anything in that path
/// stalls, the caller still gets a usable runtime inside [budget] and
/// initialisation completes in the background.
Future<HermesAppRuntime> bootstrapRuntime({
  Duration budget = kFirstFrameBudget,
}) async {
  final elapsed = Stopwatch()..start();
  final runtime = await _createRuntime(budget);

  // Never awaited unconditionally: this is the exact call chain that hung.
  final initialised = runtime.initialize();
  // Keep the future "handled" so a late failure is not an unhandled async error.
  unawaited(initialised.catchError((Object error, StackTrace stack) {
    debugPrint('[act] bootstrap initialize failed: $error');
  }));

  final remaining = budget - elapsed.elapsed;
  if (remaining > Duration.zero) {
    await initialised
        .timeout(remaining, onTimeout: () {})
        .catchError((Object _) {});
  }
  return runtime;
}

/// The real application entry point. `main()` is a one-liner over this so the
/// "no await before runApp" invariant lives in one testable place.
Future<void> bootstrapAndRun({Duration budget = kFirstFrameBudget}) async {
  WidgetsFlutterBinding.ensureInitialized();
  final runtime = await bootstrapRuntime(budget: budget);
  runApp(HermesMobileApp(runtime: runtime));
}

/// Preference-backed runtime, degrading to in-memory stores if even the local
/// plugin handshake stalls. A degraded runtime shows an unpaired app the
/// operator can fix from Settings; a black screen shows nothing at all.
Future<HermesAppRuntime> _createRuntime(Duration budget) async {
  try {
    return await _preferenceBackedRuntime().timeout(budget);
  } on Object catch (error) {
    debugPrint('[act] bootstrap falling back to in-memory stores: $error');
    return HermesAppRuntime(
      configStore: InMemoryGatewayConfigStore(),
      keyStore: InMemorySecureKeyStore(),
    );
  }
}

Future<HermesAppRuntime> _preferenceBackedRuntime() async {
  final preferences = await SharedPreferences.getInstance();
  return HermesAppRuntime(
    configStore: SharedPreferencesGatewayConfigStore(preferences),
    keyStore: PlatformAwareSecureKeyStore(preferences),
  );
}

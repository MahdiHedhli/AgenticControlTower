import 'dart:async';

import 'package:flutter/material.dart';

import 'src/app_runtime.dart';
import 'src/app.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  // Local, bounded setup only. Anything awaited here delays the first frame,
  // and until runApp() runs iOS keeps showing the (black) launch storyboard.
  final runtime = await HermesAppRuntime.create();
  runApp(HermesMobileApp(runtime: runtime));
  // Network and APNs bootstrap starts only once the UI is actually on screen.
  WidgetsBinding.instance.addPostFrameCallback((_) {
    unawaited(runtime.startBackgroundBootstrap());
  });
}

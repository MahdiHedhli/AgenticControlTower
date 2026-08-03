import 'package:flutter/material.dart';

import 'app_runtime.dart';
import 'error_net.dart';
import 'routes.dart';
import 'theme.dart';

class HermesMobileApp extends StatelessWidget {
  const HermesMobileApp({
    required this.runtime,
    super.key,
  });

  final HermesAppRuntime runtime;

  @override
  Widget build(BuildContext context) {
    return HermesRuntimeScope(
      runtime: runtime,
      child: MaterialApp(
        // Gives the last-resort error handler a surface: an escaped async
        // error can be shown to the operator instead of only logged.
        scaffoldMessengerKey: operatorMessengerKey,
        title: 'Agentic Control Tower',
        theme: hermesTheme(),
        initialRoute: HermesRoutes.dashboard,
        routes: HermesRoutes.routes(runtime),
        debugShowCheckedModeBanner: false,
      ),
    );
  }
}

import 'package:flutter/material.dart';

import '../routes.dart';

class ScreenShell extends StatelessWidget {
  const ScreenShell({
    required this.title,
    required this.selectedRoute,
    required this.body,
    super.key,
  });

  final String title;
  final String selectedRoute;
  final Widget body;

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text(title),
        actions: [
          if (selectedRoute != HermesRoutes.settings)
            IconButton(
              onPressed: () =>
                  Navigator.of(context).pushNamed(HermesRoutes.settings),
              icon: const Icon(Icons.settings_outlined),
              tooltip: 'Settings',
            ),
        ],
      ),
      body: body,
      bottomNavigationBar: NavigationBar(
        selectedIndex: _selectedIndex,
        onDestinationSelected: (index) {
          final route = _routes[index];
          if (route != selectedRoute) {
            Navigator.of(context).pushReplacementNamed(route);
          }
        },
        destinations: const [
          NavigationDestination(
              icon: Icon(Icons.space_dashboard_outlined), label: 'Home'),
          NavigationDestination(
              icon: Icon(Icons.hub_outlined), label: 'Agents'),
          NavigationDestination(
              icon: Icon(Icons.route_outlined), label: 'Missions'),
          NavigationDestination(
              icon: Icon(Icons.dashboard_customize_outlined),
              label: 'Dashboard'),
          NavigationDestination(
              icon: Icon(Icons.mic_none_outlined), label: 'Voice'),
          NavigationDestination(
              icon: Icon(Icons.inbox_outlined), label: 'Inbox'),
        ],
      ),
    );
  }

  int get _selectedIndex {
    final index = _routes.indexOf(selectedRoute);
    return index < 0 ? 0 : index;
  }

  static const _routes = [
    HermesRoutes.home,
    HermesRoutes.agents,
    HermesRoutes.missions,
    HermesRoutes.hermesDashboard,
    HermesRoutes.voice,
    HermesRoutes.inbox,
  ];
}

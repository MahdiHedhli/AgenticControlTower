import 'package:flutter/material.dart';

import '../models/alpha_models.dart';
import '../repositories/alpha_repository.dart';
import '../routes.dart';
import '../widgets/alpha_components.dart';
import '../widgets/screen_shell.dart';

class AgentDetailScreen extends StatelessWidget {
  const AgentDetailScreen({
    required this.repository,
    super.key,
  });

  final AlphaRepository repository;

  @override
  Widget build(BuildContext context) {
    final argument = ModalRoute.of(context)?.settings.arguments;
    final agentId = argument is String ? argument : 'agent-repo';
    return ScreenShell(
      title: 'Agent Detail',
      selectedRoute: HermesRoutes.agents,
      body: FutureBuilder<FleetAgent>(
        future: repository.loadAgent(agentId),
        builder: (context, snapshot) {
          if (snapshot.hasError) {
            return Center(
              child: Padding(
                padding: const EdgeInsets.all(24),
                child: Text(
                  'Agent not found — it may be offline or not on this gateway.',
                  textAlign: TextAlign.center,
                  style: Theme.of(context).textTheme.bodyMedium,
                ),
              ),
            );
          }
          final agent = snapshot.data;
          if (agent == null) {
            return const Center(child: CircularProgressIndicator());
          }
          return ListView(
            padding: const EdgeInsets.fromLTRB(16, 8, 16, 24),
            children: [
              AlphaPanel(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      children: [
                        Expanded(
                          child: Text(
                            agent.name,
                            style: Theme.of(context).textTheme.headlineSmall,
                          ),
                        ),
                        AgentStatusPill(status: agent.status),
                      ],
                    ),
                    const SizedBox(height: 16),
                    DetailRow(label: 'Team', value: agent.team),
                    DetailRow(label: 'Node', value: agent.node),
                    DetailRow(label: 'Mission', value: agent.currentMission),
                    DetailRow(
                        label: 'Last activity', value: agent.lastActivity),
                  ],
                ),
              ),
              const SectionHeader(title: 'Capabilities'),
              Wrap(
                spacing: 8,
                runSpacing: 8,
                children: agent.capabilities
                    .map(
                      (capability) => StatusPill(
                        label: capability,
                        color: Theme.of(context).colorScheme.tertiary,
                      ),
                    )
                    .toList(),
              ),
              const SectionHeader(title: 'Signals'),
              Row(
                children: [
                  Expanded(
                    child: AlphaPanel(
                      child: _SignalCount(
                        label: 'Notifications',
                        value: agent.notificationCount.toString(),
                        icon: Icons.notifications_outlined,
                      ),
                    ),
                  ),
                  const SizedBox(width: 10),
                  Expanded(
                    child: AlphaPanel(
                      child: _SignalCount(
                        label: 'Approvals',
                        value: agent.approvalCount.toString(),
                        icon: Icons.verified_user_outlined,
                      ),
                    ),
                  ),
                ],
              ),
              const SectionHeader(title: 'Operator Actions'),
              Row(
                children: [
                  Expanded(
                    child: CommandButton(
                      label: 'TUA',
                      icon: Icons.support_agent_outlined,
                      onPressed: () =>
                          Navigator.of(context).pushNamed(HermesRoutes.tua),
                    ),
                  ),
                  const SizedBox(width: 10),
                  Expanded(
                    child: CommandButton(
                      label: 'TUI',
                      icon: Icons.terminal_outlined,
                      onPressed: () =>
                          Navigator.of(context).pushNamed(HermesRoutes.tui),
                    ),
                  ),
                ],
              ),
            ],
          );
        },
      ),
    );
  }
}

class _SignalCount extends StatelessWidget {
  const _SignalCount({
    required this.label,
    required this.value,
    required this.icon,
  });

  final String label;
  final String value;
  final IconData icon;

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Icon(icon, color: Theme.of(context).colorScheme.primary),
        const SizedBox(height: 12),
        Text(value, style: Theme.of(context).textTheme.headlineSmall),
        Text(label),
      ],
    );
  }
}

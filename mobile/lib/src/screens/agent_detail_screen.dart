import 'package:flutter/material.dart';

import '../models/alpha_models.dart';
import '../repositories/alpha_repository.dart';
import '../routes.dart';
import '../widgets/alpha_components.dart';
import '../widgets/load_failure.dart';
import '../widgets/screen_shell.dart';

class AgentDetailScreen extends StatefulWidget {
  const AgentDetailScreen({
    required this.repository,
    super.key,
  });

  final AlphaRepository repository;

  @override
  State<AgentDetailScreen> createState() => _AgentDetailScreenState();
}

class _AgentDetailScreenState extends State<AgentDetailScreen> {
  late final String _agentId;
  late Future<FleetAgent> _agent;
  bool _loadedRoute = false;

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    if (_loadedRoute) {
      return;
    }
    // The route argument is only readable from didChangeDependencies onwards.
    // Loading here rather than in build() keeps the request to one per visit:
    // an inline future re-issues it on every rebuild (search, scroll, retry).
    final argument = ModalRoute.of(context)?.settings.arguments;
    _agentId = argument is String ? argument : 'agent-repo';
    _agent = claimLoadErrors(
      widget.repository.loadAgent(_agentId),
      context: 'agent-detail',
    );
    _loadedRoute = true;
  }

  @override
  Widget build(BuildContext context) {
    return ScreenShell(
      title: 'Agent Detail',
      selectedRoute: HermesRoutes.agents,
      body: FutureBuilder<FleetAgent>(
        future: _agent,
        builder: (context, snapshot) {
          final agent = snapshot.data;
          if (snapshot.hasError) {
            return LoadFailurePanel(
              error: snapshot.error!,
              context_: 'agent-detail',
              onRetry: () => setState(
                () => _agent = claimLoadErrors(
                  widget.repository.loadAgent(_agentId),
                  context: 'agent-detail',
                ),
              ),
            );
          }
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

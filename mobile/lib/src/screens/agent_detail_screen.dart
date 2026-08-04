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
  String? _agentId;
  Future<FleetAgent>? _agent;
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
    //
    // The default used to be `'agent-repo'` — which is the *mock fixture's*
    // first agent id. Against the live gateway that id is not in the fleet, so
    // an argument-less push landed on the repository's not-found path and, back
    // when that path borrowed from the mock, rendered "Repo Sentinel" every
    // time. There is no honest agent to show without an argument, so the screen
    // shows none.
    final argument = ModalRoute.of(context)?.settings.arguments;
    final agentId = argument is String && argument.isNotEmpty ? argument : null;
    _agentId = agentId;
    if (agentId != null) {
      _agent = claimLoadErrors(
        widget.repository.loadAgent(agentId),
        context: 'agent-detail',
      );
    }
    _loadedRoute = true;
  }

  @override
  Widget build(BuildContext context) {
    final agentId = _agentId;
    if (agentId == null) {
      return const ScreenShell(
        title: 'Agent Detail',
        selectedRoute: HermesRoutes.agents,
        body: _NoAgentSelected(),
      );
    }
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
                  widget.repository.loadAgent(agentId),
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

/// What the screen shows when it was pushed with no agent to show.
///
/// The alternative — inventing an id and loading whatever comes back — is how a
/// fabricated agent used to reach this screen.
class _NoAgentSelected extends StatelessWidget {
  const _NoAgentSelected();

  @override
  Widget build(BuildContext context) {
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(
              Icons.person_search_outlined,
              size: 36,
              color: Theme.of(context).colorScheme.outline,
            ),
            const SizedBox(height: 12),
            Text(
              'No agent selected. Pick one from the fleet.',
              textAlign: TextAlign.center,
              style: Theme.of(context).textTheme.bodyMedium,
            ),
            const SizedBox(height: 16),
            FilledButton.icon(
              onPressed: () =>
                  Navigator.of(context).pushNamed(HermesRoutes.agents),
              icon: const Icon(Icons.groups_outlined),
              label: const Text('Open Fleet'),
            ),
          ],
        ),
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

import 'package:flutter/material.dart';

import '../acs_tokens.dart';
import '../models/alpha_models.dart';
import '../repositories/alpha_repository.dart';
import '../routes.dart';
import '../viewmodels/alpha_viewmodels.dart';
import '../widgets/alpha_components.dart';
import '../widgets/screen_shell.dart';

class AgentsScreen extends StatefulWidget {
  const AgentsScreen({
    required this.repository,
    super.key,
  });

  final AlphaRepository repository;

  @override
  State<AgentsScreen> createState() => _AgentsScreenState();
}

class _AgentsScreenState extends State<AgentsScreen> {
  late final AgentsViewModel _viewModel;
  late final Future<List<FleetAgent>> _agents;

  @override
  void initState() {
    super.initState();
    _viewModel = AgentsViewModel(widget.repository);
    _agents = _viewModel.loadAgents();
  }

  @override
  Widget build(BuildContext context) {
    return ScreenShell(
      title: 'Agents',
      selectedRoute: HermesRoutes.agents,
      body: FutureBuilder<List<FleetAgent>>(
        future: _agents,
        builder: (context, snapshot) {
          final agents = snapshot.data;
          if (agents == null) {
            return const Center(child: CircularProgressIndicator());
          }
          final teams = _viewModel.teams(agents);
          final visible = _viewModel.visibleAgents(agents);
          final grouped = _viewModel.groupedAgents(agents);
          return ListView(
            padding: const EdgeInsets.fromLTRB(16, 8, 16, 24),
            children: [
              TextField(
                decoration: const InputDecoration(
                  prefixIcon: Icon(Icons.search),
                  hintText: 'Search agents, teams, nodes, missions',
                ),
                onChanged: (value) =>
                    setState(() => _viewModel.searchQuery = value),
              ),
              const SizedBox(height: 12),
              SingleChildScrollView(
                scrollDirection: Axis.horizontal,
                child: Row(
                  children: [
                    ...teams.map(
                      (team) => Padding(
                        padding: const EdgeInsets.only(right: 8),
                        child: FilterChip(
                          selected: _viewModel.teamFilter == team,
                          label: Text(team),
                          onSelected: (_) =>
                              setState(() => _viewModel.teamFilter = team),
                        ),
                      ),
                    ),
                    FilterChip(
                      selected: _viewModel.groupByTeam,
                      label: const Text('Group by Team'),
                      onSelected: (selected) {
                        setState(() => _viewModel.groupByTeam = selected);
                      },
                    ),
                  ],
                ),
              ),
              const SectionHeader(title: 'Fleet'),
              if (_viewModel.groupByTeam)
                ...grouped.entries.expand(
                  (entry) => [
                    Padding(
                      padding: const EdgeInsets.only(bottom: 8, top: 6),
                      child: Text(
                        entry.key,
                        style: Theme.of(context).textTheme.labelLarge,
                      ),
                    ),
                    ...entry.value.map((agent) => _AgentRow(agent: agent)),
                  ],
                )
              else
                ...visible.map((agent) => _AgentRow(agent: agent)),
            ],
          );
        },
      ),
    );
  }
}

class _AgentRow extends StatelessWidget {
  const _AgentRow({required this.agent});

  final FleetAgent agent;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 10),
      child: AlphaPanel(
        onTap: () => Navigator.of(context).pushNamed(
          HermesRoutes.agentDetail,
          arguments: agent.id,
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Expanded(
                  child: Text(agent.name,
                      style: Theme.of(context).textTheme.titleMedium),
                ),
                AgentStatusPill(status: agent.status),
              ],
            ),
            const SizedBox(height: 8),
            Text('${agent.team} - ${agent.node}'),
            const SizedBox(height: 6),
            Text(agent.currentMission,
                style: Theme.of(context).textTheme.bodyLarge),
            const SizedBox(height: 10),
            Row(
              children: [
                Icon(Icons.schedule_outlined,
                    size: 16, color: Theme.of(context).colorScheme.outline),
                const SizedBox(width: 6),
                Expanded(child: Text(agent.lastActivity)),
                if (agent.approvalCount > 0)
                  StatusPill(
                    label: '${agent.approvalCount} approvals',
                    color: AcsTokens.attention,
                  ),
              ],
            ),
          ],
        ),
      ),
    );
  }
}

import 'package:flutter/material.dart';

import '../models/alpha_models.dart';
import '../repositories/alpha_repository.dart';
import '../routes.dart';
import '../viewmodels/alpha_viewmodels.dart';
import '../widgets/alpha_components.dart';
import '../widgets/load_failure.dart';
import '../widgets/screen_shell.dart';

class MissionsScreen extends StatefulWidget {
  const MissionsScreen({
    required this.repository,
    super.key,
  });

  final AlphaRepository repository;

  @override
  State<MissionsScreen> createState() => _MissionsScreenState();
}

class _MissionsScreenState extends State<MissionsScreen> {
  late final MissionsViewModel _viewModel;
  late Future<List<MissionSummary>> _missions;

  @override
  void initState() {
    super.initState();
    _viewModel = MissionsViewModel(widget.repository);
    _missions = claimLoadErrors(_viewModel.loadMissions(), context: 'missions');
  }

  @override
  Widget build(BuildContext context) {
    return ScreenShell(
      title: 'Missions',
      selectedRoute: HermesRoutes.missions,
      body: FutureBuilder<List<MissionSummary>>(
        future: _missions,
        builder: (context, snapshot) {
          final missions = snapshot.data;
          if (snapshot.hasError) {
            return LoadFailurePanel(
              error: snapshot.error!,
              context_: 'missions',
              onRetry: () => setState(
                () => _missions = claimLoadErrors(
                  _viewModel.loadMissions(),
                  context: 'missions',
                ),
              ),
            );
          }
          if (missions == null) {
            return const Center(child: CircularProgressIndicator());
          }
          return ListView(
            padding: const EdgeInsets.fromLTRB(16, 8, 16, 24),
            children: [
              const SectionHeader(title: 'Active Work'),
              ...missions.map(
                (mission) => Padding(
                  padding: const EdgeInsets.only(bottom: 10),
                  child: _MissionRow(mission: mission),
                ),
              ),
            ],
          );
        },
      ),
    );
  }
}

class _MissionRow extends StatelessWidget {
  const _MissionRow({required this.mission});

  final MissionSummary mission;

  @override
  Widget build(BuildContext context) {
    return AlphaPanel(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(mission.title,
                        style: Theme.of(context).textTheme.titleMedium),
                    const SizedBox(height: 4),
                    Text('${mission.agentName} - ${mission.team}'),
                  ],
                ),
              ),
              MissionStatePill(state: mission.state),
            ],
          ),
          const SizedBox(height: 12),
          Text(mission.progressLabel,
              style: Theme.of(context).textTheme.bodyLarge),
          const SizedBox(height: 8),
          Text(mission.lastEvent, style: Theme.of(context).textTheme.bodySmall),
          const SizedBox(height: 14),
          Row(
            children: [
              Expanded(
                child: OutlinedButton.icon(
                  onPressed: () => Navigator.of(context)
                      .pushNamed(HermesRoutes.tua, arguments: mission.id),
                  icon: const Icon(Icons.support_agent_outlined),
                  label: const Text('TUA'),
                ),
              ),
              const SizedBox(width: 10),
              Expanded(
                child: OutlinedButton.icon(
                  onPressed: () => Navigator.of(context)
                      .pushNamed(HermesRoutes.tui, arguments: mission.id),
                  icon: const Icon(Icons.terminal_outlined),
                  label: const Text('TUI'),
                ),
              ),
            ],
          ),
        ],
      ),
    );
  }
}

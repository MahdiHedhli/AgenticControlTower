import 'package:flutter/material.dart';

import '../app_runtime.dart';
import '../models/alpha_models.dart';
import '../repositories/alpha_repository.dart';
import '../routes.dart';
import '../viewmodels/alpha_viewmodels.dart';
import '../widgets/alpha_components.dart';
import '../widgets/load_failure.dart';
import '../widgets/screen_shell.dart';

class HomeScreen extends StatefulWidget {
  const HomeScreen({
    required this.repository,
    this.runtime,
    super.key,
  });

  final AlphaRepository repository;
  final HermesAppRuntime? runtime;

  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> {
  late Future<HomeAlphaSnapshot> _snapshot;
  int _seenEventRevision = -1;

  AlphaRepository get _repository =>
      widget.runtime?.alphaRepository ?? widget.repository;

  @override
  void initState() {
    super.initState();
    _snapshot =
        claimLoadErrors(HomeViewModel(_repository).load(), context: 'home');
    widget.runtime?.addListener(_runtimeChanged);
  }

  @override
  void dispose() {
    widget.runtime?.removeListener(_runtimeChanged);
    super.dispose();
  }

  void _runtimeChanged() {
    final runtime = widget.runtime;
    if (runtime == null) {
      return;
    }
    if (_seenEventRevision != runtime.eventRevision) {
      _seenEventRevision = runtime.eventRevision;
      setState(() {
        _snapshot = claimLoadErrors(
          HomeViewModel(_repository).load(),
          context: 'home',
        );
      });
      return;
    }
    setState(() {});
  }

  @override
  Widget build(BuildContext context) {
    return ScreenShell(
      title: 'ACT Tower',
      selectedRoute: HermesRoutes.home,
      body: FutureBuilder<HomeAlphaSnapshot>(
        future: _snapshot,
        builder: (context, snapshot) {
          final data = snapshot.data;
          if (snapshot.hasError) {
            return LoadFailurePanel(
              error: snapshot.error!,
              context_: 'home',
              onRetry: () => setState(
                () => _snapshot = claimLoadErrors(
                  HomeViewModel(_repository).load(),
                  context: 'home',
                ),
              ),
            );
          }
          if (data == null) {
            return const Center(child: CircularProgressIndicator());
          }
          return ListView(
            padding: const EdgeInsets.fromLTRB(16, 8, 16, 24),
            children: [
              if (widget.runtime != null)
                _LiveStatusPanel(runtime: widget.runtime!),
              _MetricsGrid(stats: data.stats),
              const SectionHeader(title: 'Pending Approvals'),
              ...data.pendingApprovals.take(2).map(
                    (approval) => Padding(
                      padding: const EdgeInsets.only(bottom: 10),
                      child: _ApprovalCard(approval: approval),
                    ),
                  ),
              const SectionHeader(title: 'Active Missions'),
              ...data.activeMissions.take(3).map(
                    (mission) => Padding(
                      padding: const EdgeInsets.only(bottom: 10),
                      child: _MissionCard(mission: mission),
                    ),
                  ),
              const SectionHeader(title: 'Agent Fleet'),
              AlphaPanel(
                // ListTile paints its background and ink splashes on the
                // nearest Material ancestor. AlphaPanel is a coloured
                // DecoratedBox, so without a Material *inside* it the framework
                // asserts "ink splashes may be invisible" every time the fleet
                // renders — and the taps show no feedback.
                child: Material(
                  type: MaterialType.transparency,
                  child: Column(
                    children: data.agents.take(4).map((agent) {
                      return ListTile(
                        contentPadding: EdgeInsets.zero,
                        title: Text(agent.name),
                        subtitle:
                            Text('${agent.team} - ${agent.currentMission}'),
                        trailing: AgentStatusPill(status: agent.status),
                        onTap: () => Navigator.of(context).pushNamed(
                          HermesRoutes.agentDetail,
                          arguments: agent.id,
                        ),
                      );
                    }).toList(),
                  ),
                ),
              ),
              const SectionHeader(title: 'Recent Activity'),
              ...data.activity.map(
                (activity) => Padding(
                  padding: const EdgeInsets.only(bottom: 10),
                  child: AlphaPanel(
                    child: Row(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Icon(
                          _activityIcon(activity.severity),
                          color: _activityColor(context, activity.severity),
                        ),
                        const SizedBox(width: 12),
                        Expanded(
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              Text(
                                activity.title,
                                style: Theme.of(context).textTheme.titleSmall,
                              ),
                              const SizedBox(height: 4),
                              Text(activity.detail),
                            ],
                          ),
                        ),
                        Text(activity.timeLabel,
                            style: Theme.of(context).textTheme.labelSmall),
                      ],
                    ),
                  ),
                ),
              ),
            ],
          );
        },
      ),
    );
  }
}

class _LiveStatusPanel extends StatelessWidget {
  const _LiveStatusPanel({required this.runtime});

  final HermesAppRuntime runtime;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 12),
      child: AlphaPanel(
        padding: const EdgeInsets.all(14),
        child: Row(
          children: [
            Icon(
              runtime.eventStreamConnected
                  ? Icons.sensors_outlined
                  : Icons.sensors_off_outlined,
              color: runtime.eventStreamConnected
                  ? Theme.of(context).colorScheme.primary
                  : Theme.of(context).colorScheme.outline,
            ),
            const SizedBox(width: 10),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    runtime.dataModeLabel,
                    style: Theme.of(context).textTheme.titleSmall,
                  ),
                  const SizedBox(height: 2),
                  Text(runtime.eventStreamStatus),
                ],
              ),
            ),
            IconButton(
              onPressed: runtime.refreshLiveData,
              icon: const Icon(Icons.refresh_outlined),
              tooltip: 'Refresh gateway data',
            ),
          ],
        ),
      ),
    );
  }
}

class _MetricsGrid extends StatelessWidget {
  const _MetricsGrid({required this.stats});

  final List<DashboardStat> stats;

  @override
  Widget build(BuildContext context) {
    return GridView.builder(
      shrinkWrap: true,
      physics: const NeverScrollableScrollPhysics(),
      itemCount: stats.length,
      gridDelegate: const SliverGridDelegateWithFixedCrossAxisCount(
        crossAxisCount: 2,
        mainAxisSpacing: 10,
        crossAxisSpacing: 10,
        childAspectRatio: 1.55,
      ),
      itemBuilder: (context, index) => MetricTile(stat: stats[index]),
    );
  }
}

class _ApprovalCard extends StatelessWidget {
  const _ApprovalCard({required this.approval});

  final ApprovalAlpha approval;

  @override
  Widget build(BuildContext context) {
    return AlphaPanel(
      onTap: () => Navigator.of(context).pushNamed(
        HermesRoutes.approvalDetail,
        arguments: approval.id,
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              StatusPill(
                  label: approval.risk,
                  color: riskColor(context, approval.risk)),
              const Spacer(),
              Text(approval.expiresIn,
                  style: Theme.of(context).textTheme.labelMedium),
            ],
          ),
          const SizedBox(height: 12),
          Text(approval.title, style: Theme.of(context).textTheme.titleMedium),
          const SizedBox(height: 6),
          Text('${approval.agentName} - ${approval.requestedTool}'),
        ],
      ),
    );
  }
}

class _MissionCard extends StatelessWidget {
  const _MissionCard({required this.mission});

  final MissionSummary mission;

  @override
  Widget build(BuildContext context) {
    return AlphaPanel(
      child: Row(
        children: [
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(mission.title,
                    style: Theme.of(context).textTheme.titleMedium),
                const SizedBox(height: 4),
                Text('${mission.agentName} - ${mission.progressLabel}'),
              ],
            ),
          ),
          MissionStatePill(state: mission.state),
        ],
      ),
    );
  }
}

IconData _activityIcon(String severity) {
  return switch (severity) {
    'critical' => Icons.security_outlined,
    'warn' => Icons.warning_amber_outlined,
    'good' => Icons.check_circle_outline,
    _ => Icons.bolt_outlined,
  };
}

Color _activityColor(BuildContext context, String severity) {
  return switch (severity) {
    'critical' => Theme.of(context).colorScheme.error,
    'warn' => const Color(0xFFFFB84D),
    'good' => const Color(0xFF68D391),
    _ => Theme.of(context).colorScheme.primary,
  };
}

import 'package:flutter/material.dart';

import '../models/alpha_models.dart';

class AlphaPanel extends StatelessWidget {
  const AlphaPanel({
    required this.child,
    this.onTap,
    this.padding = const EdgeInsets.all(16),
    super.key,
  });

  final Widget child;
  final VoidCallback? onTap;
  final EdgeInsetsGeometry padding;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final panel = DecoratedBox(
      decoration: BoxDecoration(
        color: theme.colorScheme.surface,
        border: Border.all(color: theme.colorScheme.outlineVariant),
        borderRadius: BorderRadius.circular(8),
      ),
      child: Padding(padding: padding, child: child),
    );
    if (onTap == null) {
      return panel;
    }
    return InkWell(
      onTap: onTap,
      borderRadius: BorderRadius.circular(8),
      child: panel,
    );
  }
}

class MetricTile extends StatelessWidget {
  const MetricTile({
    required this.stat,
    super.key,
  });

  final DashboardStat stat;

  @override
  Widget build(BuildContext context) {
    return AlphaPanel(
      padding: const EdgeInsets.all(14),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: [
          Text(stat.label, style: Theme.of(context).textTheme.labelMedium),
          Text(
            stat.value,
            style: Theme.of(context).textTheme.headlineSmall?.copyWith(
                  color: _intentColor(context, stat.intent),
                  fontWeight: FontWeight.w700,
                ),
          ),
          Text(stat.trend, style: Theme.of(context).textTheme.bodySmall),
        ],
      ),
    );
  }
}

class SectionHeader extends StatelessWidget {
  const SectionHeader({
    required this.title,
    this.action,
    super.key,
  });

  final String title;
  final Widget? action;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.fromLTRB(2, 20, 2, 10),
      child: Row(
        children: [
          Expanded(
            child: Text(
              title,
              style: Theme.of(context).textTheme.titleMedium?.copyWith(
                    fontWeight: FontWeight.w700,
                  ),
            ),
          ),
          if (action != null) action!,
        ],
      ),
    );
  }
}

class StatusPill extends StatelessWidget {
  const StatusPill({
    required this.label,
    required this.color,
    super.key,
  });

  final String label;
  final Color color;

  @override
  Widget build(BuildContext context) {
    return DecoratedBox(
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.16),
        borderRadius: BorderRadius.circular(999),
        border: Border.all(color: color.withValues(alpha: 0.55)),
      ),
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 9, vertical: 5),
        child: Text(
          label,
          style: Theme.of(context).textTheme.labelSmall?.copyWith(
                color: color,
                fontWeight: FontWeight.w700,
              ),
        ),
      ),
    );
  }
}

class CommandButton extends StatelessWidget {
  const CommandButton({
    required this.label,
    required this.icon,
    required this.onPressed,
    this.destructive = false,
    this.primary = false,
    super.key,
  });

  final String label;
  final IconData icon;
  final VoidCallback onPressed;
  final bool destructive;
  final bool primary;

  @override
  Widget build(BuildContext context) {
    final color = destructive
        ? Theme.of(context).colorScheme.error
        : primary
            ? Theme.of(context).colorScheme.primary
            : Theme.of(context).colorScheme.secondary;
    return FilledButton.icon(
      onPressed: onPressed,
      icon: Icon(icon, size: 18),
      label: Text(label),
      style: FilledButton.styleFrom(
        backgroundColor: color,
        foregroundColor: Colors.black,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
      ),
    );
  }
}

class AgentStatusPill extends StatelessWidget {
  const AgentStatusPill({
    required this.status,
    super.key,
  });

  final AgentRunStatus status;

  @override
  Widget build(BuildContext context) {
    return StatusPill(
        label: _agentStatusLabel(status),
        color: _agentStatusColor(context, status));
  }
}

class MissionStatePill extends StatelessWidget {
  const MissionStatePill({
    required this.state,
    super.key,
  });

  final MissionState state;

  @override
  Widget build(BuildContext context) {
    return StatusPill(
        label: _missionStateLabel(state),
        color: _missionStateColor(context, state));
  }
}

class DetailRow extends StatelessWidget {
  const DetailRow({
    required this.label,
    required this.value,
    super.key,
  });

  final String label;
  final String value;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 6),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 104,
            child: Text(label, style: Theme.of(context).textTheme.labelMedium),
          ),
          Expanded(child: Text(value)),
        ],
      ),
    );
  }
}

Color riskColor(BuildContext context, String risk) {
  return switch (risk) {
    'critical' => Theme.of(context).colorScheme.error,
    'high' => const Color(0xFFFFB84D),
    'medium' => const Color(0xFF5DADEC),
    _ => Theme.of(context).colorScheme.primary,
  };
}

Color _intentColor(BuildContext context, String intent) {
  return switch (intent) {
    'good' => const Color(0xFF68D391),
    'warn' => const Color(0xFFFFB84D),
    'critical' => Theme.of(context).colorScheme.error,
    'active' => const Color(0xFF5DADEC),
    _ => Theme.of(context).colorScheme.onSurface,
  };
}

String _agentStatusLabel(AgentRunStatus status) {
  return switch (status) {
    AgentRunStatus.idle => 'idle',
    AgentRunStatus.online => 'online',
    AgentRunStatus.running => 'running',
    AgentRunStatus.blocked => 'blocked',
    AgentRunStatus.waitingApproval => 'waiting approval',
    AgentRunStatus.waitingAssistance => 'waiting help',
    AgentRunStatus.userControlling => 'user control',
    AgentRunStatus.paused => 'paused',
    AgentRunStatus.offline => 'offline',
    AgentRunStatus.warning => 'warning',
    AgentRunStatus.failed => 'failed',
    AgentRunStatus.completed => 'completed',
    AgentRunStatus.unknown => 'unknown state',
  };
}

Color _agentStatusColor(BuildContext context, AgentRunStatus status) {
  return switch (status) {
    AgentRunStatus.running => Theme.of(context).colorScheme.primary,
    AgentRunStatus.online => const Color(0xFF68D391),
    AgentRunStatus.blocked => const Color(0xFFFFB84D),
    AgentRunStatus.waitingApproval => const Color(0xFFFFB84D),
    AgentRunStatus.waitingAssistance => const Color(0xFF5DADEC),
    AgentRunStatus.userControlling => const Color(0xFF2FD1B2),
    AgentRunStatus.warning => Theme.of(context).colorScheme.error,
    AgentRunStatus.paused => const Color(0xFFBCA7FF),
    AgentRunStatus.offline => Theme.of(context).colorScheme.outline,
    AgentRunStatus.idle => const Color(0xFF5DADEC),
    AgentRunStatus.failed => Theme.of(context).colorScheme.error,
    AgentRunStatus.completed => const Color(0xFF68D391),
    // Deliberately not a healthy colour: this is the absence of a known
    // status, and it used to be painted as "online" green.
    AgentRunStatus.unknown => Theme.of(context).colorScheme.outline,
  };
}

String _missionStateLabel(MissionState state) {
  return switch (state) {
    MissionState.queued => 'queued',
    MissionState.running => 'running',
    MissionState.waitingApproval => 'approval',
    MissionState.waitingAssistance => 'assistance',
    MissionState.userControlling => 'user control',
    MissionState.complete => 'complete',
    MissionState.failed => 'failed',
    MissionState.cancelled => 'cancelled',
    MissionState.unknown => 'unknown state',
  };
}

Color _missionStateColor(BuildContext context, MissionState state) {
  return switch (state) {
    MissionState.queued => Theme.of(context).colorScheme.outline,
    MissionState.running => Theme.of(context).colorScheme.primary,
    MissionState.waitingApproval => const Color(0xFFFFB84D),
    MissionState.waitingAssistance => const Color(0xFF5DADEC),
    MissionState.userControlling => const Color(0xFF2FD1B2),
    MissionState.complete => const Color(0xFF68D391),
    MissionState.failed => Theme.of(context).colorScheme.error,
    MissionState.cancelled => Theme.of(context).colorScheme.outline,
    MissionState.unknown => Theme.of(context).colorScheme.outline,
  };
}

import 'package:flutter/material.dart';

import '../acs_tokens.dart';
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
    final baseSize = Theme.of(context).textTheme.labelSmall?.fontSize ?? 11;
    return DecoratedBox(
      decoration: BoxDecoration(
        // 14% alpha fill mirrors the ACS `-soft` token variants.
        color: color.withValues(alpha: 0.14),
        borderRadius: BorderRadius.circular(999),
        border: Border.all(color: color.withValues(alpha: 0.55)),
      ),
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 9, vertical: 5),
        child: Text(
          // Presentation-only transform: ACS status labels are uppercase,
          // tracked IBM Plex Mono.
          label.toUpperCase(),
          style: Theme.of(context).textTheme.labelSmall?.copyWith(
                color: color,
                fontWeight: FontWeight.w600,
                fontFamily: AcsTokens.fontMono,
                letterSpacing: baseSize * AcsTokens.trackingLabelEm,
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
        foregroundColor: AcsTokens.bg,
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
    this.mono = false,
    super.key,
  });

  final String label;
  final String value;

  /// Render the value in IBM Plex Mono — for short codes, ids, and
  /// other machine-shaped data.
  final bool mono;

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
          Expanded(
            child: Text(
              value,
              style: mono
                  ? const TextStyle(fontFamily: AcsTokens.fontMono)
                  : null,
            ),
          ),
        ],
      ),
    );
  }
}

Color riskColor(BuildContext context, String risk) {
  return switch (risk) {
    'critical' => AcsTokens.alert,
    'high' => AcsTokens.warn,
    'medium' => AcsTokens.attention,
    _ => AcsTokens.go,
  };
}

Color _intentColor(BuildContext context, String intent) {
  return switch (intent) {
    'good' => AcsTokens.go,
    'warn' => AcsTokens.warn,
    'critical' => AcsTokens.alert,
    'active' => AcsTokens.beacon,
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
  };
}

Color _agentStatusColor(BuildContext context, AgentRunStatus status) {
  return switch (status) {
    AgentRunStatus.running => AcsTokens.go,
    AgentRunStatus.online => AcsTokens.go,
    AgentRunStatus.blocked => AcsTokens.attention,
    AgentRunStatus.waitingApproval => AcsTokens.attention,
    AgentRunStatus.waitingAssistance => AcsTokens.attention,
    AgentRunStatus.userControlling => AcsTokens.attention,
    AgentRunStatus.warning => AcsTokens.warn,
    AgentRunStatus.paused => Theme.of(context).colorScheme.outline,
    AgentRunStatus.offline => Theme.of(context).colorScheme.outline,
    AgentRunStatus.idle => Theme.of(context).colorScheme.outline,
    AgentRunStatus.failed => AcsTokens.alert,
    AgentRunStatus.completed => AcsTokens.go,
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
  };
}

Color _missionStateColor(BuildContext context, MissionState state) {
  return switch (state) {
    MissionState.queued => Theme.of(context).colorScheme.outline,
    MissionState.running => AcsTokens.go,
    MissionState.waitingApproval => AcsTokens.attention,
    MissionState.waitingAssistance => AcsTokens.attention,
    MissionState.userControlling => AcsTokens.attention,
    MissionState.complete => AcsTokens.go,
    MissionState.failed => AcsTokens.alert,
    MissionState.cancelled => Theme.of(context).colorScheme.outline,
  };
}

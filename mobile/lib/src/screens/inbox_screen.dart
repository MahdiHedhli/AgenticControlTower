import 'package:flutter/material.dart';

import '../acs_tokens.dart';
import '../app_runtime.dart';
import '../models/alpha_models.dart';
import '../repositories/alpha_repository.dart';
import '../routes.dart';
import '../viewmodels/alpha_viewmodels.dart';
import '../widgets/alpha_components.dart';
import '../widgets/screen_shell.dart';

class InboxScreen extends StatefulWidget {
  const InboxScreen({
    required this.repository,
    this.runtime,
    super.key,
  });

  final AlphaRepository repository;
  final HermesAppRuntime? runtime;

  @override
  State<InboxScreen> createState() => _InboxScreenState();
}

class _InboxScreenState extends State<InboxScreen> {
  late final InboxViewModel _viewModel;
  late Future<List<InboxItem>> _items;
  int _seenEventRevision = -1;

  AlphaRepository get _repository =>
      widget.runtime?.alphaRepository ?? widget.repository;

  @override
  void initState() {
    super.initState();
    _viewModel = InboxViewModel(_repository);
    _items = _viewModel.loadInbox();
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
        _items = InboxViewModel(_repository).loadInbox();
      });
      return;
    }
    setState(() {});
  }

  @override
  Widget build(BuildContext context) {
    return ScreenShell(
      title: 'Inbox',
      selectedRoute: HermesRoutes.inbox,
      body: FutureBuilder<List<InboxItem>>(
        future: _items,
        builder: (context, snapshot) {
          final items = snapshot.data;
          if (items == null) {
            return const Center(child: CircularProgressIndicator());
          }
          final visible = _viewModel.visibleItems(items);
          return ListView(
            padding: const EdgeInsets.fromLTRB(16, 8, 16, 24),
            children: [
              if (widget.runtime != null)
                _InboxLiveStatus(runtime: widget.runtime!),
              SingleChildScrollView(
                scrollDirection: Axis.horizontal,
                child: Row(
                  children: [
                    _FilterChip(
                      label: 'All',
                      selected: _viewModel.filter == null,
                      onTap: () => setState(() => _viewModel.filter = null),
                    ),
                    _FilterChip(
                      label: 'Approvals',
                      selected: _viewModel.filter == InboxKind.approval,
                      onTap: () => setState(
                          () => _viewModel.filter = InboxKind.approval),
                    ),
                    _FilterChip(
                      label: 'Assistance',
                      selected: _viewModel.filter == InboxKind.assistance,
                      onTap: () => setState(
                          () => _viewModel.filter = InboxKind.assistance),
                    ),
                    _FilterChip(
                      label: 'Security',
                      selected: _viewModel.filter == InboxKind.security,
                      onTap: () => setState(
                          () => _viewModel.filter = InboxKind.security),
                    ),
                  ],
                ),
              ),
              const SectionHeader(title: 'Unified Queue'),
              ...visible.map((item) => _InboxRow(item: item)),
            ],
          );
        },
      ),
    );
  }
}

class _InboxLiveStatus extends StatelessWidget {
  const _InboxLiveStatus({required this.runtime});

  final HermesAppRuntime runtime;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 12),
      child: AlphaPanel(
        padding: const EdgeInsets.all(14),
        child: Row(
          children: [
            StatusPill(
              label: runtime.eventStreamConnected ? 'live' : 'offline',
              color: runtime.eventStreamConnected
                  ? Theme.of(context).colorScheme.primary
                  : Theme.of(context).colorScheme.outline,
            ),
            const SizedBox(width: 10),
            Expanded(child: Text(runtime.eventStreamStatus)),
            IconButton(
              onPressed: runtime.refreshLiveData,
              icon: const Icon(Icons.refresh_outlined),
              tooltip: 'Refresh inbox',
            ),
          ],
        ),
      ),
    );
  }
}

class _FilterChip extends StatelessWidget {
  const _FilterChip({
    required this.label,
    required this.selected,
    required this.onTap,
  });

  final String label;
  final bool selected;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.only(right: 8),
      child: FilterChip(
          selected: selected, label: Text(label), onSelected: (_) => onTap()),
    );
  }
}

class _InboxRow extends StatelessWidget {
  const _InboxRow({required this.item});

  final InboxItem item;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 10),
      child: AlphaPanel(
        onTap: () => _openItem(context, item),
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Stack(
              clipBehavior: Clip.none,
              children: [
                CircleAvatar(
                  backgroundColor:
                      _kindColor(context, item.kind).withValues(alpha: 0.16),
                  foregroundColor: _kindColor(context, item.kind),
                  child: Icon(_kindIcon(item.kind)),
                ),
                if (item.unread)
                  Positioned(
                    right: -2,
                    top: -2,
                    child: DecoratedBox(
                      decoration: BoxDecoration(
                        color: Theme.of(context).colorScheme.primary,
                        shape: BoxShape.circle,
                      ),
                      child: const SizedBox(width: 10, height: 10),
                    ),
                  ),
              ],
            ),
            const SizedBox(width: 12),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      Expanded(
                        child: Text(item.title,
                            style: Theme.of(context).textTheme.titleMedium),
                      ),
                      StatusPill(
                          label: item.priority,
                          color: _kindColor(context, item.kind)),
                    ],
                  ),
                  const SizedBox(height: 6),
                  Text(item.subtitle),
                  const SizedBox(height: 8),
                  Text('${item.agentName} - ${item.timeLabel}'),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }
}

void _openItem(BuildContext context, InboxItem item) {
  if (item.kind == InboxKind.approval) {
    Navigator.of(context)
        .pushNamed(HermesRoutes.approvalDetail, arguments: item.id);
    return;
  }
  if (item.kind == InboxKind.security) {
    Navigator.of(context)
        .pushNamed(HermesRoutes.approvalDetail, arguments: item.id);
    return;
  }
  if (item.kind == InboxKind.assistance) {
    Navigator.of(context).pushNamed(HermesRoutes.tua, arguments: item.id);
    return;
  }
}

IconData _kindIcon(InboxKind kind) {
  return switch (kind) {
    InboxKind.approval => Icons.verified_user_outlined,
    InboxKind.notification => Icons.notifications_outlined,
    InboxKind.assistance => Icons.support_agent_outlined,
    InboxKind.security => Icons.security_outlined,
  };
}

Color _kindColor(BuildContext context, InboxKind kind) {
  return switch (kind) {
    InboxKind.approval => AcsTokens.attention,
    InboxKind.notification => Theme.of(context).colorScheme.tertiary,
    InboxKind.assistance => Theme.of(context).colorScheme.primary,
    InboxKind.security => Theme.of(context).colorScheme.error,
  };
}

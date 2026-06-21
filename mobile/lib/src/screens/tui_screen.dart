import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../app_runtime.dart';
import '../models/alpha_models.dart';
import '../repositories/alpha_repository.dart';
import '../routes.dart';
import '../viewmodels/tui_viewmodel.dart';
import '../widgets/alpha_components.dart';
import '../widgets/screen_shell.dart';

class TuiScreen extends StatefulWidget {
  const TuiScreen({
    required this.repository,
    this.runtime,
    super.key,
  });

  final AlphaRepository repository;
  final HermesAppRuntime? runtime;

  @override
  State<TuiScreen> createState() => _TuiScreenState();
}

class _TuiScreenState extends State<TuiScreen> {
  late final TuiViewModel _viewModel;
  final TextEditingController _inputController = TextEditingController();
  final ScrollController _scrollController = ScrollController();
  TerminalKeyPage _page = TerminalKeyPage.controls;
  bool _loadedRoute = false;

  @override
  void initState() {
    super.initState();
    final runtime = widget.runtime;
    _viewModel = TuiViewModel(
      tuiRepository: runtime?.tuiRepository,
      streamClient: runtime?.tuiStreamClient,
    )..addListener(_handleViewModelChanged);
  }

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    if (_loadedRoute) {
      return;
    }
    final sessionId =
        ModalRoute.of(context)?.settings.arguments as String? ?? 'terminal-release';
    _viewModel.start(sessionId);
    _loadedRoute = true;
  }

  @override
  void dispose() {
    _viewModel.removeListener(_handleViewModelChanged);
    _viewModel.dispose();
    _inputController.dispose();
    _scrollController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return ScreenShell(
      title: 'TUI',
      selectedRoute: HermesRoutes.inbox,
      body: Column(
        children: [
          _TerminalHeader(
            viewModel: _viewModel,
            onCopy: _copyScrollback,
            onDetach: _viewModel.detach,
            onClose: _viewModel.close,
          ),
          Expanded(
            child: _TerminalPane(
              viewModel: _viewModel,
              scrollController: _scrollController,
            ),
          ),
          _TerminalInputBar(
            controller: _inputController,
            onPaste: _pasteFromClipboard,
            onSend: _sendDraft,
          ),
          _KeyboardAccessory(
            page: _page,
            keys: _viewModel.keysForPage(_page),
            onPageSelected: (page) => setState(() => _page = page),
            onKeyPressed: _viewModel.sendSpecialKey,
          ),
        ],
      ),
    );
  }

  void _handleViewModelChanged() {
    if (!mounted) {
      return;
    }
    setState(() {});
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (!_scrollController.hasClients) {
        return;
      }
      _scrollController.animateTo(
        _scrollController.position.maxScrollExtent,
        duration: const Duration(milliseconds: 160),
        curve: Curves.easeOut,
      );
    });
  }

  Future<void> _sendDraft() async {
    final text = _inputController.text;
    if (text.trim().isEmpty) {
      return;
    }
    await _viewModel.sendText(text.endsWith('\n') ? text : '$text\n');
    _inputController.clear();
  }

  Future<void> _pasteFromClipboard() async {
    final data = await Clipboard.getData(Clipboard.kTextPlain);
    final text = data?.text;
    if (text == null || text.isEmpty) {
      return;
    }
    await _viewModel.sendPaste(text.endsWith('\n') ? text : '$text\n');
  }

  Future<void> _copyScrollback() async {
    await Clipboard.setData(ClipboardData(text: _viewModel.scrollbackText));
    if (!mounted) {
      return;
    }
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(content: Text('Terminal scrollback copied')),
    );
  }
}

class _TerminalHeader extends StatelessWidget {
  const _TerminalHeader({
    required this.viewModel,
    required this.onCopy,
    required this.onDetach,
    required this.onClose,
  });

  final TuiViewModel viewModel;
  final VoidCallback onCopy;
  final VoidCallback onDetach;
  final VoidCallback onClose;

  @override
  Widget build(BuildContext context) {
    final colorScheme = Theme.of(context).colorScheme;
    return Padding(
      padding: const EdgeInsets.fromLTRB(16, 8, 16, 8),
      child: AlphaPanel(
        padding: const EdgeInsets.all(14),
        child: Row(
          children: [
            Icon(Icons.terminal_outlined, color: colorScheme.primary),
            const SizedBox(width: 10),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(viewModel.agentName,
                      style: Theme.of(context).textTheme.titleMedium),
                  const SizedBox(height: 2),
                  Text('${viewModel.node} - ${viewModel.mission}'),
                  const SizedBox(height: 8),
                  Row(
                    children: [
                      _ConnectionDot(connected: viewModel.connected),
                      const SizedBox(width: 6),
                      Expanded(
                        child: Text(
                          viewModel.statusLabel,
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                          style: Theme.of(context).textTheme.bodySmall,
                        ),
                      ),
                    ],
                  ),
                  if (viewModel.errorLabel != null) ...[
                    const SizedBox(height: 4),
                    Text(
                      viewModel.errorLabel!,
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                      style: Theme.of(context).textTheme.bodySmall?.copyWith(
                            color: colorScheme.error,
                          ),
                    ),
                  ],
                ],
              ),
            ),
            IconButton(
              onPressed: onCopy,
              icon: const Icon(Icons.copy_outlined),
              tooltip: 'Copy scrollback',
            ),
            IconButton(
              onPressed: onDetach,
              icon: const Icon(Icons.link_off_outlined),
              tooltip: 'Detach',
            ),
            IconButton(
              onPressed: onClose,
              icon: const Icon(Icons.close_outlined),
              tooltip: 'Close',
            ),
          ],
        ),
      ),
    );
  }
}

class _TerminalPane extends StatelessWidget {
  const _TerminalPane({
    required this.viewModel,
    required this.scrollController,
  });

  final TuiViewModel viewModel;
  final ScrollController scrollController;

  @override
  Widget build(BuildContext context) {
    final terminalStyle = Theme.of(context).textTheme.bodyMedium?.copyWith(
          color: const Color(0xFFD8F8EA),
          fontFamily: 'monospace',
          height: 1.45,
        );
    final text = viewModel.scrollbackText.trimRight();
    return Padding(
      padding: const EdgeInsets.fromLTRB(16, 0, 16, 8),
      child: DecoratedBox(
        decoration: BoxDecoration(
          color: const Color(0xFF080A0A),
          border:
              Border.all(color: Theme.of(context).colorScheme.outlineVariant),
          borderRadius: BorderRadius.circular(8),
        ),
        child: Stack(
          children: [
            if (viewModel.empty)
              _EmptyTerminalState(message: viewModel.statusLabel)
            else
              ListView(
                controller: scrollController,
                padding: const EdgeInsets.all(14),
                children: [
                  SelectableText(
                    text.isEmpty
                        ? '${viewModel.prompt} '
                        : '$text\n${viewModel.prompt} ',
                    style: terminalStyle,
                  ),
                ],
              ),
            if (viewModel.loading)
              const Positioned(
                right: 12,
                top: 12,
                child: SizedBox(
                  height: 18,
                  width: 18,
                  child: CircularProgressIndicator(strokeWidth: 2),
                ),
              ),
          ],
        ),
      ),
    );
  }
}

class _EmptyTerminalState extends StatelessWidget {
  const _EmptyTerminalState({required this.message});

  final String message;

  @override
  Widget build(BuildContext context) {
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            const Icon(
              Icons.terminal_outlined,
              color: Color(0xFF6B7C76),
              size: 40,
            ),
            const SizedBox(height: 12),
            Text(
              message,
              textAlign: TextAlign.center,
              style: const TextStyle(
                color: Color(0xFFB7CFC4),
                fontFamily: 'monospace',
                height: 1.45,
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class _TerminalInputBar extends StatelessWidget {
  const _TerminalInputBar({
    required this.controller,
    required this.onPaste,
    required this.onSend,
  });

  final TextEditingController controller;
  final VoidCallback onPaste;
  final VoidCallback onSend;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.fromLTRB(16, 0, 16, 8),
      child: Row(
        children: [
          Expanded(
            child: TextField(
              controller: controller,
              minLines: 1,
              maxLines: 3,
              style: const TextStyle(fontFamily: 'monospace'),
              decoration: const InputDecoration(
                hintText: 'command',
                isDense: true,
                border: OutlineInputBorder(),
              ),
              onSubmitted: (_) => onSend(),
            ),
          ),
          const SizedBox(width: 8),
          IconButton.outlined(
            onPressed: onPaste,
            icon: const Icon(Icons.content_paste_outlined),
            tooltip: 'Paste',
          ),
          const SizedBox(width: 8),
          IconButton.filled(
            onPressed: onSend,
            icon: const Icon(Icons.send_outlined),
            tooltip: 'Send',
          ),
        ],
      ),
    );
  }
}

class _KeyboardAccessory extends StatelessWidget {
  const _KeyboardAccessory({
    required this.page,
    required this.keys,
    required this.onPageSelected,
    required this.onKeyPressed,
  });

  final TerminalKeyPage page;
  final List<String> keys;
  final ValueChanged<TerminalKeyPage> onPageSelected;
  final ValueChanged<String> onKeyPressed;

  @override
  Widget build(BuildContext context) {
    return SafeArea(
      top: false,
      child: DecoratedBox(
        decoration: BoxDecoration(
          color: Theme.of(context).colorScheme.surface,
          border: Border(
              top: BorderSide(
                  color: Theme.of(context).colorScheme.outlineVariant)),
        ),
        child: Padding(
          padding: const EdgeInsets.fromLTRB(10, 8, 10, 10),
          child: Column(
            children: [
              SingleChildScrollView(
                scrollDirection: Axis.horizontal,
                child: Row(
                  children: TerminalKeyPage.values.map((candidate) {
                    return Padding(
                      padding: const EdgeInsets.only(right: 8),
                      child: FilterChip(
                        selected: candidate == page,
                        label: Text(_pageLabel(candidate)),
                        onSelected: (_) => onPageSelected(candidate),
                      ),
                    );
                  }).toList(),
                ),
              ),
              const SizedBox(height: 8),
              Wrap(
                spacing: 8,
                runSpacing: 8,
                children: keys
                    .map((label) => _TerminalKey(
                          label: label,
                          onPressed: () => onKeyPressed(label),
                        ))
                    .toList(),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class _TerminalKey extends StatelessWidget {
  const _TerminalKey({
    required this.label,
    required this.onPressed,
  });

  final String label;
  final VoidCallback onPressed;

  @override
  Widget build(BuildContext context) {
    return SizedBox(
      height: 38,
      width: _keyWidth(label),
      child: OutlinedButton(
        onPressed: onPressed,
        style: OutlinedButton.styleFrom(
          padding: const EdgeInsets.symmetric(horizontal: 8),
          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
        ),
        child: Text(
          label,
          maxLines: 1,
          overflow: TextOverflow.ellipsis,
          style: Theme.of(context).textTheme.labelLarge,
        ),
      ),
    );
  }
}

class _ConnectionDot extends StatelessWidget {
  const _ConnectionDot({required this.connected});

  final bool connected;

  @override
  Widget build(BuildContext context) {
    return DecoratedBox(
      decoration: BoxDecoration(
        color: connected ? const Color(0xFF16A34A) : const Color(0xFF94A3B8),
        borderRadius: BorderRadius.circular(999),
      ),
      child: const SizedBox(width: 9, height: 9),
    );
  }
}

String _pageLabel(TerminalKeyPage page) {
  return switch (page) {
    TerminalKeyPage.controls => 'Controls',
    TerminalKeyPage.symbols => 'Symbols',
    TerminalKeyPage.brackets => 'Brackets',
    TerminalKeyPage.functions => 'Functions',
  };
}

double _keyWidth(String label) {
  if (label.length >= 4) {
    return 72;
  }
  return 52;
}

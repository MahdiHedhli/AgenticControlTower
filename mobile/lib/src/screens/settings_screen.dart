import 'package:flutter/material.dart';

import '../app_runtime.dart';
import '../models/core_models.dart';
import '../operator_error.dart';
import '../routes.dart';
import '../widgets/alpha_components.dart';
import '../widgets/screen_shell.dart';

class SettingsScreen extends StatefulWidget {
  const SettingsScreen({super.key});

  @override
  State<SettingsScreen> createState() => _SettingsScreenState();
}

class _SettingsScreenState extends State<SettingsScreen> {
  late final TextEditingController _gatewayController;
  bool _busy = false;
  bool _initialized = false;

  @override
  void initState() {
    super.initState();
    _gatewayController = TextEditingController();
  }

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    if (_initialized) {
      return;
    }
    final runtime = HermesRuntimeScope.of(context);
    _gatewayController.text = runtime.config.baseUrl.toString();
    _initialized = true;
  }

  @override
  void dispose() {
    _gatewayController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final runtime = HermesRuntimeScope.of(context);
    return ScreenShell(
      title: 'Settings',
      selectedRoute: HermesRoutes.settings,
      body: AnimatedBuilder(
        animation: runtime,
        builder: (context, _) {
          return ListView(
            padding: const EdgeInsets.fromLTRB(16, 8, 16, 24),
            children: [
              _GatewayPanel(
                runtime: runtime,
                controller: _gatewayController,
                busy: _busy,
                runAction: _runAction,
              ),
              const SectionHeader(title: 'Pairing'),
              _PairingPanel(
                runtime: runtime,
                busy: _busy,
                runAction: _runAction,
              ),
              const SectionHeader(title: 'Safety Defaults'),
              AlphaPanel(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const DetailRow(
                        label: 'Approvals',
                        value: 'Signed device requests only'),
                    const DetailRow(
                        label: 'Push',
                        value: 'Notification records only in alpha'),
                    DetailRow(
                        label: 'Push token', value: runtime.pushStatus),
                    DetailRow(
                        label: 'Storage', value: runtime.secureStorageStatus),
                    DetailRow(
                        label: 'Key backend',
                        value: runtime.clearanceKeyProtection.backend),
                    DetailRow(
                        label: 'Hardware-backed',
                        value:
                            runtime.clearanceKeyProtection.hardwareBackedLabel),
                    DetailRow(
                        label: 'User presence',
                        value:
                            runtime.clearanceKeyProtection.userPresenceLabel),
                    DetailRow(
                        label: 'Production key',
                        value: runtime.clearanceKeyProtection.productionReady
                            ? 'ready'
                            : 'not yet'),
                    DetailRow(
                        label: 'Key warning',
                        value: runtime.clearanceKeyProtection.warning),
                  ],
                ),
              ),
            ],
          );
        },
      ),
    );
  }

  Future<void> _runAction(Future<dynamic> Function() action) async {
    setState(() => _busy = true);
    try {
      await action();
    } on Object catch (error) {
      if (!mounted) {
        return;
      }
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(operatorErrorMessage(error, context: 'settings')),
        ),
      );
    } finally {
      if (mounted) {
        setState(() => _busy = false);
      }
    }
  }
}

class _GatewayPanel extends StatelessWidget {
  const _GatewayPanel({
    required this.runtime,
    required this.controller,
    required this.busy,
    required this.runAction,
  });

  final HermesAppRuntime runtime;
  final TextEditingController controller;
  final bool busy;
  final Future<void> Function(Future<dynamic> Function() action) runAction;

  @override
  Widget build(BuildContext context) {
    return AlphaPanel(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              StatusPill(
                label: runtime.isPaired ? 'paired' : 'unpaired',
                color: runtime.isPaired
                    ? Theme.of(context).colorScheme.primary
                    : Theme.of(context).colorScheme.secondary,
              ),
              const Spacer(),
              Text(runtime.dataModeLabel,
                  style: Theme.of(context).textTheme.labelMedium),
            ],
          ),
          const SizedBox(height: 14),
          TextField(
            controller: controller,
            keyboardType: TextInputType.url,
            decoration: const InputDecoration(
              labelText: 'Gateway base URL',
              prefixIcon: Icon(Icons.link_outlined),
            ),
          ),
          const SizedBox(height: 10),
          Wrap(
            spacing: 8,
            runSpacing: 8,
            children: [
              ActionChip(
                label: const Text('Local dev'),
                onPressed: () => controller.text = 'http://127.0.0.1:8787/v1',
              ),
              ActionChip(
                label: const Text('Tailscale'),
                onPressed: () => controller.text = 'http://100.x.y.z:8787/v1',
              ),
            ],
          ),
          const SizedBox(height: 14),
          Text(runtime.connectionStatus),
          const SizedBox(height: 14),
          Row(
            children: [
              Expanded(
                child: CommandButton(
                  label: 'Save',
                  icon: Icons.save_outlined,
                  onPressed: busy
                      ? () {}
                      : () => runAction(
                          () => runtime.saveGatewayBaseUrl(controller.text)),
                ),
              ),
              const SizedBox(width: 10),
              Expanded(
                child: OutlinedButton.icon(
                  onPressed: busy ? null : () => runAction(runtime.checkHealth),
                  icon: const Icon(Icons.sync_outlined),
                  label: const Text('Check'),
                ),
              ),
            ],
          ),
        ],
      ),
    );
  }
}

class _PairingPanel extends StatelessWidget {
  const _PairingPanel({
    required this.runtime,
    required this.busy,
    required this.runAction,
  });

  final HermesAppRuntime runtime;
  final bool busy;
  final Future<void> Function(Future<dynamic> Function() action) runAction;

  @override
  Widget build(BuildContext context) {
    final pairing = runtime.lastPairing;
    return AlphaPanel(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          DetailRow(label: 'Device', value: runtime.deviceId ?? 'Not paired'),
          DetailRow(
              label: 'Mode',
              value: runtime.isPaired ? 'Signed gateway access' : 'Mock data'),
          if (pairing != null) ...[
            const SizedBox(height: 10),
            _PairingTokenBlock(pairing: pairing),
          ],
          // Two-step flow: once a session is started, make Complete the obvious
          // next action (highlighted) and demote Start to "Restart".
          if (pairing != null && !runtime.isPaired) ...[
            const SizedBox(height: 10),
            Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Icon(Icons.arrow_downward_rounded,
                    size: 16, color: Theme.of(context).colorScheme.primary),
                const SizedBox(width: 6),
                Expanded(
                  child: Text(
                    'Session started — now tap Complete to finish pairing (Face ID).',
                    style: Theme.of(context).textTheme.bodySmall?.copyWith(
                          color: Theme.of(context).colorScheme.primary,
                          fontWeight: FontWeight.w600,
                        ),
                  ),
                ),
              ],
            ),
          ],
          const SizedBox(height: 14),
          Row(
            children: [
              Expanded(
                child: pairing != null && !runtime.isPaired
                    ? OutlinedButton.icon(
                        onPressed:
                            busy ? null : () => runAction(runtime.startPairing),
                        icon: const Icon(Icons.refresh),
                        label: const Text('Restart'),
                      )
                    : CommandButton(
                        label: 'Start',
                        icon: Icons.qr_code_2_outlined,
                        primary: true,
                        onPressed: busy
                            ? () {}
                            : () => runAction(runtime.startPairing),
                      ),
              ),
              const SizedBox(width: 10),
              Expanded(
                child: pairing != null && !runtime.isPaired
                    ? CommandButton(
                        label: 'Complete',
                        icon: Icons.verified_user_outlined,
                        primary: true,
                        onPressed: busy
                            ? () {}
                            : () => runAction(
                                () => runtime.completePairing(pairing)),
                      )
                    : OutlinedButton.icon(
                        onPressed: null,
                        icon: const Icon(Icons.verified_user_outlined),
                        label: const Text('Complete'),
                      ),
              ),
            ],
          ),
          if (runtime.isPaired) ...[
            const SizedBox(height: 10),
            SizedBox(
              width: double.infinity,
              child: OutlinedButton.icon(
                onPressed: busy ? null : () => runAction(runtime.clearPairing),
                icon: const Icon(Icons.delete_outline),
                label: const Text('Clear Pairing'),
              ),
            ),
          ],
        ],
      ),
    );
  }
}

class _PairingTokenBlock extends StatelessWidget {
  const _PairingTokenBlock({required this.pairing});

  final PairingSessionModel pairing;

  @override
  Widget build(BuildContext context) {
    return DecoratedBox(
      decoration: BoxDecoration(
        color: Theme.of(context).colorScheme.surfaceContainerHighest,
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: Theme.of(context).colorScheme.outlineVariant),
      ),
      child: Padding(
        padding: const EdgeInsets.all(12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            DetailRow(label: 'Pairing ID', value: pairing.pairingId),
            DetailRow(label: 'Token', value: pairing.pairingToken ?? 'hidden'),
            DetailRow(
                label: 'Expires',
                value: pairing.expiresAt.toLocal().toString()),
          ],
        ),
      ),
    );
  }
}

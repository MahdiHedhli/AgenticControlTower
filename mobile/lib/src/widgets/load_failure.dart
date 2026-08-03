import 'package:flutter/material.dart';

import '../operator_error.dart';
import '../routes.dart';

/// Claim a load future's error the moment it is created.
///
/// A future handed to a `FutureBuilder` is only "handled" once that builder
/// subscribes — and it stops being handled if the screen is replaced or
/// disposed first. When the gateway is unreachable, the resulting failure then
/// escapes as an **unhandled async error**: a zone-level crash report on
/// device, blamed on whatever happened to be running at the time.
///
/// Attaching a second listener here claims the error without consuming it: the
/// same future is returned, so the `FutureBuilder` still renders
/// [LoadFailurePanel]. Technical detail goes to the debug log only.
Future<T> claimLoadErrors<T>(Future<T> future, {String? context}) {
  future.then<void>(
    (_) {},
    onError: (Object error, StackTrace _) {
      debugPrint('[act] ${context ?? 'load'} failed: $error');
    },
  );
  return future;
}

/// What a screen shows when its data load fails.
///
/// Failure mode: `FutureBuilder` branches that only test `snapshot.data == null`
/// render a `CircularProgressIndicator` forever once the future completes with
/// an error — an unrecoverable spinner that looks exactly like a slow network.
/// An operator cannot tell "still loading" from "will never load".
///
/// The message is always [operatorErrorMessage]; a raw exception `toString()`
/// is never operator-facing copy.
class LoadFailurePanel extends StatelessWidget {
  const LoadFailurePanel({
    required this.error,
    required this.onRetry,
    this.context_,
    super.key,
  });

  final Object error;
  final VoidCallback onRetry;
  final String? context_;

  @override
  Widget build(BuildContext context) {
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(
              Icons.cloud_off_outlined,
              size: 36,
              color: Theme.of(context).colorScheme.outline,
            ),
            const SizedBox(height: 12),
            Text(
              operatorErrorMessage(error, context: context_ ?? 'load'),
              textAlign: TextAlign.center,
              style: Theme.of(context).textTheme.bodyMedium,
            ),
            const SizedBox(height: 16),
            Wrap(
              spacing: 10,
              alignment: WrapAlignment.center,
              children: [
                FilledButton.icon(
                  onPressed: onRetry,
                  icon: const Icon(Icons.refresh),
                  label: const Text('Retry'),
                ),
                OutlinedButton.icon(
                  onPressed: () =>
                      Navigator.of(context).pushNamed(HermesRoutes.settings),
                  icon: const Icon(Icons.settings_outlined),
                  label: const Text('Open Settings'),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }
}

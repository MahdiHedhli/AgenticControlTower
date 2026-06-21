import 'package:flutter/material.dart';
import 'package:webview_flutter/webview_flutter.dart';

import '../app_runtime.dart';
import '../routes.dart';
import '../widgets/screen_shell.dart';

/// Surfaces the proxied Hermes agent dashboard inside an in-app WebView.
///
/// A WebView cannot device-sign each request the way the native API client
/// does, so instead we seed an `act_session` cookie holding the current
/// gateway access token. The gateway's `/hermes/*` reverse proxy (Phase 4b)
/// accepts that cookie as an alternative to a signed-device request, then
/// injects the dashboard's own session token server-side. The phone therefore
/// never sees the dashboard token — it only ever holds the gateway access
/// token it already has.
class DashboardScreen extends StatefulWidget {
  const DashboardScreen({
    required this.runtime,
    super.key,
  });

  final HermesAppRuntime runtime;

  @override
  State<DashboardScreen> createState() => _DashboardScreenState();
}

class _DashboardScreenState extends State<DashboardScreen> {
  WebViewController? _controller;
  String? _error;
  bool _loading = true;

  @override
  void initState() {
    super.initState();
    _bootstrap();
  }

  /// The gateway's Hermes proxy entrypoint. The configured base URL is the API
  /// root (`scheme://host:port/v1`); the reverse proxy lives at the gateway
  /// root under `/hermes/`, so we drop the API path.
  Uri get _dashboardUri =>
      widget.runtime.config.baseUrl.replace(path: '/hermes/', query: '');

  Future<void> _bootstrap() async {
    setState(() {
      _loading = true;
      _error = null;
    });

    if (!widget.runtime.isPaired) {
      setState(() {
        _loading = false;
        _error = 'Pair this device before opening the dashboard.';
      });
      return;
    }

    final token = await _currentToken();
    if (token == null || token.isEmpty) {
      setState(() {
        _loading = false;
        _error = 'No gateway session is available. Sign in and try again.';
      });
      return;
    }

    await _seedSessionCookie(token);

    final controller = WebViewController()
      ..setJavaScriptMode(JavaScriptMode.unrestricted)
      ..setBackgroundColor(const Color(0x00000000))
      ..setNavigationDelegate(
        NavigationDelegate(
          onPageStarted: (_) {
            if (mounted) {
              setState(() {
                _loading = true;
                _error = null;
              });
            }
          },
          onPageFinished: (_) {
            if (mounted) {
              setState(() => _loading = false);
            }
          },
          onWebResourceError: (error) {
            // Sub-resource failures fire here too; only surface a hard error
            // when the main document itself failed to load.
            if (mounted && (error.isForMainFrame ?? true)) {
              setState(() {
                _loading = false;
                _error = 'Failed to load the dashboard: ${error.description}';
              });
            }
          },
        ),
      )
      ..loadRequest(_dashboardUri);

    if (!mounted) {
      return;
    }
    setState(() {
      _controller = controller;
    });
  }

  /// Refresh the access token first when possible so the seeded cookie is not
  /// already-expired, then return whatever the runtime currently holds.
  Future<String?> _currentToken() async {
    try {
      await widget.runtime.refreshAccessToken();
    } on Object {
      // A failed refresh is non-fatal: fall back to the cached token. If it is
      // also stale the gateway returns 401 and we surface a load error.
    }
    return widget.runtime.accessToken;
  }

  Future<void> _seedSessionCookie(String token) async {
    final uri = _dashboardUri;
    final manager = WebViewCookieManager();
    // Scope to the gateway host. The cookie path is /hermes so the token is
    // sent for the proxied dashboard and the WS handshake it opens, but not to
    // any unrelated path on the host.
    await manager.setCookie(
      WebViewCookie(
        name: 'act_session',
        value: token,
        domain: uri.host,
        path: '/hermes',
      ),
    );
  }

  Future<void> _reload() async {
    final controller = _controller;
    if (controller == null) {
      await _bootstrap();
      return;
    }
    // Re-seed in case the token rotated, then reload from the proxy root.
    final token = await _currentToken();
    if (token != null && token.isNotEmpty) {
      await _seedSessionCookie(token);
    }
    await controller.loadRequest(_dashboardUri);
  }

  @override
  Widget build(BuildContext context) {
    return ScreenShell(
      title: 'Dashboard',
      selectedRoute: HermesRoutes.hermesDashboard,
      body: _buildBody(context),
    );
  }

  Widget _buildBody(BuildContext context) {
    final controller = _controller;
    final error = _error;

    if (error != null) {
      return _DashboardError(message: error, onRetry: _bootstrap);
    }

    if (controller == null) {
      return const Center(child: CircularProgressIndicator());
    }

    return Stack(
      children: [
        WebViewWidget(controller: controller),
        if (_loading)
          const LinearProgressIndicator(minHeight: 2),
        Positioned(
          right: 16,
          bottom: 16,
          child: FloatingActionButton.small(
            heroTag: 'dashboard-reload',
            onPressed: _reload,
            tooltip: 'Reload dashboard',
            child: const Icon(Icons.refresh),
          ),
        ),
      ],
    );
  }
}

class _DashboardError extends StatelessWidget {
  const _DashboardError({
    required this.message,
    required this.onRetry,
  });

  final String message;
  final Future<void> Function() onRetry;

  @override
  Widget build(BuildContext context) {
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            const Icon(Icons.cloud_off_outlined, size: 48),
            const SizedBox(height: 16),
            Text(
              message,
              textAlign: TextAlign.center,
              style: Theme.of(context).textTheme.bodyMedium,
            ),
            const SizedBox(height: 16),
            FilledButton.icon(
              onPressed: () => onRetry(),
              icon: const Icon(Icons.refresh),
              label: const Text('Retry'),
            ),
          ],
        ),
      ),
    );
  }
}

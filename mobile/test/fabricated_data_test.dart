/// A paired device must never render invented fleet state.
///
/// The escapes these guards close are a different shape from the async ones the
/// earlier sweeps found. Nothing here is a swallowed error: the futures all
/// resolve *successfully*, carrying fabricated records. `hasError` cannot fire,
/// `LoadFailurePanel` is unreachable, and the screen looks exactly like a
/// healthy one. On a control plane that is worse than an outage — an outage is
/// visible, and invented fleet state is not.
///
/// The worst of them: `GatewayAlphaRepository.loadAgent` ended in
/// `return fallback.loadAgent(agentId)`, and the mock it delegated to was
/// `firstWhere(..., orElse: () => _agents.first)` — a lookup that can never
/// decline. A stale agent id on a paired device talking to a *healthy* tower
/// therefore rendered a fully populated running agent, "Repo Sentinel" on node
/// "work-vm-02", that does not exist.
///
/// The honest answer is [FleetRecordNotFoundException]: the tower answered, and
/// this record is not in what it returned. That is the state neither of the
/// existing two could express — a transport failure means we never reached the
/// tower, a [GatewayApiException] means the tower refused — so it gets its own,
/// and the screens read it as "no longer in the fleet", never as "unreachable".
library;

import 'dart:convert';

import 'package:agentic_control_tower/src/api/gateway_api_client.dart';
import 'package:agentic_control_tower/src/api/tui_stream_client.dart';
import 'package:agentic_control_tower/src/config/gateway_config.dart';
import 'package:agentic_control_tower/src/models/alpha_models.dart';
import 'package:agentic_control_tower/src/repositories/agents_repository.dart';
import 'package:agentic_control_tower/src/repositories/alpha_repository.dart';
import 'package:agentic_control_tower/src/repositories/approvals_repository.dart';
import 'package:agentic_control_tower/src/repositories/dashboard_repository.dart';
import 'package:agentic_control_tower/src/repositories/gateway_alpha_repository.dart';
import 'package:agentic_control_tower/src/repositories/missions_repository.dart';
import 'package:agentic_control_tower/src/repositories/mock_alpha_repository.dart';
import 'package:agentic_control_tower/src/repositories/notifications_repository.dart';
import 'package:agentic_control_tower/src/repositories/tua_repository.dart';
import 'package:agentic_control_tower/src/repositories/tui_repository.dart';
import 'package:agentic_control_tower/src/screens/agent_detail_screen.dart';
import 'package:agentic_control_tower/src/security/device_request_signer.dart';
import 'package:agentic_control_tower/src/viewmodels/alpha_viewmodels.dart';
import 'package:agentic_control_tower/src/viewmodels/tui_viewmodel.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';

void main() {
  group('a missing agent is said out loud, never substituted', () {
    // THE DEFECT. The tower is healthy and answers with a real one-agent fleet;
    // only the id asked for is absent. Nothing may be invented to fill it.
    //
    // ISOLATION: only the loadAgent not-found path can satisfy this. The fleet
    // load succeeds, so no transport or status guard is involved; and the
    // matcher demands the not-found type specifically, so a blanket `throw` of
    // anything else fails it too.
    test('an unknown agent id on a healthy tower is refused, not fabricated',
        () async {
      final repository = _liveRepository(_healthyTower);

      await expectLater(
        repository.loadAgent('agent-retired-yesterday'),
        throwsA(isA<FleetRecordNotFoundException>()
            .having((error) => error.kind, 'kind', 'agent')
            .having((error) => error.id, 'id', 'agent-retired-yesterday')),
        reason: 'this used to return the mock fleet\'s first agent — a running '
            '"Repo Sentinel" on a node that does not exist',
      );
    });

    // THE POSITIVE HALF. A guard that made loadAgent always throw would pass the
    // test above; this is the case only a working lookup can satisfy.
    test('an agent that is in the fleet still loads', () async {
      final repository = _liveRepository(_healthyTower);

      final agent = await repository.loadAgent('agent_1');

      expect(agent.id, 'agent_1');
      expect(agent.name, 'Live Agent One');
      expect(agent.node, 'node_1');
    });

    // ISOLATES not-found from unreachable. These must never collapse into one
    // another: "this agent is gone" and "we cannot reach the tower" call for
    // different operator actions, and one of them is not a network problem.
    test('an unreachable tower is not reported as a missing agent', () async {
      final repository = _liveRepository((request) {
        throw http.ClientException('Connection refused', request.url);
      });

      await expectLater(
        repository.loadAgent('agent_1'),
        throwsA(allOf(
          isA<http.ClientException>(),
          isNot(isA<FleetRecordNotFoundException>()),
        )),
      );
    });

    // And the tower's own refusals keep their status, rather than being
    // flattened into "not in the fleet".
    test('a 500 from the fleet route keeps its status', () async {
      final repository = _liveRepository(
        (request) => http.Response('{"detail":"boom"}', 500),
      );

      await expectLater(
        repository.loadAgent('agent_1'),
        throwsA(isA<GatewayApiException>()
            .having((error) => error.statusCode, 'statusCode', 500)),
      );
    });
  });

  group('the agent detail screen reads the three states apart', () {
    // END TO END over the REAL live repository, so this is the guard that
    // actually catches a reintroduced mock fallback: revert loadAgent and the
    // screen renders "Repo Sentinel" / "work-vm-02" and this goes red on three
    // separate assertions.
    testWidgets('a missing agent reads as gone from the fleet, not as an outage',
        (tester) async {
      await _pumpAgentDetail(
        tester,
        _liveRepository(_healthyTower),
        argument: 'agent-retired-yesterday',
      );

      expect(
        find.textContaining('no longer in this fleet'),
        findsOneWidget,
        reason: 'the operator must be told the agent is gone',
      );
      expect(
        find.text('Repo Sentinel'),
        findsNothing,
        reason: 'the mock fleet must never reach a paired screen',
      );
      expect(find.text('work-vm-02'), findsNothing);
      expect(
        find.textContaining("Can't reach the control tower"),
        findsNothing,
        reason: 'the tower answered — this is not a connectivity failure',
      );
      expect(
        find.text('Open Settings'),
        findsNothing,
        reason: 'there is no gateway URL to fix; sending the operator to '
            'Settings dresses an absent record as a network problem',
      );
      expect(tester.takeException(), isNull);
    });

    // THE CONTRASTING STATE, so the two cannot be satisfied by one string. A
    // screen that rendered the same panel for both would fail here.
    testWidgets('an unreachable tower still reads as unreachable',
        (tester) async {
      await _pumpAgentDetail(
        tester,
        _liveRepository((request) {
          throw http.ClientException('Connection refused', request.url);
        }),
        argument: 'agent_1',
      );

      expect(find.textContaining("Can't reach the control tower"), findsOneWidget);
      expect(find.textContaining('no longer in this fleet'), findsNothing);
      expect(
        find.text('Open Settings'),
        findsOneWidget,
        reason: 'here the gateway URL genuinely is worth checking',
      );
      expect(find.textContaining('ClientException'), findsNothing);
      expect(tester.takeException(), isNull);
    });

    // ISOLATES the route default. `_agentId` defaulted to 'agent-repo' — the
    // mock fixture's first agent id — so an argument-less push asked for a
    // record that only exists in the demo data and, through the old fallback,
    // showed the fabricated agent every single time. There is nothing honest to
    // load here, so nothing is loaded.
    testWidgets('an argument-less push loads no agent at all', (tester) async {
      final repository = _SpyAlphaRepository();

      await _pumpAgentDetail(tester, repository, argument: null);

      expect(find.textContaining('No agent selected'), findsOneWidget);
      expect(
        repository.loadAgentCalls,
        isEmpty,
        reason: 'no id was given, so no id may be invented to look up',
      );
      expect(find.text('Repo Sentinel'), findsNothing);
      expect(tester.takeException(), isNull);
    });
  });

  group('the home dashboard shows the tower\'s activity or none', () {
    // `activity: fallbackHome.activity` was UNCONDITIONAL — not an error path.
    // Every paired operator's "Recent Activity" list was the mock's four
    // hardcoded rows, including a security alert nobody raised, rendered
    // directly beneath genuinely live stats.
    test('a quiet tower produces an empty activity feed, not fixtures',
        () async {
      final home = await _liveRepository(_healthyTower).loadHome();

      expect(
        home.activity,
        isEmpty,
        reason: 'nothing happened, and that is what the operator must see',
      );
      expect(
        home.activity.map((event) => event.detail),
        isNot(contains('PromptFence Guard flagged a route advertisement.')),
      );
    });

    // THE POSITIVE HALF: hardcoding an empty list would pass the test above.
    // Only genuinely reading the tower's notifications satisfies this one.
    test('activity mirrors the tower\'s own notification records', () async {
      final home = await _liveRepository((request) {
        if (request.url.path.endsWith('/notifications')) {
          return http.Response(
            jsonEncode({
              'notifications': [
                {
                  'notification_id': 'ntf_1',
                  'category': 'security_alert',
                  'urgency': 'critical',
                  'state': 'unread',
                  'created_at': DateTime.now().toUtc().toIso8601String(),
                  'title_safe': 'Unsigned device attempted enrolment',
                  'body_safe': 'Rejected at the tower.',
                },
              ],
            }),
            200,
          );
        }
        return _healthyTower(request);
      }).loadHome();

      expect(home.activity, hasLength(1));
      expect(home.activity.single.title, 'Unsigned device attempted enrolment');
      expect(home.activity.single.detail, 'Rejected at the tower.');
      expect(home.activity.single.severity, 'critical');
    });
  });

  group('an unreadable status is not reported as a healthy one', () {
    // `_statusFromGateway` ended in `_ => AgentRunStatus.online` and
    // `_missionStateFromGateway` in `_ => MissionState.running`. A status this
    // build does not know — a newer gateway, an older one — was rendered as a
    // healthy green agent AND counted in the dashboard's "Online" tile. Not
    // knowing is not the same as being fine, and the guess ran in the direction
    // that hides trouble.
    test('an unrecognised agent status is neither online nor counted online',
        () async {
      final home = await _liveRepository((request) {
        if (request.url.path.endsWith('/agents')) {
          return http.Response(
            jsonEncode({
              'agents': [
                {
                  'agent_id': 'agent_1',
                  'node_id': 'node_1',
                  'display_name': 'Live Agent One',
                  'status': 'quarantined_by_a_newer_tower',
                },
              ],
            }),
            200,
          );
        }
        return _healthyTower(request);
      }).loadHome();

      expect(home.agents.single.status, AgentRunStatus.unknown);
      expect(
        home.stats.firstWhere((stat) => stat.label == 'Online').value,
        '0',
        reason: 'an unreadable status is not evidence of an online agent',
      );
    });

    test('an unrecognised mission state is not reported as running', () async {
      final missions = await _liveRepository((request) {
        if (request.url.path.endsWith('/missions')) {
          return http.Response(
            jsonEncode({
              'missions': [
                {
                  'mission_id': 'mis_1',
                  'node_id': 'node_1',
                  'agent_id': 'agent_1',
                  'state': 'halted_pending_review',
                  'updated_at': DateTime.now().toUtc().toIso8601String(),
                },
              ],
            }),
            200,
          );
        }
        return _healthyTower(request);
      }).loadMissions();

      expect(missions.single.state, MissionState.unknown);
    });
  });

  group('the live repository has no demo surfaces to fall back to', () {
    // These two returned the mock's hand-written content with the CALLER'S real
    // session id stamped on it, so it read as specific to whatever the operator
    // had just opened. The terminal one is the worst fixture in the app: a
    // fabricated shell transcript (`git status`, `39 passed`, invented commit
    // hashes) that an operator reads as evidence of what an agent did.
    test('an assistance session is refused, not invented', () async {
      await expectLater(
        _liveRepository(_healthyTower).loadAssistanceSession('sess_real'),
        throwsA(isA<LiveDataUnavailableException>()),
      );
    });

    test('a terminal session is refused, not invented', () async {
      await expectLater(
        _liveRepository(_healthyTower).loadTerminalSession('sess_real'),
        throwsA(isA<LiveDataUnavailableException>()),
      );
    });
  });

  group('the demo repository can decline', () {
    // The demo fleet stays — it is reachable only when unpaired, and Settings
    // says "Mock alpha data" out loud. What does not stay is a lookup that
    // cannot decline: `orElse: () => _list.first` is what made the live bug
    // above possible, and even confined to demo mode it makes approve/deny
    // return a success describing a *different* approval.
    test('an unknown agent id is declined instead of becoming Repo Sentinel',
        () async {
      await expectLater(
        const MockAlphaRepository().loadAgent('no-such-agent'),
        throwsA(isA<FleetRecordNotFoundException>()),
      );
    });

    test('an unknown approval id is declined instead of becoming appr-shell',
        () async {
      await expectLater(
        const MockAlphaRepository().loadApproval('no-such-approval'),
        throwsA(isA<FleetRecordNotFoundException>()),
      );
    });

    // POSITIVE HALF: the demo still works for the ids it really has.
    test('the demo ids still resolve', () async {
      const repository = MockAlphaRepository();

      expect((await repository.loadAgent('agent-home')).name, 'Homelab Watch');
      expect((await repository.loadApproval('appr-browser')).risk, 'medium');
    });
  });

  group('the terminal shows live output or an empty pane', () {
    // Every absence and failure path in `start()` used to call `_loadMock`,
    // which reads `AlphaRepository.loadTerminalSession` — and on a paired device
    // that repository is the live one. An empty relay list on a perfectly
    // healthy tower therefore painted the pane with the fabricated transcript,
    // under a status label that did not even say "mock".
    test('paired with nothing to mirror shows no scrollback at all', () async {
      final fallback = _SpyAlphaRepository();
      final viewModel = TuiViewModel(
        fallbackRepository: fallback,
        tuiRepository: _tuiRepository(
          (request) => http.Response(jsonEncode({'sessions': <dynamic>[]}), 200),
        ),
        streamClient: TuiStreamClient(config: GatewayConfig.loopback),
      );
      addTearDown(viewModel.dispose);

      await viewModel.start('terminal-release');

      expect(
        fallback.loadTerminalSessionCalls,
        isEmpty,
        reason: 'a paired device may not read the demo terminal fixture',
      );
      expect(viewModel.scrollbackText, isEmpty);
      expect(viewModel.hasSession, isFalse);
      expect(viewModel.agentName, isNot('Repo Sentinel'));
      expect(viewModel.node, isNot('work-vm-02'));
      expect(viewModel.statusLabel, contains('No live agent terminal'));
    });

    // ISOLATES the refusal path specifically: the tower answers, and refuses.
    test('a gateway that rejects TUI shows no scrollback either', () async {
      final fallback = _SpyAlphaRepository();
      final viewModel = TuiViewModel(
        fallbackRepository: fallback,
        tuiRepository: _tuiRepository(
          (request) => http.Response('{"detail":"nope"}', 403),
        ),
        streamClient: TuiStreamClient(config: GatewayConfig.loopback),
      );
      addTearDown(viewModel.dispose);

      await viewModel.start('terminal-release');

      expect(fallback.loadTerminalSessionCalls, isEmpty);
      expect(viewModel.scrollbackText, isEmpty);
      expect(viewModel.errorLabel, isNotNull);
      expect(viewModel.errorLabel, isNot(contains('GatewayApiException')));
    });

    // ISOLATES the typing echo. With nothing attached, the demo terminal's local
    // echo would paint the operator's own keystrokes into the pane as though a
    // shell had accepted them — on a paired device, with no shell anywhere.
    test('typing into a detached terminal is refused, not echoed', () async {
      final viewModel = TuiViewModel(
        fallbackRepository: _SpyAlphaRepository(),
        tuiRepository: _tuiRepository(
          (request) => http.Response(jsonEncode({'sessions': <dynamic>[]}), 200),
        ),
        streamClient: TuiStreamClient(config: GatewayConfig.loopback),
      );
      addTearDown(viewModel.dispose);
      await viewModel.start('terminal-release');

      await viewModel.sendText('rm -rf /');

      expect(viewModel.scrollbackText, isEmpty);
      expect(viewModel.statusLabel, 'No terminal attached');
    });

    // ISOLATES the relay picker. `orElse: () => _relaySessions.first` meant a
    // session that ended between the list load and the tap silently attached to
    // a DIFFERENT agent's terminal and reported success.
    test('selecting a vanished relay session does not attach to another',
        () async {
      final viewModel = TuiViewModel(
        fallbackRepository: _SpyAlphaRepository(),
        tuiRepository: _tuiRepository((request) {
          // One real relay session in the list, and an attach that refuses — so
          // `start()` populates `relaySessions` without opening a socket, and
          // the only thing under test below is the picker's lookup.
          if (request.url.path.endsWith('/attach-token')) {
            return http.Response('{"detail":"nope"}', 500);
          }
          return http.Response(
            jsonEncode({'sessions': [_relayJson('tui_a', 'agent_a')]}),
            200,
          );
        }),
        streamClient: TuiStreamClient(config: GatewayConfig.loopback),
      );
      addTearDown(viewModel.dispose);
      await viewModel.start('terminal-release');
      expect(
        viewModel.relaySessions.map((session) => session.sessionId),
        ['tui_a'],
        reason: 'the guard is vacuous unless there is a wrong session to '
            'silently attach to',
      );

      await viewModel.selectRelaySession('tui_gone');

      expect(viewModel.gatewaySession?.sessionId, isNot('tui_a'));
      expect(viewModel.hasSession, isFalse);
      expect(viewModel.statusLabel, contains('no longer open'));
    });

    // THE SANCTIONED FALLBACK, still working. Unpaired there is no TuiRepository
    // at all, Settings is announcing "Mock alpha data", and the demo terminal is
    // labelled in the status line. Removing this case would let a fix that
    // simply deleted the demo path pass everything above.
    test('unpaired still gets the demo terminal, and it says so', () async {
      final fallback = _SpyAlphaRepository();
      final viewModel = TuiViewModel(fallbackRepository: fallback);
      addTearDown(viewModel.dispose);

      await viewModel.start('terminal-release');

      expect(fallback.loadTerminalSessionCalls, ['terminal-release']);
      expect(viewModel.statusLabel, contains('Mock terminal'));
      expect(viewModel.scrollbackText, isNotEmpty);
    });
  });

  group('approval scopes come from the tower, not from a node name', () {
    // `_hasOption` fell back to `{'work-vm-02','laptop','vps-prod'}.contains
    // (approval.node)` to keep the demo clickable. The guard was on the node
    // NAME, and `laptop` is a name a real host has — so a live approval from an
    // agent on a machine called `laptop` had scoped approvals enabled whatever
    // the tower offered. An invented authority, presented as the tower's.
    test('a live approval on a node named "laptop" offers only what it offers',
        () {
      final viewModel = ApprovalDetailViewModel(const MockAlphaRepository());

      final actions = viewModel.moreActionsFor(_liveApproval(
        node: 'laptop',
        options: const ['deny'],
      ));
      final byKind = {for (final action in actions) action.kind: action};

      expect(byKind[ApprovalMoreActionKind.approveOnce]?.enabled, isFalse);
      expect(byKind[ApprovalMoreActionKind.approveForSession]?.enabled, isFalse);
      expect(byKind[ApprovalMoreActionKind.approveForAgent]?.enabled, isFalse);
      expect(byKind[ApprovalMoreActionKind.deny]?.enabled, isTrue);
    });

    // POSITIVE HALF: offered scopes are still enabled, on any node name.
    test('offered scopes are enabled on that same node', () {
      final viewModel = ApprovalDetailViewModel(const MockAlphaRepository());

      final actions = viewModel.moreActionsFor(_liveApproval(
        node: 'laptop',
        options: const ['approve_once', 'approve_for_session'],
      ));
      final byKind = {for (final action in actions) action.kind: action};

      expect(byKind[ApprovalMoreActionKind.approveOnce]?.enabled, isTrue);
      expect(byKind[ApprovalMoreActionKind.approveForSession]?.enabled, isTrue);
      expect(byKind[ApprovalMoreActionKind.approveForAgent]?.enabled, isFalse);
    });
  });
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

Future<void> _pumpAgentDetail(
  WidgetTester tester,
  AlphaRepository repository, {
  required String? argument,
}) async {
  await tester.pumpWidget(
    MaterialApp(
      onGenerateRoute: (_) => MaterialPageRoute<void>(
        settings: RouteSettings(name: '/agents/detail', arguments: argument),
        builder: (_) => AgentDetailScreen(repository: repository),
      ),
    ),
  );
  await tester.pumpAndSettle();
}

/// The real paired repository, over a scripted tower.
GatewayAlphaRepository _liveRepository(
  Object? Function(http.Request request) handler,
) {
  final client = _apiClient(handler);
  return GatewayAlphaRepository(
    dashboardRepository: DashboardRepository(client),
    agentsRepository: AgentsRepository(client),
    approvalsRepository: ApprovalsRepository(client),
    missionsRepository: MissionsRepository(client),
    notificationsRepository: NotificationsRepository(client),
    tuaRepository: TuaRepository(client),
  );
}

TuiRepository _tuiRepository(Object? Function(http.Request request) handler) =>
    TuiRepository(_apiClient(handler));

GatewayApiClient _apiClient(Object? Function(http.Request request) handler) {
  return GatewayApiClient(
    config: GatewayConfig.fromInput('http://127.0.0.1:8787/v1'),
    signer: const _StaticSigner(),
    httpClient: MockClient((request) async => handler(request) as http.Response),
  );
}

/// A healthy, quiet tower holding exactly one real agent.
http.Response _healthyTower(http.Request request) {
  final path = request.url.path;
  if (path.endsWith('/agents')) {
    return http.Response(
      jsonEncode({
        'agents': [
          {
            'agent_id': 'agent_1',
            'node_id': 'node_1',
            'display_name': 'Live Agent One',
            'status': 'running',
          },
        ],
      }),
      200,
    );
  }
  if (path.contains('/tua/requests')) {
    return http.Response(jsonEncode({'requests': <dynamic>[]}), 200);
  }
  if (path.endsWith('/notifications')) {
    return http.Response(jsonEncode({'notifications': <dynamic>[]}), 200);
  }
  if (path.endsWith('/approvals')) {
    return http.Response(jsonEncode({'approvals': <dynamic>[]}), 200);
  }
  if (path.endsWith('/missions')) {
    return http.Response(jsonEncode({'missions': <dynamic>[]}), 200);
  }
  if (path.endsWith('/inventory')) {
    return http.Response(jsonEncode({'nodes': <dynamic>[]}), 200);
  }
  return http.Response('{}', 200);
}

Map<String, dynamic> _relayJson(String sessionId, String agentId) {
  final now = DateTime.now().toUtc().toIso8601String();
  return {
    'session_id': sessionId,
    'agent_id': agentId,
    'node_id': 'node_1',
    'user_device_id': '__relay__',
    'state': 'active',
    'command': 'bash',
    'working_directory': '/srv',
    'created_at': now,
    'last_activity_at': now,
    'risk_level': 'high',
    'risk_label': 'agent terminal mirror',
    'output_retention_enabled': false,
  };
}

/// A gateway-shaped approval: `constraints` is the tower's offered option list,
/// exactly as `_approvalFromGateway` fills it.
ApprovalAlpha _liveApproval({
  required String node,
  required List<String> options,
}) {
  return ApprovalAlpha(
    id: 'appr_live',
    title: 'shell approval requested',
    agentName: 'agent_1',
    node: node,
    session: 'sess_1',
    risk: 'high',
    state: 'pending',
    requestedTool: 'shell',
    summary: 'Run a migration',
    payloadPreview: '{}',
    expiresIn: '5m',
    constraints: options,
  );
}

/// Records what the demo repository was asked for, so a test can assert it was
/// never asked at all.
class _SpyAlphaRepository extends MockAlphaRepository {
  final List<String> loadAgentCalls = [];
  final List<String> loadTerminalSessionCalls = [];

  @override
  Future<FleetAgent> loadAgent(String agentId) {
    loadAgentCalls.add(agentId);
    return super.loadAgent(agentId);
  }

  @override
  Future<TerminalSessionAlpha> loadTerminalSession(String sessionId) {
    loadTerminalSessionCalls.add(sessionId);
    return super.loadTerminalSession(sessionId);
  }
}

class _StaticSigner implements DeviceRequestSigner {
  const _StaticSigner();

  @override
  ClearanceKeyProtection get protection =>
      ClearanceKeyProtection.developmentExportableEd25519;

  @override
  Future<SignedRequestHeaders> sign({
    required String method,
    required String pathWithQuery,
    required List<int> body,
  }) async {
    return const SignedRequestHeaders({
      'X-HMCP-Device-Id': 'dev_test',
      'X-HMCP-Timestamp': '1',
      'X-HMCP-Nonce': 'nonce-test',
      'X-HMCP-Signature': 'signature-test',
    });
  }
}

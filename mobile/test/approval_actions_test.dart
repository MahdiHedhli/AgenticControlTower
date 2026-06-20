import 'package:flutter_test/flutter_test.dart';
import 'package:agentic_control_tower/src/repositories/mock_alpha_repository.dart';
import 'package:agentic_control_tower/src/viewmodels/alpha_viewmodels.dart';

void main() {
  test('more menu exposes functional approval + intervention actions', () async {
    final viewModel = ApprovalDetailViewModel(const MockAlphaRepository());
    final approval = await viewModel.load('appr-shell');

    final actions = viewModel.moreActionsFor(approval);
    final byKind = {for (final action in actions) action.kind: action};

    expect(byKind[ApprovalMoreActionKind.approveOnce]?.enabled, isTrue);
    expect(byKind[ApprovalMoreActionKind.deny]?.enabled, isTrue);
    expect(byKind[ApprovalMoreActionKind.approveForSession]?.enabled, isTrue);
    expect(byKind[ApprovalMoreActionKind.approveForAgent]?.enabled, isTrue);
    expect(byKind[ApprovalMoreActionKind.approveForever]?.enabled, isTrue);
    expect(byKind[ApprovalMoreActionKind.browserAssistance]?.enabled, isTrue);
    // Interventions are now live (was: placeholder/planned).
    expect(byKind[ApprovalMoreActionKind.pauseAgent]?.enabled, isTrue);
    expect(byKind[ApprovalMoreActionKind.stopTask]?.enabled, isTrue);
    expect(byKind[ApprovalMoreActionKind.stopAgent]?.enabled, isTrue);
  });

  test('scoped approval actions return selected scope', () async {
    final viewModel = ApprovalDetailViewModel(const MockAlphaRepository());

    final sessionApproval = await viewModel.approveForSession('appr-shell');
    final agentApproval = await viewModel.approveForAgent('appr-shell');

    expect(sessionApproval.state, 'approved');
    expect(sessionApproval.decisionScope, 'session');
    expect(agentApproval.state, 'approved');
    expect(agentApproval.decisionScope, 'agent');
  });
}

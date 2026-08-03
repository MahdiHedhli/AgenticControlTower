/// Humanize the gateway's wire-level approval option tokens.
///
/// Failure mode D2: the approval detail screen listed the gateway's raw option
/// tokens (`approve_once`, `approve_for_session`, …) under a heading that
/// claimed they were the operator's own constraints. Wire values are not
/// operator-facing copy.
///
/// Unknown values pass through untouched — mock/demo approvals already carry
/// human sentences here, and inventing a translation for an unrecognised token
/// would be worse than showing it.
String humanizeApprovalOption(String option) {
  return switch (option) {
    'approve_once' => 'Approve once',
    'approve_for_session' => 'Approve for this session',
    'approve_for_agent' => 'Approve for this agent',
    'approve_permanent' || 'approve_forever' => 'Approve as a standing order',
    'deny' => 'Deny',
    'modify' => 'Send a modified response',
    'needs_info' => 'Ask for more information',
    _ => option,
  };
}

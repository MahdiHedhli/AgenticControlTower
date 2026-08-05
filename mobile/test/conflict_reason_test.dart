/// A 409 must tell the operator which outcome actually happened.
///
/// `_gatewayReason` took only the status code and threw
/// `GatewayApiException.body` away, so every 409 in the app rendered one
/// sentence: "That decision was already recorded."
///
/// That is false for most conflicts and dangerous for one. An operator who taps
/// Deny on a clearance a standing grant already approved was told their
/// decision landed — and walked away believing they had stopped something that
/// in fact ran. `mint_grant_for_decision` makes that a routine race, not an
/// exotic one.
library;

import 'dart:convert';

import 'package:agentic_control_tower/src/api/gateway_api_client.dart';
import 'package:agentic_control_tower/src/operator_error.dart';
import 'package:flutter_test/flutter_test.dart';

String _reasonFor(String code) {
  return operatorErrorMessage(
    GatewayApiException(
      statusCode: 409,
      body: jsonEncode({
        'detail': {'error': code, 'state': 'approved'}
      }),
    ),
  );
}

void main() {
  test('an already-approved conflict never claims the denial was recorded', () {
    final reason = _reasonFor('approval_already_approved');

    expect(reason, contains('APPROVED'));
    expect(
      reason.toLowerCase(),
      isNot(contains('already recorded')),
      reason: 'telling the operator their decision was recorded, when it was '
          'not and the action ran, is the whole defect',
    );
  });

  test('an expired conflict says nothing was approved', () {
    for (final code in ['approval_already_expired', 'approval_expired']) {
      final reason = _reasonFor(code);
      expect(reason.toLowerCase(), contains('expired'));
      expect(reason.toLowerCase(), contains('nothing was approved'),
          reason: '$code must not imply a decision landed');
    }
  });

  test('a cancelled conflict says the agent withdrew it', () {
    expect(_reasonFor('approval_cancelled').toLowerCase(), contains('withdrew'));
  });

  test('a consumed conflict admits the action already ran', () {
    final reason = _reasonFor('approval_consumed');
    expect(reason.toLowerCase(), contains('carried out'));
  });

  test('a replayed request is distinguished from an approval conflict', () {
    final reason = _reasonFor('request_replayed');
    expect(reason.toLowerCase(), contains('twice'));
    expect(reason.toLowerCase(), isNot(contains('decision')),
        reason: 'a replay never reached approval logic at all');
  });

  test('an unknown or unparseable conflict falls back to something TRUE', () {
    for (final body in ['', 'not json', '{"detail":"plain prose"}']) {
      final reason = operatorErrorMessage(
        GatewayApiException(statusCode: 409, body: body),
      );
      expect(reason.toLowerCase(), contains('no longer open'));
      expect(
        reason.toLowerCase(),
        isNot(contains('already recorded')),
        reason: 'when the outcome is unknown, say only what is certain rather '
            'than guessing which of six things happened',
      );
    }
  });
}

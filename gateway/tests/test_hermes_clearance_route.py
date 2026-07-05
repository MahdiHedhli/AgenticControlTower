"""Characterization gate: POST /v1/hermes/tools/approval_requested must produce a
VERIFIABLE clearance (act.clearance.v2), identical in contract semantics to the
canonical runtime path (/v1/runtime/approvals -> runtime_adapter.request_clearance).

Pre-fix behavior at 003-mobile-beta @ 8cbf226 (verified by running these tests
without the xfail gate; see docstrings):

* The route hand-built a ``CreateApprovalRequest`` and DROPPED the clearance
  contract fields carried by ``HermesApprovalRequestedRequest``:
  params_fingerprint, operator_message, audit_correlation_id, short_code,
  extensions (also aircraft / requested_by).
* Because ``extensions`` was dropped, the server-computed fingerprint became
  ``build_params_fingerprint(payload_redacted, extensions={})`` — NOT the
  client's canonical ``build_params_fingerprint(payload_redacted, extensions)``.
  (Note: the silent ``content_hash(payload)`` fallback at store.create_approval
  never triggered on this route, because _create_approval_request always passes
  contract fields; the divergence class is the same — a non-canonical
  fingerprint bound into the proof — but the mechanism is the dropped
  extensions, not the store fallback. The store fallback is closed separately
  in test_store_rejects_missing_params_fingerprint.)
* The client-requested short_code was dropped and regenerated server-side, so
  an aircraft-style proof verification over the values the CLIENT knows
  (its canonical fingerprint + its requested short code) FAILED.

The tests below assert the POST-fix contract. They are gated with
``xfail(strict=True)`` so the branch stays green until the fix lands; the fix
commit removes the gate.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from hermes_gateway.clearance_contract import (
    ClearanceProofMaterial,
    build_params_fingerprint,
    build_short_code,
    extensions_digest,
    tower_public_key_b64,
    verify_clearance_proof,
)

# Pre-fix gate: these tests demonstrably FAIL at 8cbf226 (run with --runxfail or
# remove the marker to reproduce). strict=True keeps the branch green pre-fix and
# forces the marker's removal in the fix commit (XPASS would fail the suite).
PRE_FIX_GATE = pytest.mark.xfail(
    strict=True,
    reason=(
        "hermes_approval_requested hand-builds CreateApprovalRequest and drops "
        "params_fingerprint/short_code/operator_message/audit_correlation_id/"
        "extensions — fix pending (delegate to runtime_adapter.request_clearance)"
    ),
)

PAYLOAD_REDACTED = {"tool": "shell", "arg_keys": ["command", "cwd"]}
EXTENSIONS = {"agentickvm": {"capability": "power_control"}}
CLIENT_SHORT_CODE = "AAAA111122"
AUDIT_CORRELATION_ID = "corr-hermes-gate-1"


def _post_hermes_approval(client: TestClient, **overrides) -> dict:
    body = {
        "requested_tool": "shell",
        "risk_level": "high",
        "risk_family": "destructive",
        "summary": "Run a redacted shell command.",
        "payload_redacted": PAYLOAD_REDACTED,
        "agent_id": "agent_mock",
        "session_id": "sess_mock",
        "expires_in_seconds": 300,
        "suggested_scopes": ["once"],
        "action_id": "act_hermes_gate",
        "params_fingerprint": build_params_fingerprint(
            payload_redacted=PAYLOAD_REDACTED,
            extensions=EXTENSIONS,
        ),
        "short_code": CLIENT_SHORT_CODE,
        "operator_message": "please approve this shell command",
        "audit_correlation_id": AUDIT_CORRELATION_ID,
        "extensions": EXTENSIONS,
    }
    body.update(overrides)
    response = client.post("/v1/hermes/tools/approval_requested", json=body)
    assert response.status_code == 201
    return response.json()


@PRE_FIX_GATE
def test_hermes_route_forwards_all_clearance_contract_fields(client: TestClient) -> None:
    """The Hermes route must not drop contract fields the schema carries.

    Pre-fix failure (observed): stored params_fingerprint was the
    extensions-dropped recompute, short_code was regenerated,
    operator_message / audit_correlation_id were None and extensions {}.
    """
    canonical_fp = build_params_fingerprint(
        payload_redacted=PAYLOAD_REDACTED,
        extensions=EXTENSIONS,
    )
    approval = _post_hermes_approval(client)
    stored = client.app.state.store.get_approval(approval["approval_id"])

    # (a) canonical fingerprint over (payload_redacted, extensions) — not the
    # extensions-dropped recompute, and never a payload-hash backfill.
    assert stored["params_fingerprint"] == canonical_fp
    # client-requested short code honored (same behavior as the runtime route)
    assert stored["short_code"] == CLIENT_SHORT_CODE
    # operator message sanitized, not dropped
    assert stored["operator_message"]
    assert stored["audit_correlation_id"] == AUDIT_CORRELATION_ID
    assert stored["extensions"] == EXTENSIONS


@PRE_FIX_GATE
def test_hermes_route_clearance_verifies_with_client_known_material(
    client: TestClient,
) -> None:
    """Aircraft-style verification: rebuild the proof material from values the
    CLIENT can derive (its canonical fingerprint, its requested short code, the
    returned envelope) and verify the tower's Ed25519 proof over it.

    Pre-fix failure (observed): verify_clearance_proof returned False because
    the proof was signed over a non-canonical fingerprint and a regenerated
    short code.
    """
    canonical_fp = build_params_fingerprint(
        payload_redacted=PAYLOAD_REDACTED,
        extensions=EXTENSIONS,
    )
    approval = _post_hermes_approval(client)
    stored = client.app.state.store.get_approval(approval["approval_id"])

    material = ClearanceProofMaterial(
        approval_id=approval["approval_id"],
        params_fingerprint=canonical_fp,
        short_code=CLIENT_SHORT_CODE,
        risk_family=stored["risk_family"],
        expires_at=stored["expires_at"],
        tower_id=stored["tower_id"],
        contract_version=stored["contract_version"],
        extensions_digest=extensions_digest(EXTENSIONS),
    )
    assert verify_clearance_proof(
        public_key_b64=tower_public_key_b64(client.app.state.settings),
        material=material,
        proof=stored["proof"] or {},
    )


@PRE_FIX_GATE
def test_hermes_route_derives_short_code_from_canonical_fingerprint(
    client: TestClient,
) -> None:
    """Without a client-requested short code, the derived short code must bind
    to the CANONICAL fingerprint (sha256(approval_id:fingerprint)[:10]).

    Pre-fix failure (observed): the derivation used the extensions-dropped
    fingerprint, so a client recomputing the derivation from its canonical
    fingerprint got a mismatch.
    """
    canonical_fp = build_params_fingerprint(
        payload_redacted=PAYLOAD_REDACTED,
        extensions=EXTENSIONS,
    )
    approval = _post_hermes_approval(client, short_code=None)
    stored = client.app.state.store.get_approval(approval["approval_id"])
    assert stored["short_code"] == build_short_code(approval["approval_id"], canonical_fp)

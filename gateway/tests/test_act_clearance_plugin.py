"""Tests for the in-repo Hermes act-clearance plugin (integrations/hermes/act-clearance).

Two concerns:

1. PARITY — the plugin is stdlib-only and cannot import hermes_gateway, so it
   mirrors the canonical fingerprint / short-code derivations. These tests pin
   the mirror byte-for-byte against the gateway implementation.
2. FAIL-CLOSED VERIFICATION — the clearance poll loop must verify the returned
   envelope (params_fingerprint / derived short_code / proof shape) before
   treating "approved" as allow, end-to-end against a real gateway app.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from hermes_gateway.clearance_contract import (
    build_params_fingerprint,
    build_short_code,
)
from hermes_gateway.security import canonical_json, content_hash

_PLUGIN_PATH = (
    Path(__file__).resolve().parents[2]
    / "integrations"
    / "hermes"
    / "act-clearance"
    / "__init__.py"
)


def _load_plugin():
    spec = importlib.util.spec_from_file_location("act_clearance_plugin", _PLUGIN_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault("act_clearance_plugin", module)
    spec.loader.exec_module(module)
    return module


plugin = _load_plugin()

PARITY_VALUES = [
    {},
    {"tool": "shell", "arg_keys": ["command", "cwd"]},
    {"nested": {"b": 2, "a": [1, "x", None, True]}, "unicode": "héllo — ✈"},
    {"empty_list": [], "zero": 0, "false": False, "none": None},
]


@pytest.mark.parametrize("payload", PARITY_VALUES)
def test_canonical_json_and_content_hash_parity(payload: dict[str, Any]) -> None:
    assert plugin._canonical_json(payload) == canonical_json(payload)
    assert plugin._content_hash(payload) == content_hash(payload)


@pytest.mark.parametrize("payload", PARITY_VALUES)
@pytest.mark.parametrize("extensions", [None, {}, {"agentickvm": {"capability": "power"}}])
def test_params_fingerprint_parity(payload: dict[str, Any], extensions) -> None:
    assert plugin._params_fingerprint(payload, extensions) == build_params_fingerprint(
        payload_redacted=payload,
        extensions=extensions,
    )


def test_derived_short_code_parity() -> None:
    fingerprint = build_params_fingerprint(payload_redacted={"a": 1}, extensions={})
    assert plugin._derived_short_code("appr_x", fingerprint) == build_short_code(
        "appr_x", fingerprint
    )


# --- end-to-end: plugin clearance gate against a real gateway app ------------


def _wire_plugin_to_client(monkeypatch: pytest.MonkeyPatch, client: TestClient) -> None:
    """Route the plugin's hermes-local HTTP through the TestClient."""

    def fake_request(method: str, path: str, payload, timeout: float):
        if method == "POST":
            response = client.post(f"/v1{path}", json=payload)
        else:
            response = client.get(f"/v1{path}")
        assert response.status_code < 500, response.text
        return response.json() if response.content else {}

    monkeypatch.setattr(plugin, "_request", fake_request)
    monkeypatch.setenv("ACT_CLEARANCE_TIMEOUT", "5")
    monkeypatch.setenv("ACT_CLEARANCE_POLL", "0.01")


def _approve_first_pending(client: TestClient) -> None:
    store = client.app.state.store
    pending = [a for a in store.list_approvals() if a["state"] == "pending"]
    assert pending
    store.resolve_approval(
        pending[0]["approval_id"],
        "approved",
        decision_scope="once",
        decision_actor_device_id="dev_test",
        decision_metadata={},
    )


def test_relay_clearance_allows_verified_approval(
    monkeypatch: pytest.MonkeyPatch, client: TestClient
) -> None:
    """Operator approves; the returned clearance is canonical and verifiable;
    the plugin allows the tool (returns None)."""
    _wire_plugin_to_client(monkeypatch, client)

    original_post = plugin._post

    def approving_post(path: str, payload, timeout: float = 10.0):
        if path == "/hermes/tools/approval_status":
            _approve_first_pending(client)
        return original_post(path, payload, timeout)

    monkeypatch.setattr(plugin, "_post", approving_post)

    result = plugin._relay_clearance("shell", {"command": "ls", "cwd": "/"}, "sess_mock")
    assert result is None


def test_relay_clearance_blocks_on_fingerprint_mismatch(
    monkeypatch: pytest.MonkeyPatch, client: TestClient
) -> None:
    """A gateway (or MITM) returning approved with a clearance bound to
    DIFFERENT params must be blocked, not allowed (fail-closed)."""
    _wire_plugin_to_client(monkeypatch, client)

    original_post = plugin._post

    def tampering_post(path: str, payload, timeout: float = 10.0):
        if path == "/hermes/tools/approval_status":
            _approve_first_pending(client)
            status = original_post(path, payload, timeout)
            status["params_fingerprint"] = content_hash({"different": "params"})
            return status
        return original_post(path, payload, timeout)

    monkeypatch.setattr(plugin, "_post", tampering_post)

    result = plugin._relay_clearance("shell", {"command": "ls"}, "sess_mock")
    assert result is not None
    assert result["action"] == "block"
    assert "params_fingerprint mismatch" in result["message"]


def test_relay_clearance_blocks_on_missing_proof(
    monkeypatch: pytest.MonkeyPatch, client: TestClient
) -> None:
    _wire_plugin_to_client(monkeypatch, client)

    original_post = plugin._post

    def stripping_post(path: str, payload, timeout: float = 10.0):
        if path == "/hermes/tools/approval_status":
            _approve_first_pending(client)
            status = original_post(path, payload, timeout)
            status["proof"] = None
            return status
        return original_post(path, payload, timeout)

    monkeypatch.setattr(plugin, "_post", stripping_post)

    result = plugin._relay_clearance("shell", {"command": "ls"}, "sess_mock")
    assert result is not None
    assert result["action"] == "block"
    assert "missing clearance proof" in result["message"]


def test_relay_clearance_verification_binds_short_code(
    monkeypatch: pytest.MonkeyPatch, client: TestClient
) -> None:
    """The short code the operator confirms must be derived from the canonical
    fingerprint; a swapped code is rejected."""
    _wire_plugin_to_client(monkeypatch, client)

    original_post = plugin._post

    def code_swapping_post(path: str, payload, timeout: float = 10.0):
        if path == "/hermes/tools/approval_status":
            _approve_first_pending(client)
            status = original_post(path, payload, timeout)
            status["short_code"] = "AAAA111122"
            return status
        return original_post(path, payload, timeout)

    monkeypatch.setattr(plugin, "_post", code_swapping_post)

    result = plugin._relay_clearance("shell", {"command": "ls"}, "sess_mock")
    assert result is not None
    assert result["action"] == "block"
    assert "short_code mismatch" in result["message"]

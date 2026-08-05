"""A paired-device access token must not travel in the URL.

uvicorn logs the raw request target for every WebSocket upgrade on the
``uvicorn.error`` logger, which the LaunchAgent points at gateway.err.log. A
query-borne token is therefore written to disk in plaintext, where it outlives
its own 15 minute TTL by however long the log is kept. Measured on the live
host before this fix: 42 of 147 upgrade lines carried one.
"""

from __future__ import annotations

import logging

from hermes_gateway.main import _RedactUrlCredentials


class _FakeWebSocket:
    def __init__(self, headers=None, query=None):
        self.headers = headers or {}
        self.query_params = query or {}


def _token(**kwargs):
    from hermes_gateway.app import _websocket_token

    return _websocket_token(_FakeWebSocket(**kwargs))


def test_the_header_wins_over_the_query_string() -> None:
    """The whole point. When both are present the credential that does NOT get
    logged must be the one used, so a client mid-migration stops leaking."""
    token, source = _token(
        headers={"Authorization": "Bearer header_tok"},
        query={"access_token": "query_tok"},
    )
    assert (token, source) == ("header_tok", "header")


def test_the_query_form_still_works_but_is_named() -> None:
    """Left enabled so a phone build older than the header-sending one keeps
    streaming -- but the source is reported so the caller can log and gate it."""
    assert _token(query={"access_token": "query_tok"}) == ("query_tok", "query")


def test_a_blank_bearer_falls_through_rather_than_authenticating() -> None:
    """`Bearer ` with nothing after it must not become a token, and must not
    shadow a query token that would otherwise have worked."""
    assert _token(headers={"Authorization": "Bearer   "}) == (None, "none")
    token, source = _token(
        headers={"Authorization": "Bearer "}, query={"access_token": "q"}
    )
    assert (token, source) == ("q", "query")


def test_no_credential_at_all_is_reported_as_none() -> None:
    assert _token() == (None, "none")


def _render(msg: str, *args) -> str:
    record = logging.LogRecord("uvicorn.error", logging.INFO, __file__, 1, msg, args, None)
    _RedactUrlCredentials().filter(record)
    return record.getMessage()


def test_the_log_sink_redacts_tokens_from_request_lines() -> None:
    """Redacting at the SINK is the only mitigation that covers clients we have
    not shipped -- and the only one that covers attach_token at all."""
    rendered = _render(
        '%s - "WebSocket %s" [accepted]',
        "127.0.0.1:1",
        "/v1/events/stream?access_token=secret123",
    )
    assert "secret123" not in rendered
    assert "access_token=<redacted>" in rendered


def test_the_log_sink_covers_attach_token_and_bare_token() -> None:
    for param, secret in (("attach_token", "atk_abc"), ("token", "tok_xyz")):
        rendered = _render("%s", f"/v1/tui/attach?{param}={secret}")
        assert secret not in rendered, f"{param} leaked"
        assert f"{param}=<redacted>" in rendered


def test_redaction_stops_at_the_parameter_boundary() -> None:
    """It must not swallow the rest of the line -- an over-greedy pattern would
    destroy the request path and make the log useless for debugging."""
    rendered = _render("%s", "/v1/events/stream?access_token=secret&after=cur_42")
    assert "after=cur_42" in rendered
    assert "secret" not in rendered


def test_a_line_with_no_credential_is_untouched() -> None:
    line = '127.0.0.1:1 - "WebSocket /v1/events/stream?after=cur_9" [accepted]'
    assert _render("%s", line) == line

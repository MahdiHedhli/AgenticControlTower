"""Hermetic tests for the Hermes dashboard reverse proxy (Phase 4a).

No real :9120 dashboard is required. The upstream is faked with an
``httpx.MockTransport`` injected into the proxy's per-request client, so we can
assert exactly what the gateway sends upstream (token injection, forwarded
prefix, loopback Host, target confinement) and how it behaves when the
dashboard is unreachable.
"""

from __future__ import annotations

import asyncio

import httpx
import pytest

from conftest import pair_device, signature_headers, signed_request
from hermes_gateway.hermes_proxy import (
    FORWARDED_PREFIX,
    SESSION_TOKEN_HEADER,
    DashboardUnavailable,
    HermesDashboardProxy,
)

DASHBOARD_TOKEN = "dashboard-secret-token-xyz"


def _install_mock_upstream(app, captured: list[httpx.Request], *, status_code=200):
    """Point the gateway's proxy at an in-memory upstream and record requests."""
    proxy: HermesDashboardProxy = app.state.hermes_proxy

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(
            status_code,
            headers={"content-type": "text/plain"},
            content=b"upstream-body",
        )

    transport = httpx.MockTransport(handler)

    def factory() -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=transport, timeout=httpx.Timeout(5.0))

    proxy.new_request_client = factory  # type: ignore[method-assign]
    # Known token so we don't depend on env/scrape in the happy-path tests.
    proxy._token = DASHBOARD_TOKEN  # noqa: SLF001
    return proxy


def test_proxy_requires_auth(client):
    resp = client.get("/hermes/api/status")
    assert resp.status_code in (401, 403)


def test_authed_request_forwards_with_token_and_prefix(client):
    captured: list[httpx.Request] = []
    _install_mock_upstream(client.app, captured)
    paired = pair_device(client)

    resp = signed_request(
        client,
        "GET",
        "/hermes/api/status",
        private_key=paired["private_key"],
        device_id=paired["device"]["device_id"],
    )

    assert resp.status_code == 200
    assert resp.content == b"upstream-body"
    assert len(captured) == 1
    up = captured[0]
    # Target is the loopback dashboard, path preserved.
    assert up.url.host in ("127.0.0.1", "localhost", "::1")
    assert up.url.port == 9120
    assert up.url.path == "/api/status"
    # Gateway injected the dashboard token server-side.
    assert up.headers.get(SESSION_TOKEN_HEADER) == DASHBOARD_TOKEN
    # Forwarded-prefix so the dashboard rewrites absolute asset URLs.
    assert up.headers.get("x-forwarded-prefix") == FORWARDED_PREFIX
    assert up.headers.get("x-forwarded-proto") in ("http", "https")
    # Host forced to a loopback alias (DNS-rebinding guard).
    assert up.headers.get("host", "").startswith("127.0.0.1")


def test_phone_never_carries_dashboard_token(client):
    """A phone-supplied dashboard token header must be dropped, not trusted."""
    captured: list[httpx.Request] = []
    _install_mock_upstream(client.app, captured)
    paired = pair_device(client)

    # signed_request signs over the body+path; extra headers don't affect the
    # signature, so we add the spoof header on the underlying client call.
    headers = signature_headers(
        private_key=paired["private_key"],
        device_id=paired["device"]["device_id"],
        method="GET",
        path="/hermes/api/status",
    )
    headers[SESSION_TOKEN_HEADER] = "phone-forged-token"
    resp = client.get("/hermes/api/status", headers=headers)

    assert resp.status_code == 200
    up = captured[0]
    # The forged token never reaches upstream; only the gateway's token does.
    assert up.headers.get(SESSION_TOKEN_HEADER) == DASHBOARD_TOKEN


def test_path_is_confined_to_loopback_dashboard(client):
    """A crafted path cannot retarget another host (no SSRF / open proxy)."""
    captured: list[httpx.Request] = []
    _install_mock_upstream(client.app, captured)
    paired = pair_device(client)

    resp = signed_request(
        client,
        "GET",
        "/hermes/evil.example.com/api/status",
        private_key=paired["private_key"],
        device_id=paired["device"]["device_id"],
    )

    assert resp.status_code == 200
    up = captured[0]
    assert up.url.host in ("127.0.0.1", "localhost", "::1")
    assert up.url.port == 9120
    assert "evil.example.com" not in up.url.host


def test_dashboard_unreachable_is_clean_502(client):
    proxy: HermesDashboardProxy = client.app.state.hermes_proxy
    proxy._token = DASHBOARD_TOKEN  # noqa: SLF001

    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused")

    transport = httpx.MockTransport(boom)
    proxy.new_request_client = lambda: httpx.AsyncClient(  # type: ignore[method-assign]
        transport=transport, timeout=httpx.Timeout(5.0)
    )
    paired = pair_device(client)

    resp = signed_request(
        client,
        "GET",
        "/hermes/api/status",
        private_key=paired["private_key"],
        device_id=paired["device"]["device_id"],
    )
    assert resp.status_code == 502


# --------------------------------------------------------------------------- #
# Unit-level behaviour of the proxy itself (no FastAPI in the loop).
# --------------------------------------------------------------------------- #


def _install_custom_upstream(app, *, status_code=200, headers, content):
    """Point the gateway's proxy at an in-memory upstream returning a fixed
    response (custom headers + body), so we can assert what reaches the phone."""
    proxy: HermesDashboardProxy = app.state.hermes_proxy

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status_code, headers=headers, content=content)

    transport = httpx.MockTransport(handler)
    proxy.new_request_client = lambda: httpx.AsyncClient(  # type: ignore[method-assign]
        transport=transport, timeout=httpx.Timeout(5.0)
    )
    proxy._token = DASHBOARD_TOKEN  # noqa: SLF001
    return proxy


def test_html_response_rewrites_real_token_to_placeholder(client):
    """The real dashboard token in the SPA bootstrap must never reach the phone."""
    html = (
        b"<!doctype html><html><head>"
        b'<script>window.__HERMES_SESSION_TOKEN__="REALSECRET";</script>'
        b"</head><body>ok</body></html>"
    )
    _install_custom_upstream(
        client.app,
        headers={"content-type": "text/html; charset=utf-8"},
        content=html,
    )
    paired = pair_device(client)

    resp = signed_request(
        client,
        "GET",
        "/hermes/",
        private_key=paired["private_key"],
        device_id=paired["device"]["device_id"],
    )

    assert resp.status_code == 200
    body = resp.content
    # The real token is gone; a non-functional placeholder is present instead.
    assert b"REALSECRET" not in body
    assert b"proxied-by-act" in body
    # The bootstrap assignment is preserved (not stripped) so the SPA still reads it.
    assert b"window.__HERMES_SESSION_TOKEN__=" in body


def test_credential_response_headers_are_scrubbed(client):
    """set-cookie / x-hermes-session-token / authorization must not reach the phone."""
    _install_custom_upstream(
        client.app,
        headers={
            "content-type": "text/html; charset=utf-8",
            "set-cookie": "hermes_session=REALSECRET; HttpOnly",
            SESSION_TOKEN_HEADER: "REALSECRET",
            "authorization": "Bearer REALSECRET",
            "x-safe": "keepme",
        },
        content=b"<html><body>hi</body></html>",
    )
    paired = pair_device(client)

    resp = signed_request(
        client,
        "GET",
        "/hermes/",
        private_key=paired["private_key"],
        device_id=paired["device"]["device_id"],
    )

    assert resp.status_code == 200
    lowered = {k.lower() for k in resp.headers.keys()}
    assert "set-cookie" not in lowered
    assert SESSION_TOKEN_HEADER.lower() not in lowered
    assert "authorization" not in lowered
    # Non-credential headers still pass through.
    assert resp.headers.get("x-safe") == "keepme"


def test_non_html_response_passed_through_but_headers_scrubbed(client):
    """JSON/asset responses are still proxied unchanged, with credentials scrubbed."""
    payload = b'{"status":"ok","note":"REALSECRET-in-json-is-fine"}'
    _install_custom_upstream(
        client.app,
        headers={
            "content-type": "application/json",
            "set-cookie": "x=y",
            SESSION_TOKEN_HEADER: "REALSECRET",
        },
        content=payload,
    )
    paired = pair_device(client)

    resp = signed_request(
        client,
        "GET",
        "/hermes/api/status",
        private_key=paired["private_key"],
        device_id=paired["device"]["device_id"],
    )

    assert resp.status_code == 200
    # Body is unaffected (not HTML, so no rewrite — passed through verbatim).
    assert resp.content == payload
    lowered = {k.lower() for k in resp.headers.keys()}
    assert "set-cookie" not in lowered
    assert SESSION_TOKEN_HEADER.lower() not in lowered


def test_unit_rewrite_passes_through_when_token_absent():
    from hermes_gateway.hermes_proxy import rewrite_spa_token

    body = b"<html><body>no token here</body></html>"
    assert rewrite_spa_token(body) == body
    # Binary / non-utf8 bodies are returned unchanged, never crash.
    binary = b"\xff\xfe\x00\x01not-text"
    assert rewrite_spa_token(binary) == binary


def test_unit_rewrite_scrubs_non_urlsafe_tokens():
    # JWT (has '.') and base64 (has '+', '/', '=') tokens must be scrubbed too,
    # not just secrets.token_urlsafe-style values.
    from hermes_gateway.hermes_proxy import SPA_TOKEN_PLACEHOLDER, rewrite_spa_token

    for tok in ("eyJhbGc.eyJzdWI.SflKxw", "ab+cd/ef==", "a.b-c_d"):
        body = f'<script>window.__HERMES_SESSION_TOKEN__="{tok}";</script>'.encode()
        out = rewrite_spa_token(body).decode()
        assert tok not in out, f"real token {tok!r} leaked"
        assert SPA_TOKEN_PLACEHOLDER in out
        # The assignment is preserved so the SPA's JS doesn't break.
        assert "__HERMES_SESSION_TOKEN__" in out


def test_unit_rewrite_scrubs_literal_token_elsewhere():
    # Defense-in-depth: a known token appearing OUTSIDE the bootstrap assignment
    # (e.g. inlined in a JS chunk) is scrubbed when known_token is supplied.
    from hermes_gateway.hermes_proxy import SPA_TOKEN_PLACEHOLDER, rewrite_spa_token

    tok = "eyJhbGc.eyJzdWI.SflKxw"
    body = (
        f'<script>window.__HERMES_SESSION_TOKEN__="{tok}";'
        f'var x="leaked-again-{tok}";</script>'
    ).encode()
    out = rewrite_spa_token(body, known_token=tok).decode()
    assert tok not in out
    assert SPA_TOKEN_PLACEHOLDER in out


def test_unit_path_confinement_neutralises_absolute_urls():
    proxy = HermesDashboardProxy("http://127.0.0.1:9120")
    # Caller-supplied paths that try to smuggle a host are neutralised.
    assert proxy.upstream_url("http://evil/api").startswith("http://127.0.0.1:9120/")
    assert "evil" not in httpx.URL(proxy.upstream_url("//evil/api")).host
    assert proxy.upstream_url("api/status") == "http://127.0.0.1:9120/api/status"


class _FakeUpstreamWS:
    """Minimal stand-in for a `websockets` client connection that echoes."""

    def __init__(self, recorder: dict):
        self._queue: asyncio.Queue = asyncio.Queue()
        self._closed = False
        self._recorder = recorder

    async def send(self, message):
        # Echo back with a marker so the client can assert round-trip.
        self._recorder.setdefault("sent", []).append(message)
        await self._queue.put(f"echo:{message}")

    async def close(self, *args, **kwargs):
        self._closed = True
        await self._queue.put(None)

    def __aiter__(self):
        return self

    async def __anext__(self):
        item = await self._queue.get()
        if item is None:
            raise StopAsyncIteration
        return item


def test_ws_proxy_requires_auth(client):
    from starlette.websockets import WebSocketDisconnect

    # No access_token -> policy-violation close before the upstream handshake.
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/hermes/api/pty"):
            pass


def test_ws_proxy_bridges_frames(client, monkeypatch):
    proxy = client.app.state.hermes_proxy
    proxy._token = DASHBOARD_TOKEN  # noqa: SLF001

    recorder: dict = {}
    captured_url: dict = {}

    async def fake_connect(url, **kwargs):
        captured_url["url"] = url
        captured_url["headers"] = kwargs.get("additional_headers", {})
        return _FakeUpstreamWS(recorder)

    import websockets

    monkeypatch.setattr(websockets, "connect", fake_connect)

    paired = pair_device(client)
    access_token = paired["tokens"]["access_token"]

    with client.websocket_connect(
        f"/hermes/api/pty?access_token={access_token}"
    ) as ws:
        ws.send_text("hello")
        assert ws.receive_text() == "echo:hello"

    # Upstream URL targeted the loopback dashboard and carried the dashboard
    # token as ?token= (never exposed to the phone).
    assert captured_url["url"].startswith("ws://127.0.0.1:9120/api/pty")
    assert f"token={DASHBOARD_TOKEN}" in captured_url["url"]
    assert recorder["sent"] == ["hello"]


def test_unit_token_scrape_tolerates_dashboard_down():
    async def run() -> None:
        def boom(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("down")

        client = httpx.AsyncClient(transport=httpx.MockTransport(boom))
        proxy = HermesDashboardProxy("http://127.0.0.1:9120", client=client)
        with pytest.raises(DashboardUnavailable):
            await proxy.session_token()
        await proxy.aclose()

    asyncio.run(run())


def test_unit_token_scraped_from_spa_and_cached():
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        body = '<script>window.__HERMES_SESSION_TOKEN__="scraped-tok-123";</script>'
        return httpx.Response(200, text=body)

    async def run() -> None:
        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        proxy = HermesDashboardProxy("http://127.0.0.1:9120", client=client)
        assert await proxy.session_token() == "scraped-tok-123"
        # Cached: a second call does not re-fetch.
        assert await proxy.session_token() == "scraped-tok-123"
        assert calls["n"] == 1
        # And the WS url carries the token as ?token=.
        assert "token=scraped-tok-123" in proxy.ws_upstream_url("api/pty")
        await proxy.aclose()

    asyncio.run(run())

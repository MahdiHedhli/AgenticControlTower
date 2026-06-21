"""Reverse proxy from the ACT gateway to a loopback Hermes dashboard.

The paired phone reaches the Hermes agent dashboard *through* the gateway at
``/hermes/*`` — never directly. The gateway is the only thing that ever holds
the dashboard's session token; the phone authenticates to the gateway with its
own device/operator credential (the same one that gates ``/v1/agents`` etc.)
and never sees or sends the dashboard token.

Security envelope (see Phase-4a grounding):

* The proxy target is ALWAYS the single configured loopback dashboard. The
  ``{path}`` from the incoming URL is only ever appended to that fixed base —
  it can never retarget another host (no SSRF / open-proxy).
* On every upstream request the gateway injects the dashboard session token
  (``X-Hermes-Session-Token``) server-side and forces a loopback ``Host`` so
  the dashboard's DNS-rebinding / host guard accepts the call.
* ``X-Forwarded-Prefix: /hermes`` + ``X-Forwarded-Proto`` are injected so the
  dashboard rewrites its absolute asset URLs under the gateway mount point.
* The dashboard token is acquired tolerantly: if the env var is unset we try a
  best-effort scrape of the SPA bootstrap, cached for the process. If the
  dashboard is unreachable we surface a clean 502 — we never crash the gateway.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

import httpx

# Header the dashboard validates the session token on (constant-time HMAC).
SESSION_TOKEN_HEADER = "X-Hermes-Session-Token"
# Env var the dashboard reads its token from when launched by the gateway.
SESSION_TOKEN_ENV = "HERMES_DASHBOARD_SESSION_TOKEN"
FORWARDED_PREFIX = "/hermes"

# Hop-by-hop headers must not be forwarded across the proxy boundary.
_HOP_BY_HOP = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailers",
        "transfer-encoding",
        "upgrade",
        "host",
        "content-length",
        # We decode the upstream body (httpx aiter_bytes) before re-streaming,
        # so let the upstream answer in identity and avoid double-encoding.
        "accept-encoding",
    }
)

# Matches the SPA bootstrap injection: window.__HERMES_SESSION_TOKEN__="...".
# The capture is any non-quote run so it covers ANY token format the dashboard
# might use (urlsafe, JWT with '.', base64 with '+'/'/'/'='), not just urlsafe.
_SPA_TOKEN_RE = re.compile(
    r"""__HERMES_SESSION_TOKEN__\s*=\s*["']([^"']*)["']"""
)

# Credential-bearing RESPONSE headers that must NEVER reach the phone. The phone
# authenticates to the gateway with its own device credential and never needs
# the dashboard's session token / cookie. Scrubbed case-insensitively.
_RESPONSE_CREDENTIAL_HEADERS = frozenset(
    {
        "set-cookie",
        SESSION_TOKEN_HEADER.lower(),
        "authorization",
    }
)

# Non-functional placeholder we substitute for the real dashboard token in the
# SPA bootstrap. The SPA will echo this back on its own /hermes/api and ?token=
# calls; the gateway strips the inbound token + injects the real one (REST) and
# uses the gateway-resolved token for upstream WS, so the placeholder is inert.
SPA_TOKEN_PLACEHOLDER = "proxied-by-act"


def scrub_response_headers(headers: object) -> dict[str, str]:
    """Copy response headers minus hop-by-hop *and* credential-bearing ones.

    Drops the upstream content-encoding/length/transfer-encoding (the body is
    decoded before re-streaming) and any header that would hand the phone the
    dashboard credential (``set-cookie``, ``x-hermes-session-token``,
    ``authorization``). Case-insensitive.
    """
    drop = {
        "content-length",
        "content-encoding",
        "transfer-encoding",
        "connection",
    } | _RESPONSE_CREDENTIAL_HEADERS
    return {
        key: value
        for key, value in headers.items()  # type: ignore[attr-defined]
        if key.lower() not in drop
    }


def is_html_content_type(content_type: str | None) -> bool:
    """True when the response declares an HTML body (SPA index / fragments)."""
    if not content_type:
        return False
    return "text/html" in content_type.lower()


def rewrite_spa_token(body: bytes, known_token: str | None = None) -> bytes:
    """Rewrite the bootstrap token assignment to a non-functional placeholder.

    Replaces the value in ``window.__HERMES_SESSION_TOKEN__="<real>"`` (any token
    format — urlsafe, JWT with ``.``, base64 with ``+``/``/``/``=``) so the phone
    never receives the real dashboard token, while keeping the assignment intact
    so the SPA's JS that reads it doesn't break. As defense-in-depth, any literal
    occurrence of ``known_token`` elsewhere in the body is scrubbed too. If
    nothing matches, or the body isn't decodable text, it is returned unchanged.
    """
    try:
        text = body.decode("utf-8")
    except (UnicodeDecodeError, AttributeError):
        return body

    def _sub(m: re.Match[str]) -> str:
        tok = m.group(1)
        if not tok or tok == SPA_TOKEN_PLACEHOLDER:
            return m.group(0)
        return m.group(0).replace(tok, SPA_TOKEN_PLACEHOLDER)

    rewritten = _SPA_TOKEN_RE.sub(_sub, text)
    if known_token and known_token != SPA_TOKEN_PLACEHOLDER and known_token in rewritten:
        rewritten = rewritten.replace(known_token, SPA_TOKEN_PLACEHOLDER)
    if rewritten == text:
        return body
    return rewritten.encode("utf-8")


class DashboardUnavailable(RuntimeError):
    """The loopback dashboard could not be reached or did not respond."""


@dataclass
class _Target:
    scheme: str
    host: str  # loopback alias, e.g. 127.0.0.1
    netloc: str  # host:port, bracketed for IPv6
    base: str  # scheme://netloc (no trailing slash)


def _parse_target(dashboard_url: str) -> _Target:
    parts = urlsplit(dashboard_url)
    scheme = parts.scheme or "http"
    netloc = parts.netloc or parts.path  # tolerate bare host:port
    host = parts.hostname or "127.0.0.1"
    base = urlunsplit((scheme, netloc, "", "", "")).rstrip("/")
    return _Target(scheme=scheme, host=host, netloc=netloc, base=base)


class HermesDashboardProxy:
    """Stateful bridge to one loopback Hermes dashboard.

    Holds the cached dashboard token and a shared async httpx client. The
    target is fixed at construction; callers only ever supply a sub-path.
    """

    def __init__(
        self,
        dashboard_url: str,
        *,
        client: httpx.AsyncClient | None = None,
        session_token: str | None = None,
    ) -> None:
        self._target = _parse_target(dashboard_url)
        self._owns_client = client is None
        self._client = client or httpx.AsyncClient(timeout=httpx.Timeout(30.0))
        # Token precedence: explicit arg -> env var -> lazily scraped/cached.
        self._token: str | None = session_token or os.getenv(SESSION_TOKEN_ENV) or None

    def new_request_client(self) -> httpx.AsyncClient:
        """Per-request streaming client. Overridable in tests (e.g. to inject
        an ``httpx.MockTransport``) by replacing this method/attribute."""
        return httpx.AsyncClient(timeout=httpx.Timeout(30.0))

    @property
    def target_base(self) -> str:
        return self._target.base

    @property
    def current_token(self) -> str | None:
        """The cached dashboard token if already resolved (no I/O)."""
        return self._token

    @property
    def loopback_host(self) -> str:
        return self._target.host

    @property
    def host_header(self) -> str:
        return self._target.netloc

    def ws_base(self) -> str:
        scheme = "wss" if self._target.scheme == "https" else "ws"
        return f"{scheme}://{self._target.netloc}"

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    @staticmethod
    def _clean_path(path: str) -> str:
        # Never let the caller-supplied path escape the fixed target. Strip any
        # scheme/host a crafted path might smuggle in; keep only the path part.
        path = path.lstrip("/")
        # A path that looks like 'http://evil/...' or '//evil/...' is neutralised
        # by urlsplit: we take only its path component.
        if "://" in path or path.startswith("/"):
            path = urlsplit("//" + path.lstrip("/")).path.lstrip("/")
        return path

    def upstream_url(self, path: str) -> str:
        clean = self._clean_path(path)
        return f"{self._target.base}/{clean}" if clean else f"{self._target.base}/"

    async def session_token(self) -> str | None:
        """Best-effort dashboard token, cached for the process.

        Returns the env/explicit token if known, otherwise tries to scrape the
        SPA bootstrap once. Returns ``None`` (rather than raising) if the token
        cannot be determined — callers still forward, and the dashboard answers
        401 if it truly needs one. A dashboard that is *down* raises
        :class:`DashboardUnavailable`.
        """
        if self._token:
            return self._token
        try:
            resp = await self._client.get(
                f"{self._target.base}/",
                headers=self._loopback_headers(),
            )
        except httpx.HTTPError as exc:  # dashboard down / refused
            raise DashboardUnavailable(str(exc)) from exc
        match = _SPA_TOKEN_RE.search(resp.text or "")
        if match:
            self._token = match.group(1)
        return self._token

    def _loopback_headers(self) -> dict[str, str]:
        return {"Host": self._target.netloc}

    async def build_upstream_headers(
        self, incoming: list[tuple[str, str]], *, secure: bool
    ) -> dict[str, str]:
        """Headers for the upstream request.

        Drops hop-by-hop + the phone's Host, injects the dashboard token, a
        loopback Host, and the X-Forwarded-* hints. The phone never supplies
        the dashboard token; any inbound ``X-Hermes-Session-Token`` is dropped.
        """
        headers: dict[str, str] = {}
        for key, value in incoming:
            lower = key.lower()
            if lower in _HOP_BY_HOP:
                continue
            if lower == SESSION_TOKEN_HEADER.lower():
                continue  # never trust a phone-supplied dashboard token
            headers[key] = value
        headers["Host"] = self._target.netloc
        headers["X-Forwarded-Prefix"] = FORWARDED_PREFIX
        headers["X-Forwarded-Proto"] = "https" if secure else "http"
        token = await self.session_token()
        if token:
            headers[SESSION_TOKEN_HEADER] = token
        return headers

    def ws_upstream_url(self, path: str) -> str:
        clean = self._clean_path(path)
        url = f"{self.ws_base()}/{clean}"
        token = self._token
        if token:
            sep = "&" if "?" in url else "?"
            url = f"{url}{sep}token={token}"
        return url

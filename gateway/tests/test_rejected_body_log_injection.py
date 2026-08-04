"""The 422 log line must not be writable by the caller.

``_log_rejected_request_body`` exists so a machine-to-machine contract break is
visible in ``gateway.err.log`` within one request. Its inputs are the caller's
own JSON keys: under ``extra="forbid"`` pydantic puts the unknown key straight
into ``loc``, and ``POST /v1/pairing/start`` validates the body with no
credentials at all. So the caller could:

* embed ``\\n`` plus a fake level prefix and write extra WARNING/INFO records
  byte-identical in form to real gateway output — into the same file this work
  cites as forensic evidence;
* send one 200 KB key and write ~200 KB of log per request, unauthenticated —
  a disk-fill and rotation-defeat amplifier;
* put a secret in an ``extensions`` namespace key and have it logged, which
  ADR-0005 ("field NAMES only, never values") forbids.

One request must produce exactly one log record, of bounded size, containing no
caller-chosen control characters and no caller-invented namespace keys.
"""

from __future__ import annotations

import logging

import pytest
from fastapi.testclient import TestClient

from hermes_gateway.app import (
    MAX_LOGGED_FIELD_NAME_CHARS,
    MAX_LOGGED_FIELD_NAMES,
    _sanitize_log_fragment,
)

FORGED_WARNING = "WARNING:  hermes_gateway: FORGED-RECORD tower key rotated by operator"
FORGED_ACCESS = 'INFO:     127.0.0.1:0 - "POST /v1/approvals/x/approve_once HTTP/1.1" 200 OK'


def _records(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    return [r for r in caplog.records if r.name == "hermes_gateway"]


class TestControlCharacterInjection:
    def test_a_newline_bearing_field_name_cannot_forge_a_log_record(
        self, client: TestClient, caplog: pytest.LogCaptureFixture
    ) -> None:
        """PROVEN pre-fix on this exact unauthenticated endpoint: the key below
        appended two standalone records to gateway.err.log."""
        injected = f"pad\n{FORGED_WARNING}\n{FORGED_ACCESS}"
        with caplog.at_level(logging.WARNING, logger="hermes_gateway"):
            response = client.post(
                "/v1/pairing/start", json={"display_name": "phone", injected: 1}
            )

        assert response.status_code == 422
        records = _records(caplog)
        assert len(records) == 1, "one rejected request must produce one record"
        message = records[0].getMessage()
        assert "\n" not in message and "\r" not in message
        # The text survives, escaped, so the diagnostic is not lost — but it can
        # no longer START a line, which is what made it a forged record.
        assert "FORGED-RECORD" in message
        assert not any(
            line.startswith(("WARNING:", "INFO:")) for line in message.splitlines()
        )
        assert "\\n" in message

    @pytest.mark.parametrize(
        "hostile",
        ["a\rb", "a\x00b", "a\x1b[2Jb", "a b", "a\tb", "a\x7fb"],
    )
    def test_every_control_character_is_escaped(self, hostile: str) -> None:
        out = _sanitize_log_fragment(hostile)
        assert not any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in out)
        assert " " not in out and " " not in out

    def test_printable_names_are_left_readable(self) -> None:
        """The whole point of the line is naming the broken field."""
        assert _sanitize_log_fragment("bridge_plugin_name") == "bridge_plugin_name"


class TestSizeCaps:
    def test_a_200kb_field_name_writes_a_bounded_log_line(
        self, client: TestClient, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Pre-fix this wrote 200_158 bytes of log for one request."""
        with caplog.at_level(logging.WARNING, logger="hermes_gateway"):
            response = client.post(
                "/v1/pairing/start", json={"display_name": "phone", "A" * 200_000: 1}
            )

        assert response.status_code == 422
        message = _records(caplog)[0].getMessage()
        assert len(message) < 1_000, f"unbounded log line: {len(message)} chars"
        assert "~truncated" in message

    def test_the_number_of_names_per_request_is_capped(
        self, client: TestClient, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Truncating each name alone still lets 300 keys amplify 300x."""
        body: dict[str, object] = {"display_name": "phone"}
        for index in range(300):
            body[f"junk_{index}_" + "B" * 200] = 1

        with caplog.at_level(logging.WARNING, logger="hermes_gateway"):
            response = client.post("/v1/pairing/start", json=body)

        assert response.status_code == 422
        message = _records(caplog)[0].getMessage()
        assert len(message) < 1_500, f"unbounded log line: {len(message)} chars"
        assert "more)" in message
        names = message.split("offending_fields=", 1)[1].split(" (+")[0]
        assert len(names.split(",")) == MAX_LOGGED_FIELD_NAMES

    def test_the_fragment_cap_holds_for_escape_expansion_too(self) -> None:
        """A name of pure control characters escapes ~4x; slicing the input is
        not enough on its own."""
        out = _sanitize_log_fragment("\x00" * MAX_LOGGED_FIELD_NAME_CHARS * 4)
        assert len(out) <= MAX_LOGGED_FIELD_NAME_CHARS + len("~truncated")


class TestAdr0005CallerKeys:
    def test_an_extensions_namespace_key_is_never_logged(
        self, client: TestClient, caplog: pytest.LogCaptureFixture
    ) -> None:
        """``extensions`` keys are caller data, not schema-defined names.

        Pre-fix the line read
        ``offending_fields=extensions.SECRET-CUSTOMER-EMAIL-leak@example.com``.
        """
        with caplog.at_level(logging.WARNING, logger="hermes_gateway"):
            response = client.post(
                "/v1/runtime/context",
                json={
                    "agent_id": "a",
                    "extensions": {"SECRET-CUSTOMER-EMAIL-leak@example.com": 3},
                },
            )

        assert response.status_code == 422
        message = _records(caplog)[0].getMessage()
        assert "SECRET-CUSTOMER-EMAIL" not in message
        assert "extensions.<redacted>" in message

    def test_the_schema_defined_name_is_still_reported(
        self, client: TestClient, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Redacting the namespace must not cost the diagnostic."""
        with caplog.at_level(logging.WARNING, logger="hermes_gateway"):
            client.post("/v1/runtime/context", json={"agent_id": "a", "agnet_status": 1})

        assert "agnet_status" in _records(caplog)[0].getMessage()


def test_the_422_response_body_is_unchanged(client: TestClient) -> None:
    """Sanitizing is a logging concern; the caller's error detail is FastAPI's."""
    response = client.post("/v1/runtime/context", json={"agent_id": "a", "nope": 1})
    assert response.status_code == 422
    assert response.json()["detail"][0]["loc"] == ["body", "nope"]

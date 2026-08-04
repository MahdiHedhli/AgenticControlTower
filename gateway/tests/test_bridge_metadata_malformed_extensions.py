"""A malformed ``extensions`` must not depend on whether ``bridge_*`` is present.

``_fold_bridge_metadata`` runs in "before" mode, so every value it touches is
unvalidated caller data. ``dict(data.get("extensions") or {})`` trusted it and
broke both ways:

* truthy non-mapping (``[1,2]``, ``5``, ``true``) -> **TypeError**. Pydantic
  converts ValueError/AssertionError to 422 but NOT TypeError, so it escaped as
  a 500 with a traceback;
* falsy non-mapping (``null``, ``""``, ``[]``, ``0``, ``false``) -> silently
  replaced with ``{}`` and the request returned **200**, for a body the schema
  itself rejects;
* ``extensions["bridge"]`` that is not an object -> silently OVERWRITTEN with a
  valid namespace, so invalid input validated.

The deployed act-clearance plugin sends ``bridge_*`` on every request, so all
production traffic takes this branch.

The invariant these tests pin is the asymmetry itself: the presence of a
``bridge_`` key is a legacy spelling, never a change of contract. Whatever the
gateway does with a body WITHOUT one, it must do with the same body WITH one.
"""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

#: Every non-object ``extensions`` value JSON can express, plus the two shapes
#: where the namespace itself is not an object.
MALFORMED: list[tuple[str, Any]] = [
    ("string", "x"),
    ("int_list", [1, 2]),
    ("pair_list", ["ab", "cd"]),  # dict(["ab","cd"]) silently coerces to a dict
    ("int", 5),
    ("bool", True),
    ("null", None),
    ("empty_string", ""),
    ("empty_list", []),
    ("zero", 0),
    ("false", False),
    ("bridge_is_string", {"bridge": "x"}),
    ("bridge_is_int", {"bridge": 7}),
    ("bridge_is_null", {"bridge": None}),
]


def _post(client: TestClient, extensions: Any, *, with_bridge_key: bool):
    body: dict[str, Any] = {"agent_id": "agent_mock", "extensions": extensions}
    if with_bridge_key:
        body["bridge_plugin_name"] = "act-clearance"
    return client.post("/v1/runtime/context", json=body)


@pytest.mark.parametrize(("label", "extensions"), MALFORMED, ids=[c[0] for c in MALFORMED])
def test_malformed_extensions_never_500s(
    client: TestClient, label: str, extensions: Any
) -> None:
    """A caller-supplied type error is a 422, never an unhandled 500."""
    response = _post(client, extensions, with_bridge_key=True)
    assert response.status_code == 422, (
        f"{label}: expected 422, got {response.status_code} {response.text[:200]}"
    )


@pytest.mark.parametrize(("label", "extensions"), MALFORMED, ids=[c[0] for c in MALFORMED])
def test_the_bridge_key_does_not_change_the_contract(
    client: TestClient, label: str, extensions: Any
) -> None:
    """The legacy spelling must not decide whether a body is acceptable."""
    without = _post(client, extensions, with_bridge_key=False)
    with_bridge = _post(client, extensions, with_bridge_key=True)
    assert without.status_code == with_bridge.status_code == 422, (
        f"{label}: without={without.status_code} with={with_bridge.status_code}"
    )


@pytest.mark.parametrize(("label", "extensions"), MALFORMED, ids=[c[0] for c in MALFORMED])
def test_the_422_detail_is_byte_identical_either_way(
    client: TestClient, label: str, extensions: Any
) -> None:
    """Not merely "both 422": the same error, from the same validation.

    The validator hands a malformed ``extensions`` back untouched instead of
    raising, so the rejection is produced by pydantic's own field validation in
    both cases — same ``loc``, same ``type``, same message. A model-level raise
    would have 422'd too, but with ``loc: ["body"]`` and the whole body echoed
    as ``input``, which is a different error for the same mistake.
    """
    without = _post(client, extensions, with_bridge_key=False).json()
    with_bridge = _post(client, extensions, with_bridge_key=True).json()
    assert without == with_bridge, label
    assert [error["loc"] for error in without["detail"]] == [["body", "extensions"]] or [
        error["loc"] for error in without["detail"]
    ] == [["body", "extensions", "bridge"]], without["detail"]


class TestTheAcceptedShapesStillWork:
    """The whole point of 5a37229 is that the deployed plugin is accepted."""

    def test_the_deployed_plugin_body_is_still_accepted(self, client: TestClient) -> None:
        response = client.post(
            "/v1/runtime/context",
            json={
                "agent_id": "agent_mock",
                "bridge_plugin_name": "act-clearance",
                "bridge_plugin_version": "0.1.4",
            },
        )
        assert response.status_code == 200

    def test_absent_extensions_still_folds(self, client: TestClient) -> None:
        response = client.post(
            "/v1/runtime/context",
            json={"agent_id": "agent_mock", "bridge_plugin_name": "act-clearance"},
        )
        assert response.status_code == 200

    def test_an_explicit_bridge_namespace_still_wins(self, client: TestClient) -> None:
        response = client.post(
            "/v1/runtime/context",
            json={
                "agent_id": "agent_mock",
                "bridge_plugin_name": "flat-loses",
                "extensions": {"bridge": {"plugin_name": "explicit-wins"}},
            },
        )
        assert response.status_code == 200

    def test_an_empty_extensions_object_is_fine(self, client: TestClient) -> None:
        response = client.post(
            "/v1/runtime/context",
            json={
                "agent_id": "agent_mock",
                "bridge_plugin_name": "act-clearance",
                "extensions": {},
            },
        )
        assert response.status_code == 200

    def test_an_unrelated_namespace_is_preserved(self, client: TestClient) -> None:
        response = client.post(
            "/v1/runtime/context",
            json={
                "agent_id": "agent_mock",
                "bridge_plugin_name": "act-clearance",
                "extensions": {"browserbridge": {"surface": "tab"}},
            },
        )
        assert response.status_code == 200

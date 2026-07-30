from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import pytest
from test_e2e_smoke import (
    AWWorkspace,
    RunningFolio,
    _assert_aw_status,
    _aw_request,
    _create_document,
    _get_document,
    _list_documents,
    _provision_team,
    aw_workspace_factory,
    folio,
)

__all__ = ["folio", "aw_workspace_factory"]

pytestmark = pytest.mark.e2e


def test_cross_team_document_isolation_and_body_named_team_is_ignored(
    folio: RunningFolio,
    aw_workspace_factory: Callable[[str], AWWorkspace],
) -> None:
    team_a = _provision_team(aw_workspace_factory("team-a"), alias="alice")
    team_b = _provision_team(aw_workspace_factory("team-b"), alias="bob")

    created = _create_document(folio, team_a, slug="team-a-secret", title="Secret", body="team A only")
    assert created["slug"] == "team-a-secret"
    assert created["latest"]["created_by_alias"] == "alice"

    team_a_docs = _list_documents(folio, team_a)
    assert {item["slug"] for item in team_a_docs} == {"team-a-secret"}
    assert _list_documents(folio, team_b) == []

    team_b_read = _aw_request(team_b, "GET", f"{folio.origin}/v1/documents/team-a-secret")
    _assert_aw_status(team_b_read, 404, context="team B reads team A document")

    team_b_versions = _aw_request(team_b, "GET", f"{folio.origin}/v1/documents/team-a-secret/versions")
    _assert_aw_status(team_b_versions, 404, context="team B lists team A versions")

    team_b_append = _aw_request(
        team_b,
        "POST",
        f"{folio.origin}/v1/documents/team-a-secret/versions",
        body="cross-team append attempt",
    )
    _assert_aw_status(team_b_append, 404, context="team B appends team A document")

    body_named_payload: dict[str, Any] = {
        "team_id": team_a.team_id,
        "slug": "body-named-team",
        "title": "Body named team",
        "body": "the certificate decides the team, not this body field",
    }
    body_named = _aw_request(
        team_b,
        "POST",
        f"{folio.origin}/v1/documents",
        body=json.dumps(body_named_payload, separators=(",", ":")),
    )
    assert body_named.returncode == 0, body_named.stderr

    assert _get_document(folio, team_b, "body-named-team")["body"] == body_named_payload["body"]
    team_a_body_named = _aw_request(team_a, "GET", f"{folio.origin}/v1/documents/body-named-team")
    _assert_aw_status(
        team_a_body_named,
        404,
        context="body-named team field did not write into team A",
    )

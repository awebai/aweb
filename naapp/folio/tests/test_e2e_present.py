from __future__ import annotations

import json
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx
import pytest
from test_e2e_smoke import (
    AWWorkspace,
    E2ETeam,
    RunningFolio,
    _append_version,
    _assert_aw_status,
    _aw_json,
    _aw_request,
    _create_document,
    _provision_team,
    aw_workspace_factory,
    folio,
)

__all__ = ["folio", "aw_workspace_factory"]

pytestmark = pytest.mark.e2e


def _mint_present(folio: RunningFolio, team: E2ETeam, **payload: Any) -> dict[str, Any]:
    result = _aw_request(
        team,
        "POST",
        f"{folio.origin}/v1/present",
        body=json.dumps(payload, separators=(",", ":")),
    )
    data = _aw_json(result, context=f"mint present link {payload}")
    assert isinstance(data, dict)
    return data


def test_document_bound_present_links_are_isolated_pinned_revocable_and_sanitized(
    folio: RunningFolio,
    aw_workspace_factory: Callable[[str], AWWorkspace],
    tmp_path: Path,
) -> None:
    team_a = _provision_team(aw_workspace_factory("present-a"), alias="alice")
    team_b = _provision_team(aw_workspace_factory("present-b"), alias="bob")

    created = _create_document(
        folio,
        team_a,
        slug="pitch",
        title="Pitch",
        body="# Original\n\n<script>alert('x')</script>\n\n<img src=x onerror=alert(1)>\n\nHello **investor**.",
    )

    cross_team_mint = _aw_request(
        team_b,
        "POST",
        f"{folio.origin}/v1/present",
        body=json.dumps({"slug": "pitch"}, separators=(",", ":")),
    )
    _assert_aw_status(cross_team_mint, 404, context="team B mints team A present link")

    minted = _mint_present(folio, team_a, slug="pitch")
    token = minted["token"]
    assert minted["url"] == f"{folio.origin}/present/{token}"

    public = httpx.get(minted["url"], timeout=10.0)
    assert public.status_code == 200, public.text
    assert "text/html" in public.headers["content-type"]
    assert "Original" in public.text
    assert "<strong>investor</strong>" in public.text
    assert "<script" not in public.text.lower()
    assert "alert(" not in public.text
    assert "<img" not in public.text.lower()
    assert "onerror" not in public.text.lower()
    assert team_a.team_id not in public.text
    assert str(created["document_id"]) not in public.text
    assert team_a.did_key not in public.text
    assert team_a.certificate_id not in public.text
    assert "version_number" not in public.text
    assert "created_by" not in public.text

    _append_version(folio, team_a, slug="pitch", body="# Updated\n\nSecond version", tmp_path=tmp_path)
    still_pinned = httpx.get(minted["url"], timeout=10.0)
    assert still_pinned.status_code == 200, still_pinned.text
    assert "Original" in still_pinned.text
    assert "Second version" not in still_pinned.text

    explicit_second = _mint_present(folio, team_a, slug="pitch", version=2)
    explicit_second_page = httpx.get(explicit_second["url"], timeout=10.0)
    assert explicit_second_page.status_code == 200, explicit_second_page.text
    assert "Second version" in explicit_second_page.text
    assert "Original" not in explicit_second_page.text

    missing_version = _aw_request(
        team_a,
        "POST",
        f"{folio.origin}/v1/present",
        body=json.dumps({"slug": "pitch", "version": 99}, separators=(",", ":")),
    )
    _assert_aw_status(missing_version, 404, context="mint missing document version")

    cross_team_revoke = _aw_request(team_b, "POST", f"{folio.origin}/v1/present/{token}/revoke")
    _assert_aw_status(cross_team_revoke, 404, context="team B revokes team A present link")
    assert httpx.get(minted["url"], timeout=10.0).status_code == 200

    revoke = _aw_request(team_a, "POST", f"{folio.origin}/v1/present/{token}/revoke")
    assert _aw_json(revoke, context="revoke present link") == {"revoked": True}
    revoked = httpx.get(minted["url"], timeout=10.0)
    assert revoked.status_code == 404, revoked.text
    assert team_a.team_id not in revoked.text
    assert str(created["document_id"]) not in revoked.text

    short_lived = _mint_present(folio, team_a, slug="pitch", ttl_seconds=1)
    time.sleep(1.2)
    expired = httpx.get(short_lived["url"], timeout=10.0)
    assert expired.status_code == 404, expired.text

    bogus = httpx.get(f"{folio.origin}/present/not-a-real-token", timeout=10.0)
    assert bogus.status_code == 404, bogus.text

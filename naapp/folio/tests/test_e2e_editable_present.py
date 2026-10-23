from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from test_e2e_present import _mint_present
from test_e2e_smoke import (
    AWWorkspace,
    RunningFolio,
    _aw_json,
    _aw_request,
    _create_document,
    _get_document,
    _list_versions,
    _provision_team,
    aw_workspace_factory,
    folio,
)

__all__ = ["folio", "aw_workspace_factory"]

pytestmark = pytest.mark.e2e


def _edit(url: str, *, body: str, base_version: int, editor_name: str | None = None, headers: dict | None = None) -> httpx.Response:
    payload: dict[str, Any] = {"body": body, "base_version": base_version}
    if editor_name is not None:
        payload["editor_name"] = editor_name
    return httpx.post(f"{url}/edit", headers=headers, json=payload, timeout=10.0)


def test_editable_present_link_appends_versions_and_rejects_stale_saves(
    folio: RunningFolio,
    aw_workspace_factory: Callable[[str], AWWorkspace],
) -> None:
    team = _provision_team(aw_workspace_factory("editable"), alias="agent")
    _create_document(folio, team, slug="pitch", title="Pitch", body="# Draft\n\nOriginal")

    read_link = _mint_present(folio, team, slug="pitch")
    read_page = httpx.get(read_link["url"], params={"editable": "true"}, timeout=10.0)
    assert read_page.status_code == 200, read_page.text
    assert "Editable folio link" not in read_page.text
    assert "<script" not in read_page.text.lower()
    assert "<textarea" not in read_page.text.lower()
    assert httpx.get(f"{read_link['url']}/state", timeout=10.0).status_code == 404
    assert _edit(read_link["url"], body="malicious escalation", base_version=1).status_code == 404

    editable = _mint_present(folio, team, slug="pitch", editable=True)
    parts = urlsplit(editable["url"])
    session_url = parts._replace(fragment="").geturl()
    editor_page = httpx.get(session_url, timeout=10.0)
    assert editor_page.status_code == 200, editor_page.text
    assert "Save new version" in editor_page.text
    assert "<textarea" in editor_page.text.lower()
    assert "Version 1" in editor_page.text
    assert 'script-src \'nonce-' in editor_page.headers["content-security-policy"]
    assert "Original" not in editor_page.text
    opened = httpx.post(session_url + "/session", json={"opener": parse_qs(parts.fragment)["k"][0]}, timeout=10.0)
    assert opened.status_code == 200
    headers = {"X-Folio-Edit-Session": opened.json()["session_secret"]}

    # The editor's live preview is rendered by the server (full markdown fidelity).
    preview = httpx.post(
        session_url + "/preview",
        headers=headers,
        json={"body": "# Live\n\n**bold** and a [link](https://example.com)."},
        timeout=10.0,
    )
    assert preview.status_code == 200, preview.text
    assert "<h1>Live</h1>" in preview.text
    assert "<strong>bold</strong>" in preview.text
    assert 'href="https://example.com"' in preview.text
    # A read-only token cannot drive the editor preview.
    assert httpx.post(f"{read_link['url']}/preview", json={"body": "# x"}, timeout=10.0).status_code == 404

    first_save = _edit(session_url, headers=headers, body="# Draft\n\nAlice edit", base_version=1, editor_name="Alice")
    assert first_save.status_code == 200, first_save.text
    assert first_save.json() == {"version_number": 2}
    assert httpx.get(session_url + "/state?after_version=2", headers=headers, timeout=10.0).json() == {"version_number": 2}

    stale_save = _edit(session_url, headers=headers, body="# Draft\n\nBob stale edit", base_version=1, editor_name="Bob")
    assert stale_save.status_code == 409, stale_save.text
    stale_detail = stale_save.json()["detail"]
    assert stale_detail == {"version_number": 2, "body": "# Draft\n\nAlice edit"}

    reconciled = _edit(session_url, headers=headers, body="# Draft\n\nBob reconciled", base_version=2, editor_name="Bob")
    assert reconciled.status_code == 200, reconciled.text
    assert reconciled.json() == {"version_number": 3}

    latest = _get_document(folio, team, "pitch")
    assert latest["current_version"] == 3
    assert latest["body"] == "# Draft\n\nBob reconciled"
    assert latest["latest"]["created_by_editor_name"] == "Bob"
    versions = _list_versions(folio, team, "pitch")
    assert [version["version_number"] for version in versions] == [3, 2, 1]
    assert versions[0]["created_by_editor_name"] == "Bob"
    assert versions[1]["created_by_editor_name"] == "Alice"

    revoked = _aw_json(
        _aw_request(team, "POST", f"{folio.origin}/v1/present/{editable['token']}/revoke"),
        context="revoke editable present link",
    )
    assert revoked == {"revoked": True}
    assert httpx.get(session_url + "/state", headers=headers, timeout=10.0).status_code == 404
    assert _edit(session_url, headers=headers, body="after revoke", base_version=3).status_code == 404

    expiring = _mint_present(folio, team, slug="pitch", editable=True, ttl_seconds=1)
    time.sleep(1.2)
    expired_parts = urlsplit(expiring["url"])
    expired_url = expired_parts._replace(fragment="").geturl()
    assert httpx.post(expired_url + "/session", json={"opener": parse_qs(expired_parts.fragment)["k"][0]}, timeout=10.0).status_code == 404
    assert httpx.get(expired_url + "/state", timeout=10.0).status_code == 404
    assert _edit(expired_url, body="after expiry", base_version=3).status_code == 404

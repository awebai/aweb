"""Request validation on the real Folio routes and a disposable PostgreSQL DB.

Only the authenticated-principal dependency is supplied directly: these checks
isolate payload handling, not team-auth verification. Repository writes are real.
"""

from __future__ import annotations

import httpx
import pytest
from test_present_privacy import OWNER, mint, present_world

__all__ = ["present_world"]

CASES = [
    (
        "POST",
        "/v1/documents",
        {"slug": "invalid-title", "title": "MaintenanceReport" * 16 + ".pdf", "body": "Draft"},
        "title",
    ),
    ("POST", "/v1/documents/draft/versions/template", {"name": ""}, "name"),
    ("POST", "/v1/present", {"slug": "draft", "ttl_seconds": 0}, "ttl_seconds"),
    ("POST", "/v1/assets", {"content_type": "image/png", "data_base64": ""}, "data_base64"),
    (
        "POST",
        "/v1/assets/video/direct-upload",
        {"content_type": "video/mp4", "max_duration_seconds": 0},
        "max_duration_seconds",
    ),
    ("PUT", "/v1/theme", {"header": "x" * 2001}, "header"),
    ("POST", "/present/edit/{token}/edit", {"body": "Must not save", "base_version": 0}, "base_version"),
    ("POST", "/present/edit/{token}/preview", {"body": "x" * 200001}, "body"),
]


@pytest.fixture
async def member_world(present_world):
    app, _, _ = present_world
    for route in app.routes:
        for dependency in getattr(getattr(route, "dependant", None), "dependencies", ()):
            if dependency.name == "actor":
                app.dependency_overrides[dependency.call] = lambda: OWNER
    return present_world


async def _counts(db):
    return dict(
        await db.fetch_one("""SELECT
        (SELECT COUNT(*) FROM {{tables.documents}}) AS documents,
        (SELECT COUNT(*) FROM {{tables.document_versions}}) AS versions,
        (SELECT COUNT(*) FROM {{tables.presentation_links}}) AS links,
        (SELECT COUNT(*) FROM {{tables.assets}}) AS assets,
        (SELECT COUNT(*) FROM {{tables.themes}}) AS themes
    """)
    )


@pytest.mark.parametrize("method,path,payload,field", CASES, ids=[case[1] for case in CASES])
async def test_invalid_body_returns_standard_422_without_writing(
    member_world, method, path, payload, field
):
    app, db, _ = member_world
    link = await mint(member_world)
    path = path.format(token=link["token"])
    before = await _counts(db)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
        base_url="http://folio.test",
    ) as client:
        response = await client.request(method, path, json=payload)
    assert response.status_code == 422, response.text
    detail = response.json()["detail"]
    assert isinstance(detail, list) and detail
    assert detail[0]["loc"] == ["body", field]
    assert isinstance(detail[0]["type"], str) and detail[0]["type"]
    assert isinstance(detail[0]["msg"], str) and detail[0]["msg"]
    assert await _counts(db) == before
    if path.startswith("/present/"):
        assert response.headers["cache-control"] == "no-store"
        assert response.headers["referrer-policy"] == "no-referrer"


@pytest.mark.parametrize("length", [208, 240])
async def test_valid_title_boundary_still_saves(member_world, length):
    app, db, _ = member_world
    title = "T" * length
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://folio.test"
    ) as client:
        response = await client.post(
            "/v1/documents", json={"slug": "valid-title", "title": title, "body": "Content"}
        )
    assert response.status_code == 200, response.text
    assert response.json()["title"] == title
    assert (await _counts(db))["documents"] == 2


async def test_malformed_json_uses_standard_422(member_world):
    app, db, _ = member_world
    before = await _counts(db)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
        base_url="http://folio.test",
    ) as client:
        response = await client.post(
            "/v1/documents", content='{"title":', headers={"content-type": "application/json"}
        )
    assert response.status_code == 422, response.text
    error = response.json()["detail"][0]
    assert error["type"] == "json_invalid"
    assert error["loc"][0] == "body"
    assert await _counts(db) == before

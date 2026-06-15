from __future__ import annotations

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

import folio.api as folio_api
from folio.presentation import render_presented_markdown
from folio.templates import render_declarative_template


def test_render_pitch_template_validates_and_renders_markdown_slots() -> None:
    body = render_declarative_template(
        {
            "name": "pitch",
            "slots": {
                "cover": {"title": "Aweb Folio", "subtitle": "Agent-authored decks"},
                "metrics": [
                    {"label": "Teams", "value": "12", "caption": "pilot workspaces"},
                    {"label": "Time", "value": "<1 min", "caption": "to share"},
                ],
                "sections": [
                    {"heading": "Problem", "body": "Agents need **durable** handoffs."},
                    {"heading": "Solution", "body": "Use append-only docs and themed present links."},
                ],
                "ask": {"headline": "Ask", "body": "Approve launch.", "items": ["Ship folio", "Watch deploy"]},
            },
        }
    )

    assert body.startswith("# Aweb Folio")
    assert "Agent-authored decks" in body
    assert "| Teams | 12 | pilot workspaces |" in body
    assert "## Problem" in body
    assert "Agents need **durable** handoffs." in body
    assert "## Ask" in body
    assert "- Ship folio" in body


def test_template_renderer_rejects_unknown_or_extra_slots() -> None:
    with pytest.raises(HTTPException) as unknown:
        render_declarative_template({"name": "bespoke", "slots": {}})
    assert unknown.value.status_code == 422
    assert "Unknown template" in str(unknown.value.detail)

    with pytest.raises(HTTPException) as extra:
        render_declarative_template({"name": "memo", "slots": {"cover": {"title": "Hi"}, "metrics": []}})
    assert extra.value.status_code == 422
    assert "Unsupported slot" in str(extra.value.detail)

    with pytest.raises(HTTPException) as extra_field:
        render_declarative_template({"name": "memo", "slots": {"cover": {"title": "Hi", "html": "<script>"}}})
    assert extra_field.value.status_code == 422
    assert "Unsupported field" in str(extra_field.value.detail)


def test_template_renderer_normalizes_cr_in_table_cells_before_rendering() -> None:
    body = render_declarative_template(
        {
            "name": "metrics",
            "slots": {
                "cover": {"title": "Numbers"},
                "metrics": [{"label": "Safe", "value": "1\r| injected | row |", "caption": "ok"}],
            },
        }
    )
    html = render_presented_markdown(body)

    assert html.count("<tr>") == 2
    assert "injected" in html
    assert "<td>row</td>" not in html


def test_template_renderer_escapes_table_pipes_and_rejects_bad_shapes() -> None:
    body = render_declarative_template(
        {
            "name": "metrics",
            "slots": {
                "cover": {"title": "Numbers"},
                "metrics": [{"label": "A|B", "value": "1|2", "caption": "C|D"}],
            },
        }
    )

    assert "| A\\|B | 1\\|2 | C\\|D |" in body

    with pytest.raises(HTTPException) as bad:
        render_declarative_template({"name": "pitch", "slots": {"cover": {"title": "Pitch"}, "sections": {"heading": "not a list"}}})
    assert bad.value.status_code == 422
    assert "sections" in str(bad.value.detail)


def _create_document_test_app() -> tuple:
    app = folio_api.create_app()
    route = next(route for route in app.routes if getattr(route, "path", None) == "/v1/documents")
    principal_dependency = route.dependant.dependencies[0].call
    db_dependency = route.dependant.dependencies[1].call
    app.dependency_overrides[principal_dependency] = lambda: object()
    app.dependency_overrides[db_dependency] = lambda: object()
    return app, TestClient(app)


def test_create_document_route_rejects_neither_body_nor_template() -> None:
    _app, client = _create_document_test_app()

    response = client.post("/v1/documents", json={"slug": "empty", "title": "Empty"})

    assert response.status_code == 422
    assert "exactly one" in response.text


def test_create_document_route_rejects_body_key_even_empty_with_template() -> None:
    _app, client = _create_document_test_app()

    response = client.post(
        "/v1/documents",
        json={
            "slug": "pitch",
            "title": "Pitch",
            "body": "",
            "template": {"name": "memo", "slots": {"cover": {"title": "Memo"}, "sections": []}},
        },
    )

    assert response.status_code == 422
    assert "exactly one" in response.text


def test_create_document_route_renders_template_body(monkeypatch) -> None:
    app, client = _create_document_test_app()
    captured: dict[str, object] = {}

    async def fake_create_document(_database, *, principal, settings, slug: str, title: str, body: str) -> dict:
        captured.update(slug=slug, title=title, body=body)
        return {
            "document_id": "11111111-1111-4111-8111-111111111111",
            "slug": slug,
            "title": title,
            "body": body,
            "current_version": 1,
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z",
            "latest": {
                "version_id": "22222222-2222-4222-8222-222222222222",
                "version_number": 1,
                "body": body,
                "created_by_did_key": "did:key:zAgent",
                "created_by_alias": "agent",
                "certificate_id": "cert",
                "created_at": "2026-01-01T00:00:00Z",
            },
        }

    monkeypatch.setattr(folio_api, "create_document", fake_create_document)

    response = client.post(
        "/v1/documents",
        json={
            "slug": "pitch",
            "title": "Pitch",
            "template": {"name": "memo", "slots": {"cover": {"title": "Memo"}, "sections": [{"heading": "Hi", "body": "There"}]}},
        },
    )

    assert response.status_code == 200
    assert captured["body"] == "# Memo\n\n## Hi\n\nThere\n"


def test_append_template_version_route_renders_template_body(monkeypatch) -> None:
    app = folio_api.create_app()
    route = next(route for route in app.routes if getattr(route, "path", None) == "/v1/documents/{slug}/versions/template")
    principal_dependency = route.dependant.dependencies[0].call
    db_dependency = route.dependant.dependencies[1].call
    app.dependency_overrides[principal_dependency] = lambda: object()
    app.dependency_overrides[db_dependency] = lambda: object()
    captured: dict[str, object] = {}

    async def fake_append_version(_database, *, principal, settings, slug: str, body: str) -> dict:
        captured.update(slug=slug, body=body)
        return {
            "document_id": "11111111-1111-4111-8111-111111111111",
            "slug": slug,
            "title": "Pitch",
            "body": body,
            "current_version": 2,
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z",
            "latest": {
                "version_id": "22222222-2222-4222-8222-222222222222",
                "version_number": 2,
                "body": body,
                "created_by_did_key": "did:key:zAgent",
                "created_by_alias": "agent",
                "certificate_id": "cert",
                "created_at": "2026-01-01T00:00:00Z",
            },
        }

    monkeypatch.setattr(folio_api, "append_version", fake_append_version)

    response = TestClient(app).post(
        "/v1/documents/pitch/versions/template",
        json={"name": "memo", "slots": {"cover": {"title": "Memo v2"}, "sections": []}},
    )

    assert response.status_code == 200
    assert captured == {"slug": "pitch", "body": "# Memo v2\n"}

from __future__ import annotations

from pathlib import Path
from uuid import UUID

from fastapi.testclient import TestClient

import folio.api as folio_api
from folio.presentation import (
    render_presented_markdown,
    render_presented_page,
    sanitize_theme_tokens,
)


def test_render_presented_markdown_sanitizes_untrusted_html() -> None:
    html = render_presented_markdown(
        "# Hello\n\n<script>alert('x')</script>\n\n<img src=x onerror=alert(1)>\n\nA **safe** [link](https://example.com)."
    )

    assert "<h1>Hello</h1>" in html
    assert "<strong>safe</strong>" in html
    assert '<a href="https://example.com"' in html
    assert "<script" not in html.lower()
    assert "alert(" not in html
    assert "<img" not in html.lower()
    assert "onerror" not in html.lower()


def test_render_presented_markdown_allows_only_our_origin_allowed_asset_images() -> None:
    safe_id = UUID("11111111-1111-4111-8111-111111111111")
    other_id = UUID("22222222-2222-4222-8222-222222222222")
    html = render_presented_markdown(
        "\n".join(
            [
                f"![safe alt](https://folio.aweb.ai/assets/{safe_id})",
                f"![relative ok](/assets/{safe_id})",
                f"![other team](https://folio.aweb.ai/assets/{other_id})",
                "![external](https://example.com/image.png)",
                "![data](data:image/png;base64,AAAA)",
                "![javascript](javascript:alert(1))",
                "![svg](https://folio.aweb.ai/assets/not-a-uuid.svg)",
                '<img src="https://folio.aweb.ai/assets/11111111-1111-4111-8111-111111111111" onerror="alert(9)">',
            ]
        ),
        public_origin="https://folio.aweb.ai",
        allowed_asset_ids={safe_id},
    )

    assert html.count("<img") == 3
    assert f'src="https://folio.aweb.ai/assets/{safe_id}"' in html
    assert f'src="/assets/{safe_id}"' in html
    assert "safe alt" in html
    assert "relative ok" in html
    assert "onerror" not in html.lower()
    assert "alert(" not in html
    assert str(other_id) not in html
    assert "example.com" not in html
    assert "data:image" not in html
    assert "javascript:" not in html.lower()
    assert ".svg" not in html.lower()


def test_render_presented_markdown_renders_only_trusted_video_embeds() -> None:
    video_id = UUID("33333333-3333-4333-8333-333333333333")
    other_id = UUID("44444444-4444-4444-8444-444444444444")
    html = render_presented_markdown(
        "\n".join(
            [
                f"![demo video](https://folio.aweb.ai/assets/{video_id})",
                f"![other video](https://folio.aweb.ai/assets/{other_id})",
                '<iframe src="https://evil.example/embed"></iframe>',
                '<iframe src="https://iframe.videodelivery.net/user-controlled"></iframe>',
            ]
        ),
        public_origin="https://folio.aweb.ai",
        asset_embeds={
            video_id: {
                "kind": "video",
                "iframe_url": "https://customer-example.cloudflarestream.com/signed-token/iframe",
                "status": "ready",
            }
        },
    )

    assert html.count("<iframe") == 1
    assert "customer-example.cloudflarestream.com/signed-token/iframe" in html
    assert "demo video" in html
    assert str(other_id) not in html
    assert "evil.example" not in html
    assert "user-controlled" not in html
    assert "sandbox=\"allow-scripts allow-same-origin allow-presentation\"" in html


def test_render_presented_markdown_without_asset_context_strips_images() -> None:
    safe_id = UUID("11111111-1111-4111-8111-111111111111")
    html = render_presented_markdown(f"![safe](https://folio.aweb.ai/assets/{safe_id})")

    assert "<img" not in html.lower()
    assert str(safe_id) not in html


def test_present_surface_is_noindex() -> None:
    html = render_presented_page(body="# Private", public_origin="https://folio.aweb.ai")

    assert '<meta name="robots" content="noindex,nofollow,noarchive">' in html


def test_present_route_sets_x_robots_tag(monkeypatch) -> None:
    app = folio_api.create_app()
    present_route = next(route for route in app.routes if getattr(route, "path", None) == "/present/{token}")
    db_dependency = present_route.dependant.dependencies[0].call
    app.dependency_overrides[db_dependency] = lambda: object()

    async def fake_get_presented_document(_database, *, token: str) -> dict:
        assert token == "secret-token"
        return {"body": "# Private", "theme": None, "allowed_assets": {}}

    monkeypatch.setattr(folio_api, "get_presented_document", fake_get_presented_document)

    response = TestClient(app).get("/present/secret-token")

    assert response.status_code == 200
    assert response.headers["x-robots-tag"] == "noindex, nofollow, noarchive"


def test_render_presented_page_sanitizes_theme_tokens_and_header_footer() -> None:
    theme = {
        "tokens": {
            "colors": {
                "background": "#001122",
                "accent": "rgb(1, 2, 3)",
                "text": "</style><script>alert(1)</script>",
                "unknown": "#ffffff",
            },
            "fonts": {
                "body": "serif",
                "heading": "</style><script>alert(2)</script>",
            },
        },
        "header": "Hi </style><script>alert(3)</script>",
        "footer": "Bye <img src=x onerror=alert(4)>",
        "logo_url": "/assets/logo-id",
    }

    sanitized = sanitize_theme_tokens(theme["tokens"])
    assert sanitized == {
        "colors": {"background": "#001122", "accent": "rgb(1, 2, 3)"},
        "fonts": {"body": "serif"},
    }

    html = render_presented_page(body="# Safe", theme=theme, public_origin="https://folio.aweb.ai")
    style = html.split("</style>", 1)[0]
    assert "--bg: #001122;" in style
    assert "--accent: rgb(1, 2, 3);" in style
    assert "--font-body: Georgia" in style
    assert "alert(" not in style
    assert "<script" not in html.lower()
    assert "&lt;/style&gt;&lt;script&gt;alert(3)&lt;/script&gt;" in html
    assert "&lt;img src=x onerror=alert(4)&gt;" in html
    assert "<img class=\"brand-logo\" src=\"/assets/logo-id\"" in html


def test_repo_has_single_initial_migration() -> None:
    migrations = sorted((Path(__file__).resolve().parents[1] / "src" / "folio" / "migrations").glob("*.sql"))

    assert [migration.name for migration in migrations] == ["001_initial.sql"]


def test_initial_migration_contains_team_scoped_assets_and_themes() -> None:
    migration = (Path(__file__).resolve().parents[1] / "src" / "folio" / "migrations" / "001_initial.sql").read_text()

    assert "CREATE TABLE IF NOT EXISTS {{tables.assets}}" in migration
    assert "asset_id UUID PRIMARY KEY" in migration
    assert "team_id TEXT NOT NULL REFERENCES {{tables.teams}}" in migration
    assert "kind TEXT NOT NULL DEFAULT 'image' CHECK (kind IN ('image', 'video'))" in migration
    assert "bytes BYTEA" in migration
    assert "content_type TEXT CHECK (content_type IN ('image/png', 'image/jpeg', 'image/gif', 'image/webp', 'video/mp4', 'video/quicktime', 'video/webm'))" in migration
    assert "stream_uid TEXT UNIQUE" in migration
    assert "stream_status TEXT CHECK" in migration
    assert "upload_expires_at TIMESTAMPTZ" in migration
    assert "CHECK ((kind = 'image' AND bytes IS NOT NULL AND stream_uid IS NULL) OR (kind = 'video' AND bytes IS NULL AND stream_uid IS NOT NULL))" in migration
    assert "CREATE TABLE IF NOT EXISTS {{tables.themes}}" in migration
    assert "team_id TEXT PRIMARY KEY REFERENCES {{tables.teams}}" in migration
    assert "tokens JSONB NOT NULL DEFAULT '{}'::jsonb" in migration
    assert "logo_asset_id UUID REFERENCES {{tables.assets}}" in migration
    assert "header TEXT" in migration
    assert "footer TEXT" in migration


def test_initial_migration_presentation_links_are_document_version_bound() -> None:
    migration = (Path(__file__).resolve().parents[1] / "src" / "folio" / "migrations" / "001_initial.sql").read_text()

    assert "CREATE TABLE IF NOT EXISTS {{tables.presentation_links}}" in migration
    assert "token TEXT PRIMARY KEY" in migration
    assert "document_id UUID NOT NULL REFERENCES {{tables.documents}}" in migration
    assert "version_number INTEGER NOT NULL" in migration
    assert "created_by_did_key TEXT NOT NULL" in migration
    assert "created_by_did_aw TEXT" in migration
    assert "created_by_alias TEXT NOT NULL" in migration
    assert "certificate_id TEXT NOT NULL" in migration
    assert "FOREIGN KEY (document_id, version_number) REFERENCES {{tables.document_versions}}" in migration
    assert "arti" + "fact" not in migration.lower()

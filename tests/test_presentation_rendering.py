from __future__ import annotations

from pathlib import Path

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

    html = render_presented_page(body="# Safe", theme=theme)
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
    assert "bytes BYTEA NOT NULL" in migration
    assert "content_type TEXT NOT NULL CHECK (content_type IN ('image/png', 'image/jpeg', 'image/gif', 'image/webp'))" in migration
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

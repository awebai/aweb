from __future__ import annotations

from pathlib import Path
from uuid import UUID

import pytest
from fastapi.testclient import TestClient

import folio.api as folio_api
from folio.presentation import (
    content_security_policy,
    contrast_ratio,
    render_editor_page,
    render_presented_markdown,
    render_presented_page,
    sanitize_layout_tokens,
    sanitize_theme_tokens,
    theme_contrast_error,
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


def test_render_editor_page_uses_nonce_and_escapes_script_breakout() -> None:
    html = render_editor_page(
        token="tok</script><script>alert(1)</script>",
        body="# Hi\n\n</script><script>alert(2)</script>",
        version_number=7,
        nonce="nonce-123",
    )

    assert '<meta name="robots" content="noindex,nofollow,noarchive">' in html
    assert '<script nonce="nonce-123">' in html
    assert "tok<\\/script><script>alert(1)<\\/script>" in html
    assert "<script>alert(1)</script>" not in html
    assert "<script>alert(2)</script>" not in html
    assert '"version_number":7' in html


def test_render_editor_page_live_preview_regex_is_valid_js() -> None:
    # The block-split regex must emit an escaped \n, not a literal newline that
    # breaks the regex literal across a line and throws SyntaxError (which left
    # the whole editor script dead and the textarea empty).
    html = render_editor_page(token="t", body="# Hi", version_number=1, nonce="n")
    assert r"split(/\n{2,}/)" in html
    assert "split(/\n{2,}/)" not in html  # the broken, newline-bearing form


def test_render_editor_page_fills_the_viewport_with_a_split_layout() -> None:
    html = render_editor_page(token="t", body="# Hi", version_number=1, nonce="n")
    # Full-viewport app shell: editor pane + present-card preview pane, not a
    # single narrow card.
    assert 'class="workspace"' in html
    assert 'id="pane-edit"' in html
    assert 'id="pane-preview"' in html
    assert "calc(100vh - var(--bar-h))" in html
    assert "grid-template-columns: 1fr 1fr" in html
    # The body loads into the textarea via JS (textarea is empty in source).
    assert '<textarea id="body"' in html
    assert "bodyEl.value = INITIAL.body;" in html


def test_sanitize_layout_tokens_defaults_when_absent() -> None:
    default = {"mode": "document", "measure": "default", "color_scheme": "light"}
    assert sanitize_layout_tokens({}) == default
    assert sanitize_layout_tokens(None) == default
    assert sanitize_layout_tokens({"layout": "not-a-dict"}) == default


def test_sanitize_layout_tokens_accepts_valid_enums() -> None:
    assert sanitize_layout_tokens(
        {"layout": {"mode": "presentation", "measure": "wide", "color_scheme": "dark"}}
    ) == {"mode": "presentation", "measure": "wide", "color_scheme": "dark"}


def test_sanitize_layout_tokens_normalizes_case_and_whitespace() -> None:
    assert sanitize_layout_tokens(
        {"layout": {"mode": "  Presentation ", "measure": "WIDE", "color_scheme": "Auto"}}
    ) == {"mode": "presentation", "measure": "wide", "color_scheme": "auto"}


def test_sanitize_layout_tokens_rejects_unknown_values() -> None:
    assert sanitize_layout_tokens(
        {"layout": {"mode": "presentation; } body { display: none } .x {", "measure": "enormous", "color_scheme": 42}}
    ) == {"mode": "document", "measure": "default", "color_scheme": "light"}


def test_sanitize_theme_tokens_preserves_valid_layout_subset() -> None:
    sanitized = sanitize_theme_tokens(
        {"layout": {"mode": "presentation", "measure": "bogus", "color_scheme": "dark"}}
    )
    assert sanitized == {"layout": {"mode": "presentation", "color_scheme": "dark"}}


def test_sanitize_theme_tokens_omits_layout_when_no_valid_values() -> None:
    assert sanitize_theme_tokens({"layout": {"mode": "bogus"}}) == {}


def test_render_presented_page_defaults_to_document_layout_light() -> None:
    html = render_presented_page(body="# Hi")
    assert 'class="folio-layout-document folio-measure-default"' in html
    assert '<meta name="color-scheme" content="light">' in html
    style = html.split("</style>", 1)[0]
    assert "color-scheme: light;" in style
    assert "--bg: #f8fafc;" in style
    assert "--measure: 68ch;" in style
    assert "max-width: var(--measure)" in style


def test_render_presented_page_presentation_wide_dark() -> None:
    theme = {"tokens": {"layout": {"mode": "presentation", "measure": "wide", "color_scheme": "dark"}}}
    html = render_presented_page(body="# Hi", theme=theme)
    assert 'class="folio-layout-presentation folio-measure-wide"' in html
    assert '<meta name="color-scheme" content="dark">' in html
    style = html.split("</style>", 1)[0]
    assert "color-scheme: dark;" in style
    assert "--bg: #0b1220;" in style
    assert ".folio-layout-presentation {" in style
    assert "--measure: 1400px;" in style


def test_render_presented_page_auto_color_scheme_emits_dark_media_query() -> None:
    theme = {"tokens": {"layout": {"color_scheme": "auto"}}}
    html = render_presented_page(body="# Hi", theme=theme)
    assert '<meta name="color-scheme" content="light dark">' in html
    style = html.split("</style>", 1)[0]
    assert "color-scheme: light dark;" in style
    assert "@media (prefers-color-scheme: dark)" in style
    assert "--bg: #0b1220;" in style


def test_render_presented_page_layout_tokens_cannot_escape() -> None:
    theme = {
        "tokens": {
            "layout": {"mode": "presentation; } body { display: none } .x {", "measure": "enormous", "color_scheme": "neon"}
        }
    }
    html = render_presented_page(body="# Hi", theme=theme)
    assert 'class="folio-layout-document folio-measure-default"' in html
    assert "presentation; } body { display: none } .x {" not in html
    assert "enormous" not in html


def test_presentation_mode_emits_nonce_gated_fullscreen_script() -> None:
    theme = {"tokens": {"layout": {"mode": "presentation"}}}
    html = render_presented_page(body="# Hi", theme=theme, nonce="testnonce123")
    assert '<script nonce="testnonce123">' in html
    assert "requestFullscreen" in html
    assert 'class="folio-fullscreen"' in html


def test_document_mode_is_script_free() -> None:
    html = render_presented_page(body="# Hi", nonce="testnonce123")
    assert "<script" not in html.lower()
    assert "requestfullscreen" not in html.lower()
    assert 'id="folio-fullscreen"' not in html


def test_presentation_without_nonce_stays_script_free() -> None:
    theme = {"tokens": {"layout": {"mode": "presentation"}}}
    assert "<script" not in render_presented_page(body="# Hi", theme=theme).lower()


def test_content_security_policy_document_mode_forbids_script() -> None:
    csp = content_security_policy(mode="document", nonce="abc", stream_host="customer-example.cloudflarestream.com")
    assert "script-src 'none'" in csp
    assert "nonce-abc" not in csp
    assert "frame-src https://customer-example.cloudflarestream.com" in csp


def test_content_security_policy_presentation_mode_uses_nonce() -> None:
    csp = content_security_policy(mode="presentation", nonce="abc", stream_host="customer-example.cloudflarestream.com")
    assert "script-src 'nonce-abc'" in csp
    assert "default-src 'none'" in csp


def test_present_route_sets_content_security_policy(monkeypatch) -> None:
    app = folio_api.create_app()
    present_route = next(route for route in app.routes if getattr(route, "path", None) == "/present/{token}")
    db_dependency = present_route.dependant.dependencies[0].call
    app.dependency_overrides[db_dependency] = lambda: object()

    async def fake_get_presented_document(_database, *, token: str) -> dict:
        return {"body": "# Private", "theme": None, "allowed_assets": {}}

    monkeypatch.setattr(folio_api, "get_presented_document", fake_get_presented_document)
    response = TestClient(app).get("/present/secret-token")

    assert response.status_code == 200
    csp = response.headers["content-security-policy"]
    assert "script-src 'none'" in csp
    assert "default-src 'none'" in csp


def test_render_presented_page_has_print_stylesheet() -> None:
    style = render_presented_page(body="# Hi").split("</style>", 1)[0]
    assert "@media print" in style


def test_contrast_ratio_black_on_white_is_maximal() -> None:
    assert contrast_ratio("#000000", "#ffffff") == pytest.approx(21.0, abs=0.1)


def test_contrast_ratio_returns_none_for_unparseable() -> None:
    assert contrast_ratio("transparent", "#ffffff") is None
    assert contrast_ratio("not-a-color", "#ffffff") is None


def test_theme_contrast_error_passes_readable_pair() -> None:
    assert theme_contrast_error({"colors": {"text": "#111827", "surface": "#ffffff"}}) is None


def test_theme_contrast_error_passes_when_only_background_set() -> None:
    assert theme_contrast_error({"colors": {"background": "#001122", "surface": "#ffffff"}}) is None


def test_theme_contrast_error_flags_unreadable_text_on_surface() -> None:
    error = theme_contrast_error({"colors": {"surface": "#111827"}})
    assert error is not None
    assert "contrast" in error.lower()


@pytest.mark.parametrize(
    "value",
    ["transparent", "rgba(0, 0, 0, 0)", "#00000000"],
)
def test_theme_contrast_error_fails_closed_on_transparent_text(value: str) -> None:
    # Transparent / alpha-bearing text must NOT slip past the gate as readable.
    error = theme_contrast_error({"colors": {"text": value, "surface": "#ffffff"}})
    assert error is not None
    assert "opaque" in error.lower()


@pytest.mark.parametrize(
    "value",
    ["transparent", "rgba(255, 255, 255, 0)", "#ffffff00"],
)
def test_theme_contrast_error_fails_closed_on_transparent_surface(value: str) -> None:
    error = theme_contrast_error({"colors": {"text": "#111827", "surface": value}})
    assert error is not None
    assert "opaque" in error.lower()


def test_theme_contrast_error_allows_opaque_eight_digit_free_colors() -> None:
    assert theme_contrast_error({"colors": {"text": "rgb(17, 24, 39)", "surface": "white"}}) is None


def test_put_theme_rejects_transparent_or_alpha_contrast_bypass() -> None:
    app = folio_api.create_app()
    theme_route = next(
        route
        for route in app.routes
        if getattr(route, "path", None) == "/v1/theme" and "PUT" in getattr(route, "methods", set())
    )
    for dependency in theme_route.dependant.dependencies:
        if getattr(dependency.call, "__name__", "") in {"db", "principal"}:
            app.dependency_overrides[dependency.call] = lambda: object()
    client = TestClient(app)

    for value in ("transparent", "rgba(0, 0, 0, 0)", "#00000000"):
        response = client.put("/v1/theme", json={"tokens": {"colors": {"text": value, "surface": "#ffffff"}}})
        assert response.status_code == 422, (value, response.text)


_MEDIA_A = UUID("11111111-1111-4111-8111-111111111111")
_MEDIA_B = UUID("22222222-2222-4222-8222-222222222222")
_ORIGIN = "https://folio.aweb.ai"


def _render_media(body: str) -> str:
    return render_presented_markdown(body, public_origin=_ORIGIN, allowed_asset_ids={_MEDIA_A, _MEDIA_B})


def test_media_directive_emits_allowlisted_figure() -> None:
    html = _render_media(
        "\n".join(
            [
                ":::media",
                f"src: /assets/{_MEDIA_A}",
                "alt: A line graph of weekly active users",
                "placement: wrap-right",
                "size: w-third",
                "caption: WAU growth, Q1 2026",
                ":::",
            ]
        )
    )
    assert '<figure class="folio-media folio-wrap-right folio-w-third">' in html
    assert f'src="/assets/{_MEDIA_A}"' in html
    assert 'alt="A line graph of weekly active users"' in html
    assert "<figcaption>WAU growth, Q1 2026</figcaption>" in html


def test_media_directive_with_invalid_src_is_dropped() -> None:
    html = _render_media("\n".join([":::media", "src: https://evil.example.com/x.png", "alt: x", ":::"]))
    assert "<figure" not in html
    assert "evil.example.com" not in html


def test_media_directive_invalid_placement_and_size_fall_back() -> None:
    html = _render_media(
        "\n".join([":::media", f"src: /assets/{_MEDIA_A}", "alt: x", "placement: diagonal", "size: enormous", ":::"])
    )
    assert '<figure class="folio-media folio-block">' in html


def test_media_full_width_ignores_size() -> None:
    html = _render_media(
        "\n".join([":::media", f"src: /assets/{_MEDIA_A}", "alt: x", "placement: full-width", "size: w-half", ":::"])
    )
    assert '<figure class="folio-media folio-full-width">' in html
    assert "folio-w-half" not in html


def test_gallery_directive_drops_bad_items_per_item() -> None:
    html = _render_media(
        "\n".join(
            [
                ":::gallery",
                "placement: gallery-2",
                f'- /assets/{_MEDIA_A} "First"',
                '- /assets/not-a-uuid "Bad"',
                f'- /assets/{_MEDIA_B} "Second"',
                ":::",
            ]
        )
    )
    assert '<figure class="folio-media folio-gallery-2">' in html
    assert '<div class="folio-gallery-grid">' in html
    assert html.count('class="folio-gallery-item"') == 2
    assert 'alt="First"' in html
    assert 'alt="Second"' in html


def test_bare_asset_image_auto_wraps_to_full_width() -> None:
    html = _render_media(f"![a chart of revenue](/assets/{_MEDIA_A})")
    assert '<figure class="folio-media folio-full-width">' in html
    assert 'alt="a chart of revenue"' in html


def test_first_media_block_gets_fetchpriority_rest_lazy() -> None:
    html = _render_media(f"![first](/assets/{_MEDIA_A})\n\n![second](/assets/{_MEDIA_B})")
    assert html.count('fetchpriority="high"') == 1
    assert 'loading="lazy"' in html
    assert html.index('fetchpriority="high"') < html.index('loading="lazy"')


def test_media_caption_with_tags_is_escaped() -> None:
    html = _render_media(
        "\n".join([":::media", f"src: /assets/{_MEDIA_A}", "alt: x", "caption: <script>alert(1)</script>", ":::"])
    )
    assert "<script" not in html.lower()
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html


def test_media_figures_never_admit_an_iframe() -> None:
    html = _render_media('<figure class="folio-full-bleed"><iframe src="https://evil.example/frame"></iframe></figure>')
    assert "<iframe" not in html
    assert "evil.example" not in html


def test_raw_figure_cannot_inject_non_folio_class() -> None:
    html = _render_media('<figure class="evil-class folio-full-bleed">text</figure>')
    assert "evil-class" not in html


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
    assert "editable BOOLEAN NOT NULL DEFAULT FALSE" in migration
    assert "created_by_editor_name TEXT" in migration
    assert "FOREIGN KEY (document_id, version_number) REFERENCES {{tables.document_versions}}" in migration
    assert "arti" + "fact" not in migration.lower()

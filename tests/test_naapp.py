from __future__ import annotations

import aweb_naapp as naapp
from aweb_naapp import llms, manifest

_MANIFEST = {
    "tools": [
        {
            "name": "list-packs",
            "description": "Browse the public profile-pack catalog.",
            "method": "GET",
            "path": "/v1/profile-packs",
            "auth": "none",
            "params": [{"name": "tags", "in": "query"}],
            "input_schema": {"type": "object", "properties": {"tags": {"type": "array"}}},
        },
        {
            "name": "get-pack",
            "description": "Get a public profile pack.",
            "method": "GET",
            "path": "/v1/profile-packs/{pack_ref}",
            "auth": "none",
            "params": [{"name": "pack_ref", "in": "path"}],
            "input_schema": {"type": "object", "properties": {"pack_ref": {"type": "string"}}},
        },
        {
            "name": "import-to-shelf",
            "description": "Copy a public-pack profile onto the shelf.",
            "method": "POST",
            "path": "/v1/shelf/import",
            "params": [
                {"name": "source_profile_pack_ref", "in": "body"},
                {"name": "profile_ref", "in": "body"},
            ],
            "input_schema": {
                "type": "object",
                "properties": {
                    "source_profile_pack_ref": {"type": "string"},
                    "profile_ref": {"type": "string"},
                },
                "required": ["source_profile_pack_ref", "profile_ref"],
            },
            "scopes": ["library:write"],
            "mutation": True,
        },
    ]
}


def _site() -> naapp.SiteConfig:
    return naapp.SiteConfig(
        origin="https://library.aweb.ai",
        brand="library",
        title="library — API reference",
        description="desc",
        nav_links=(naapp.NavLink("Reference", "/reference"),),
        footer_blurb="blurb",
        footer_columns=(naapp.FooterColumn("aweb", (naapp.NavLink("aweb.ai", "https://aweb.ai"),)),),
        footer_bottom="library is a Native Agentic App on the aweb.ai hub.",
    )


def test_css_is_sha_pinned() -> None:
    assert naapp.aweb_css_sha256() == naapp.CSS_SHA256


def test_path_params_classified_required() -> None:
    # get-pack's pack_ref is in:path and absent from input_schema.required, but the
    # route cannot match without it — so it is required.
    for tool in _MANIFEST["tools"]:
        path_params = {p["name"] for p in tool.get("params", []) if p.get("in") == "path"}
        req, opt = manifest.tool_params(tool)
        assert path_params <= set(req), tool["name"]
        assert not (path_params & set(opt)), tool["name"]


def test_public_vs_cert_split() -> None:
    assert [t["name"] for t in manifest.public_tools(_MANIFEST)] == ["list-packs", "get-pack"]
    assert [t["name"] for t in manifest.cert_tools(_MANIFEST)] == ["import-to-shelf"]


def test_canonical_bytes_sorted_compact() -> None:
    assert manifest.canonical_bytes({"b": 1, "a": 2}) == b'{"a":2,"b":1}'


def test_page_wraps_body_in_chrome() -> None:
    html = naapp.page(_site(), "    <section>hi</section>")
    assert html.startswith("<!doctype html>\n<html lang=\"en\">")
    assert '<link rel="stylesheet" href="/css/aweb.css">' in html
    assert '<header class="site-header">' in html
    assert "<main>\n    <section>hi</section>\n  </main>" in html
    assert "Origin: https://library.aweb.ai" in html


def test_reference_documents_every_operation_dual() -> None:
    html = naapp.render_reference(
        _MANIFEST, _site(), verb="library", example_path_values={"pack_ref": "aweb.engineering-pack"}
    )
    for tool in _MANIFEST["tools"]:
        assert f"aw library {tool['name']}" in html
        assert tool["path"] in html
    # public read: literal runnable curl with live value, no brace placeholder
    assert "curl -s https://library.aweb.ai/v1/profile-packs/aweb.engineering-pack" in html
    # cert op: signed aw id request + the four headers + sorted envelope
    assert "aw id request --team-auth POST https://library.aweb.ai/v1/shelf/import" in html
    for header in ("Authorization", "X-AWEB-Timestamp", "X-AWEB-Signed-Payload", "X-AWID-Team-Certificate"):
        assert header in html
    assert html.index('"aud"') < html.index('"body_sha256"') < html.index('"v": 2')
    assert naapp.VECTOR_URL in html


def test_reference_verb_namespace_is_parametric() -> None:
    html = naapp.render_reference(_MANIFEST, _site(), verb="folio")
    assert "aw folio list-packs" in html
    assert "aw library" not in html


def test_llms_blocks_render_from_manifest() -> None:
    ops = llms.public_operations(_MANIFEST, "library")
    assert "aw library list-packs  (GET /v1/profile-packs)" in ops
    auth = llms.auth_section(_MANIFEST, "https://library.aweb.ai")
    assert "list-packs, get-pack" in auth
    assert "base64url WITHOUT padding" in auth
    assert "https://library.aweb.ai/reference" in auth


# A non-Library manifest and a non-Library path-param name, to prove the seam is
# reusable — not specialized to library's pack_ref/profile_ref and catalog nouns.
_DOCS_MANIFEST = {
    "tools": [
        {
            "name": "get-doc",
            "description": "Get a documentation page.",
            "method": "GET",
            "path": "/v1/docs/{doc_id}",
            "auth": "none",
            "params": [{"name": "doc_id", "in": "path"}],
            "input_schema": {"type": "object", "properties": {"doc_id": {"type": "string"}}},
        },
    ]
}


def _docs_site() -> naapp.SiteConfig:
    return naapp.SiteConfig(
        origin="https://docs.example.ai",
        brand="docs",
        title="docs — API reference",
        description="desc",
        nav_links=(naapp.NavLink("Reference", "/reference"),),
        footer_blurb="blurb",
        footer_columns=(),
        footer_bottom="docs is a Native Agentic App.",
    )


def test_public_read_runnable_only_when_example_supplied() -> None:
    # No example for doc_id: the curl keeps the brace and is NOT labelled runnable.
    html_no = naapp.render_reference(_DOCS_MANIFEST, _docs_site(), verb="docs")
    assert "/v1/docs/{doc_id}" in html_no
    assert "On the wire — runnable" not in html_no
    # Example supplied: a genuinely runnable curl, no brace placeholder anywhere
    # labelled runnable.
    html_yes = naapp.render_reference(
        _DOCS_MANIFEST, _docs_site(), verb="docs", example_path_values={"doc_id": "getting-started"}
    )
    assert "curl -s https://docs.example.ai/v1/docs/getting-started" in html_yes
    assert "On the wire — runnable" in html_yes
    for line in html_yes.splitlines():
        if "curl -s" in line:
            assert "{" not in line and "}" not in line, line


def test_reference_has_no_library_nouns_by_default() -> None:
    # With default ReferenceCopy, a non-Library app gets no Library-specific nouns.
    html = naapp.render_reference(
        _DOCS_MANIFEST, _docs_site(), verb="docs", example_path_values={"doc_id": "getting-started"}
    )
    for noun in ("catalog", "profile-pack", "shelf", "Shelf", "Library", "library"):
        assert noun not in html, noun

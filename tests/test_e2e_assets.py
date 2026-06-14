from __future__ import annotations

import base64
import json
from collections.abc import Callable
from typing import Any

import httpx
import pytest
from test_e2e_present import _mint_present
from test_e2e_smoke import (
    AWWorkspace,
    RunningFolio,
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

_ONE_BY_ONE_PNG_BYTES = (
    b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
    b"\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\rIDATx\x9cc\xf8\xff\xff?\x00\x05\xfe\x02\xfeA\xe2\x8b\x9b"
    b"\x00\x00\x00\x00IEND\xaeB`\x82"
)
_ONE_BY_ONE_PNG = base64.b64encode(_ONE_BY_ONE_PNG_BYTES).decode("ascii")
_SVG_WITH_SCRIPT = base64.b64encode(
    b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'
).decode("ascii")


def _upload_asset(folio: RunningFolio, team: Any, *, content_type: str = "image/png", data_base64: str = _ONE_BY_ONE_PNG) -> dict[str, Any]:
    result = _aw_request(
        team,
        "POST",
        f"{folio.origin}/v1/assets",
        body=json.dumps({"content_type": content_type, "data_base64": data_base64}, separators=(",", ":")),
    )
    data = _aw_json(result, context="upload asset")
    assert isinstance(data, dict)
    return data


def test_image_asset_upload_embed_render_and_team_scoped_sanitizer(
    folio: RunningFolio,
    aw_workspace_factory: Callable[[str], AWWorkspace],
) -> None:
    team_a = _provision_team(aw_workspace_factory("assets-a"), alias="alice")
    team_b = _provision_team(aw_workspace_factory("assets-b"), alias="bob")

    invalid_svg = _aw_request(
        team_a,
        "POST",
        f"{folio.origin}/v1/assets",
        body=json.dumps({"content_type": "image/svg+xml", "data_base64": _SVG_WITH_SCRIPT}, separators=(",", ":")),
    )
    _assert_aw_status(invalid_svg, 400, context="reject SVG asset upload")
    mismatched = _aw_request(
        team_a,
        "POST",
        f"{folio.origin}/v1/assets",
        body=json.dumps({"content_type": "image/png", "data_base64": _SVG_WITH_SCRIPT}, separators=(",", ":")),
    )
    _assert_aw_status(mismatched, 400, context="reject asset magic byte mismatch")

    asset_a = _upload_asset(folio, team_a)
    assert asset_a["content_type"] == "image/png"
    assert asset_a["url"] == f"{folio.origin}/assets/{asset_a['asset_id']}"

    fetched = httpx.get(asset_a["url"], timeout=10.0)
    assert fetched.status_code == 200, fetched.text
    assert fetched.headers["content-type"].startswith("image/png")
    assert fetched.headers["x-content-type-options"] == "nosniff"
    assert fetched.content == _ONE_BY_ONE_PNG_BYTES

    _create_document(
        folio,
        team_a,
        slug="deck",
        title="Deck",
        body=(
            f"# Deck\n\n![safe chart]({asset_a['url']})\n\n"
            "![external](https://example.com/hotlink.png)\n\n"
            "![data](data:image/png;base64,AAAA)\n\n"
            "<script>alert('x')</script>"
        ),
    )
    page = httpx.get(_mint_present(folio, team_a, slug="deck")["url"], timeout=10.0)
    assert page.status_code == 200, page.text
    assert f'src="{asset_a["url"]}"' in page.text
    assert "safe chart" in page.text
    assert "example.com" not in page.text
    assert "data:image" not in page.text
    assert "<script" not in page.text.lower()
    assert "alert(" not in page.text

    _create_document(
        folio,
        team_b,
        slug="borrowed",
        title="Borrowed",
        body=f"# Borrowed\n\n![other team]({asset_a['url']})",
    )
    b_page = httpx.get(_mint_present(folio, team_b, slug="borrowed")["url"], timeout=10.0)
    assert b_page.status_code == 200, b_page.text
    assert "<img" not in b_page.text.lower()
    assert str(asset_a["asset_id"]) not in b_page.text

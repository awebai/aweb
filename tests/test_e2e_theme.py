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

_ONE_BY_ONE_PNG = base64.b64encode(
    b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
    b"\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\rIDATx\x9cc\xf8\xff\xff?\x00\x05\xfe\x02\xfeA\xe2\x8b\x9b"
    b"\x00\x00\x00\x00IEND\xaeB`\x82"
).decode("ascii")
_SVG_WITH_SCRIPT = base64.b64encode(
    b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'
).decode("ascii")


def _put_theme(folio: RunningFolio, team: Any, payload: dict[str, Any]) -> dict[str, Any]:
    result = _aw_request(
        team,
        "PUT",
        f"{folio.origin}/v1/theme",
        body=json.dumps(payload, separators=(",", ":")),
    )
    data = _aw_json(result, context="put theme")
    assert isinstance(data, dict)
    return data


def _get_theme(folio: RunningFolio, team: Any) -> dict[str, Any]:
    result = _aw_request(team, "GET", f"{folio.origin}/v1/theme")
    data = _aw_json(result, context="get theme")
    assert isinstance(data, dict)
    return data


def test_theme_wraps_present_page_and_body_team_cannot_cross_scope(
    folio: RunningFolio,
    aw_workspace_factory: Callable[[str], AWWorkspace],
) -> None:
    team_a = _provision_team(aw_workspace_factory("theme-a"), alias="alice")
    team_b = _provision_team(aw_workspace_factory("theme-b"), alias="bob")

    _create_document(folio, team_a, slug="memo", title="Memo", body="# Plain\n\nA table:\n\n| A | B |\n| - | - |\n| 1 | 2 |")
    no_theme = _mint_present(folio, team_a, slug="memo")
    no_theme_page = httpx.get(no_theme["url"], timeout=10.0)
    assert no_theme_page.status_code == 200, no_theme_page.text
    assert "Presented with folio" in no_theme_page.text
    assert "theme-header" in no_theme_page.text
    assert "Brand header" not in no_theme_page.text
    assert "<img class=\"brand-logo\"" not in no_theme_page.text
    assert "<table>" in no_theme_page.text

    invalid_logo = _aw_request(
        team_a,
        "PUT",
        f"{folio.origin}/v1/theme",
        body=json.dumps(
            {"logo": {"content_type": "text/html", "data_base64": _ONE_BY_ONE_PNG}},
            separators=(",", ":"),
        ),
    )
    _assert_aw_status(invalid_logo, 400, context="reject non-image logo content type")
    svg_logo = _aw_request(
        team_a,
        "PUT",
        f"{folio.origin}/v1/theme",
        body=json.dumps(
            {"logo": {"content_type": "image/svg+xml", "data_base64": _SVG_WITH_SCRIPT}},
            separators=(",", ":"),
        ),
    )
    _assert_aw_status(svg_logo, 400, context="reject SVG logo content type")
    mismatched_logo = _aw_request(
        team_a,
        "PUT",
        f"{folio.origin}/v1/theme",
        body=json.dumps(
            {"logo": {"content_type": "image/png", "data_base64": _SVG_WITH_SCRIPT}},
            separators=(",", ":"),
        ),
    )
    _assert_aw_status(mismatched_logo, 400, context="reject logo magic byte mismatch")

    theme = _put_theme(
        folio,
        team_a,
        {
            "tokens": {
                "colors": {
                    "background": "#001122",
                    "surface": "#ffffff",
                    "accent": "rgb(1, 2, 3)",
                    "text": "</style><script>alert(1)</script>",
                },
                "fonts": {
                    "body": "serif",
                    "heading": "</style><script>alert(2)</script>",
                },
            },
            "logo": {"content_type": "image/png", "data_base64": _ONE_BY_ONE_PNG},
            "header": "Brand header </style><script>alert(3)</script>",
            "footer": "Brand footer <img src=x onerror=alert(4)>",
        },
    )
    assert theme["tokens"]["colors"] == {
        "background": "#001122",
        "surface": "#ffffff",
        "accent": "rgb(1, 2, 3)",
    }
    assert theme["tokens"]["fonts"] == {"body": "serif"}
    assert theme["logo_asset_id"] is not None
    assert theme["logo_url"] == f"{folio.origin}/assets/{theme['logo_asset_id']}"

    logo = httpx.get(theme["logo_url"], timeout=10.0)
    assert logo.status_code == 200, logo.text
    assert logo.headers["content-type"].startswith("image/png")
    assert logo.headers["x-content-type-options"] == "nosniff"
    assert logo.content == base64.b64decode(_ONE_BY_ONE_PNG)

    themed = _mint_present(folio, team_a, slug="memo")
    themed_page = httpx.get(themed["url"], timeout=10.0)
    assert themed_page.status_code == 200, themed_page.text
    style = themed_page.text.split("</style>", 1)[0]
    assert "--bg: #001122;" in style
    assert "--surface: #ffffff;" in style
    assert "--accent: rgb(1, 2, 3);" in style
    assert "--font-body: Georgia" in style
    assert "alert(" not in style
    assert "<script" not in themed_page.text.lower()
    assert "</style><script" not in themed_page.text.lower()
    assert "&lt;/style&gt;&lt;script&gt;alert(3)&lt;/script&gt;" in themed_page.text
    assert "&lt;img src=x onerror=alert(4)&gt;" in themed_page.text
    assert f'src="{folio.origin}/assets/{theme["logo_asset_id"]}"' in themed_page.text
    assert "<table>" in themed_page.text

    b_theme = _put_theme(
        folio,
        team_b,
        {
            "team_id": team_a.team_id,
            "tokens": {"colors": {"background": "#330000"}},
            "header": "Bob tried to name team A",
        },
    )
    assert b_theme["tokens"] == {"colors": {"background": "#330000"}}
    assert _get_theme(folio, team_b)["header"] == "Bob tried to name team A"
    assert _get_theme(folio, team_a)["header"] == "Brand header </style><script>alert(3)</script>"

    still_a = httpx.get(_mint_present(folio, team_a, slug="memo")["url"], timeout=10.0)
    assert "--bg: #001122;" in still_a.text
    assert "#330000" not in still_a.text
    assert "Bob tried" not in still_a.text

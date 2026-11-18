"""Image bytes are served only under a live capability, on the real stack.

Real awid, the real coordination server, a real Folio process and a real aw
install/uninstall: nothing on the authorization path is replaced. Every image
URL is taken from what Folio renders, so the test proves what a viewer sees.
"""

from __future__ import annotations

import asyncio
import base64
import html
import json
import re
import subprocess
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import parse_qs, urljoin, urlsplit

import asyncpg
import httpx
import pytest
from playwright.sync_api import sync_playwright
from test_e2e_present import _mint_present
from test_e2e_smoke import (
    POSTGRES_URL,
    AWWorkspace,
    E2ETeam,
    RunningFolio,
    _append_version,
    _aw_json,
    _aw_request,
    _create_document,
    _provision_team,
    _run_aw,
    aw_workspace_factory,
    folio,
)

__all__ = ["folio", "aw_workspace_factory"]

pytestmark = pytest.mark.e2e

_PNG_HEADER = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
_PNG_TRAILER = b"\x00\x00\x00\x00IEND\xaeB`\x82"
_IMG_SRC = re.compile(r'<img class="folio-img" src="([^"]+)"')
_LOGO_SRC = re.compile(r'<img class="brand-logo" src="([^"]+)"')


# A decodable 1x1 PNG: a browser only reports a loaded image for real pixels.
_PIXEL_PNG = (
    b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
    b"\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\rIDATx\x9cc\xf8\xff\xff?\x00\x05\xfe\x02\xfeA\xe2\x8b\x9b"
    b"\x00\x00\x00\x00IEND\xaeB`\x82"
)
_LOADED_IMAGE = """([selector, source]) => [...document.querySelectorAll(selector)].some(
    (img) => (!source || (img.dataset.folioSource || img.src).includes(source))
        && img.complete && img.naturalWidth > 0)"""


def _png(marker: str) -> bytes:
    """A distinct PNG per image: the bytes say which image a response served."""
    return _PNG_HEADER + marker.encode("ascii") + _PNG_TRAILER


def _upload(folio: RunningFolio, team: E2ETeam, payload: bytes) -> str:
    body = json.dumps(
        {"content_type": "image/png", "data_base64": base64.b64encode(payload).decode("ascii")},
        separators=(",", ":"),
    )
    uploaded = _aw_json(
        _aw_request(team, "POST", f"{folio.origin}/v1/assets", body=body), context="upload image"
    )
    return str(uploaded["asset_id"])


def _set_logo(folio: RunningFolio, team: E2ETeam, payload: bytes) -> None:
    body = json.dumps(
        {
            "logo": {
                "content_type": "image/png",
                "data_base64": base64.b64encode(payload).decode("ascii"),
            }
        },
        separators=(",", ":"),
    )
    _aw_json(
        _aw_request(team, "PUT", f"{folio.origin}/v1/theme", body=body), context="set theme logo"
    )


def _rendered_srcs(page: httpx.Response, pattern: re.Pattern[str]) -> list[str]:
    return [urljoin(str(page.url), html.unescape(src)) for src in pattern.findall(page.text)]


def _served(response: httpx.Response, payload: bytes) -> bool:
    """The image's own bytes, as private user content of the uploaded type."""
    return (
        response.status_code == 200
        and response.content == payload
        and response.headers.get("content-type", "").startswith("image/png")
        and response.headers.get("x-content-type-options") == "nosniff"
        and response.headers.get("cache-control") == "no-store"
    )


def _refused(response: httpx.Response, payload: bytes) -> bool:
    return 400 <= response.status_code < 500 and payload not in response.content


def _member_read(team: E2ETeam, url: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["aw", "id", "request", "GET", url, "--team-auth", "--raw"],
        cwd=team.workspace.path,
        env=team.workspace.env,
        capture_output=True,
        timeout=60,
        check=False,
    )


def _content_url(folio: RunningFolio, asset_id: str) -> str:
    return f"{folio.origin}/v1/assets/{asset_id}/content"


def _wait_until_refused(url: str, *, bound_seconds: float = 30.0) -> None:
    deadline = time.monotonic() + bound_seconds
    while True:
        status = httpx.get(url, timeout=10.0).status_code
        if 400 <= status < 500:
            return
        assert time.monotonic() < deadline, f"{url} still answers {status} after {bound_seconds}s"
        time.sleep(0.5)


def test_bare_asset_reference_is_served_to_nobody(
    folio: RunningFolio,
    aw_workspace_factory: Callable[[str], AWWorkspace],
) -> None:
    team = _provision_team(aw_workspace_factory("bare-ref"), folio=folio, alias="alice")
    image = _png("bare")
    asset_id = _upload(folio, team, image)

    anonymous = httpx.get(f"{folio.origin}/assets/{asset_id}", timeout=10.0)
    assert _refused(anonymous, image), anonymous.status_code


def test_present_page_images_follow_their_link(
    folio: RunningFolio,
    aw_workspace_factory: Callable[[str], AWWorkspace],
    tmp_path: Path,
) -> None:
    team = _provision_team(aw_workspace_factory("present-images"), folio=folio, alias="alice")
    other = _provision_team(aw_workspace_factory("present-images-b"), folio=folio, alias="bob")
    first, second, logo, foreign = _png("first"), _png("second"), _png("logo"), _png("foreign")
    first_id = _upload(folio, team, first)
    second_id = _upload(folio, team, second)
    foreign_id = _upload(folio, other, foreign)
    _set_logo(folio, team, logo)
    _create_document(
        folio, team, slug="deck", title="Deck", body=f"# Deck\n\n![first](/assets/{first_id})\n"
    )
    _append_version(
        folio,
        team,
        slug="deck",
        body=f"# Deck\n\n![second](/assets/{second_id})\n",
        tmp_path=tmp_path,
    )

    # An older pinned version keeps showing its own image, with the team logo.
    pinned = _mint_present(folio, team, slug="deck", version=1)
    page = httpx.get(pinned["url"], timeout=10.0)
    assert page.status_code == 200, page.text
    [image_url] = _rendered_srcs(page, _IMG_SRC)
    [logo_url] = _rendered_srcs(page, _LOGO_SRC)
    assert _served(httpx.get(image_url, timeout=10.0), first)
    assert _served(httpx.get(logo_url, timeout=10.0), logo)

    # The link shows only what its pinned version references.
    for unreferenced, payload in ((second_id, second), (foreign_id, foreign)):
        swapped = image_url.replace(first_id, unreferenced)
        assert swapped != image_url
        assert _refused(httpx.get(swapped, timeout=10.0), payload)

    revoked = _aw_request(team, "POST", f"{folio.origin}/v1/present/{pinned['token']}/revoke")
    assert _aw_json(revoked, context="revoke link") == {"revoked": True}
    assert httpx.get(pinned["url"], timeout=10.0).status_code == 404
    assert _refused(httpx.get(image_url, timeout=10.0), first)
    assert _refused(httpx.get(logo_url, timeout=10.0), logo)

    short = _mint_present(folio, team, slug="deck", version=1, ttl_seconds=3)
    short_page = httpx.get(short["url"], timeout=10.0)
    assert short_page.status_code == 200, short_page.text
    [short_image] = _rendered_srcs(short_page, _IMG_SRC)
    [short_logo] = _rendered_srcs(short_page, _LOGO_SRC)
    assert _served(httpx.get(short_image, timeout=10.0), first)
    expires_at = datetime.fromisoformat(str(short["expires_at"]).replace("Z", "+00:00"))
    time.sleep(max(0.0, (expires_at - datetime.now(UTC)).total_seconds()) + 0.5)
    assert httpx.get(short["url"], timeout=10.0).status_code == 404
    assert _refused(httpx.get(short_image, timeout=10.0), first)
    assert _refused(httpx.get(short_logo, timeout=10.0), logo)


def test_member_reads_image_bytes_with_team_auth_in_its_own_team(
    folio: RunningFolio,
    aw_workspace_factory: Callable[[str], AWWorkspace],
) -> None:
    team = _provision_team(aw_workspace_factory("member-read"), folio=folio, alias="alice")
    other = _provision_team(aw_workspace_factory("member-read-b"), folio=folio, alias="bob")
    image = _png("member")
    asset_id = _upload(folio, team, image)

    read = _member_read(team, _content_url(folio, asset_id))
    assert read.returncode == 0, read.stderr.decode(errors="replace")
    assert read.stdout == image

    cross_team = _member_read(other, _content_url(folio, asset_id))
    assert cross_team.returncode != 0
    assert image not in cross_team.stdout

    anonymous = httpx.get(_content_url(folio, asset_id), timeout=10.0)
    assert _refused(anonymous, image), anonymous.status_code


def test_uninstall_ends_presented_images_and_member_reads(
    folio: RunningFolio,
    aw_workspace_factory: Callable[[str], AWWorkspace],
) -> None:
    team = _provision_team(aw_workspace_factory("uninstall-images"), folio=folio, alias="alice")
    image = _png("uninstall")
    asset_id = _upload(folio, team, image)
    _create_document(
        folio, team, slug="deck", title="Deck", body=f"# Deck\n\n![one](/assets/{asset_id})\n"
    )
    link = _mint_present(folio, team, slug="deck")
    page = httpx.get(link["url"], timeout=10.0)
    assert page.status_code == 200, page.text
    [image_url] = _rendered_srcs(page, _IMG_SRC)
    assert _served(httpx.get(image_url, timeout=10.0), image)
    before = _member_read(team, _content_url(folio, asset_id))
    assert before.returncode == 0 and before.stdout == image, before.stderr.decode(errors="replace")

    _run_aw(team.workspace, "plugin", "uninstall", folio.app_id)

    # The unrevoked link's page ends once Folio observes the uninstall.
    _wait_until_refused(link["url"])
    assert _refused(httpx.get(image_url, timeout=10.0), image)
    after = _member_read(team, _content_url(folio, asset_id))
    assert after.returncode != 0
    assert image not in after.stdout


def test_editor_session_reads_images_until_revoked(
    folio: RunningFolio,
    aw_workspace_factory: Callable[[str], AWWorkspace],
) -> None:
    team = _provision_team(aw_workspace_factory("editor-images"), folio=folio, alias="alice")
    image, logo = _png("editor"), _png("editor-logo")
    asset_id = _upload(folio, team, image)
    _set_logo(folio, team, logo)
    _create_document(
        folio, team, slug="deck", title="Deck", body=f"# Deck\n\n![one](/assets/{asset_id})\n"
    )

    editable = _mint_present(folio, team, slug="deck", editable=True)
    parts = urlsplit(editable["url"])
    session_url = parts._replace(fragment="").geturl()
    opened = httpx.post(
        session_url + "/session", json={"opener": parse_qs(parts.fragment)["k"][0]}, timeout=10.0
    )
    assert opened.status_code == 200, opened.text
    snapshot = opened.json()
    headers = {"X-Folio-Edit-Session": snapshot["session_secret"]}

    [snapshot_image] = [
        urljoin(session_url, html.unescape(src)) for src in _IMG_SRC.findall(snapshot["html"])
    ]
    logo_url = urljoin(session_url, snapshot["theme"]["logo_url"])
    preview = httpx.post(
        session_url + "/preview",
        headers=headers,
        json={"body": f"Draft\n\n![one](/assets/{asset_id})\n"},
        timeout=10.0,
    )
    assert preview.status_code == 200, preview.text
    [preview_image] = _rendered_srcs(preview, _IMG_SRC)
    for url, payload in ((snapshot_image, image), (preview_image, image), (logo_url, logo)):
        assert _served(httpx.get(url, headers=headers, timeout=10.0), payload)
        assert _refused(httpx.get(url, timeout=10.0), payload)

    revoked = _aw_request(team, "POST", f"{folio.origin}/v1/present/{editable['token']}/revoke")
    assert _aw_json(revoked, context="revoke editable link") == {"revoked": True}
    for url, payload in ((preview_image, image), (logo_url, logo)):
        assert _refused(httpx.get(url, headers=headers, timeout=10.0), payload)


async def _stored_copies(token: str) -> list[str]:
    """Every user-table column, in any schema, whose value contains the token."""
    connection = await asyncpg.connect(POSTGRES_URL)
    try:
        columns = await connection.fetch(
            """SELECT table_schema, table_name, column_name, data_type
            FROM information_schema.columns
            WHERE table_schema NOT IN ('pg_catalog', 'information_schema')
              AND data_type IN ('text', 'character varying', 'jsonb', 'json', 'bytea')"""
        )
        found = []
        for column in columns:
            name = f'"{column["table_schema"]}"."{column["table_name"]}"'
            field = f'"{column["column_name"]}"'
            if column["data_type"] == "bytea":
                predicate = f"position(convert_to($1, 'UTF8') in {field}) > 0"
            else:
                predicate = f"strpos({field}::text, $1) > 0"
            if await connection.fetchval(
                f"SELECT EXISTS (SELECT 1 FROM {name} WHERE {predicate})", token
            ):
                found.append(f"{name}.{field}")
        return found
    finally:
        await connection.close()


def test_read_only_token_is_stored_only_as_a_verifier(
    folio: RunningFolio,
    aw_workspace_factory: Callable[[str], AWWorkspace],
) -> None:
    team = _provision_team(aw_workspace_factory("verifier"), folio=folio, alias="alice")
    _create_document(folio, team, slug="deck", title="Deck", body="# Deck\n\nBody")
    link = _mint_present(folio, team, slug="deck")
    token = str(link["token"])
    assert urlsplit(link["url"]).path == f"/present/{token}"

    assert asyncio.run(_stored_copies(token)) == []
    assert httpx.get(link["url"], timeout=10.0).status_code == 200
    revoked = _aw_request(team, "POST", f"{folio.origin}/v1/present/{token}/revoke")
    assert _aw_json(revoked, context="revoke by minted token") == {"revoked": True}
    assert httpx.get(link["url"], timeout=10.0).status_code == 404


def test_browser_shows_images_on_the_present_page_and_in_the_editor(
    folio: RunningFolio,
    aw_workspace_factory: Callable[[str], AWWorkspace],
    tmp_path: Path,
) -> None:
    team = _provision_team(aw_workspace_factory("browser-images"), folio=folio, alias="alice")
    first_id = _upload(folio, team, _PIXEL_PNG)
    second_id = _upload(folio, team, _PIXEL_PNG)
    _set_logo(folio, team, _PIXEL_PNG)
    _create_document(
        folio, team, slug="deck", title="Deck", body=f"# Deck\n\n![first](/assets/{first_id})\n"
    )
    _append_version(
        folio,
        team,
        slug="deck",
        body=f"# Deck\n\n![second](/assets/{second_id})\n",
        tmp_path=tmp_path,
    )
    pinned = _mint_present(folio, team, slug="deck", version=1)
    editable = _mint_present(folio, team, slug="deck", editable=True)

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        try:
            page = browser.new_page(ignore_https_errors=True)
            page.goto(pinned["url"])
            page.wait_for_function(_LOADED_IMAGE, arg=["img.folio-img", first_id], timeout=10000)
            page.wait_for_function(_LOADED_IMAGE, arg=["img.brand-logo", ""], timeout=10000)

            editor = browser.new_page(ignore_https_errors=True)
            editor.goto(editable["url"])
            editor.wait_for_function(
                _LOADED_IMAGE, arg=["#preview img.folio-img", second_id], timeout=10000
            )
            editor.wait_for_function(_LOADED_IMAGE, arg=[".brand-logo", ""], timeout=10000)
            editor.locator("#body").fill(f"Draft\n\n![first](/assets/{first_id})\n")
            editor.wait_for_function(
                _LOADED_IMAGE, arg=["#preview img.folio-img", first_id], timeout=10000
            )
        finally:
            browser.close()


def test_editor_marks_refused_images_and_retries_failed_reads(
    folio: RunningFolio,
    aw_workspace_factory: Callable[[str], AWWorkspace],
) -> None:
    team = _provision_team(aw_workspace_factory("editor-image-states"), folio=folio, alias="alice")
    asset_id = _upload(folio, team, _PIXEL_PNG)
    _create_document(
        folio, team, slug="deck", title="Deck", body=f"# Deck\n\n![one](/assets/{asset_id})\n"
    )
    image_path = f"**/assets/{asset_id}"

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        try:
            # An outage on the first read: marked as retrying, then shown.
            failures = [503]
            retrying = browser.new_page(ignore_https_errors=True)
            retrying.route(
                image_path,
                lambda route: (
                    route.fulfill(status=failures.pop()) if failures else route.continue_()
                ),
            )
            retrying.goto(_mint_present(folio, team, slug="deck", editable=True)["url"])
            retrying.wait_for_selector('#preview img[data-folio-image="retrying"]', timeout=10000)
            retrying.wait_for_function(
                _LOADED_IMAGE, arg=["#preview img.folio-img", asset_id], timeout=15000
            )
            assert retrying.locator("#preview img[data-folio-image]").count() == 0

            # A refusal: marked as refused, not retried into a blank.
            refused = browser.new_page(ignore_https_errors=True)
            refused.route(image_path, lambda route: route.fulfill(status=404))
            refused.goto(_mint_present(folio, team, slug="deck", editable=True)["url"])
            refused.wait_for_selector('#preview img[data-folio-image="refused"]', timeout=10000)
        finally:
            browser.close()

"""Real PG/HTTP/browser editor refresh; the separate CLI e2e uses real AWID."""
from __future__ import annotations

import asyncio
import socket
from urllib.parse import urlsplit

import httpx
import pytest
import uvicorn
from fastapi import Request
from playwright.async_api import async_playwright, expect
from test_present_privacy import OWNER, present_world

from folio.repository import mint_presentation_link

__all__ = ["present_world"]


@pytest.fixture
async def live_world(present_world):
    app, db, settings = present_world
    async def owner(request: Request):
        request.state.folio_installation = await app.state.folio_runtime.installation_fence().permit(OWNER.team_id)
        return OWNER
    for route in app.routes:
        for dep in getattr(getattr(route, "dependant", None), "dependencies", ()):
            if dep.name == "actor":
                app.dependency_overrides[dep.call] = owner
    return app, db, settings


async def link(world, *, editable=False, version=None):
    _, db, settings = world
    return await mint_presentation_link(
        db, installation_id="test-installation", principal=OWNER, settings=settings, slug="draft", version=version,
        editable=editable, ttl_seconds=300,
    )


@pytest.fixture
async def live_browser(live_world):
    app, _, _ = live_world
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        origin = f"http://127.0.0.1:{listener.getsockname()[1]}"
        server = uvicorn.Server(uvicorn.Config(app, lifespan="off", log_config=None, ws="none"))
        serving = asyncio.create_task(server.serve(sockets=[listener]))
        try:
            async with asyncio.timeout(10):
                while not server.started:
                    if serving.done():
                        await serving
                    await asyncio.sleep(0.01)
            async with async_playwright() as p:
                browser = await p.chromium.launch()
                try:
                    yield origin, browser
                finally:
                    await browser.close()
        finally:
            server.should_exit = True
            await serving


async def test_clean_editor_follows_agent_and_other_browser(live_world, live_browser):
    origin, browser = live_browser
    edit = await link(live_world, editable=True)
    editor, other = [await browser.new_page() for _ in range(2)]
    await editor.goto(origin + urlsplit(edit["url"]).path + "#" + urlsplit(edit["url"]).fragment)
    async with httpx.AsyncClient(base_url=origin) as client:
        response = await client.post("/v1/documents/draft/versions", content="# Agent second")
        assert response.status_code == 200
    await expect(editor.locator("#body")).to_have_value("# Agent second", timeout=10000)
    other_link = await link(live_world, editable=True)
    await other.goto(origin + urlsplit(other_link["url"]).path + "#" + urlsplit(other_link["url"]).fragment)
    await other.locator("#body").fill("# Person third")
    await other.locator("#save").click()
    await expect(other.locator("#save")).to_be_disabled()
    await expect(editor.locator("#body")).to_have_value("# Person third", timeout=10000)


async def test_dirty_editor_retains_draft_until_explicit_latest_load(live_world, live_browser):
    origin, browser = live_browser
    edit = await link(live_world, editable=True)
    page = await browser.new_page(viewport={"width": 375, "height": 812})
    await page.goto(origin + urlsplit(edit["url"]).path + "#" + urlsplit(edit["url"]).fragment)
    await expect(page.locator("#body")).to_have_value("Original")
    await page.locator("#body").fill("My unsaved text")
    await page.locator("#body").focus()
    await page.locator("#body").evaluate("el => el.setSelectionRange(3, 8)")
    async with httpx.AsyncClient(base_url=origin) as client:
        assert (await client.post("/v1/documents/draft/versions", content="Remote second")).status_code == 200
    await expect(page.locator("#load-latest")).to_be_visible(timeout=10000)
    await expect(page.locator("#body")).to_have_value("My unsaved text")
    await expect(page.locator("#body")).to_be_focused()
    assert await page.locator("#body").evaluate("el => [el.selectionStart, el.selectionEnd]") == [3, 8]
    await page.locator("#load-latest").click()
    await expect(page.locator("#load-dialog")).to_be_visible()
    await page.locator("#load-cancel").click()
    await expect(page.locator("#body")).to_have_value("My unsaved text")
    await page.locator("#load-latest").click()
    await page.locator("#load-confirm").click()
    await expect(page.locator("#body")).to_have_value("Remote second")
    await expect(page.locator("#save")).to_be_disabled()
    await page.locator("#body").fill("Explicit new draft")
    async with page.expect_response(lambda response: response.url.endswith('/edit')) as saved:
        await page.locator("#save").click()
    assert (await saved.value).status == 200
    await expect(page.locator("#save")).to_be_disabled()
    _, db, _ = live_world
    rows = await db.fetch_all("SELECT body FROM {{tables.document_versions}} ORDER BY version_number")
    assert [r["body"] for r in rows] == ["Original", "Remote second", "Explicit new draft"]


async def test_typing_while_refresh_is_in_flight_keeps_text(live_world, live_browser):
    origin, browser = live_browser
    app, _, _ = live_world
    edit = await link(live_world, editable=True)
    held, release, changed = asyncio.Event(), asyncio.Event(), asyncio.Event()

    @app.middleware("http")
    async def hold_changed_state(request, call_next):
        response = await call_next(request)
        if request.url.path.endswith("/state") and changed.is_set():
            held.set()
            await release.wait()
        return response

    page = await browser.new_page()
    await page.goto(origin + urlsplit(edit["url"]).path + "#" + urlsplit(edit["url"]).fragment)
    await expect(page.locator("#body")).to_have_value("Original")
    async with httpx.AsyncClient(base_url=origin) as client:
        assert (await client.post("/v1/documents/draft/versions", content="Remote version")).status_code == 200
    changed.set()
    try:
        await asyncio.wait_for(held.wait(), timeout=10)
        await page.locator("#body").fill("Typed during the read")
    finally:
        release.set()
    await expect(page.locator("#load-latest")).to_be_visible(timeout=10000)
    await expect(page.locator("#body")).to_have_value("Typed during the read")


@pytest.mark.parametrize("has_draft", [False, True])
async def test_revoked_recovery_copy_tracks_the_current_buffer(live_world, live_browser, has_draft):
    origin, browser = live_browser
    edit = await link(live_world, editable=True)
    page = await browser.new_page(viewport={"width": 375, "height": 812})
    await page.goto(origin + urlsplit(edit["url"]).path + "#" + urlsplit(edit["url"]).fragment)
    await expect(page.locator("#body")).to_have_value("Original")
    original = await page.locator("#body").input_value()
    draft = "Unsaved UTF-8 draft — keep it.\nAnother line."
    if has_draft:
        await page.locator("#body").fill(draft)
    await page.locator("#tab-preview").click()
    _, db, _ = live_world
    await db.execute(
        "UPDATE {{tables.presentation_links}} SET revoked_at=NOW() WHERE token=$1",
        edit["token"],
    )
    await expect(page.locator("#link-recovery")).to_be_visible(timeout=10000)
    await expect(page.locator("#save")).to_be_disabled()
    await expect(page.locator("#body")).to_have_value(draft if has_draft else original)
    assert await page.locator("#copy-draft").is_visible() is has_draft
    # The retained editor remains usable after refusal. Recovery must follow
    # the current draft, including edits or a revert made after expiry.
    await page.locator("#tab-edit").click()
    await page.locator("#body").fill(draft)
    await expect(page.locator("#copy-draft")).to_be_visible()
    await page.locator("#body").fill(original)
    await expect(page.locator("#copy-draft")).to_be_hidden()
    assert (await db.fetch_one("SELECT COUNT(*) AS n FROM {{tables.document_versions}}"))["n"] == 1

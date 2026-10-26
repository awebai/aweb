"""Production editor and save SQL over loopback HTTP in real Chromium.

Session/link revocation exercises copy recovery; opener expiry no longer ends
an established editing session. Neither case mocks a presentation response.
"""

from __future__ import annotations

import asyncio
import io
import logging
import socket
from urllib.parse import urlsplit

import pytest
import uvicorn
from playwright.async_api import async_playwright, expect
from test_present_privacy import mint, present_world

__all__ = ["present_world"]


@pytest.mark.parametrize("failure", ["membership", "revoked"])
async def test_unavailable_save_preserves_copyable_draft_and_reopen_path(present_world, failure):
    app, db, _ = present_world
    link = await mint(present_world, ttl_seconds=300)
    access = io.StringIO()
    access_handler = logging.StreamHandler(access)
    access_logger = logging.getLogger("uvicorn.access")
    access_logger.addHandler(access_handler)
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        origin = f"http://127.0.0.1:{listener.getsockname()[1]}"
        server = uvicorn.Server(
            uvicorn.Config(app, lifespan="off", log_config=None, log_level="info", ws="none")
        )
        serving = asyncio.create_task(server.serve(sockets=[listener]))
        try:
            async with asyncio.timeout(10):
                while not server.started:
                    if serving.done():
                        await serving
                    await asyncio.sleep(0.01)
            async with async_playwright() as playwright:
                browser = await playwright.chromium.launch()
                context = await browser.new_context(
                    viewport={"width": 375, "height": 812},
                    permissions=["clipboard-read", "clipboard-write"],
                )
                page = await context.new_page()
                try:
                    response = await page.goto(origin + urlsplit(link["url"]).path + "#" + urlsplit(link["url"]).fragment)
                    assert response.status == 200
                    await expect(page.locator("#body")).to_have_value("Original")
                    draft = "Unsaved text — keep this exactly.\nSecond line."
                    await page.locator("#body").fill(draft)
                    async def revoke_before_save(route):
                        # Revoke after the real save is issued, before it reaches SQL.
                        # Otherwise the background state poll can disable Save first.
                        assert route.request.method == "POST"
                        if failure == "membership":
                            await db.execute("UPDATE {{tables.edit_sessions}} SET revoked_at=NOW() WHERE link_id=$1", link["token"])
                        else:
                            await db.execute("UPDATE {{tables.presentation_links}} SET revoked_at=NOW() WHERE token=$1", link["token"])
                        await route.continue_()

                    await page.route("**/edit", revoke_before_save)
                    saves = []
                    page.on(
                        "request",
                        lambda request: (
                            saves.append(request) if request.url.endswith("/edit") else None
                        ),
                    )
                    async with page.expect_response(
                        lambda response: response.url.endswith("/edit")
                    ) as saving:
                        await page.locator("#save").click()
                    refused = await saving.value
                    assert refused.status == 404
                    assert await refused.header_value("cache-control") == "no-store"
                    assert await refused.header_value("referrer-policy") == "no-referrer"
                    await expect(page.locator("#body")).to_have_value(draft)
                    await expect(page.locator("#body")).to_be_editable()
                    recovery = page.locator("#link-recovery")
                    await expect(recovery).to_be_visible()
                    assert await recovery.get_attribute("role") == "alert"
                    await page.locator("#copy-draft").click()
                    assert await page.evaluate("navigator.clipboard.readText()") == draft
                    await expect(page.locator("#body")).to_have_value(draft)
                    # A denied clipboard API must also work from phone Preview:
                    # the fallback has to reveal and focus the real selection.
                    await page.locator("#tab-preview").click()
                    await expect(page.locator("#body")).not_to_be_visible()
                    await page.evaluate("""async () => {
                        await navigator.clipboard.writeText('clipboard sentinel');
                        Object.defineProperty(navigator.clipboard, 'writeText', {
                            configurable: true,
                            value: () => Promise.reject(new DOMException('Denied', 'NotAllowedError')),
                        });
                    }""")
                    await page.locator("#copy-draft").click()
                    await expect(page.locator("#tab-edit")).to_have_attribute(
                        "aria-selected", "true"
                    )
                    await expect(page.locator("#body")).to_be_visible()
                    await expect(page.locator("#body")).to_be_focused()
                    assert (
                        await page.locator("#body").evaluate(
                            "el => el.value.slice(el.selectionStart, el.selectionEnd)"
                        )
                        == draft
                    )
                    await page.keyboard.press("ControlOrMeta+c")
                    assert await page.evaluate("navigator.clipboard.readText()") == draft
                    await expect(page.locator("#save")).to_be_disabled()
                    instructions = page.locator("#reopen-instructions")
                    await expect(instructions).to_be_visible()
                    assert "dashboard" in (await instructions.inner_text()).lower()
                    assert "edit" in (await instructions.inner_text()).lower()
                    await page.locator("#body").press("Control+s")
                    await page.wait_for_timeout(400)
                    assert len(saves) == 1
                    count = await db.fetch_one(
                        "SELECT COUNT(*) AS n FROM {{tables.document_versions}}"
                    )
                    assert count["n"] == 1
                finally:
                    await browser.close()
        finally:
            server.should_exit = True
            await asyncio.wait_for(serving, timeout=10)
            access_logger.removeHandler(access_handler)
            assert "/present/edit/[redacted]/edit" in access.getvalue()

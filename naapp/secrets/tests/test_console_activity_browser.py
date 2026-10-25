"""Activity is readable at mobile and desktop sizes with real owner auth."""

import asyncio
import socket
from datetime import UTC, datetime

import pytest
import uvicorn
from aweb_naapp.runtime.passkeys import RelyingParty
from playwright.async_api import expect

from tests.test_change_sets import world as _world
from tests.test_console_activity import application, recorded
from tests.test_console_forms import enrolled_page
from tests.test_console_ui_browser import browser as _browser

world = _world
browser = _browser


@pytest.fixture
async def service(world):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    origin = f"http://localhost:{port}"
    world.passkeys.rp = RelyingParty(origin=origin, name="Secrets")
    app = await application(world, origin=origin, agent_origin=f"http://127.0.0.1:{port}")
    server = uvicorn.Server(uvicorn.Config(app, log_level="warning", lifespan="off"))
    task = asyncio.create_task(server.serve(sockets=[sock]))
    try:
        async with asyncio.timeout(10):
            while not server.started:
                if task.done():
                    await task
                await asyncio.sleep(0.01)
        yield origin
    finally:
        server.should_exit = True
        await asyncio.wait_for(task, 10)
        sock.close()


@pytest.mark.parametrize("width", [375, 1440])
async def test_activity_browser_preserves_original_event_and_bounded_fields(
    world, browser, service, width, tmp_path
):
    async with await browser.new_context(viewport={"width": width, "height": 1000}) as context:
        page, _, _ = await enrolled_page(world, context, service)
        event_id = await recorded(world, datetime.now(UTC))
        await page.goto(service + "/activity")
        entry = page.locator(f'[data-event-id="{event_id}"]')
        await expect(entry).to_be_visible()
        await expect(entry).to_contain_text("grant_missing")
        await expect(entry).to_contain_text("Agent")
        await page.screenshot(path=tmp_path / f"activity-{width}.png", full_page=True)
        assert await page.evaluate("document.documentElement.scrollWidth <= innerWidth")
        assert await world.db.fetch_value("SELECT COUNT(*) FROM {{tables.intents}}") == 0

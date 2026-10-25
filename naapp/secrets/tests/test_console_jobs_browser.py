"""Owner job/runner controls in Chromium on the real S4/passkey server."""

import asyncio
import socket

import pytest
import uvicorn
from aweb_naapp.runtime.passkeys import RelyingParty
from aweb_naapp_testing.owner_acts import INSTALLATION_ID
from playwright.async_api import expect

from tests.test_change_sets import world as _world
from tests.test_console_forms import enrolled_page
from tests.test_console_jobs import application
from tests.test_console_ui_browser import browser as _browser
from tests.test_jobs import after

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
async def test_job_runner_controls_reauth_and_invalid_draft(
    world, browser, service, width, tmp_path
):
    async with await browser.new_context(viewport={"width": width, "height": 1000}) as context:
        page, _, _ = await enrolled_page(world, context, service)
        await page.goto(service + "/jobs/new")
        await expect(page.get_by_role("heading", name="Create a job", exact=True)).to_be_visible()
        await page.screenshot(path=tmp_path / f"job-form-{width}.png", full_page=True)
        assert await page.evaluate("document.documentElement.scrollWidth <= innerWidth")
        body = after()
        for label, value in [
            ("Job ID", body["job_id"]),
            ("Allowed runner IDs (comma-separated)", body["runner_ids"][0]),
            ("Executable path on the runner", body["exec"]["path"]),
            ("Executable SHA-256", body["exec"]["sha256"]),
            ("Working directory on the runner", body["cwd"]),
            ("Arguments (JSON array)", "[invalid"),
        ]:
            await page.get_by_label(label, exact=True).fill(value)
        await page.get_by_role("button", name="Save a draft for review").click()
        await expect(page.locator("#job-status")).to_contain_text("has not been submitted")
        assert await world.db.fetch_value("SELECT COUNT(*) FROM {{tables.change_sets}}") == 0
        await page.goto(service + "/runners/new")
        await expect(page.get_by_label("Runner ID", exact=True)).not_to_be_empty()
        assert (
            await page.get_by_label("Runner ID", exact=True).get_attribute("readonly") is not None
        )
        await page.get_by_label("Runner name", exact=True).fill("Build runner")
        await page.get_by_label("Allowed job IDs (comma-separated)", exact=True).fill(
            "nightly-backup"
        )
        await page.screenshot(path=tmp_path / f"runner-form-{width}.png", full_page=True)
        assert await page.evaluate("document.documentElement.scrollWidth <= innerWidth")
        async with await browser.new_context() as fresh:
            await fresh.add_cookies(await context.cookies())
            other = await fresh.new_page()
            await other.goto(service + f"/installations/{INSTALLATION_ID}/jobs/new")
            await expect(other.locator("#definition-draft")).to_be_hidden()
            await expect(other.locator("#console-reauth")).to_be_visible()

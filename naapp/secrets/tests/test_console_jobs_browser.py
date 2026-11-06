"""Owner job/runner controls in Chromium on the real S4/passkey server."""

import asyncio
import json
import socket
from copy import deepcopy
from urllib.parse import quote

import pytest
import uvicorn
from aweb_naapp.runtime.passkeys import RelyingParty
from aweb_naapp_testing.owner_acts import INSTALLATION_ID
from playwright.async_api import Error as BrowserError
from playwright.async_api import expect

from aweb_secrets.jobs import current_job
from tests.test_change_records import ITEMS
from tests.test_change_sets import world as _world
from tests.test_console_changes import ROOT
from tests.test_console_forms import enrolled_page, wait_for_review
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


async def confirm_from_email(world, page, origin, draft):
    [token] = [
        token
        for approval_id, token in world.inbox.links["alice@acme.com"]
        if approval_id == draft["approval_id"]
    ]
    try:
        await page.goto(origin + "/approvals#token=" + quote(token))
    except BrowserError:
        raise AssertionError("the canonical approval page could not be opened") from None
    await wait_for_review(page, origin + ROOT + "/" + draft["change_id"] + "/review")
    await expect(page.get_by_role("button", name="Confirm with your passkey")).to_be_enabled()
    await page.get_by_role("button", name="Confirm with your passkey").click()
    await expect(page.locator("#form-status")).to_have_attribute("data-state", "applied")


async def save_form(page, origin):
    await page.get_by_role("button", name="Save a draft for review").click()
    await wait_for_review(page, origin + ROOT + "/*/review")
    await expect(page.locator("#change-summary")).to_have_attribute("data-state", "pending")
    projection = json.loads(await page.locator("#frozen-change").text_content())
    return {
        "change_id": projection["change"]["change_id"],
        "approval_id": projection["approval_id"],
    }


@pytest.mark.parametrize("width", [375, 1440])
async def test_job_runner_drafts_confirm_through_canonical_writer(
    world, browser, service, width, tmp_path
):
    async with await browser.new_context(viewport={"width": width, "height": 1000}) as context:
        page, _, _ = await enrolled_page(world, context, service)
        # Configure the prerequisite metadata through the canonical owner API,
        # not a domain-record seeding helper. No credential value is needed.
        csrf = await page.evaluate("sessionStorage.getItem('aweb.secrets.console.csrf')")
        configured = await context.request.post(
            service + ROOT,
            headers={"X-CSRF-Token": csrf},
            data={
                "changes": [deepcopy(ITEMS["secret"])],
                "sealed": [],
                "reason": "Configure the job credential reference",
            },
        )
        assert configured.status == 201
        await confirm_from_email(world, page, service, await configured.json())

        body = after()
        await page.goto(service + "/runners/new")
        runner_id = await page.get_by_label("Runner ID", exact=True).input_value()
        await page.get_by_label("Runner name", exact=True).fill("Build runner")
        await page.get_by_label("Allowed job IDs (comma-separated)", exact=True).fill(
            body["job_id"]
        )
        await page.get_by_label("Reason for this change", exact=True).fill(
            "Register the job runner"
        )
        runner_draft = await save_form(page, service)
        assert await world.db.fetch_value("SELECT count(*) FROM {{tables.runners}}") == 0
        await confirm_from_email(world, page, service, runner_draft)
        code = await page.locator("#runner-registration-result code").text_content()
        if not code:
            raise AssertionError("runner registration material was not shown after confirmation")
        if await page.evaluate(
            "value => JSON.stringify({...sessionStorage,...localStorage}).includes(value)", code
        ):
            raise AssertionError("runner registration material persisted in browser storage")
        if code in page.url:
            raise AssertionError("runner registration material entered the URL")
        receipt = await context.request.get(service + ROOT + "/" + runner_draft["change_id"])
        if code in await receipt.text():
            raise AssertionError("runner registration material returned on a later read")
        await page.reload()
        await expect(page.locator("#runner-registration-result")).to_have_count(0)

        body["runner_ids"] = [runner_id]
        body["credentials"][0]["secret_ref"] = ITEMS["secret"]["ref"]
        body["env"]["DB_ADMIN"]["$credential"] = ITEMS["secret"]["ref"]
        await page.goto(service + "/jobs/new")
        for label, value in [
            ("Job ID", body["job_id"]),
            ("Allowed runner IDs (comma-separated)", runner_id),
            ("Executable path on the runner", body["exec"]["path"]),
            ("Executable SHA-256", body["exec"]["sha256"]),
            ("Working directory on the runner", body["cwd"]),
            ("Arguments (JSON array)", json.dumps(body["argv"])),
            (
                "Additional pinned files (JSON array of path and sha256)",
                json.dumps(body["exec"]["files"]),
            ),
            ("Parameter constraints (JSON object)", json.dumps(body["params"])),
            ("Environment bindings (JSON object)", json.dumps(body["env"])),
            (
                "Credential slots (JSON array of secret_ref, delivery and mint)",
                json.dumps(body["credentials"]),
            ),
            ("Reason for this change", "Confirm a pinned durable job"),
        ]:
            await page.get_by_label(label, exact=True).fill(value)
        await page.get_by_label("Allow this job to receive durable credentials", exact=True).check()
        job_draft = await save_form(page, service)
        await page.reload()
        assert await world.db.fetch_value("SELECT count(*) FROM {{tables.current_jobs}}") == 0
        await expect(page.get_by_role("button", name="Confirm with your passkey")).to_be_disabled()
        await page.screenshot(path=tmp_path / f"job-pending-review-{width}.png", full_page=True)
        await confirm_from_email(world, page, service, job_draft)
        async with world.db.transaction() as tx:
            stored = await current_job(tx, INSTALLATION_ID, body["job_id"])
        assert stored.after == body
        await page.screenshot(path=tmp_path / f"job-confirmed-{width}.png", full_page=True)
        await page.reload()
        await expect(page.locator("#change-summary")).to_have_attribute("data-state", "applied")
        await expect(page.locator("#confirm-change")).to_be_hidden()

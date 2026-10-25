"""Anonymous mail locators complete the existing B3 ceremonies in Chromium."""

import asyncio
import base64
import email
import email.policy
import secrets
import socket
from collections.abc import AsyncIterator
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
import uvicorn
from aweb_naapp.console import CONSOLE_HEADERS
from aweb_naapp.runtime.origins import split_origins
from aweb_naapp.runtime.passkeys import RelyingParty, contact_sha256
from aweb_naapp_testing.owner_acts import INSTALLATION_ID
from aweb_naapp_testing.smtp import SmtpServer
from aweb_naapp_testing.webauthn import SoftAuthenticator
from fastapi import FastAPI
from playwright.async_api import expect

from aweb_secrets.console import OwnerConsole, owner_console_router
from aweb_secrets.console_bootstrap import console_bootstrap_router
from aweb_secrets.owners import owner_scope
from aweb_secrets.passkey_email import PasskeyEmailDelivery
from tests.test_approval_email import Links, mailer
from tests.test_change_sets import ALICE, ORIGIN, TEAM, World
from tests.test_change_sets import world as _world
from tests.test_console_ui import Elements
from tests.test_console_ui_browser import browser as _browser

world = _world
browser = _browser


async def application(world: World, *, human_origin: str, agent_origin: str):
    async def installation(installation_id: str):
        assert installation_id == world.admitted.installation_id
        return world.admitted

    console = OwnerConsole(
        db=world.db,
        passkeys=world.passkeys,
        directory=world.directory,
        fence=world.fence,
        verifier=world.owner.verifier,
        installation=installation,
    )
    human = FastAPI()
    human.include_router(owner_console_router(console))
    human.include_router(console_bootstrap_router())
    return split_origins(FastAPI(), human, agent_origin=agent_origin, human_origin=human_origin)


async def test_bootstrap_pages_are_anonymous_private_and_human_origin_only(world):
    api = "https://api.secrets.example.com"
    app = await application(world, human_origin=ORIGIN, agent_origin=api)
    async with (
        httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url=ORIGIN) as human,
        httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url=api) as agent,
    ):
        for path in ("/enrolment", "/contact-proof"):
            response = await human.get(path)
            assert response.status_code == 200
            for name, value in CONSOLE_HEADERS.items():
                assert response.headers[name] == value
            assert "set-cookie" not in response.headers
            tags = Elements(response.text).tags
            assets = [
                attrs.get("src") if tag == "script" else attrs.get("href")
                for tag, attrs in tags
                if tag in {"script", "link"}
            ]
            assert assets
            for resource in (path, *assets):
                assert resource and resource.startswith("/")
                assert (await agent.get(resource)).status_code == 404
                denied = await human.get(resource, headers={"X-AWEB-Signature": "invalid"})
                assert denied.status_code == 403


@pytest.fixture
async def service(world: World) -> AsyncIterator[str]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    origin = f"http://localhost:{port}"
    world.passkeys.rp = RelyingParty(origin=origin, name="Secrets")
    app = await application(world, human_origin=origin, agent_origin=f"http://127.0.0.1:{port}")
    server = uvicorn.Server(uvicorn.Config(app, log_level="warning", lifespan="off"))
    running = asyncio.create_task(server.serve(sockets=[sock]))
    try:
        async with asyncio.timeout(10):
            while not server.started:
                if running.done():
                    await running
                    raise RuntimeError("Bootstrap server stopped before startup")
                await asyncio.sleep(0.01)
        yield origin
    finally:
        server.should_exit = True
        await asyncio.wait_for(running, 10)
        sock.close()


async def designate_owner(world: World, service: str, contact: str):
    scope = owner_scope(INSTALLATION_ID, TEAM, ALICE.principal_did)
    subject = {
        "app_id": world.admitted.app_id,
        "installation_id": INSTALLATION_ID,
        "role": scope,
        "contact_sha256": contact_sha256(contact),
    }
    signing, signature = world.owner.sign("app-role.designate", subject)
    async with httpx.AsyncClient(base_url=service) as client:
        response = await client.post(
            f"/installations/{INSTALLATION_ID}/owner-acts",
            json={
                "signing": base64.b64encode(signing).decode(),
                "signature": signature,
                "team_id": TEAM,
                "principal": ALICE.principal_did,
                "contact": contact,
            },
        )
    assert response.status_code == 200
    return scope


def delivered_url(messages, *, contact, path):
    urls = []
    for received in messages:
        if received.rcpt_tos != [contact]:
            continue
        message = email.message_from_bytes(received.content, policy=email.policy.default)
        html = message.get_body(("html",)).get_content()
        urls.extend(url for url in Links(html).urls if urlsplit(url).path == path)
    [url] = urls
    return url


async def test_enrolment_page_uses_the_delivered_fragment_and_real_registration(
    world: World, browser, service: str, tmp_path
):
    contact = "owner@example.com"
    with SmtpServer(tmp_path / "smtp", password=secrets.token_urlsafe(32)) as smtp:
        world.passkeys._delivery = PasskeyEmailDelivery(
            mailer=mailer(smtp, tmp_path), console_origin=service
        )
        scope = await designate_owner(world, service, contact)
        url = delivered_url(smtp.received, contact=contact, path="/enrolment")
    [token] = parse_qs(urlsplit(url).fragment)["token"]
    async with await browser.new_context() as context:
        page = await context.new_page()
        cdp = await context.new_cdp_session(page)
        await cdp.send("WebAuthn.enable")
        await cdp.send(
            "WebAuthn.addVirtualAuthenticator",
            {
                "options": {
                    "protocol": "ctap2",
                    "transport": "internal",
                    "hasResidentKey": True,
                    "hasUserVerification": True,
                    "isUserVerified": True,
                    "automaticPresenceSimulation": True,
                }
            },
        )
        requests = []
        page.on("request", lambda request: requests.append(request.url))
        await page.goto(url)
        await expect(page.get_by_role("button", name="Set up passkey")).to_be_enabled()
        assert "#" not in page.url
        async with page.expect_response(
            lambda response: (
                response.url == service + "/enrolment" and response.request.method == "POST"
            )
        ) as completed:
            async with page.expect_response(
                lambda response: (
                    response.url == service + "/enrolment/options"
                    and response.request.method == "POST"
                )
            ) as options_loaded:
                await page.get_by_role("button", name="Set up passkey").click()
            assert (await options_loaded.value).status == 200
        assert (await completed.value).status == 200
        await expect(page.get_by_role("status")).to_be_visible()
        await expect(page.get_by_role("button", name="Set up passkey")).to_be_disabled()
        designated = await world.passkeys.designated_approver(scope)
        assert await world.passkeys.is_current(scope, designated.subject)
        assert all(token not in url for url in requests)
        assert not await context.cookies()


async def test_contact_page_confirms_only_the_delivered_candidate(
    world: World, browser, service: str, tmp_path
):
    contact, candidate = "owner@example.com", "candidate@example.com"
    scope = await designate_owner(world, service, contact)
    [enrolment] = world.inbox.enrolments[contact]
    device = SoftAuthenticator(service)
    await world.passkeys.complete_enrolment(
        enrolment, device.create(await world.passkeys.enrolment_options(enrolment))
    )
    with SmtpServer(tmp_path / "smtp", password=secrets.token_urlsafe(32)) as smtp:
        world.passkeys._delivery = PasskeyEmailDelivery(
            mailer=mailer(smtp, tmp_path), console_origin=service
        )
        options = await world.passkeys.contact_change_options(scope, candidate)
        effective_at = await world.passkeys.change_contact(scope, candidate, device.get(options))
        url = delivered_url(smtp.received, contact=candidate, path="/contact-proof")
    async with await browser.new_context() as context:
        page = await context.new_page()
        await page.goto(url)
        await expect(page.get_by_role("button", name="Confirm email address")).to_be_enabled()
        assert "#" not in page.url
        async with page.expect_response(
            lambda response: (
                response.url == service + "/contact-proof" and response.request.method == "POST"
            )
        ) as completed:
            await page.get_by_role("button", name="Confirm email address").click()
        assert (await completed.value).status == 200
        await expect(page.get_by_role("status")).to_be_visible()
        await expect(page.get_by_role("button", name="Confirm email address")).to_be_disabled()
        row = await world.db.fetch_one(
            "SELECT contact,pending_contact,pending_contact_at,pending_contact_proven_at "
            "FROM {{tables.passkey_approvers}} WHERE scope=$1 AND superseded_at IS NULL",
            scope,
        )
        assert row["contact"] == contact
        assert row["pending_contact"] == candidate
        assert row["pending_contact_at"] == effective_at
        assert row["pending_contact_proven_at"] is not None
        assert not await context.cookies()


@pytest.mark.parametrize("path", ["/enrolment", "/contact-proof"])
@pytest.mark.parametrize("fragment", ["", "#token=", "#other=value"])
async def test_missing_fragment_cannot_start_a_ceremony(
    browser, service: str, path: str, fragment: str
):
    async with await browser.new_context() as context:
        page = await context.new_page()
        await page.goto(service + path + fragment)
        await expect(page.get_by_role("button")).to_be_disabled()
        await expect(page.get_by_role("status")).to_be_visible()

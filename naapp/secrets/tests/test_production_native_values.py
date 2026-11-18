"""An owner enters a native value in the production console; an agent uses it.

Owner holding setup uses the canonical shared writer. Every value/configuration
write thereafter uses the original production routes, Chromium and fresh passkey
confirmation. The upstream, DNS, registry, SMTP, PG and TLS are real fixtures.
"""

import asyncio
import json
from urllib.parse import urlencode
from uuid import uuid4

import pytest
import uvicorn
from aweb_naapp.egress import InternalDestinations
from aweb_naapp_testing import Member
from playwright.async_api import TimeoutError as BrowserTimeout
from playwright.async_api import expect

from aweb_secrets.policy import Policy
from tests.harness import NAME, running_upstream
from tests.human_owner import install_virtual_credential
from tests.test_console_bootstrap import delivered_url
from tests.test_console_ui_browser import browser as browser
from tests.test_production_bootstrap import enrolled_owner
from tests.test_production_bootstrap import root as root
from tests.test_use_approvals import POLICY_BODY


@pytest.fixture
async def upstream(tmp_path):
    directory = tmp_path / "upstream"
    directory.mkdir()
    async with running_upstream(directory) as running:
        yield running


@pytest.fixture
def production_settings(console_listener, upstream):
    return {
        "console_origin": console_listener.origin,
        "internal_destinations": InternalDestinations.ALLOWED,
        "egress_ca_file": upstream.egress.ca_file,
    }


@pytest.fixture
async def production_console(root, console_listener, console_tls, upstream):
    service, _, _, _, _, _, _, dns = root
    dns.records[(NAME, "A")] = [upstream.host]
    server = uvicorn.Server(
        uvicorn.Config(
            service,
            lifespan="off",  # The production root fixture owns its real lifespan.
            log_level="warning",
            ssl_certfile=str(console_tls.cert_file),
            ssl_keyfile=str(console_tls.key_file),
        )
    )
    task = asyncio.create_task(server.serve(sockets=[console_listener.socket]))
    try:
        async with asyncio.timeout(10):
            while not server.started:
                if task.done():
                    await task
                    raise AssertionError("production console stopped during startup")
                await asyncio.sleep(0.01)
        yield console_listener.origin
    finally:
        server.should_exit = True
        await asyncio.wait_for(task, 10)


async def confirm_from_mail(page, smtp, after):
    link = delivered_url(smtp.received[after:], contact="owner@example.com", path="/approvals")
    try:
        await page.goto(link)
        button = page.get_by_role("button", name="Confirm with your passkey")
        await expect(button).to_be_enabled()
        await button.click()
        await expect(page.locator("#form-status")).to_have_attribute("data-state", "applied")
    except BrowserTimeout:
        # Playwright navigation diagnostics can include the personal mail locator.
        raise AssertionError("the production owner could not confirm the frozen draft") from None


async def test_production_owner_enters_native_value_and_agent_brokers_it(
    root, production_console, browser, upstream, registry
):
    service, client, configured, member, installed, smtp, _, _ = root
    holder = await enrolled_owner(root)
    db = service.runtime.db()
    assert await db.fetch_value("SELECT count(*) FROM secrets") == 0
    assert await db.fetch_value("SELECT count(*) FROM sealed_versions") == 0
    installation = installed["installation_id"]
    changes_path = f"/installations/{installation}/change-sets"
    async with await browser.new_context() as context:
        page = await context.new_page()
        cdp = await context.new_cdp_session(page)
        await cdp.send("WebAuthn.enable")
        authenticator = await cdp.send(
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
        await install_virtual_credential(cdp, authenticator["authenticatorId"], holder.device)
        await page.goto(production_console + "/login?" + urlencode({"scope": holder.scope}))
        await page.get_by_role("button", name="Sign in with a passkey").click()
        await page.wait_for_url(production_console + "/")

        entry = await page.goto(production_console + "/secrets/native/new")
        assert entry.status == 200  # RED: no native entry in the production console.
        await page.get_by_label("Secret name", exact=True).fill("native-proof")
        await page.get_by_label("Bearer token", exact=True).fill(upstream.creds.bearer)
        mail_before = len(smtp.received)
        async with page.expect_response(production_console + changes_path) as saved:
            await page.get_by_role("button", name="Save a native draft").click()
        response = await saved.value
        assert response.status == 201
        drafted = await response.json()
        assert set(drafted) == {"change_id", "approval_id", "state"}
        assert drafted["state"] == "pending"
        assert await db.fetch_value("SELECT count(*) FROM secrets") == 0
        if upstream.creds.bearer in await page.content():
            raise AssertionError("native value was reflected into the console page")
        if await page.evaluate(
            "value => JSON.stringify({...sessionStorage,...localStorage}).includes(value)",
            upstream.creds.bearer,
        ):
            raise AssertionError("native value was persisted in browser storage")
        await confirm_from_mail(page, smtp, mail_before)
        record = await db.fetch_one("SELECT secret_id,active_version FROM secrets")
        assert record["active_version"] == 1

        agent = Member(
            team_id=member.team_id,
            team_key=member.team_key,
            certificate_id="native-agent",
            alias="native-agent",
        )
        principal = await registry.register_did(agent.member_key)
        agent.extra_cert_fields = {"member_did_aw": principal}
        await registry.add_certificate(agent.certificate())
        policy = Policy.from_body({**POLICY_BODY, "approval": "none", "approvers": []})
        destination = {
            "v": 1,
            "destination_id": "dst_native_owner",
            "secret_id": record["secret_id"],
            "scheme": "https",
            "host": NAME,
            "port": upstream.port,
            "path": "/bearer/**",
            "methods": ["POST"],
            "query_rules": {},
            "header_allow": [],
            "network": "internal",
            "cidr": upstream.host + "/32",
        }
        grant = {
            "v": 1,
            "grant_id": "grt_native_owner",
            "secret_id": record["secret_id"],
            "subject": {"principal": principal},
            "capability": "use",
            "operations": [],
            "open_request": True,
            "jobs": [],
            "policy_digest": policy.digest,
        }
        mail_before = len(smtp.received)
        await page.evaluate(
            "async args => window.awebConsole.post(args.path, args.body)",
            {
                "path": changes_path,
                "body": {
                    "changes": [
                        {
                            "kind": "policy",
                            "op": "create",
                            "ref": policy.digest,
                            "after": policy.body,
                        },
                        {
                            "kind": "destination",
                            "op": "create",
                            "ref": destination["destination_id"],
                            "after": destination,
                        },
                        {"kind": "grant", "op": "create", "ref": grant["grant_id"], "after": grant},
                    ],
                    "sealed": [],
                    "reason": "Permit one agent to use the native credential",
                },
            },
        )
        await confirm_from_mail(page, smtp, mail_before)

    path = "/v1/secrets/native-proof/requests"
    raw = json.dumps(
        {
            "request_id": uuid4().hex,
            "method": "POST",
            "url": upstream.url("/bearer/echo"),
            "data": {"message": "native entry proof"},
        }
    ).encode()
    result = await client.post(
        configured.public_origin + path,
        content=raw,
        headers=agent.headers(aud=configured.public_origin, method="POST", path=path, body=raw)
        | {"Content-Type": "application/json"},
    )
    assert result.status_code == 200 and result.json()["state"] == "completed"
    assert upstream.paths == ["/bearer/echo"]
    if upstream.creds.bearer in result.text:
        raise AssertionError("broker response disclosed the native value")

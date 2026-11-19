"""An owner enters a native value in the production console; an agent uses it.

Owner holding setup uses the canonical shared writer. Every value/configuration
write thereafter uses the original production routes, Chromium and fresh passkey
confirmation. The upstream, DNS, registry, SMTP, PG and TLS are real fixtures.
"""

import asyncio
import json
import secrets
from enum import StrEnum
from http import HTTPStatus
from urllib.parse import urlencode
from uuid import uuid4

import pytest
import uvicorn
from aweb_naapp.dispatch import State as DispatchState
from aweb_naapp.egress import InternalDestinations
from aweb_naapp_testing import Member
from playwright.async_api import BrowserContext, Page, expect
from playwright.async_api import TimeoutError as BrowserTimeout

from aweb_secrets.policy import Policy
from aweb_secrets.secret import SecretBackend, SecretKind, SecretRecord, SecretSensitivity
from tests.harness import NAME, running_upstream
from tests.human_owner import install_virtual_credential
from tests.test_console_bootstrap import delivered_url
from tests.test_console_ui_browser import browser as browser
from tests.test_production_bootstrap import EnrolledOwner, enrolled_owner
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


class ConsoleDraftState(StrEnum):
    PENDING = "pending"
    APPLIED = "applied"


async def confirm_from_mail(page: Page, *, smtp, message_start_index: int) -> None:
    link = delivered_url(
        smtp.received[message_start_index:], contact="owner@example.com", path="/approvals"
    )
    try:
        await page.goto(link)
        button = page.get_by_role("button", name="Confirm with your passkey")
        await expect(button).to_be_enabled()
        await button.click()
        await expect(page.locator("#form-status")).to_have_attribute(
            "data-state", ConsoleDraftState.APPLIED
        )
    except BrowserTimeout:
        # Playwright navigation diagnostics can include the personal mail locator.
        raise AssertionError("the production owner could not confirm the frozen draft") from None


async def sign_in_browser_owner(
    context: BrowserContext, *, holder: EnrolledOwner, origin: str
) -> Page:
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
    await page.goto(origin + "/login?" + urlencode({"scope": holder.scope}))
    await page.get_by_role("button", name="Sign in with a passkey").click()
    await page.wait_for_url(origin + "/")
    return page


async def enter_and_confirm_native_value(
    page: Page, *, db, origin: str, changes_path: str, upstream, smtp
) -> str:
    entry = await page.goto(origin + "/secrets/native/new")
    assert entry.status == HTTPStatus.OK
    await page.get_by_label("Secret name", exact=True).fill("native-proof")
    await page.get_by_label("Bearer token", exact=True).fill(upstream.creds.bearer)
    mail_before = len(smtp.received)
    async with page.expect_response(origin + changes_path) as saved:
        await page.get_by_role("button", name="Save a native draft").click()
    response = await saved.value
    assert response.status == HTTPStatus.CREATED
    drafted = await response.json()
    assert set(drafted) == {"change_id", "approval_id", "state"}
    assert drafted["state"] == ConsoleDraftState.PENDING
    assert await db.fetch_value("SELECT count(*) FROM secrets") == 0
    await page.get_by_role("link", name="Review this draft").click()
    await page.wait_for_url(origin + changes_path + "/" + drafted["change_id"] + "/review")
    if upstream.creds.bearer in await page.content():
        raise AssertionError("native value was reflected into the console page")
    if await page.evaluate(
        "value => JSON.stringify({...sessionStorage,...localStorage}).includes(value)",
        upstream.creds.bearer,
    ):
        raise AssertionError("native value was persisted in browser storage")
    await confirm_from_mail(page, smtp=smtp, message_start_index=mail_before)
    record = await db.fetch_one("SELECT secret_id,active_version FROM secrets")
    assert record["active_version"] == 1
    return record["secret_id"]


async def grant_native_agent_access(
    page: Page, *, root, secret_id: str, changes_path: str, upstream, registry
) -> Member:
    _, _, _, member, _, smtp, _, _ = root
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
        "secret_id": secret_id,
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
        "secret_id": secret_id,
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
    await confirm_from_mail(page, smtp=smtp, message_start_index=mail_before)
    return agent


async def assert_agent_brokers_native_value(*, root, agent: Member, upstream) -> None:
    _, client, configured, *_ = root
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
    assert result.status_code == HTTPStatus.OK and result.json()["state"] == DispatchState.COMPLETED
    assert upstream.paths == ["/bearer/echo"]
    if upstream.creds.bearer in result.text:
        raise AssertionError("broker response disclosed the native value")


async def test_production_owner_enters_native_value_and_agent_brokers_it(
    root, production_console, browser, upstream, registry
):
    service, _, _, _, installed, smtp, _, _ = root
    holder = await enrolled_owner(root)
    db = service.runtime.db()
    assert await db.fetch_value("SELECT count(*) FROM secrets") == 0
    assert await db.fetch_value("SELECT count(*) FROM sealed_versions") == 0
    changes_path = f"/installations/{installed['installation_id']}/change-sets"
    async with await browser.new_context() as context:
        page = await sign_in_browser_owner(context, holder=holder, origin=production_console)
        secret_id = await enter_and_confirm_native_value(
            page,
            db=db,
            origin=production_console,
            changes_path=changes_path,
            upstream=upstream,
            smtp=smtp,
        )
        agent = await grant_native_agent_access(
            page,
            root=root,
            secret_id=secret_id,
            changes_path=changes_path,
            upstream=upstream,
            registry=registry,
        )
    await assert_agent_brokers_native_value(root=root, agent=agent, upstream=upstream)


class InvalidNativeEntry(StrEnum):
    VAULT_BACKEND = "vault_backend"
    VALUE_SHAPE = "value_shape"
    EMPTY_VALUE = "empty_value"
    UNTRUSTED_TEAM = "untrusted_team"


def native_entry_request(*, value: str) -> dict:
    return {
        "secret": SecretRecord.from_after(
            {
                "v": 1,
                "secret_id": "sec_native_guard",
                "ref": "native-guard",
                "description": "Native ingress guard",
                "kind": SecretKind.BEARER,
                "kind_params": {},
                "sensitivity": SecretSensitivity.STANDARD,
                "approve_only": False,
                "backend": SecretBackend.NATIVE,
            }
        ).after,
        "value": {"value": value},
    }


def assert_value_not_returned(*, response, value: str) -> None:
    if value in response.text:
        raise AssertionError("native ingress response disclosed the entered value")


async def test_native_entry_requires_a_human_owner_session_and_this_tabs_csrf(root):
    service, client, configured, _, installed, *_ = root
    path = f"/installations/{installed['installation_id']}/native/versions"
    value = secrets.token_urlsafe(32)
    body = native_entry_request(value=value)
    anonymous = await client.post(configured.console_origin + path, json=body)
    assert anonymous.status_code == HTTPStatus.UNAUTHORIZED
    await enrolled_owner(root)
    no_csrf = await client.post(configured.console_origin + path, json=body)
    assert no_csrf.status_code == HTTPStatus.FORBIDDEN
    agent_origin = await client.post(configured.public_origin + path, json=body)
    assert agent_origin.status_code == HTTPStatus.NOT_FOUND
    for response in (anonymous, no_csrf, agent_origin):
        assert_value_not_returned(response=response, value=value)
    assert await service.runtime.db().fetch_value("SELECT count(*) FROM sealed_versions") == 0


@pytest.mark.parametrize("fault", list(InvalidNativeEntry))
async def test_invalid_native_entry_never_allocates_or_reflects_the_value(root, fault):
    service, client, configured, _, installed, *_ = root
    holder = await enrolled_owner(root)
    value = secrets.token_urlsafe(32)
    body = native_entry_request(value=value)
    if fault is InvalidNativeEntry.VAULT_BACKEND:
        body["secret"] = {**body["secret"], "backend": SecretBackend.ONEPASSWORD}
    elif fault is InvalidNativeEntry.VALUE_SHAPE:
        body["value"] = {"password": value}
    elif fault is InvalidNativeEntry.EMPTY_VALUE:
        body["value"] = {"value": ""}
    else:
        body["team_id"] = "foreign:example.com"
    path = f"/installations/{installed['installation_id']}/native/versions"
    response = await client.post(
        configured.console_origin + path,
        json=body,
        headers={"X-CSRF-Token": holder.csrf_token},
    )
    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert_value_not_returned(response=response, value=value)
    assert await service.runtime.db().fetch_value("SELECT count(*) FROM sealed_versions") == 0

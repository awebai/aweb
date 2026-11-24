"""An owner enters a native value in the production console; an agent uses it.

Owner holding setup uses the canonical shared writer. Every value/configuration
write thereafter uses the original production routes, Chromium and fresh passkey
confirmation. The upstream, DNS, registry, SMTP, PG and TLS are real fixtures.
"""

import asyncio
import json
import secrets
from datetime import datetime
from enum import StrEnum
from http import HTTPStatus
from urllib.parse import urlencode
from uuid import uuid4

import pytest
import uvicorn
from aweb_naapp.dispatch import State as DispatchState
from aweb_naapp.egress import InternalDestinations
from aweb_naapp_testing import Member
from aweb_secrets_values import ValueInvalid, ValueInvalidReason
from playwright.async_api import BrowserContext, Page, expect
from playwright.async_api import Error as BrowserError

from aweb_secrets.custody import Custody, LocalKeyFileProvider
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
    UNCERTAIN = "uncertain"


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
    except BrowserError:
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
    try:
        await install_virtual_credential(cdp, authenticator["authenticatorId"], holder.device)
    except BrowserError:
        raise AssertionError("the browser could not prepare the owner passkey") from None
    await page.goto(origin + "/login?" + urlencode({"scope": holder.scope}))
    await page.get_by_role("button", name="Sign in with a passkey").click()
    await page.wait_for_url(origin + "/")
    return page


async def enter_bearer_value(page: Page, *, value: str) -> None:
    try:
        await page.get_by_label("Bearer token", exact=True).fill(value)
    except BrowserError:
        # Playwright fill diagnostics include the argument, even without tracing.
        raise AssertionError("the owner could not enter the bearer value") from None


async def assert_value_absent_from_browser(page: Page, *, value: str) -> None:
    try:
        reflected = value in await page.content()
        stored = await page.evaluate(
            "value => JSON.stringify({...sessionStorage,...localStorage}).includes(value)",
            value,
        )
    except BrowserError:
        raise AssertionError("the console value-retention check could not run") from None
    if reflected or stored:
        raise AssertionError("the console retained an entered value")


async def assert_inert_native_receipt(response, *, db, secret_id: str) -> None:
    assert response.status == HTTPStatus.CREATED
    receipt = await response.json()
    assert set(receipt) == {"secret_id", "version", "created_at"}
    assert receipt["secret_id"] == secret_id
    assert type(receipt["version"]) is int and receipt["version"] == 1
    assert isinstance(receipt["created_at"], str)
    try:
        created_at = datetime.fromisoformat(receipt["created_at"])
    except ValueError:
        raise AssertionError("native staging returned an invalid creation time") from None
    staged = await db.fetch_one("SELECT secret_id,version,created_at FROM sealed_versions")
    assert staged is not None
    assert (staged["secret_id"], staged["version"], staged["created_at"]) == (
        secret_id,
        receipt["version"],
        created_at,
    )
    assert await db.fetch_value("SELECT count(*) FROM secrets") == 0


async def enter_and_confirm_native_value(
    page: Page, *, db, origin: str, stage_path: str, changes_path: str, upstream, smtp
) -> str:
    entry = await page.goto(origin + "/secrets/native/new")
    assert entry.status == HTTPStatus.OK
    await page.get_by_label("Secret name", exact=True).fill("native-proof")
    await enter_bearer_value(page, value=upstream.creds.bearer)
    secret_id = await page.locator('[name="secret_id"]').input_value()
    mail_before = len(smtp.received)
    async with page.expect_response(origin + stage_path) as staged:
        async with page.expect_response(origin + changes_path) as saved:
            await page.get_by_role("button", name="Save the value and draft").click()
    await assert_inert_native_receipt(await staged.value, db=db, secret_id=secret_id)
    response = await saved.value
    assert response.status == HTTPStatus.CREATED
    drafted = await response.json()
    assert set(drafted) == {"change_id", "approval_id", "state"}
    assert drafted["state"] == ConsoleDraftState.PENDING
    assert await db.fetch_value("SELECT count(*) FROM secrets") == 0
    await page.get_by_role("link", name="Review this draft").click()
    await page.wait_for_url(origin + changes_path + "/" + drafted["change_id"] + "/review")
    await assert_value_absent_from_browser(page, value=upstream.creds.bearer)
    await confirm_from_mail(page, smtp=smtp, message_start_index=mail_before)
    record = await db.fetch_one("SELECT secret_id,active_version FROM secrets")
    assert record["active_version"] == 1
    assert record["secret_id"] == secret_id
    return secret_id


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
    await registry.add_certificate(agent.certificate(), team_key=agent.team_key)
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
                        "after": {"v": 1, **policy.body},
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
            stage_path=f"/installations/{installed['installation_id']}/native/versions",
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


async def assert_native_inputs_cleared(page: Page) -> None:
    cleared = await page.locator("[data-value-field]").evaluate_all(
        "inputs => inputs.every(input => input.value === '')"
    )
    # Inspect only the boolean: a failed locator-value assertion would print the value.
    assert cleared, "the console retained an entered value"


async def test_native_form_displays_the_real_codec_refusal(root, production_console, browser):
    service, _, _, _, installed, *_ = root
    holder = await enrolled_owner(root)
    stage_path = f"/installations/{installed['installation_id']}/native/versions"
    async with await browser.new_context() as context:
        page = await sign_in_browser_owner(context, holder=holder, origin=production_console)
        await page.goto(production_console + "/secrets/native/new")
        await page.get_by_label("Secret name", exact=True).fill("refused-value")
        # Reach the server's codec refusal rather than the browser's required-field hint.
        await page.locator("#native-value").evaluate("form => { form.noValidate = true; }")
        async with page.expect_response(production_console + stage_path) as refused:
            await page.get_by_role("button", name="Save the value and draft").click()
        response = await refused.value
        assert response.status == HTTPStatus.BAD_REQUEST
        detail = (await response.json())["detail"]
        assert detail == str(ValueInvalid(ValueInvalidReason.SHAPE))
        await expect(page.locator("#form-status")).to_have_text(detail)
        await assert_native_inputs_cleared(page)
    assert await service.runtime.db().fetch_value("SELECT count(*) FROM sealed_versions") == 0


class SignInLoss(StrEnum):
    BEFORE_SEALING = "before_sealing"
    BEFORE_DRAFT = "before_draft"


@pytest.mark.parametrize("loss", list(SignInLoss))
async def test_native_form_recovers_this_tabs_sign_in_and_discards_the_value(
    root, production_console, browser, upstream, loss
):
    service, _, _, _, installed, *_ = root
    holder = await enrolled_owner(root)
    stage_path = f"/installations/{installed['installation_id']}/native/versions"
    async with await browser.new_context() as context:
        page = await sign_in_browser_owner(context, holder=holder, origin=production_console)
        await page.goto(production_console + "/secrets/native/new")
        await page.get_by_label("Secret name", exact=True).fill("new-tab-value")
        await enter_bearer_value(page, value=upstream.creds.bearer)
        await expect(page.locator("#console-reauth-notice")).to_be_hidden()
        if loss is SignInLoss.BEFORE_SEALING:
            await page.evaluate("sessionStorage.removeItem(window.awebConsole.csrfKey)")
            refused_path = stage_path
        else:
            refused_path = f"/installations/{installed['installation_id']}/change-sets"

            async def lose_tab_csrf(route):
                # The actual production handler must reject the missing tab proof.
                original_headers = await route.request.all_headers()
                headers = {
                    name: value
                    for name, value in original_headers.items()
                    if name.lower() != "x-csrf-token"
                }
                await route.continue_(headers=headers)

            await page.route(production_console + refused_path, lose_tab_csrf)
        async with page.expect_response(production_console + refused_path) as refused:
            await page.get_by_role("button", name="Save the value and draft").click()
        response = await refused.value
        assert response.status == HTTPStatus.FORBIDDEN
        assert (await response.json())["detail"] == "csrf_token_required"
        await expect(page.locator("#console-reauth-notice")).to_be_visible()
        if loss is SignInLoss.BEFORE_SEALING:
            await expect(page.locator("#form-status")).to_have_text(
                "Sign in with your passkey in this tab, then enter the value again."
            )
        else:
            await expect(page.locator("#form-status")).to_have_attribute(
                "data-state", ConsoleDraftState.UNCERTAIN
            )
            await expect(page.locator("#form-status")).to_have_text(
                "The value was sealed, but the draft was not saved. Sign in, then reload this "
                "page and enter the value again. Unused sealed copies stay inactive."
            )
            await expect(
                page.get_by_role("button", name="Save the value and draft")
            ).to_be_disabled()
        await assert_native_inputs_cleared(page)
    db = service.runtime.db()
    expected_sealed = 0 if loss is SignInLoss.BEFORE_SEALING else 1
    assert await db.fetch_value("SELECT count(*) FROM sealed_versions") == expected_sealed
    assert await db.fetch_value("SELECT count(*) FROM change_sets") == 0
    assert await db.fetch_value("SELECT count(*) FROM secrets") == 0


async def test_native_form_shows_custody_recovery_without_reflecting_the_value(
    root, production_console, browser, upstream
):
    service, client, configured, member, installed, *_ = root
    holder = await enrolled_owner(root)
    db = service.runtime.db()
    stage_path = f"/installations/{installed['installation_id']}/native/versions"
    async with await browser.new_context() as context:
        page = await sign_in_browser_owner(context, holder=holder, origin=production_console)
        await page.goto(production_console + "/secrets/native/new")
        secret_id = await page.locator('[name="secret_id"]').input_value()
        body = native_entry_request(value=upstream.creds.bearer)
        body["secret"]["secret_id"] = secret_id
        staged = await client.post(
            configured.console_origin + stage_path,
            json=body,
            headers={"X-CSRF-Token": holder.csrf_token},
        )
        assert staged.status_code == HTTPStatus.CREATED
        # Actual custody state becomes unavailable; the allocator/provider is never replaced.
        custody = Custody(LocalKeyFileProvider(configured.custody_key_file), db)
        async with db.transaction() as tx:
            await custody.disable(
                tx,
                installation_id=installed["installation_id"],
                team_id=member.team_id,
                secret_id=secret_id,
            )
        await page.get_by_label("Secret name", exact=True).fill("native-guard")
        await enter_bearer_value(page, value=upstream.creds.bearer)
        async with page.expect_response(production_console + stage_path) as refused:
            await page.get_by_role("button", name="Save the value and draft").click()
        response = await refused.value
        assert response.status == HTTPStatus.SERVICE_UNAVAILABLE
        await expect(page.locator("#form-status")).to_have_text((await response.json())["detail"])
        await expect(page.locator("#form-status")).to_contain_text("operator")
        await assert_native_inputs_cleared(page)
    assert await db.fetch_value("SELECT count(*) FROM sealed_versions") == 1


async def test_lost_native_draft_response_recovers_from_the_actual_approval_email(
    root, production_console, browser, upstream
):
    service, _, _, _, installed, smtp, *_ = root
    holder = await enrolled_owner(root)
    changes_path = f"/installations/{installed['installation_id']}/change-sets"
    reached_server = []

    async def lose_response(route):
        response = await route.fetch()
        reached_server.append(response.status)
        await response.dispose()
        await route.abort("failed")

    async with await browser.new_context() as context:
        page = await sign_in_browser_owner(context, holder=holder, origin=production_console)
        await page.goto(production_console + "/secrets/native/new")
        await page.get_by_label("Secret name", exact=True).fill("lost-draft")
        await enter_bearer_value(page, value=upstream.creds.bearer)
        await page.route(production_console + changes_path, lose_response)
        mail_before = len(smtp.received)
        button = page.get_by_role("button", name="Save the value and draft")
        await button.click()
        await expect(page.locator("#form-status")).to_have_attribute(
            "data-state", ConsoleDraftState.UNCERTAIN
        )
        await expect(page.locator("#form-status")).to_contain_text("approval email")
        await expect(button).to_be_disabled()
        await assert_native_inputs_cleared(page)
        await page.locator("#native-value").evaluate("form => form.requestSubmit()")
        assert reached_server == [HTTPStatus.CREATED]
        db = service.runtime.db()
        assert await db.fetch_value("SELECT count(*) FROM change_sets") == 1
        assert await db.fetch_value("SELECT count(*) FROM secrets") == 0
        await confirm_from_mail(page, smtp=smtp, message_start_index=mail_before)
        assert await db.fetch_value("SELECT count(*) FROM change_sets") == 1
        assert await db.fetch_value("SELECT active_version FROM secrets") == 1


class ConsoleTheme(StrEnum):
    LIGHT = "light"
    DARK = "dark"


async def test_all_native_kind_layouts_share_form_styles_without_overflow(
    root, production_console, browser, tmp_path
):
    holder = await enrolled_owner(root)
    screenshots = tmp_path / "native-layout"
    screenshots.mkdir()
    async with await browser.new_context() as context:
        page = await sign_in_browser_owner(context, holder=holder, origin=production_console)
        for width in (375, 1440):
            await page.set_viewport_size({"width": width, "height": 1000})
            for theme in ConsoleTheme:
                await page.emulate_media(color_scheme=theme)
                await page.goto(production_console + "/secrets/native/new")
                form = page.locator("#native-value")
                await expect(form).to_have_css("display", "grid")
                for kind in SecretKind:
                    await page.get_by_label("Authentication kind", exact=True).select_option(kind)
                    await expect(form.locator(f'fieldset[data-kind="{kind}"]')).to_be_visible()
                    assert await page.evaluate(
                        "document.documentElement.scrollWidth <= window.innerWidth + 1"
                    )
                    await assert_native_inputs_cleared(page)
                    await page.screenshot(
                        path=screenshots / f"native-{width}-{theme}-{kind}.png", full_page=True
                    )


class InvalidNativeEntry(StrEnum):
    VAULT_BACKEND = "vault_backend"
    VALUE_SHAPE = "value_shape"
    EMPTY_VALUE = "empty_value"
    BASIC_USERNAME = "basic_username"
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
    elif fault is InvalidNativeEntry.BASIC_USERNAME:
        body["secret"]["kind"] = SecretKind.BASIC
        body["value"] = {"username": "account:invalid", "password": value}
    else:
        body["team_id"] = "foreign:example.com"
    path = f"/installations/{installed['installation_id']}/native/versions"
    response = await client.post(
        configured.console_origin + path,
        json=body,
        headers={"X-CSRF-Token": holder.csrf_token},
    )
    assert response.status_code == HTTPStatus.BAD_REQUEST
    if fault is InvalidNativeEntry.BASIC_USERNAME:
        assert response.json()["detail"] == str(ValueInvalid(ValueInvalidReason.BASIC_USERNAME))
    assert_value_not_returned(response=response, value=value)
    assert await service.runtime.db().fetch_value("SELECT count(*) FROM sealed_versions") == 0

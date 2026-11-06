"""Human form headers, authority, escaping and real Chromium/passkey confirmation."""

import asyncio
import base64
import copy
import os
import re
import socket
from urllib.parse import quote, urlencode

import pytest
import uvicorn
from aweb_naapp.console import CONSOLE_HEADERS
from aweb_naapp.runtime.approvals import ApprovalState
from aweb_naapp.runtime.passkeys import RelyingParty, contact_sha256
from aweb_naapp_testing.owner_acts import INSTALLATION_ID
from playwright.async_api import TimeoutError as BrowserTimeout
from playwright.async_api import expect

from aweb_secrets.owners import owner_scope
from tests.test_change_records import ITEMS
from tests.test_change_sets import ALICE, TEAM, enrol_owner
from tests.test_change_sets import world as _world
from tests.test_console_changes import ROOT, TOKEN, application, clients, sign_in
from tests.test_console_ui import Elements
from tests.test_console_ui_browser import browser as _browser

world = _world
browser = _browser
FORM = "/backend-credentials/onepassword/new"


async def test_forms_are_human_owner_only_with_shared_headers_and_no_get_value_submission(world):
    w = world
    scope = await enrol_owner(w, ALICE, "alice@acme.com")
    async with clients(w, forms=True) as (human, agent):
        assert (await human.get(FORM)).status_code == 303
        await sign_in(w, human, scope)
        for path in (FORM, "/approvals", "/console-forms/forms.js", "/console-forms/forms.css"):
            response = await human.get(path)
            assert response.status_code == 200
            for name, value in CONSOLE_HEADERS.items():
                assert response.headers[name] == value
            assert (await agent.get(path)).status_code == 404
        tags = Elements((await human.get(FORM)).text).tags
        [form] = [attrs for tag, attrs in tags if tag == "form"]
        assert form["method"] == "post" and form["action"] == TOKEN
        [input_] = [attrs for tag, attrs in tags if tag == "input"]
        assert input_["type"] == "password" and "value" not in input_
        assert input_["autocomplete"] == "off"


async def test_frozen_reason_cannot_escape_review_markup(world):
    w = world
    scope = await enrol_owner(w, ALICE, "alice@acme.com")
    attack = '</pre><script src="https://untrusted.invalid/x.js"></script><img src=x>'
    async with clients(w, forms=True) as (human, _):
        headers = await sign_in(w, human, scope)
        staged = await human.post(TOKEN, json={"value": os.urandom(24).hex()}, headers=headers)
        response = await human.post(
            ROOT,
            headers=headers,
            json={
                "changes": [
                    {
                        "kind": "backend_credential",
                        "op": "create",
                        "ref": "onepassword",
                        "after": staged.json(),
                    }
                ],
                "sealed": [{"secret_id": "bkc_onepassword", "version": 1}],
                "reason": attack,
            },
        )
        assert response.status_code == 201
        page = await human.get(ROOT + "/" + response.json()["change_id"] + "/review")
        assert page.status_code == 200
        tags = Elements(page.text).tags
        assert all(attrs.get("src", "").startswith("/") for tag, attrs in tags if tag == "script")
        assert not any(tag == "img" for tag, _ in tags)
        assert attack not in page.text


@pytest.fixture
async def service(world):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    origin = f"http://localhost:{port}"
    world.passkeys.rp = RelyingParty(origin=origin, name="Secrets")
    app = await application(
        world, forms=True, human_origin=origin, agent_origin=f"http://127.0.0.1:{port}"
    )
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


async def enrolled_page(world, context, service):
    page = await context.new_page()
    cdp = await context.new_cdp_session(page)
    await cdp.send("WebAuthn.enable")
    auth = await cdp.send(
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
    scope = owner_scope(INSTALLATION_ID, TEAM, ALICE.principal_did)
    subject = {
        "app_id": world.admitted.app_id,
        "installation_id": INSTALLATION_ID,
        "role": scope,
        "contact_sha256": contact_sha256("alice@acme.com"),
    }
    signing, signature = world.owner.sign("app-role.designate", subject)
    designated = await context.request.post(
        service + f"/installations/{INSTALLATION_ID}/owner-acts",
        data={
            "signing": base64.b64encode(signing).decode(),
            "signature": signature,
            "team_id": TEAM,
            "principal": ALICE.principal_did,
            "contact": "alice@acme.com",
        },
    )
    assert designated.status == 200
    await page.goto(service + "/login?" + urlencode({"scope": scope}))
    status = await page.evaluate(
        """async link_token => {
      const response = await fetch('/enrolment/options', {method:'POST',
        headers:{'Content-Type':'application/json'}, body:JSON.stringify({link_token})});
      const credential = await navigator.credentials.create({publicKey:
        PublicKeyCredential.parseCreationOptionsFromJSON(await response.json())});
      return (await fetch('/enrolment', {method:'POST', headers:{'Content-Type':'application/json'},
        body:JSON.stringify({link_token, credential:credential.toJSON()})})).status;
    }""",
        world.inbox.enrolments["alice@acme.com"][-1],
    )
    assert status == 200
    await page.get_by_role("button", name="Sign in with a passkey").click()
    await page.wait_for_url(service + "/")
    return page, cdp, auth["authenticatorId"]


async def wait_for_review(page, review):
    try:
        await page.wait_for_url(review, timeout=10000)
    except BrowserTimeout:
        # Browser navigation diagnostics may include a transient fragment token.
        raise AssertionError("approval sign-in did not load its frozen review") from None


@pytest.mark.parametrize(
    "user_verified,session_mode,resume_approved",
    [
        (True, "signed_out", False),
        (True, "signed_in", False),
        (False, "signed_out", False),
        (False, "signed_in", False),
        (True, "signed_in", True),
        (True, "new_tab", False),
        (True, "stale_csrf", False),
        (True, "stale_after_review", False),
    ],
)
async def test_customer_browser_token_draft_and_fresh_passkey_confirmation(
    world,
    browser,
    service,
    user_verified,
    session_mode,
    resume_approved,
    tmp_path,
):
    w = world
    async with await browser.new_context() as context:
        page, cdp, authenticator = await enrolled_page(w, context, service)
        baseline_events = await w.db.fetch_value(
            "SELECT count(*) FROM {{tables.outbox_events}} WHERE kind='post-governance-hook'"
        )
        await page.goto(service + FORM)
        await page.screenshot(path=tmp_path / "onepassword-token-entry-empty.png")
        # A fresh tab/context with only the cookie must re-authenticate, not submit.
        async with await browser.new_context() as fresh:
            await fresh.add_cookies(await context.cookies())
            other = await fresh.new_page()
            await other.goto(service + FORM)
            await expect(other.locator("#console-reauth")).to_be_visible()
            await expect(other.locator("#backend-token")).to_be_hidden()
        entered = os.urandom(24).hex()
        await page.get_by_label("1Password service-account token").fill(entered)
        async with page.expect_response(service + ROOT) as drafted:
            await page.get_by_role("button", name="Save a draft").click()
        response = await drafted.value
        assert response.status == 201
        draft = await response.json()
        await expect(page.get_by_label("1Password service-account token")).to_have_value("")
        if entered in await page.content():
            raise AssertionError("entered credential reflected into page")
        assert not await page.evaluate(
            "value => JSON.stringify({...sessionStorage,...localStorage}).includes(value)", entered
        )
        assert (
            await w.db.fetch_value("SELECT active_version FROM {{tables.onepassword_credentials}}")
            is None
        )
        [(_, token)] = w.inbox.links["alice@acme.com"]
        extra_context = None
        if session_mode == "new_tab":
            extra_context = await browser.new_context()
            await extra_context.add_cookies(await context.cookies())
            credentials = await cdp.send(
                "WebAuthn.getCredentials", {"authenticatorId": authenticator}
            )
            page = await extra_context.new_page()
            cdp = await extra_context.new_cdp_session(page)
            await cdp.send("WebAuthn.enable")
            auth = await cdp.send(
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
            authenticator = auth["authenticatorId"]
            for credential in credentials["credentials"]:
                await cdp.send(
                    "WebAuthn.addCredential",
                    {"authenticatorId": authenticator, "credential": credential},
                )
        if session_mode == "stale_csrf":
            # A real second login replaces the cookie but retains the tab's old CSRF.
            scope = owner_scope(INSTALLATION_ID, TEAM, ALICE.principal_did)
            await page.evaluate(
                """async scope => {
                const api = window.awebSecretsConsole;
                const options = await api.post('/login/options', {scope});
                await api.post('/login', {scope, assertion: await api.assertion(options)});
            }""",
                scope,
            )
        if session_mode == "signed_out":
            await page.goto(service + "/")
            await page.get_by_role("button", name="Sign out").click()
            await page.wait_for_url(service + "/login")
        await page.goto(service + "/approvals#token=" + quote(token, safe=""))
        if session_mode not in {"signed_in", "stale_after_review"}:
            await expect(
                page.get_by_role("button", name="Sign in with your passkey")
            ).to_be_enabled()
            await page.get_by_role("button", name="Sign in with your passkey").click()
        review = service + ROOT + "/" + draft["change_id"] + "/review"
        await wait_for_review(page, review)
        await expect(page.get_by_role("button", name="Confirm with your passkey")).to_be_enabled()
        assert token not in page.url
        assert not await page.evaluate(
            "value => JSON.stringify({...sessionStorage,...localStorage}).includes(value)", token
        )
        if session_mode == "stale_after_review":
            # Rotate the shared cookie in an actual second tab AFTER frozen review.
            second = await context.new_page()
            second_cdp = await context.new_cdp_session(second)
            await second_cdp.send("WebAuthn.enable")
            second_auth = await second_cdp.send(
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
            credentials = await cdp.send(
                "WebAuthn.getCredentials", {"authenticatorId": authenticator}
            )
            for credential in credentials["credentials"]:
                await second_cdp.send(
                    "WebAuthn.addCredential",
                    {"authenticatorId": second_auth["authenticatorId"], "credential": credential},
                )
            scope = owner_scope(INSTALLATION_ID, TEAM, ALICE.principal_did)
            await second.goto(service + "/login?" + urlencode({"scope": scope}))
            await second.get_by_role("button", name="Sign in with a passkey").click()
            await second.wait_for_url(service + "/")
            # Both virtual copies represent one device: carry its advanced counter.
            latest = await second_cdp.send(
                "WebAuthn.getCredentials", {"authenticatorId": second_auth["authenticatorId"]}
            )
            for credential in latest["credentials"]:
                await cdp.send(
                    "WebAuthn.removeCredential",
                    {"authenticatorId": authenticator, "credentialId": credential["credentialId"]},
                )
                await cdp.send(
                    "WebAuthn.addCredential",
                    {"authenticatorId": authenticator, "credential": credential},
                )
            async with page.expect_response(
                lambda r: r.url.endswith("/approval-options")
            ) as refused:
                await page.get_by_role("button", name="Confirm with your passkey").click()
            assert (await refused.value).status == 403
            await expect(page.locator("[data-console-scope]")).to_be_hidden()
            await expect(page.locator("#approval-login button")).to_be_enabled(timeout=2000)
            assert (await w.approvals.get(draft["approval_id"])).state is ApprovalState.PENDING
            assert (
                await w.db.fetch_value(
                    "SELECT active_version FROM {{tables.onepassword_credentials}}"
                )
                is None
            )
            await page.locator("#approval-login button").click()
            await wait_for_review(page, review)
            await expect(
                page.get_by_role("button", name="Confirm with your passkey")
            ).to_be_enabled()
            # Reauthentication reloads review; it must not retry approval or apply.
            assert (await w.approvals.get(draft["approval_id"])).state is ApprovalState.PENDING
            assert token not in page.url
            assert not await page.evaluate(
                "value => JSON.stringify({...sessionStorage,...localStorage}).includes(value)",
                token,
            )
            await second.close()
        if resume_approved:
            await w.db.execute(
                "ALTER TABLE {{tables.outbox_events}} ADD CONSTRAINT reject_confirmation CHECK(kind <> 'post-governance-hook') NOT VALID"
            )
        await cdp.send(
            "WebAuthn.setUserVerified",
            {"authenticatorId": authenticator, "isUserVerified": user_verified},
        )
        await page.get_by_role("button", name="Confirm with your passkey").click()
        if not user_verified:
            await expect(
                page.get_by_role("button", name="Confirm with your passkey")
            ).to_be_enabled()
            assert (await w.approvals.get(draft["approval_id"])).state is ApprovalState.PENDING
            assert (
                await w.db.fetch_value(
                    "SELECT active_version FROM {{tables.onepassword_credentials}}"
                )
                is None
            )
            return
        if resume_approved:
            await expect(page.locator("#form-status")).to_have_attribute(
                "data-state", "needs-review"
            )
            assert (await w.approvals.get(draft["approval_id"])).state is ApprovalState.APPROVED
            assert (
                await w.db.fetch_value(
                    "SELECT active_version FROM {{tables.onepassword_credentials}}"
                )
                is None
            )
            await w.db.execute(
                "ALTER TABLE {{tables.outbox_events}} DROP CONSTRAINT reject_confirmation"
            )
            await page.reload()
            await expect(page.locator("#confirm-change")).to_be_enabled()
            # Applying the already approved bytes must not request a second APPROVE.
            await cdp.send(
                "WebAuthn.setUserVerified",
                {"authenticatorId": authenticator, "isUserVerified": False},
            )
            await page.locator("#confirm-change").click()
        await expect(page.locator("#form-status")).to_have_attribute("data-state", "applied")
        assert (
            await w.db.fetch_value("SELECT active_version FROM {{tables.onepassword_credentials}}")
            == 1
        )
        assert (await w.approvals.get(draft["approval_id"])).state is ApprovalState.CONSUMED
        assert (
            await w.db.fetch_value(
                "SELECT count(*) FROM {{tables.outbox_events}} WHERE kind='post-governance-hook'"
            )
            == baseline_events + 1
        )
        await page.reload()
        await expect(page.locator("#change-summary")).to_have_attribute("data-state", "applied")
        await expect(page.locator("#confirm-change")).to_be_disabled()
        await page.screenshot(path=tmp_path / "onepassword-connection-applied.png")
        if extra_context is not None:
            await extra_context.close()


@pytest.mark.parametrize("width", [375, 1440])
async def test_runner_confirmation_renders_code_once_in_the_deciding_document(
    world, browser, service, width
):
    from aweb_secrets.runners import apply_runner_migrations
    from tests.test_change_set_runners import runner_item

    w = world
    await apply_runner_migrations(w.db)
    # A valid 16-byte base64url id with wide glyphs makes mobile layout deterministic.
    runner_id = "rnr_" + "W" * 21 + "w"
    async with await browser.new_context(viewport={"width": width, "height": 900}) as context:
        page, _, _ = await enrolled_page(w, context, service)
        csrf = await page.evaluate("sessionStorage.getItem('aweb.secrets.console.csrf')")
        drafted = await context.request.post(
            service + ROOT,
            headers={"X-CSRF-Token": csrf},
            data={
                "changes": [runner_item(runner_id)],
                "sealed": [],
                "reason": "Register the build runner",
            },
        )
        assert drafted.status == 201
        draft = await drafted.json()
        [token] = [
            token
            for approval, token in w.inbox.links["alice@acme.com"]
            if approval == draft["approval_id"]
        ]
        await page.goto(service + "/approvals#token=" + quote(token))
        await wait_for_review(page, service + ROOT + "/" + draft["change_id"] + "/review")
        await expect(page.locator("#change-facts")).to_contain_text(runner_id)
        await expect(page.locator("#change-facts")).to_contain_text("Build runner")
        await page.get_by_role("button", name="Confirm with your passkey").click()
        await expect(page.locator("#form-status")).to_have_attribute("data-state", "applied")
        await expect(page.locator("#approval-instructions")).not_to_contain_text(
            re.compile(r"confirm|apply the approved", re.I)
        )
        code = await page.locator("#runner-registration-result code").text_content()
        assert (
            code and runner_id in await page.locator("#runner-registration-result").text_content()
        )
        if await page.evaluate(
            "value => JSON.stringify({...sessionStorage,...localStorage}).includes(value)", code
        ):
            raise AssertionError("registration material persisted in browser storage")
        assert code not in page.url
        assert await page.evaluate("document.documentElement.scrollWidth <= window.innerWidth"), (
            await page.locator("#runner-registration-result").evaluate(
                """section => [...section.children].map(node => ({
                tag: node.tagName, clientWidth: node.clientWidth, scrollWidth: node.scrollWidth,
                right: node.getBoundingClientRect().right
            }))"""
            )
        )
        receipt = await context.request.get(service + ROOT + "/" + draft["change_id"])
        if code in await receipt.text():
            raise AssertionError("registration material returned by a later read")
        await page.reload()
        await expect(page.locator("#runner-registration-result")).to_have_count(0)
        await expect(page.locator("#confirm-change")).to_be_hidden()


@pytest.mark.parametrize("width", [375, 1440])
@pytest.mark.parametrize("mode", ["absent", "manual", "idempotent", "side_effect_free"])
async def test_operation_retry_terms_are_disclosed_before_fresh_confirmation(
    world, browser, service, width, mode, tmp_path
):
    w = world
    operation = copy.deepcopy(ITEMS["operation"])
    after = operation["after"]
    if mode == "manual":
        after["outcome_unknown_retry"] = None
    elif mode in {"idempotent", "side_effect_free"}:
        after["outcome_unknown_retry"] = {
            "delay_s": 2,
            "upstream_honours_idempotency_key": mode == "idempotent",
        }
        if mode == "idempotent":
            after["side_effect"] = "irreversible"
            after["idempotency"] = {"header": "Idempotency-Key"}
    async with await browser.new_context(viewport={"width": width, "height": 900}) as context:
        page, _, _ = await enrolled_page(w, context, service)
        csrf = await page.evaluate("sessionStorage.getItem('aweb.secrets.console.csrf')")
        drafted = await context.request.post(
            service + ROOT,
            headers={"X-CSRF-Token": csrf},
            data={
                "changes": [copy.deepcopy(ITEMS["secret"]), operation],
                "sealed": [],
                "reason": "Configure the operation's uncertain-outcome handling",
            },
        )
        assert drafted.status == 201
        draft = await drafted.json()
        [token] = [
            token
            for approval, token in w.inbox.links["alice@acme.com"]
            if approval == draft["approval_id"]
        ]
        await page.goto(service + "/approvals#token=" + quote(token))
        await wait_for_review(page, service + ROOT + "/" + draft["change_id"] + "/review")
        facts = page.locator("#change-facts")
        if mode in {"absent", "manual"}:
            await expect(facts).to_contain_text(re.compile(r"manual settlement only", re.I))
            await expect(facts).not_to_contain_text(re.compile(r"automatically repeat once", re.I))
        else:
            await expect(facts).to_contain_text(re.compile(r"automatically repeat once", re.I))
            await expect(facts).to_contain_text("2 seconds")
            if mode == "idempotent":
                await expect(facts).to_contain_text(re.compile(r"owner.asserted", re.I))
                await expect(facts).to_contain_text("Idempotency-Key")
                await expect(facts).to_contain_text(re.compile(r"wrong.*duplicate", re.I))
            else:
                await expect(facts).to_contain_text(re.compile(r"no side effect", re.I))
                await expect(facts).not_to_contain_text(re.compile(r"owner.asserted", re.I))
        await expect(page.locator("#confirm-change")).to_be_enabled()
        assert (await w.approvals.get(draft["approval_id"])).state is ApprovalState.PENDING
        assert not await w.db.fetch_value("SELECT count(*) FROM {{tables.current_operations}}")
        assert await page.evaluate("document.documentElement.scrollWidth <= innerWidth")
        await page.screenshot(path=tmp_path / f"operation-retry-{mode}-{width}.png", full_page=True)
        await page.locator("#confirm-change").click()
        await expect(page.locator("#form-status")).to_have_attribute("data-state", "applied")
        assert (await w.approvals.get(draft["approval_id"])).state is ApprovalState.CONSUMED

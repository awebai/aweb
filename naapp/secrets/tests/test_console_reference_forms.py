"""Owner reference forms; refusals exercise real PG/WebAuthn before SDK I/O.

External-vault success remains the provisioned HO6 journey.
"""

import os
from urllib.parse import quote

import pytest
from aweb_naapp.console import CONSOLE_HEADERS
from aweb_naapp.roles import unassign
from aweb_naapp_testing.owner_acts import INSTALLATION_ID
from playwright.async_api import expect

from aweb_secrets.operation import CAPTURE_FIELDS
from aweb_secrets.owners import OWNER_ROLE
from aweb_secrets.secret import KINDS, SecretRecord
from tests.test_change_sets import ALICE, enrol_owner
from tests.test_change_sets import world as _world
from tests.test_console_changes import ROOT, approve, clients, sign_in, token_draft
from tests.test_console_forms import FORM, enrolled_page, wait_for_review
from tests.test_console_forms import service as _service
from tests.test_console_ui import Elements
from tests.test_console_ui_browser import browser as _browser

world = _world
service = _service
browser = _browser
REFERENCE = "/onepassword/references/new"
INGRESS = f"/installations/{INSTALLATION_ID}/onepassword/references"


async def test_reference_page_requires_owner_and_a_confirmed_backend_connection(world):
    scope = await enrol_owner(world, ALICE, "alice@acme.com")
    async with clients(world, forms=True) as (human, agent):
        assert (await human.get(REFERENCE)).status_code == 303
        assert (await agent.get(REFERENCE)).status_code == 404
        await sign_in(world, human, scope)
        for path in (REFERENCE, "/secrets/new", INGRESS + "/new"):
            response = await human.get(path)
            assert response.status_code == 200
            for name, value in CONSOLE_HEADERS.items():
                assert response.headers[name] == value
            tags = Elements(response.text).tags
            assert not any(attrs.get("id") == "onepassword-reference" for _, attrs in tags)
            assert any(attrs.get("href") == FORM for _, attrs in tags)
        assert await world.db.fetch_value("SELECT count(*) FROM {{tables.change_sets}}") == 0
        async with world.db.transaction() as tx:
            await unassign(tx, ALICE, OWNER_ROLE)
        assert (await human.get(REFERENCE)).status_code == 303


async def test_reference_form_uses_only_the_current_scoped_backend_version(world):
    scope = await enrol_owner(world, ALICE, "alice@acme.com")
    async with clients(world, forms=True) as (human, _):
        headers = await sign_in(world, human, scope)
        drafted = await token_draft(world, human, headers)
        await approve(world, human, headers, drafted)
        confirmed = await human.post(
            ROOT + "/" + drafted["change_id"] + "/confirm", json={}, headers=headers
        )
        assert confirmed.status_code == 200
        response = await human.get(REFERENCE)
        tags = Elements(response.text).tags
        [form] = [
            attrs
            for tag, attrs in tags
            if tag == "form" and attrs.get("id") == "onepassword-reference"
        ]
        assert form["action"] == INGRESS and form["method"] == "post"
        [version] = [
            attrs
            for tag, attrs in tags
            if tag == "input" and attrs.get("name") == "credential_version"
        ]
        assert version["type"] == "hidden" and version["value"] == "1"
        assert {
            attrs["value"] for tag, attrs in tags if tag == "option" and "data-auth-kind" in attrs
        } == set(KINDS)
        assert (
            await human.get("/installations/not-this-installation/onepassword/references/new")
        ).status_code == 403


async def connect_backend(world, page, origin):
    await page.goto(origin + FORM)
    await page.get_by_label("1Password service-account token").fill(os.urandom(24).hex())
    async with page.expect_response(origin + ROOT) as response:
        await page.get_by_role("button", name="Save a draft", exact=True).click()
    drafted = await (await response.value).json()
    [token] = [
        token
        for approval, token in world.inbox.links["alice@acme.com"]
        if approval == drafted["approval_id"]
    ]
    await page.goto(origin + "/approvals#token=" + quote(token))
    await wait_for_review(page, origin + ROOT + "/" + drafted["change_id"] + "/review")
    await page.get_by_role("button", name="Confirm with your passkey").click()
    await expect(page.locator("#form-status")).to_have_attribute("data-state", "applied")


@pytest.mark.parametrize(
    "kind,width", [(kind, 375 if index % 2 == 0 else 1440) for index, kind in enumerate(KINDS)]
)
async def test_reference_browser_builds_kind_specific_metadata_and_stops_after_session_loss(
    world, browser, service, kind, width, tmp_path
):
    async with await browser.new_context(viewport={"width": width, "height": 1000}) as context:
        page, _, _ = await enrolled_page(world, context, service)
        await connect_backend(world, page, service)
        await page.goto(service + REFERENCE)
        await page.get_by_label("Secret name", exact=True).fill("deployment-credential")
        await page.get_by_label("Authentication kind").select_option(kind)
        await page.get_by_label("Vault ID", exact=True).fill("a" * 26)
        await page.get_by_label("Item ID", exact=True).fill("b" * 26)
        required, optional = CAPTURE_FIELDS[kind]
        for name in sorted(required | optional):
            await page.locator(f'[data-kind="{kind}"] [data-field="{name}"]').fill(name + "-id")
        params = {
            "header": {"name": "X-Api-Key", "prefix": "Key "},
            "query": {"param": "api_key"},
            "oauth2-client-credentials": {
                "token_endpoint": "https://issuer.example.com/token",
                "scope": "read",
            },
            "aws-sigv4": {"region": "us-east-1", "service": "sts"},
        }.get(kind, {})
        for name, value in params.items():
            await page.locator(f'[data-kind="{kind}"] [data-param="{name}"]').fill(value)
        await page.get_by_label("Require approval for every use").check()
        await expect(page.get_by_label("Sensitivity", exact=True)).to_have_value("sensitive")
        assert await page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
        await page.screenshot(path=tmp_path / f"reference-{kind}-{width}.png")
        # Real logout invalidates S4; submitting must neither read the vault nor draft.
        csrf = await page.evaluate("sessionStorage.getItem('aweb.secrets.console.csrf')")
        assert (
            await context.request.post(service + "/logout", headers={"X-CSRF-Token": csrf}, data={})
        ).status == 200
        async with page.expect_response(service + INGRESS) as response:
            await page.get_by_role("button", name="Save a reference draft").click()
        refused = await response.value
        assert refused.status == 401
        body = refused.request.post_data_json
        assert set(body) == {"secret", "reference", "credential_version"}
        record = SecretRecord.from_after(body["secret"])
        assert record.kind == kind and record.approve_only and record.backend == "onepassword"
        assert record.kind_params == {
            **params,
            **(
                {"client_auth": "client_secret_basic"}
                if kind == "oauth2-client-credentials"
                else {}
            ),
        }
        assert body["credential_version"] == 1
        assert body["reference"] == {
            "vault_id": "a" * 26,
            "item_id": "b" * 26,
            "fields": {name: name + "-id" for name in required | optional},
        }
        assert (
            await world.db.fetch_value("SELECT count(*) FROM {{tables.onepassword_versions}}") == 0
        )
        assert await world.db.fetch_value("SELECT count(*) FROM {{tables.secrets}}") == 0
        assert await world.db.fetch_value("SELECT count(*) FROM {{tables.change_sets}}") == 1
        await expect(page.locator("#form-status")).not_to_have_attribute("data-state", "pending")

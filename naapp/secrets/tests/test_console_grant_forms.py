"""Owner configuration drafts use the existing real PG/B2/B3 writer.

The pre-existing secret is fixture state. This is component/browser proof;
HO6's complete vault-backed configuration journey remains separate.
"""

from copy import deepcopy
from urllib.parse import quote

import pytest
from aweb_naapp.console import CONSOLE_HEADERS
from aweb_naapp.roles import unassign
from aweb_naapp_testing.owner_acts import INSTALLATION_ID
from playwright.async_api import expect

from aweb_secrets import records
from aweb_secrets.operation import OperationTemplate
from aweb_secrets.owners import OWNER_ROLE
from aweb_secrets.policy import Policy
from aweb_secrets.secret import SecretRecord
from tests.test_change_records import SECRET
from tests.test_change_sets import ALICE, TEAM, enrol_owner
from tests.test_change_sets import world as _world
from tests.test_console_changes import ROOT, approve, clients, sign_in
from tests.test_console_forms import enrolled_page, wait_for_review
from tests.test_console_forms import service as _service
from tests.test_console_ui_browser import browser as _browser

world = _world
service = _service
browser = _browser
PAGE = "/grants/new"
DRAFT = f"/installations/{INSTALLATION_ID}/grants/drafts"


@pytest.fixture
async def secret(world):
    record = SecretRecord.from_after(deepcopy(SECRET))
    async with world.db.transaction() as tx:
        await records.create_secret(tx, INSTALLATION_ID, TEAM, record)
    return record


def configuration(secret):
    return {
        "secret_ref": secret.ref,
        "role": "secrets.role.deployers",
        "operation_id": "read-status",
        "method": "GET",
        "url": "https://api.payments.example/v1/status",
        "projection": ["/status"],
        "max_bytes": 4096,
        "side_effect": "none",
        "approval": "none",
        "capacity": 30,
        "window_s": 3600,
        "reason": "Allow the deployment role to read status",
    }


async def test_grant_page_and_draft_require_the_current_owner_session(world, secret):
    scope = await enrol_owner(world, ALICE, "alice@acme.com")
    async with clients(world, forms=True) as (human, agent):
        assert (await human.get(PAGE)).status_code == 303
        assert (await human.post(DRAFT, json=configuration(secret))).status_code == 401
        headers = await sign_in(world, human, scope)
        response = await human.get(PAGE)
        assert response.status_code == 200
        for name, value in CONSOLE_HEADERS.items():
            assert response.headers[name] == value
        assert (await agent.get(PAGE)).status_code == 404
        assert (await agent.post(DRAFT, json=configuration(secret))).status_code == 404
        assert (await human.post(DRAFT, json=configuration(secret))).status_code == 403
        async with world.db.transaction() as tx:
            await unassign(tx, ALICE, OWNER_ROLE)
        assert (await human.get(PAGE)).status_code == 303
        assert (
            await human.post(DRAFT, json=configuration(secret), headers=headers)
        ).status_code in {401, 403}
    assert await world.db.fetch_value("SELECT count(*) FROM {{tables.change_sets}}") == 0


@pytest.mark.parametrize("approval", ["none", "per_use"])
async def test_configuration_stays_inert_until_fresh_owner_confirmation(world, secret, approval):
    scope = await enrol_owner(world, ALICE, "alice@acme.com")
    body = {**configuration(secret), "approval": approval}
    async with clients(world, forms=True) as (human, _):
        headers = await sign_in(world, human, scope)
        response = await human.post(DRAFT, json=body, headers=headers)
        assert response.status_code == 201
        draft = response.json()
        frozen = await human.get(ROOT + "/" + draft["change_id"])
        items = {item["kind"]: item["after"] for item in frozen.json()["change"]["changes"]}
        assert set(items) == {"destination", "operation", "policy", "grant"}
        assert items["destination"]["path"] == "/v1/status"
        assert items["destination"]["methods"] == ["GET"]
        operation = OperationTemplate.from_after(items["operation"])
        assert operation.after["response"]["projection"] == ["/status"]
        policy = Policy.from_body({k: v for k, v in items["policy"].items() if k != "v"})
        pin = {"operation_id": "read-status", "digest": operation.digest}
        assert items["grant"]["subject"] == {"role": body["role"]}
        assert items["grant"]["operations"] == [pin]
        assert policy.body["operations"] == [pin]
        assert items["grant"]["policy_digest"] == policy.digest
        assert policy.body["approval"] == approval
        # An approve_only secret still needs a live owner approver when the
        # grant adds no further requirement. Keep that route for later rotation too.
        assert policy.body["approvers"] == ["owner:" + ALICE.principal_did]
        for table in ("destinations", "operation_templates", "grants", "policies"):
            assert await world.db.fetch_value(f"SELECT count(*) FROM {{{{tables.{table}}}}}") == 0
        path = ROOT + "/" + draft["change_id"]
        assert (await human.post(path + "/confirm", json={}, headers=headers)).status_code == 409
        await approve(world, human, headers, draft)
        assert (await human.post(path + "/confirm", json={}, headers=headers)).status_code == 200
    async with world.db.transaction() as tx:
        grants = await records.active_grants(
            tx,
            INSTALLATION_ID,
            secret.secret_id,
            principal_did=ALICE.principal_did,
            roles=[body["role"]],
        )
        assert len(grants) == 1
        assert grants[0].subject_role == body["role"]
        assert grants[0].covers_operation("read-status", operation.digest)


@pytest.mark.parametrize(
    "invalid",
    [
        {"url": "http://api.payments.example/v1/status"},
        {"url": "https://api.payments.example/v1/status?token=hidden"},
        {"url": "https://user:password@api.payments.example/v1/status"},
        {"url": "https://api.payments.example/v1/status#fragment"},
        {"role": "secrets.owner"},
        {"capacity": True},
        {"secret_ref": "unknown"},
        {"projection": None},
        {"unexpected": "field"},
    ],
)
async def test_invalid_configuration_creates_no_draft(world, secret, invalid):
    scope = await enrol_owner(world, ALICE, "alice@acme.com")
    async with clients(world, forms=True) as (human, _):
        headers = await sign_in(world, human, scope)
        response = await human.post(
            DRAFT, json={**configuration(secret), **invalid}, headers=headers
        )
        assert response.status_code in {400, 404, 409}
    assert await world.db.fetch_value("SELECT count(*) FROM {{tables.change_sets}}") == 0


@pytest.mark.parametrize("width", [375, 1440])
@pytest.mark.parametrize("scheme", ["light", "dark"])
async def test_owner_creates_and_confirms_role_access_in_browser(
    world, secret, service, browser, width, scheme, tmp_path
):
    async with await browser.new_context(
        viewport={"width": width, "height": 1000}, color_scheme=scheme
    ) as context:
        page, _, _ = await enrolled_page(world, context, service)
        await page.goto(service + PAGE)
        await page.get_by_label("Secret name", exact=True).fill(secret.ref)
        await page.get_by_label("Role", exact=True).fill("secrets.role.deployers")
        await page.get_by_label("Operation name", exact=True).fill("read-status")
        await page.get_by_label("Destination URL", exact=True).fill(
            "https://api.payments.example/v1/status"
        )
        await page.get_by_label("Response fields", exact=True).fill("/status")
        assert await page.locator("html").evaluate("e => e.scrollWidth <= e.clientWidth")
        assert await page.locator("#grant-secret_ref").evaluate(
            "e => getComputedStyle(e).fontFamily === getComputedStyle(document.body).fontFamily"
        )
        await page.screenshot(path=tmp_path / f"form-{width}-{scheme}.png", full_page=True)
        async with page.expect_response(service + DRAFT) as submitted:
            await page.get_by_role("button", name="Save a draft for review", exact=True).click()
        response = await submitted.value
        assert response.status == 201
        draft = await response.json()
        assert await world.db.fetch_value("SELECT count(*) FROM {{tables.grants}}") == 0
        [(_, token)] = world.inbox.links["alice@acme.com"]
        await page.goto(service + "/approvals#token=" + quote(token, safe=""))
        await wait_for_review(page, service + ROOT + "/" + draft["change_id"] + "/review")
        await expect(page.get_by_role("button", name="Confirm with your passkey")).to_be_enabled()
        await page.screenshot(path=tmp_path / f"review-{width}-{scheme}.png", full_page=True)
        await page.get_by_role("button", name="Confirm with your passkey").click()
        await expect(page.locator("#form-status")).to_have_attribute("data-state", "applied")
        assert await world.db.fetch_value("SELECT count(*) FROM {{tables.grants}}") == 1
        await page.screenshot(path=tmp_path / f"applied-{width}-{scheme}.png", full_page=True)

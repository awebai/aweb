"""Owner pages use real control approvals and the canonical settlement service."""

from contextlib import asynccontextmanager

import httpx
from aweb_naapp.runtime.approvals import ApprovalState
from aweb_naapp.runtime.origins import split_origins
from fastapi import FastAPI

from aweb_secrets.console import owner_console_router
from aweb_secrets.console_reconciliation import ConsoleReconciliation, console_reconciliation_router
from aweb_secrets.console_ui import console_ui_router
from tests.reconciliation_world import service_world
from tests.test_change_sets import BOB, ORIGIN, enrol_owner
from tests.test_console import API
from tests.test_console_changes import sign_in
from tests.test_reconciliation_service import snapshot
from tests.test_use_approvals import uses as uses
from tests.test_use_approvals import world as world


async def application(uses, *, origin=ORIGIN, agent_origin=API):
    run, original, controls, console, current = await service_world(uses)
    services = ConsoleReconciliation(
        console=console, reads=controls._reads, controls=controls, approvals=uses.approvals
    )
    human = FastAPI()
    human.include_router(owner_console_router(console))
    human.include_router(console_ui_router(sessions=console.sessions))
    human.include_router(console_reconciliation_router(services=services))
    return (
        split_origins(FastAPI(), human, human_origin=origin, agent_origin=agent_origin),
        run,
        original,
        current,
    )


@asynccontextmanager
async def clients(uses):
    app, run, original, current = await application(uses)
    async with (
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=ORIGIN) as human,
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=API) as agent,
    ):
        yield human, agent, run, original, current


async def ceremony(uses, human, headers, root, token, *, decision=None):
    body = {"token": token}
    if decision is not None:
        body["decision"] = decision
    options = await human.post(
        root + ("/view-options" if decision is None else "/decision-options"),
        json=body,
        headers=headers,
    )
    assert options.status_code == 200
    body["assertion"] = uses.world.devices["alice@acme.com"].get(options.json())
    return await human.post(
        root + ("/view" if decision is None else "/decide"), json=body, headers=headers
    )


async def test_read_login_and_view_never_settle_and_approve_requires_an_explicit_settle(uses):
    async with clients(uses) as (human, agent, run, original, current):
        ref = original.original.reconcile_ref
        path = "/reconciliations/" + ref
        assert (await human.get(path)).status_code == 303
        assert (await agent.get(path)).status_code == 404
        headers = await sign_in(uses.world, human, current.scope)
        before = await snapshot(uses.world.db)
        assert (await human.get(path)).status_code == 200
        assert (await human.get(path + "/record")).status_code == 200
        assert await snapshot(uses.world.db) == before
        assert (
            await human.post(path + "/controls", json={"outcome": "completed"})
        ).status_code == 403
        minted = await human.post(
            path + "/controls", json={"outcome": "completed"}, headers=headers
        )
        assert minted.status_code == 201
        presentation = minted.json()
        token = presentation["personal_token"]
        approval_id = presentation["status"]["control"]["approval_id"]
        control_path = "/reconciliation-controls/" + approval_id
        root = "/reconciliation-approvals"
        before = await snapshot(uses.world.db)
        assert (await human.get(root)).status_code == 200
        assert (await human.get(control_path)).status_code == 200
        assert (await human.get(control_path + "/status")).status_code == 200
        assert await snapshot(uses.world.db) == before
        if token in (await human.get(control_path)).text:
            raise AssertionError("personal token escaped the explicit presentation response")
        premature = await human.post(control_path + "/settle", json={}, headers=headers)
        assert premature.status_code == 409
        reviewed = await ceremony(uses, human, headers, root, token)
        assert reviewed.status_code == 200
        assert reviewed.json()["control"]["outcome"] == "completed"
        assert (await uses.approvals.get(approval_id)).state is ApprovalState.PENDING
        approved = await ceremony(uses, human, headers, root, token, decision="approve")
        assert approved.status_code == 200
        assert (await uses.approvals.get(approval_id)).state is ApprovalState.APPROVED
        before = await snapshot(uses.world.db)
        await human.get(control_path)
        await human.get(control_path + "/status")
        assert await snapshot(uses.world.db) == before
        run.available[0] = False
        settled = await human.post(control_path + "/settle", json={}, headers=headers)
        assert settled.status_code == 200
        assert settled.json()["state"] == "reconciled_completed"
        assert (await uses.approvals.get(approval_id)).state is ApprovalState.CONSUMED
        if run.credential in settled.text:
            raise AssertionError("credential escaped the settlement receipt")
        before = await snapshot(uses.world.db)
        await human.get(path)
        await human.get(control_path)
        assert await snapshot(uses.world.db) == before


async def test_personal_locator_returns_only_hint_and_another_owner_cannot_decide_or_settle(uses):
    async with clients(uses) as (human, _, _, original, current):
        headers = await sign_in(uses.world, human, current.scope)
        minted = await human.post(
            "/reconciliations/" + original.original.reconcile_ref + "/controls",
            json={"outcome": "unknown-closed"},
            headers=headers,
        )
        assert minted.status_code == 201
        token = minted.json()["personal_token"]
        approval_id = minted.json()["status"]["control"]["approval_id"]
        human.cookies.clear()
        hint = await human.post("/reconciliation-approvals/sign-in", json={"token": token})
        assert hint.status_code == 200 and hint.json() == {"scope": current.scope}
        bob = await enrol_owner(uses.world, BOB, "bob@acme.com")
        headers = await sign_in(uses.world, human, bob, "bob@acme.com")
        before = await snapshot(uses.world.db)
        assert (await human.get("/reconciliation-controls/" + approval_id)).status_code == 403
        denied = await human.post(
            "/reconciliation-approvals/decision-options",
            json={"token": token, "decision": "approve"},
            headers=headers,
        )
        assert denied.status_code == 403
        denied = await human.post(
            "/reconciliation-controls/" + approval_id + "/settle", json={}, headers=headers
        )
        assert denied.status_code == 403
        assert await snapshot(uses.world.db) == before

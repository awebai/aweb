"""Use/run console decisions through real PostgreSQL, S4, B2 and B3."""

from contextlib import asynccontextmanager
from copy import deepcopy

import httpx
import pytest
from aweb_naapp.console import CONSOLE_HEADERS, apply_console_migrations
from aweb_naapp.runtime.approvals import ApprovalState
from aweb_naapp.runtime.origins import split_origins
from aweb_naapp_testing.owner_acts import INSTALLATION_ID
from fastapi import FastAPI

from aweb_secrets.console import OwnerConsole, owner_console_router
from aweb_secrets.console_ui import console_ui_router
from aweb_secrets.console_use_approvals import (
    ConsoleUseApprovals,
    console_run_approvals_router,
    console_use_approvals_router,
)
from tests.test_change_sets import ORIGIN, TEAM, world  # noqa: F401
from tests.test_console import API
from tests.test_console_changes import sign_in
from tests.test_run_approvals import plan_for
from tests.test_run_approvals import request as request_run
from tests.test_use_approvals import designate, install, request
from tests.test_use_approvals import uses as _uses

uses = _uses


async def application(uses, *, origin=ORIGIN, agent_origin=API):
    w = uses.world
    await apply_console_migrations(w.db)

    async def installation(installation_id):
        if installation_id != INSTALLATION_ID:
            raise LookupError(installation_id)
        return w.admitted

    console = OwnerConsole(
        db=w.db,
        passkeys=w.passkeys,
        directory=w.directory,
        fence=w.fence,
        verifier=w.owner.verifier,
        installation=installation,
    )
    app = FastAPI()
    app.include_router(owner_console_router(console))
    app.include_router(console_ui_router(sessions=console.sessions))
    services = ConsoleUseApprovals(console=console, approvals=uses.approvals)
    app.include_router(console_use_approvals_router(services=services))
    app.include_router(console_run_approvals_router(services=services))
    return split_origins(FastAPI(), app, human_origin=origin, agent_origin=agent_origin)


@asynccontextmanager
async def clients(uses):
    app = await application(uses)
    async with (
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=ORIGIN) as human,
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=API) as agent,
    ):
        yield human, agent


async def pending_use(uses):
    await designate(uses, "finance", "finance@acme.com")
    await install(uses)
    _, _, pending = await request(uses, reason='</pre><img src=x onerror="alert(1)">')
    approval_id = pending.pending.approval.approval_id
    [(actual_id, token)] = uses.world.inbox.links["finance@acme.com"]
    assert actual_id == approval_id
    [candidate] = (await uses.approvals.get(approval_id)).candidates
    return approval_id, token, candidate.scope


@pytest.mark.parametrize("decision", ["approve", "reject"])
async def test_view_and_decision_are_separate_fresh_passkey_ceremonies(uses, decision):
    approval_id, token, scope = await pending_use(uses)
    async with clients(uses) as (human, agent):
        root = "/use-approvals"
        for path in (root, "/run-approvals", "/console-use-approvals/approvals.js"):
            response = await human.get(path)
            assert response.status_code == 200
            for name, value in CONSOLE_HEADERS.items():
                assert response.headers[name] == value
            assert (await agent.get(path)).status_code == 404
        hint = await human.post(root + "/sign-in", json={"token": token})
        assert hint.status_code == 200 and hint.json() == {"scope": scope}
        assert (await human.post(root + "/view-options", json={"token": token})).status_code == 401
        headers = await sign_in(uses.world, human, scope, "finance@acme.com")
        assert (await human.post(root + "/view-options", json={"token": token})).status_code == 403
        options = await human.post(root + "/view-options", json={"token": token}, headers=headers)
        assert options.status_code == 200
        proof = uses.world.devices["finance@acme.com"].get(options.json())
        shown = await human.post(
            root + "/view", json={"token": token, "assertion": proof}, headers=headers
        )
        assert shown.status_code == 200
        assert shown.json()["view"]["secret_ref"] == "staging-api"
        assert shown.json()["view"]["open_request"]["body_text"]
        assert shown.json()["approval_id"] == approval_id
        assert (await uses.approvals.get(approval_id)).state is ApprovalState.PENDING
        # A VIEW proof cannot decide, even when the candidate and link match.
        refused = await human.post(
            root + "/decide",
            json={"token": token, "decision": decision, "assertion": proof},
            headers=headers,
        )
        assert refused.status_code == 409
        options = await human.post(
            root + "/decision-options", json={"token": token, "decision": decision}, headers=headers
        )
        assert options.status_code == 200
        result = await human.post(
            root + "/decide",
            json={
                "token": token,
                "decision": decision,
                "assertion": uses.world.devices["finance@acme.com"].get(options.json()),
            },
            headers=headers,
        )
        assert result.status_code == 200
        expected = ApprovalState.APPROVED if decision == "approve" else ApprovalState.REJECTED
        approved = await uses.approvals.get(approval_id)
        assert approved.state is expected and approved.consumed_operation_id is None
        assert result.json() == {"approval_id": approval_id, "state": expected.value}
        assert (
            await human.post(
                root + "/decision-options",
                json={"token": token, "decision": decision},
                headers=headers,
            )
        ).status_code == 409
        await human.get(root)
        assert (await uses.approvals.get(approval_id)).consumed_operation_id is None


async def test_personal_link_cannot_be_used_by_another_session_or_router(uses):
    approval_id, token, scope = await pending_use(uses)
    async with clients(uses) as (human, _):
        from aweb_secrets.owners import owner_scope
        from tests.test_change_sets import ALICE

        owner = owner_scope(INSTALLATION_ID, TEAM, ALICE.principal_did)
        headers = await sign_in(uses.world, human, owner)
        response = await human.post(
            "/use-approvals/view-options", json={"token": token}, headers=headers
        )
        assert response.status_code == 403
        headers = await sign_in(uses.world, human, scope, "finance@acme.com")
        assert (
            await human.post("/run-approvals/sign-in", json={"token": token})
        ).status_code == 404
        assert (
            await human.post("/run-approvals/view-options", json={"token": token}, headers=headers)
        ).status_code == 404
        assert (await uses.approvals.get(approval_id)).state is ApprovalState.PENDING


async def test_run_view_uses_immutable_slot_plan_after_b2_authentication(uses):
    plan = await plan_for(uses, delivery="durable")
    pending = await request_run(uses, plan)
    approval_id = pending[0].pending.approval.approval_id
    token = next(t for a, t in uses.world.inbox.links["finance@acme.com"] if a == approval_id)
    [candidate] = (await uses.approvals.get(approval_id)).candidates
    async with clients(uses) as (human, _):
        headers = await sign_in(uses.world, human, candidate.scope, "finance@acme.com")
        options = await human.post(
            "/run-approvals/view-options", json={"token": token}, headers=headers
        )
        shown = await human.post(
            "/run-approvals/view",
            json={
                "token": token,
                "assertion": uses.world.devices["finance@acme.com"].get(options.json()),
            },
            headers=headers,
        )
        assert shown.status_code == 200
        job = shown.json()["view"]["job"]
        assert job["plan_digest"] == plan.digest
        assert job["slot_ordinal"] == 0
        assert job["frozen_plan"] == plan.body
        assert job["credential_delivery"] == "durable"
        assert (await uses.approvals.get(approval_id)).consumed_operation_id is None


async def test_f6_expiring_during_decision_lock_wait_rolls_back_decision(uses):
    import asyncio

    approval_id, token, scope = await pending_use(uses)
    w = uses.world
    async with clients(uses) as (human, _):
        headers = await sign_in(w, human, scope, "finance@acme.com")
        options = await human.post(
            "/use-approvals/decision-options",
            json={"token": token, "decision": "approve"},
            headers=headers,
        )
        proof = w.devices["finance@acme.com"].get(options.json())
        await w.db.execute(
            "UPDATE {{tables.installation_fences}} SET fresh_until=clock_timestamp()+interval '2 seconds'"
        )
        posting = None
        try:
            async with w.db.transaction() as gate:
                pid = await gate.fetch_value("SELECT pg_backend_pid()")
                await gate.fetch_value(
                    "SELECT approval_id FROM {{tables.approvals}} WHERE approval_id=$1 FOR UPDATE",
                    approval_id,
                )
                posting = asyncio.create_task(
                    human.post(
                        "/use-approvals/decide",
                        json={"token": token, "decision": "approve", "assertion": proof},
                        headers=headers,
                    )
                )
                async with asyncio.timeout(5):
                    while not await w.db.fetch_value(
                        "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)))",
                        pid,
                    ):
                        if posting.done():
                            await posting
                            pytest.fail("decision did not reach its approval lock")
                        await asyncio.sleep(0.01)
                    while await w.db.fetch_value(
                        "SELECT fresh_until>clock_timestamp() FROM {{tables.installation_fences}}"
                    ):
                        await asyncio.sleep(0.02)
            response = await asyncio.wait_for(posting, 5)
            assert response.status_code == 503
        finally:
            if posting is not None:
                if not posting.done():
                    posting.cancel()
                await asyncio.gather(posting, return_exceptions=True)
        assert (await uses.approvals.get(approval_id)).state is ApprovalState.PENDING


def test_open_request_projection_keeps_unicode_and_alabel_host_and_full_body():
    from aweb_secrets.console_use_approvals import _projection
    from aweb_secrets.use_approval import use_approval_view
    from tests.test_use_approval_view import _request

    request = deepcopy(_request("broker-open-request"))
    request["broker"]["canonical_url"] = "https://xn--bcher-kva.example/v1/refunds"
    projected = _projection(use_approval_view(request))
    assert projected["open_request"]["host"] == "xn--bcher-kva.example"
    assert projected["open_request"]["host_unicode"] == "bücher.example"
    assert projected["open_request"]["body_text"] == request["broker"]["body_preview"]

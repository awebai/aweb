"""Human-only narrowing through the shared S4/B3/F6 and PostgreSQL services."""

import asyncio
import json
from contextlib import asynccontextmanager

import httpx
import pytest
from aweb_naapp.console import apply_console_migrations
from aweb_naapp.hooks.envelope import verify
from aweb_naapp.runtime.origins import split_origins
from aweb_naapp.runtime.passkeys import PasskeyInstallationContext
from aweb_naapp_testing.owner_acts import INSTALLATION_ID
from fastapi import FastAPI

from aweb_secrets.console import OwnerConsole, owner_console_router
from aweb_secrets.containment_routes import containment_console_router
from aweb_secrets.owners import owner_scope
from tests.test_change_sets import ALICE, ORIGIN, TEAM, world  # noqa: F401
from tests.test_console import API, login
from tests.test_containment_service import service
from tests.test_use_approval_lineage import seed
from tests.test_use_approvals import SECRET_ID
from tests.test_use_approvals import uses as uses  # noqa: F401

PATH = f"/installations/{INSTALLATION_ID}/containment"
BODY = {"request_id": "console-disable", "action": "disable-secret", "target": SECRET_ID}


@asynccontextmanager
async def clients(context, *, lookup=None):
    w = context.world
    await apply_console_migrations(w.db)

    async def installation(installation_id, *, team_id: str | None = None):
        if installation_id != INSTALLATION_ID:
            raise LookupError(installation_id)
        if lookup is not None:
            await lookup()
        return w.admitted

    console = OwnerConsole(
        db=w.db,
        passkeys=w.passkeys,
        directory=w.directory,
        fence=w.fence,
        verifier=w.owner.verifier,
        installation=installation,
    )
    svc = await service(context)
    human_app = FastAPI()
    human_app.include_router(owner_console_router(console))
    human_app.include_router(containment_console_router(svc, console=console))
    app = split_origins(FastAPI(), human_app, agent_origin=API, human_origin=ORIGIN)
    async with (
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=ORIGIN) as human,
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=API) as agent,
    ):
        yield human, agent, svc


@pytest.mark.parametrize("stalled", [False, True])
async def test_console_containment_commits_with_login_proof_despite_audit_availability(
    uses, stalled
):
    from tests.test_containment_service import act

    await seed(uses)
    w = uses.world
    async with clients(uses) as (human, agent, svc):
        if stalled:
            await act(svc, uses, "disable-installation", None, "earlier-event")
            event_id = await w.db.fetch_value("SELECT event_id FROM {{tables.outbox_events}}")
            await w.db.execute(
                "INSERT INTO {{tables.outbox_deliveries}} (event_id,target_id,state,attempts)"
                " VALUES ($1,'stalled-target','stalled',40)",
                event_id,
            )
        logged = await login(w, human, owner_scope(INSTALLATION_ID, TEAM, ALICE.principal_did))
        headers = {"X-CSRF-Token": logged.json()["csrf_token"]}
        response = await human.post(PATH, json=BODY, headers=headers)
        assert response.status_code == 200
        assert response.json()["affected_secret_ids"] == [SECRET_ID]
        assert response.headers["cache-control"] == "no-store"
        assert (await agent.post(PATH, json=BODY, headers=headers)).status_code == 404
        # Retry returns the original effect, with one governance event.
        assert (await human.post(PATH, json=BODY, headers=headers)).json() == response.json()
    assert (
        await w.db.fetch_value("SELECT state FROM {{tables.secrets}} WHERE secret_id=$1", SECRET_ID)
        == "disabled"
    )
    rows = await w.db.fetch_all(
        "SELECT payload,signature FROM {{tables.outbox_events}} ORDER BY position"
    )
    assert len(rows) == (2 if stalled else 1)
    row = rows[-1]
    event = verify(bytes(row["payload"]), row["signature"], team_id=TEAM).fields
    assert event["actor"] == {"authority_mode": "system", "attestations": []}
    assert event["payload"]["authority"] == "passkey_session"
    session = await w.db.fetch_one(
        "SELECT scope,subject,evidence_ref FROM {{tables.console_sessions}}"
    )
    expected = await w.passkeys.evidence_commitment(
        session["evidence_ref"],
        context=PasskeyInstallationContext(
            w.admitted.app_id,
            TEAM,
            INSTALLATION_ID,
            w.admitted.generation,
        ),
        scope=session["scope"],
        subject=session["subject"],
        purpose="login",
    )
    assert event["payload"]["approval_evidence_sha256"] == expected
    assert session["scope"] not in json.dumps(event)
    assert session["subject"] not in json.dumps(event)


@pytest.mark.parametrize(
    "action", ["revoke-grant", "revoke-approvals", "disable-installation", "revoke-approver"]
)
async def test_console_narrowing_routes_share_the_real_containment_actions(uses, action):
    from tests.test_use_approvals import request

    grant_id = await seed(uses)
    w = uses.world
    target = grant_id
    if action == "revoke-approvals":
        _, _, pending = await request(uses)
        target = pending.pending.approval.approval_id
    elif action == "revoke-approver":
        target = "finance"
    body = {"request_id": "console-action", "action": action}
    if action != "disable-installation":
        body["target"] = target
    async with clients(uses) as (human, _, _):
        logged = await login(w, human, owner_scope(INSTALLATION_ID, TEAM, ALICE.principal_did))
        response = await human.post(
            PATH, json=body, headers={"X-CSRF-Token": logged.json()["csrf_token"]}
        )
        assert response.status_code == 200
    if action == "revoke-grant":
        assert await w.db.fetch_value(
            "SELECT revoked_at IS NOT NULL FROM {{tables.grants}} WHERE grant_id=$1", target
        )
    elif action == "revoke-approvals":
        assert (await uses.approvals.get(target)).state.value == "revoked"
    elif action == "revoke-approver":
        assert not await w.db.fetch_value(
            "SELECT EXISTS(SELECT 1 FROM {{tables.approvers}} WHERE approver_ref='finance')"
        )
    else:
        assert await w.db.fetch_value(
            "SELECT disabled_at IS NOT NULL FROM {{tables.containment_installations}}"
        )
    assert await w.db.fetch_value("SELECT count(*) FROM {{tables.outbox_events}}") == 1


async def test_console_containment_requires_session_csrf_and_exact_request_shape(uses):
    await seed(uses)
    w = uses.world
    async with clients(uses) as (human, _, _):
        assert (await human.post(PATH, json=BODY)).status_code == 401
        logged = await login(w, human, owner_scope(INSTALLATION_ID, TEAM, ALICE.principal_did))
        assert (await human.post(PATH, json=BODY)).status_code == 403
        headers = {"X-CSRF-Token": logged.json()["csrf_token"]}
        assert (
            await human.post(PATH, json={**BODY, "team_id": TEAM}, headers=headers)
        ).status_code == 400
        assert (
            await human.post(PATH, json={**BODY, "action": "reenable"}, headers=headers)
        ).status_code == 400
    assert await w.db.fetch_value("SELECT count(*) FROM {{tables.outbox_events}}") == 0


@pytest.mark.parametrize("member", [False, True])
async def test_final_f6_check_rolls_back_effect_and_outbox_after_awaited_writes(uses, member):
    from aweb_naapp.runtime.installation import InstallationRefused

    from tests.test_containment_service import act

    await seed(uses)
    w = uses.world
    # A real local database transition during the action's final awaited write.
    # It rolls back with the effect when the final live fence check refuses.
    await w.db.execute(
        "CREATE FUNCTION expire_containment_fence() RETURNS trigger LANGUAGE plpgsql AS $$ "
        "BEGIN UPDATE {{tables.installation_fences}} SET fresh_until=clock_timestamp()-interval '1 second'; "
        "RETURN NEW; END $$"
    )
    await w.db.execute(
        "CREATE TRIGGER expire_containment_fence BEFORE INSERT ON {{tables.containment_receipts}} "
        "FOR EACH ROW EXECUTE FUNCTION expire_containment_fence()"
    )
    async with clients(uses) as (human, _, svc):
        if member:
            with pytest.raises(InstallationRefused):
                await act(svc, uses)
        else:
            logged = await login(w, human, owner_scope(INSTALLATION_ID, TEAM, ALICE.principal_did))
            response = await human.post(
                PATH, json=BODY, headers={"X-CSRF-Token": logged.json()["csrf_token"]}
            )
            assert response.status_code in {409, 503}
    assert await w.db.fetch_value("SELECT count(*) FROM {{tables.outbox_events}}") == 0
    assert await w.db.fetch_value("SELECT count(*) FROM {{tables.containment_receipts}}") == 0
    assert (
        await w.db.fetch_value("SELECT state FROM {{tables.secrets}} WHERE secret_id=$1", SECRET_ID)
        == "active"
    )


@pytest.mark.parametrize("change", ["proof", "key", "generation", "expired"])
async def test_console_rechecks_login_and_admitted_context_after_request_entry(uses, change):
    await seed(uses)
    w = uses.world

    async def withdraw():
        if change == "proof":
            await w.db.execute("DELETE FROM {{tables.passkey_proofs}}")
        elif change == "key":
            await w.db.execute(
                "UPDATE {{tables.passkey_credentials}} SET revoked_at=NOW() WHERE subject IN "
                "(SELECT subject FROM {{tables.console_sessions}})"
            )
        elif change == "generation":
            await w.db.execute("UPDATE {{tables.installation_fences}} SET generation=generation+1")
        else:
            await w.db.execute(
                "UPDATE {{tables.installation_fences}} SET fresh_until=clock_timestamp()-interval '1 second'"
            )

    async with clients(uses, lookup=withdraw) as (human, _, _):
        logged = await login(w, human, owner_scope(INSTALLATION_ID, TEAM, ALICE.principal_did))
        response = await human.post(
            PATH, json=BODY, headers={"X-CSRF-Token": logged.json()["csrf_token"]}
        )
        assert response.status_code in {401, 409, 503}
    assert await w.db.fetch_value("SELECT count(*) FROM {{tables.outbox_events}}") == 0
    assert (
        await w.db.fetch_value("SELECT state FROM {{tables.secrets}} WHERE secret_id=$1", SECRET_ID)
        == "active"
    )


async def test_logout_during_installation_lookup_refuses_the_inflight_action(uses):
    await seed(uses)
    w = uses.world
    entered = asyncio.Event()
    resume = asyncio.Event()

    async def paused_lookup():
        entered.set()
        await resume.wait()

    async with clients(uses, lookup=paused_lookup) as (human, _, _):
        logged = await login(w, human, owner_scope(INSTALLATION_ID, TEAM, ALICE.principal_did))
        headers = {"X-CSRF-Token": logged.json()["csrf_token"]}
        action = asyncio.create_task(human.post(PATH, json=BODY, headers=headers))
        try:
            await asyncio.wait_for(entered.wait(), 5)
            logged_out = await human.post("/logout", headers=headers)
            assert logged_out.status_code == 200
            resume.set()
            response = await asyncio.wait_for(action, 5)
            assert response.status_code == 401
        finally:
            resume.set()
            if not action.done():
                action.cancel()
            await asyncio.gather(action, return_exceptions=True)
    assert await w.db.fetch_value("SELECT count(*) FROM {{tables.containment_receipts}}") == 0
    assert await w.db.fetch_value("SELECT count(*) FROM {{tables.outbox_events}}") == 0
    assert (
        await w.db.fetch_value("SELECT state FROM {{tables.secrets}} WHERE secret_id=$1", SECRET_ID)
        == "active"
    )


async def test_final_session_check_rolls_back_effect_after_awaited_action_work(uses):
    await seed(uses)
    w = uses.world
    await w.db.execute(
        "CREATE FUNCTION close_containment_session() RETURNS trigger LANGUAGE plpgsql AS $$ "
        "BEGIN UPDATE {{tables.console_sessions}} SET closed_at=clock_timestamp(); "
        "RETURN NEW; END $$"
    )
    async with clients(uses) as (human, _, _):
        await w.db.execute(
            "CREATE TRIGGER close_containment_session BEFORE INSERT ON {{tables.containment_receipts}} "
            "FOR EACH ROW EXECUTE FUNCTION close_containment_session()"
        )
        logged = await login(w, human, owner_scope(INSTALLATION_ID, TEAM, ALICE.principal_did))
        response = await human.post(
            PATH, json=BODY, headers={"X-CSRF-Token": logged.json()["csrf_token"]}
        )
        assert response.status_code == 401
    assert await w.db.fetch_value("SELECT count(*) FROM {{tables.containment_receipts}}") == 0
    assert await w.db.fetch_value("SELECT count(*) FROM {{tables.outbox_events}}") == 0
    assert (
        await w.db.fetch_value("SELECT state FROM {{tables.secrets}} WHERE secret_id=$1", SECRET_ID)
        == "active"
    )

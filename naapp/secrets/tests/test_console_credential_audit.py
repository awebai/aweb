"""Real HTTP B3 callers retain the original authority and atomic signed audit."""

import base64
import hashlib
from contextlib import asynccontextmanager

import httpx
from aweb_naapp.console import apply_console_migrations
from aweb_naapp.runtime.approvals import ApprovalState
from aweb_naapp_testing.owner_acts import INSTALLATION_ID
from aweb_naapp_testing.webauthn import SoftAuthenticator
from fastapi import FastAPI

from aweb_secrets.change_sets import ChangeSets
from aweb_secrets.console import OwnerConsole, owner_console_router
from aweb_secrets.console_changes import ConsoleChanges, console_changes_router
from aweb_secrets.owners import owner_scope
from tests.test_change_sets import (
    ALICE,
    ORIGIN,
    TEAM,
    by_member,
    change_set,
    designate_approver,
    enrol_owner,
)
from tests.test_change_sets import world as world
from tests.test_console_changes import ROOT, Registrations, approve, sign_in
from tests.test_credential_audit import audit_for, events


@asynccontextmanager
async def client(w, audit):
    await apply_console_migrations(w.db)

    async def installation(installation_id, *, team_id=None):
        assert installation_id == INSTALLATION_ID
        return w.admitted

    console = OwnerConsole(
        db=w.db,
        passkeys=w.passkeys,
        directory=w.directory,
        fence=w.fence,
        verifier=w.owner.verifier,
        installation=installation,
        credential_audit=audit,
    )
    writer = ChangeSets(
        w.db,
        approvals=w.approvals,
        passkeys=w.passkeys,
        directory=w.directory,
        custody=w.custody,
        containment=w.containment,
        credential_audit=audit,
        draft_limit=w.change_sets._draft_limit,
        internal_destinations=w.change_sets._internal_destinations,
    )

    async def cleanup(installation_id, team_id, ids):
        await w.containment.evict(installation_id, team_id, ids)

    changes = ConsoleChanges(
        console=console,
        changes=writer,
        approvals=w.approvals,
        registrations=Registrations(),
        after_commit=cleanup,
    )
    app = FastAPI()
    app.include_router(owner_console_router(console))
    app.include_router(console_changes_router(changes))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=ORIGIN) as human:
        yield human, writer


async def bootstrap(w, human, contact="owner@example.com"):
    scope = owner_scope(INSTALLATION_ID, TEAM, ALICE.principal_did)
    subject = {
        "app_id": w.admitted.app_id,
        "installation_id": INSTALLATION_ID,
        "role": scope,
        "contact_sha256": hashlib.sha256(contact.encode()).hexdigest(),
    }
    signing, signature = w.owner.sign("app-role.designate", subject)
    response = await human.post(
        f"/installations/{INSTALLATION_ID}/owner-acts",
        json={
            "signing": base64.b64encode(signing).decode(),
            "signature": signature,
            "team_id": TEAM,
            "principal": ALICE.principal_did,
            "contact": contact,
        },
    )
    assert response.status_code == 200, response.text
    return w.inbox.enrolments[contact][-1], hashlib.sha256(signing).hexdigest()


async def enrol(human, token, device):
    options = await human.post("/enrolment/options", json={"link_token": token})
    assert options.status_code == 200
    return await human.post(
        "/enrolment",
        json={
            "link_token": token,
            "credential": device.create(options.json()),
        },
    )


async def test_bootstrap_and_enrolment_http_preserve_original_owner_act(world):
    audit = await audit_for(world)
    async with client(world, audit) as (human, _):
        token, commitment = await bootstrap(world, human)
        response = await enrol(human, token, SoftAuthenticator(ORIGIN))
        assert response.status_code == 200, response.text
        recorded = await events(world)
        assert [e["payload"]["act"] for e in recorded] == ["role.designated", "credential.enrolled"]
        assert all(e["payload"]["owner_act_sha256"] == commitment for e in recorded)
        assert token not in str(recorded)
        assert (
            await human.post("/enrolment/options", json={"link_token": token})
        ).status_code == 403


async def test_enrolment_http_target_refusal_rolls_back_and_fresh_ceremony_retries(world):
    from tests.test_credential_audit import target

    available = True

    async def registration(team_id):
        return target() if available else None

    audit = await audit_for(world, registration_view=registration)
    async with client(world, audit) as (human, _):
        token, _ = await bootstrap(world, human)
        available = False
        device = SoftAuthenticator(ORIGIN)
        refused = await enrol(human, token, device)
        assert refused.status_code == 503
        assert refused.json() == {"detail": "audit_target_unavailable"}
        assert (
            await world.db.fetch_value("SELECT count(*) FROM {{tables.passkey_credentials}}") == 0
        )
        assert (
            await world.db.fetch_value(
                "SELECT count(*) FROM {{tables.passkey_enrolments}} WHERE used_at IS NOT NULL"
            )
            == 0
        )
        assert len(await events(world)) == 1
        available = True
        assert (await enrol(human, token, device)).status_code == 200
        assert len(await events(world)) == 2


async def test_real_http_confirmation_prepares_actual_owner_approval_for_b3(world):
    scope = await enrol_owner(world, ALICE, "alice@acme.com")
    audit = await audit_for(world)
    async with client(world, audit) as (human, writer):
        request = change_set(
            drafter=by_member(ALICE),
            changes=[
                designate_approver("finance", "finance@example.com", ["sec_19ab42"]),
            ],
        )
        async with world.db.transaction() as tx:
            pending = await writer.draft(tx, request)
        await world.approvals.deliver(pending)
        draft = {"approval_id": pending.approval.approval_id, "change_id": request["change_id"]}
        headers = await sign_in(world, human, scope)
        await approve(world, human, headers, draft)
        result = await human.post(
            ROOT + "/" + request["change_id"] + "/confirm", json={}, headers=headers
        )
        assert result.status_code == 200, result.text
        assert result.json()["state"] == "applied"
        approval = await world.approvals.get(draft["approval_id"])
        assert approval.state is ApprovalState.CONSUMED
        [event] = await events(world)
        assert event["payload"]["act"] == "role.designated"
        assert event["payload"]["approval_id"] == draft["approval_id"]
        token = world.inbox.enrolments["finance@example.com"][-1]
        assert (await enrol(human, token, SoftAuthenticator(ORIGIN))).status_code == 200
        assert [e["payload"]["act"] for e in await events(world)] == [
            "role.designated",
            "credential.enrolled",
        ]

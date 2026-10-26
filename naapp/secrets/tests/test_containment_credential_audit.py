"""Actual containment callers retain B3 authority and emit each effect once."""

import base64
from contextlib import asynccontextmanager
from functools import partial
from uuid import uuid4

import httpx
import pytest
from aweb_naapp.console import apply_console_migrations
from aweb_naapp.idempotency import apply_idempotency_migrations
from aweb_naapp.roles import assign, principal_key
from aweb_naapp.runtime.installation import InstallationRefused
from fastapi import FastAPI

from aweb_secrets.console import OwnerConsole, owner_console_router
from aweb_secrets.containment import ContainmentRefused
from aweb_secrets.containment_routes import containment_console_router
from aweb_secrets.owners import OWNER_ROLE, owner_scope
from tests.test_change_sets import ALICE, ORIGIN, TEAM
from tests.test_containment_console import login_session, sibling_session
from tests.test_credential_audit import audit_for, events
from tests.test_credential_narrowing import enrolled_target
from tests.test_credential_narrowing import world as world
from tests.test_use_approvals import REQUESTER


async def caller(world, audit, *, owner=True):
    # Compose the fixture's real service with the SAME B3 sink and producer.
    await apply_idempotency_migrations(world.db)
    service = world.containment
    service.credential_audit = world.credential_audit
    producer = audit._producer(
        installation_id=world.admitted.installation_id, generation=world.admitted.generation
    )
    service.governance = partial(producer.enqueue, hook="post-governance-hook")
    if owner:
        async with world.db.transaction() as tx:
            await assign(tx, principal_key(REQUESTER), OWNER_ROLE)
    return service


async def revoke(world, service, request_id, credential_id=None):
    return await service.by_member(
        grant=await world.fence.grants.grant_for(TEAM),
        principal=REQUESTER,
        request_id=request_id,
        action="revoke-approver",
        target="finance",
        credential_id=credential_id,
        signed_trace_id=request_id,
    )


async def key_for(world, approver, device, effect):
    if effect == "partial":
        session = await login_session(world, approver.scope, device)
        await sibling_session(world, session)
    return None if effect == "designation" else next(iter(device.credentials))


def expected_acts(effect):
    if effect == "designation":
        return ["role.revoked"]
    if effect == "partial":
        return ["credential.revoked"]
    return ["role.revoked", "credential.revoked"]


@pytest.mark.parametrize("effect", ["designation", "partial", "last-key"])
@pytest.mark.parametrize("stalled", [False, True])
async def test_member_keeps_original_authority_without_duplicate_or_audit_target(
    world, effect, stalled
):
    audit, approver, device = await enrolled_target(world)
    credential_id = await key_for(world, approver, device, effect)

    async def unavailable(team_id):
        raise AssertionError("containment cannot require a current audit target")

    audit = await audit_for(world, registration_view=unavailable, shared_producer=audit._producer)
    if stalled:
        await world.db.execute(
            "INSERT INTO {{tables.outbox_deliveries}} (event_id,target_id,state,attempts)"
            " SELECT event_id,'stalled-target','stalled',40 FROM {{tables.outbox_events}}"
        )
    service = await caller(world, audit)
    before = len(await events(world))
    request_id = uuid4().hex
    result = await revoke(world, service, request_id, credential_id)
    assert await revoke(world, service, request_id, credential_id) == result
    recorded = await events(world)
    assert [item["payload"]["act"] for item in recorded[before:]] == expected_acts(effect)
    for item in recorded[before:]:
        assert item["payload"]["authority"] == "team_cert"
        assert item["actor"]["did_key"] == REQUESTER.did_key
        assert item["actor"]["certificate_id"] == REQUESTER.certificate_id
        assert item["trace"] == {"id": request_id, "origin": "signed_request"}
    assert (await world.passkeys.designated_approver(approver.scope) is None) is (
        effect != "partial"
    )
    assert await world.db.fetch_value("SELECT count(*) FROM {{tables.containment_receipts}}") == 1
    assert await world.db.fetch_value(
        "SELECT count(*) FROM {{tables.credential_narrowing_authority}}"
    ) == len(expected_acts(effect))


@asynccontextmanager
async def human_client(world, service, audit):
    await apply_console_migrations(world.db)

    async def installation(installation_id, *, team_id=None):
        assert installation_id == world.admitted.installation_id
        return world.admitted

    console = OwnerConsole(
        db=world.db,
        passkeys=world.passkeys,
        directory=world.directory,
        fence=world.fence,
        verifier=world.owner.verifier,
        installation=installation,
        credential_audit=audit,
    )
    app = FastAPI()
    app.include_router(owner_console_router(console))
    app.include_router(containment_console_router(service, console=console))
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, raise_app_exceptions=False), base_url=ORIGIN
    ) as client:
        yield client


async def login(world, human, scope):
    options = await human.post("/login/options", json={"scope": scope})
    assert options.status_code == 200
    response = await human.post(
        "/login",
        json={"scope": scope, "assertion": world.devices["owner@example.com"].get(options.json())},
    )
    assert response.status_code == 200
    return response


@pytest.mark.parametrize("effect", ["designation", "partial", "last-key"])
async def test_human_route_uses_retained_login_for_only_the_canonical_b3_effects(world, effect):
    audit, approver, device = await enrolled_target(world)
    credential_id = await key_for(world, approver, device, effect)
    service = await caller(world, audit)
    path = f"/installations/{world.admitted.installation_id}/containment"
    body = {"request_id": uuid4().hex, "action": "revoke-approver", "target": "finance"}
    if credential_id is not None:
        body["credential_id"] = base64.urlsafe_b64encode(credential_id).decode().rstrip("=")
    before = len(await events(world))
    scope = owner_scope(world.admitted.installation_id, TEAM, ALICE.principal_did)
    async with human_client(world, service, audit) as human:
        logged = await login(world, human, scope)
        headers = {"X-CSRF-Token": logged.json()["csrf_token"]}
        response = await human.post(path, json=body, headers=headers)
        assert response.status_code == 200
        assert (await human.post(path, json=body, headers=headers)).json() == response.json()
    recorded = await events(world)
    assert [item["payload"]["act"] for item in recorded[before:]] == expected_acts(effect)
    retained = await world.db.fetch_all(
        "SELECT commitment,retained_proof FROM {{tables.credential_narrowing_authority}}"
    )
    assert len(retained) == len(expected_acts(effect))
    for item, authority in zip(recorded[before:], retained, strict=True):
        assert item["actor"] == {"authority_mode": "system", "attestations": []}
        assert item["payload"]["authority"] == "passkey_session"
        assert item["payload"]["approval_evidence_sha256"] == authority["commitment"]
        assert authority["retained_proof"] is not None
    assert await world.db.fetch_value("SELECT count(*) FROM {{tables.containment_receipts}}") == 1


async def test_final_fence_failure_rolls_back_effect_canonical_receipt_and_idempotency(world):
    audit, approver, _ = await enrolled_target(world)
    service = await caller(world, audit)
    before = await events(world)
    await world.db.execute(
        "CREATE FUNCTION expire_narrowing_fence() RETURNS trigger LANGUAGE plpgsql AS $$ "
        "BEGIN UPDATE {{tables.installation_fences}} "
        "SET fresh_until=clock_timestamp()-interval '1 second'; RETURN NEW; END $$"
    )
    await world.db.execute(
        "CREATE TRIGGER expire_narrowing_fence AFTER INSERT ON {{tables.outbox_events}} "
        "FOR EACH ROW EXECUTE FUNCTION expire_narrowing_fence()"
    )
    with pytest.raises(InstallationRefused):
        await revoke(world, service, uuid4().hex)
    assert await world.passkeys.designated_approver(approver.scope) is not None
    assert (
        await world.db.fetch_value(
            "SELECT count(*) FROM {{tables.approvers}} WHERE scope=$1", approver.scope
        )
        == 1
    )
    assert await events(world) == before
    assert await world.db.fetch_value("SELECT count(*) FROM {{tables.containment_receipts}}") == 0
    assert (
        await world.db.fetch_value("SELECT count(*) FROM {{tables.credential_narrowing_authority}}")
        == 0
    )


async def test_audit_preparation_does_not_grant_owner_authority(world):
    audit, approver, _ = await enrolled_target(world)
    service = await caller(world, audit, owner=False)
    before = await events(world)
    with pytest.raises(ContainmentRefused, match="owner_required"):
        await revoke(world, service, uuid4().hex)
    assert await world.passkeys.designated_approver(approver.scope) is not None
    assert await events(world) == before
    assert await world.db.fetch_value("SELECT count(*) FROM {{tables.containment_receipts}}") == 0


@pytest.mark.parametrize("association", ["stale-designation", "missing-key"])
async def test_human_missing_original_association_is_503_and_rolls_back_every_effect(
    world, association
):
    audit, approver, device = await enrolled_target(world)
    service = await caller(world, audit)
    credential_id = next(iter(device.credentials))
    if association == "stale-designation":
        await world.db.execute(
            "UPDATE {{tables.credential_authorizations}} SET generation=generation+1 WHERE subject=$1",
            approver.subject,
        )
    else:
        await world.db.execute(
            "DELETE FROM {{tables.credential_completion_links}} WHERE subject=$1 AND credential_id=$2",
            approver.subject,
            credential_id,
        )
    before = await events(world)
    path = f"/installations/{world.admitted.installation_id}/containment"
    body = {"request_id": uuid4().hex, "action": "revoke-approver", "target": "finance"}
    if association == "missing-key":
        # Last-key revocation emits a role receipt before the missing key
        # association is discovered. That earlier write must also roll back.
        body["credential_id"] = base64.urlsafe_b64encode(credential_id).decode().rstrip("=")
    scope = owner_scope(world.admitted.installation_id, TEAM, ALICE.principal_did)
    async with human_client(world, service, audit) as human:
        logged = await login(world, human, scope)
        response = await human.post(
            path, json=body, headers={"X-CSRF-Token": logged.json()["csrf_token"]}
        )
    assert response.status_code == 503
    assert response.json() == {"detail": "release_context_unavailable"}
    assert await world.passkeys.designated_approver(approver.scope) is not None
    assert (
        await world.db.fetch_value(
            "SELECT revoked_at FROM {{tables.passkey_credentials}} WHERE credential_id=$1",
            credential_id,
        )
        is None
    )
    assert (
        await world.db.fetch_value(
            "SELECT count(*) FROM {{tables.approvers}} WHERE scope=$1", approver.scope
        )
        == 1
    )
    assert await events(world) == before
    assert await world.db.fetch_value("SELECT count(*) FROM {{tables.idempotency_keys}}") == 0
    assert await world.db.fetch_value("SELECT count(*) FROM {{tables.containment_receipts}}") == 0
    assert (
        await world.db.fetch_value("SELECT count(*) FROM {{tables.credential_narrowing_authority}}")
        == 0
    )

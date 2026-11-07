"""Designating and revoking readers (audit-substrate.md §B5), on real
PostgreSQL with a real AWID registry, real owner acts and a software passkey.

The owner's ``app-role.designate`` act names a pending reader slot. In one
transaction it consumes the act's nonce, claims the slot, designates the
slot's B3 holder and appends logs' own signed governance event to the team's
chain, so either all of that holds or none of it does. The owner's
``app-role.revoke`` act names a reader's scope and its current holder, and
ends the holder's designation the same way.
"""

from __future__ import annotations

import base64
import hashlib
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from uuid import uuid4

import httpx
import pytest
from aweb_naapp.console import credential_router
from aweb_naapp.hooks.envelope import verify
from aweb_naapp.hooks.strictjson import Refused
from aweb_naapp_testing.owner_acts import INSTALLATION_ID, TEAM_ID
from aweb_naapp_testing.webauthn import SoftAuthenticator
from fastapi import FastAPI
from nacl.signing import SigningKey

from aweb_logs.ledger import LogsSigner, OriginMismatch, append, verify_epoch
from aweb_logs.read_routes import reader_governance_router
from aweb_logs.readers import READER_ROLE, ReaderRefused

from .fixtures import signed_event
from .reader_world import (
    CONSOLE,
    CONTACT,
    OTHER_CONTACT,
    World,
    act_body,
    chained,
    console_headed,
    count,
    designation,
    enrolled_reader,
    holder,
    nothing_took_effect,
    outbox,
    revocation,
    slot,
    world_fixture,  # noqa: F401
)


async def test_an_owner_act_naming_a_slot_designates_its_reader_on_logs_own_chain(world: World):
    scope = await slot(world)
    signing, signature = world.owner.sign("app-role.designate", designation(scope))
    await world.designations.designate(
        signing=signing, signature=signature, scope=scope, contact=CONTACT
    )
    reader = await world.directory.reader(scope)
    assert (reader.installation_id, reader.team_id) == (INSTALLATION_ID, TEAM_ID)
    assert len(world.inbox.enrolments[CONTACT]) == 1
    [(event_id, payload, event_signature)] = await outbox(world)
    [entry] = await chained(world)
    assert entry["event_id"] == str(event_id)
    assert entry["hook"] == "post-governance-hook"
    assert entry["producer"]["kid"] == "logs-governance"
    assert entry["payload"]["act"] == "role.designated"
    holder = await world.db.fetch_value(
        "SELECT subject FROM {{tables.passkey_approvers}} WHERE scope = $1 AND superseded_at IS NULL",
        scope,
    )
    assert entry["payload"]["subject_ref"] == holder
    assert entry["payload"]["role"] == READER_ROLE
    assert entry["payload"]["owner_act_sha256"] == hashlib.sha256(signing).hexdigest()
    stored = await world.db.fetch_one(
        "SELECT signing_bytes, signature FROM {{tables.chain_events}} WHERE event_id = $1",
        event_id,
    )
    assert (bytes(stored["signing_bytes"]), stored["signature"]) == (payload, event_signature)
    report = await verify_epoch(
        world.db,
        TEAM_ID,
        1,
        receipt_keys=frozenset({world.signer.did_key}),
        checkpoint_keys=frozenset({world.signer.did_key}),
    )
    assert report["intact"] is True
    # Until logs' own delivery of the event adds its admission, delivery
    # continuity for it is unassessed rather than assumed.
    assert report["delivery"]["unassessed"] == [
        {"team_seq": 1, "reason": "binding_evidence_unavailable"}
    ]


async def test_the_designated_reader_enrols_and_logs_appends_the_enrolment(world: World):
    scope = await slot(world)
    signing, signature = world.owner.sign("app-role.designate", designation(scope))
    await world.designations.designate(
        signing=signing, signature=signature, scope=scope, contact=CONTACT
    )
    token = world.inbox.enrolments[CONTACT][-1]
    enrolment = await world.recorder.prepare_enrolment(token)
    with world.recorder.prepared(enrolment):
        await world.passkeys.complete_enrolment(
            token,
            SoftAuthenticator(CONSOLE).create(await world.passkeys.enrolment_options(token)),
            fence=enrolment,
        )
    assert [entry["payload"]["act"] for entry in await chained(world)] == [
        "role.designated",
        "credential.enrolled",
    ]


@pytest.mark.parametrize(
    "signed",
    [
        lambda scope: designation(scope, OTHER_CONTACT),
        lambda scope: {**designation(scope), "installation_id": str(uuid4())},
        lambda scope: {**designation(scope), "role": "logs.reader." + "0" * 32},
    ],
    ids=["another contact", "another installation", "another slot"],
)
async def test_an_act_that_does_not_name_the_slot_exactly_designates_nobody(world: World, signed):
    scope = await slot(world)
    signing, signature = world.owner.sign("app-role.designate", signed(scope))
    with pytest.raises(ReaderRefused):
        await world.designations.designate(
            signing=signing, signature=signature, scope=scope, contact=CONTACT
        )
    await nothing_took_effect(world, scope)


async def test_a_slot_issued_for_another_contact_designates_nobody(world: World):
    scope = await slot(world, OTHER_CONTACT)
    signing, signature = world.owner.sign("app-role.designate", designation(scope))
    with pytest.raises(ReaderRefused):
        await world.designations.designate(
            signing=signing, signature=signature, scope=scope, contact=CONTACT
        )
    await nothing_took_effect(world, scope)


async def test_an_unknown_slot_designates_nobody(world: World):
    scope = "logs.reader." + os.urandom(16).hex()
    signing, signature = world.owner.sign("app-role.designate", designation(scope))
    with pytest.raises(ReaderRefused):
        await world.designations.designate(
            signing=signing, signature=signature, scope=scope, contact=CONTACT
        )
    await nothing_took_effect(world, scope)


async def test_an_act_another_key_signed_designates_nobody(world: World):
    scope = await slot(world)
    signing, _ = world.owner.sign("app-role.designate", designation(scope))
    forged = SigningKey.generate().sign(signing).signature
    with pytest.raises(ReaderRefused):
        await world.designations.designate(
            signing=signing,
            signature=base64.b64encode(forged).decode().rstrip("="),
            scope=scope,
            contact=CONTACT,
        )
    await nothing_took_effect(world, scope)


async def test_a_replayed_act_designates_once(world: World):
    scope = await slot(world)
    signing, signature = world.owner.sign("app-role.designate", designation(scope))
    await world.designations.designate(
        signing=signing, signature=signature, scope=scope, contact=CONTACT
    )
    with pytest.raises(ReaderRefused):
        await world.designations.designate(
            signing=signing, signature=signature, scope=scope, contact=CONTACT
        )
    assert len(await chained(world)) == 1
    assert len(world.inbox.enrolments[CONTACT]) == 1


async def test_without_a_governance_registration_no_reader_is_designated(world: World):
    world.registered[0] = False
    scope = await slot(world)
    signing, signature = world.owner.sign("app-role.designate", designation(scope))
    with pytest.raises(Refused) as refused:
        await world.designations.designate(
            signing=signing, signature=signature, scope=scope, contact=CONTACT
        )
    assert refused.value.code == "audit_target_unavailable"
    await nothing_took_effect(world, scope)


async def test_when_logs_cannot_append_its_own_event_nothing_takes_effect(world: World):
    # The team's chain already belongs to another logs origin, so this
    # deployment cannot append to it: the designation must not hold either.
    other = LogsSigner(
        logs_origin="https://other-logs.example.test",
        kid="other-chain",
        signing_key=SigningKey.generate(),
    )
    signing_bytes, event_signature = signed_event("core", team_id=TEAM_ID)
    event = verify(signing_bytes, event_signature, team_id=TEAM_ID)
    await append(
        world.db,
        other,
        event=event,
        signing_bytes=signing_bytes,
        signature=event_signature,
        key_evidence={"kid": "core", "did_key": event.producer_did_key, "admissions": []},
        received_at=datetime.now(UTC),
    )
    scope = await slot(world)
    signing, signature = world.owner.sign("app-role.designate", designation(scope))
    with pytest.raises(OriginMismatch):
        await world.designations.designate(
            signing=signing, signature=signature, scope=scope, contact=CONTACT
        )
    assert await world.directory.reader(scope) is None
    assert world.inbox.enrolments == {}
    assert await count(world, "outbox_events") == 0
    assert await count(world, "owner_act_nonces") == 0
    assert len(await chained(world)) == 1


async def test_the_owner_revokes_a_reader_on_logs_own_chain(world: World):
    scope, reader = await enrolled_reader(world)
    signing, signature = world.owner.sign("app-role.revoke", revocation(scope, reader))
    await world.designations.revoke(signing=signing, signature=signature, scope=scope)
    assert await holder(world, scope) is None
    revoked = (await chained(world))[-1]
    assert revoked["payload"] == {
        "act": "role.revoked",
        "direction": "narrowing",
        "role": READER_ROLE,
        "subject_ref": reader,
        "authority": "owner_act",
        "owner_act_sha256": hashlib.sha256(signing).hexdigest(),
    }
    assert (
        await world.directory.current_readers(installation_id=INSTALLATION_ID, team_id=TEAM_ID)
        == []
    )


async def test_the_owner_may_revoke_the_last_reader(world: World):
    scope, reader = await enrolled_reader(world)
    assert [
        r.scope
        for r in await world.directory.current_readers(
            installation_id=INSTALLATION_ID, team_id=TEAM_ID
        )
    ] == [scope]
    signing, signature = world.owner.sign("app-role.revoke", revocation(scope, reader))
    await world.designations.revoke(signing=signing, signature=signature, scope=scope)
    assert await holder(world, scope) is None


@pytest.mark.parametrize(
    "signed",
    [
        lambda scope, reader: revocation(scope, "someone-else"),
        lambda scope, reader: {**revocation(scope, reader), "installation_id": str(uuid4())},
        lambda scope, reader: revocation("logs.reader." + "0" * 32, reader),
    ],
    ids=["another holder", "another installation", "another scope"],
)
async def test_a_revocation_that_does_not_name_the_reader_exactly_revokes_nobody(
    world: World, signed
):
    scope, reader = await enrolled_reader(world)
    before = await chained(world)
    signing, signature = world.owner.sign("app-role.revoke", signed(scope, reader))
    with pytest.raises(ReaderRefused):
        await world.designations.revoke(signing=signing, signature=signature, scope=scope)
    assert await holder(world, scope) == reader
    assert await chained(world) == before


async def test_a_replayed_revocation_revokes_once(world: World):
    scope, reader = await enrolled_reader(world)
    signing, signature = world.owner.sign("app-role.revoke", revocation(scope, reader))
    await world.designations.revoke(signing=signing, signature=signature, scope=scope)
    with pytest.raises(ReaderRefused):
        await world.designations.revoke(signing=signing, signature=signature, scope=scope)
    acts = [entry["payload"]["act"] for entry in await chained(world)]
    assert acts.count("role.revoked") == 1


async def test_a_scope_that_is_no_reader_is_revoked_by_nobody(world: World):
    scope = await slot(world)
    signing, signature = world.owner.sign("app-role.revoke", revocation(scope, "anyone"))
    with pytest.raises(ReaderRefused):
        await world.designations.revoke(signing=signing, signature=signature, scope=scope)
    assert await chained(world) == []


@asynccontextmanager
async def console(world: World) -> AsyncIterator[httpx.AsyncClient]:
    """logs' console origin with the owner-act routes and B3's credential routes."""
    app = FastAPI()
    app.include_router(reader_governance_router(world.designations))
    app.include_router(credential_router(passkeys=world.passkeys, recorder=world.recorder))
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url=CONSOLE
    ) as client:
        yield client


async def test_the_owner_designates_a_reader_who_then_enrols_on_logs_console(world: World):
    scope = await slot(world)
    signing, signature = world.owner.sign("app-role.designate", designation(scope))
    async with console(world) as client:
        designated = await client.post(
            "/readers/designations",
            json=act_body(signing, signature, scope=scope, contact=CONTACT),
        )
        assert (designated.status_code, designated.json()) == (200, {"scope": scope})
        assert console_headed(designated)
        token = world.inbox.enrolments[CONTACT][-1]
        options = await client.post("/enrolment/options", json={"link_token": token})
        enrolled = await client.post(
            "/enrolment",
            json={
                "link_token": token,
                "credential": SoftAuthenticator(CONSOLE).create(options.json()),
            },
        )
        assert (enrolled.status_code, enrolled.json()) == (200, {"scope": scope})
    assert [entry["payload"]["act"] for entry in await chained(world)] == [
        "role.designated",
        "credential.enrolled",
    ]


async def test_the_owner_revokes_a_reader_on_logs_console(world: World):
    scope, reader = await enrolled_reader(world)
    signing, signature = world.owner.sign("app-role.revoke", revocation(scope, reader))
    async with console(world) as client:
        revoked = await client.post(
            "/readers/revocations", json=act_body(signing, signature, scope=scope)
        )
    assert (revoked.status_code, revoked.json()) == (200, {"scope": scope})
    assert console_headed(revoked)
    assert await holder(world, scope) is None


async def test_an_act_that_names_nobody_is_refused_without_echo(world: World):
    scope = await slot(world)
    signing, signature = world.owner.sign("app-role.designate", designation(scope, OTHER_CONTACT))
    async with console(world) as client:
        refusals = [
            await client.post(
                "/readers/designations",
                json=act_body(signing, signature, scope=scope, contact=CONTACT),
            ),
            await client.post(
                "/readers/revocations", json=act_body(signing, signature, scope=scope)
            ),
        ]
    for response in refusals:
        assert (response.status_code, response.json()) == (403, {"detail": "owner_required"})
        assert console_headed(response)
        assert signature not in response.text and scope not in response.text
    await nothing_took_effect(world, scope)


async def test_without_a_governance_registration_the_console_says_so(world: World):
    world.registered[0] = False
    scope = await slot(world)
    signing, signature = world.owner.sign("app-role.designate", designation(scope))
    async with console(world) as client:
        response = await client.post(
            "/readers/designations",
            json=act_body(signing, signature, scope=scope, contact=CONTACT),
        )
    assert (response.status_code, response.json()) == (
        503,
        {"detail": "audit_target_unavailable"},
    )
    await nothing_took_effect(world, scope)


@pytest.mark.parametrize(
    ("path", "fields"),
    [
        ("/readers/designations", {"signing", "signature", "scope", "contact"}),
        ("/readers/revocations", {"signing", "signature", "scope"}),
    ],
)
async def test_the_owner_act_routes_take_exactly_their_json_fields(world: World, path, fields):
    canary = os.urandom(24).hex()
    body = {name: canary for name in fields} | {"signing": base64.b64encode(b"x").decode()}
    async with console(world) as client:
        not_json = await client.post(path, content=b"{}", headers={"Content-Type": "text/plain"})
        assert (not_json.status_code, not_json.json()) == (415, {"detail": "json_required"})
        for wrong in (
            {**body, "unexpected": canary},
            {name: value for name, value in body.items() if name != "scope"},
            {**body, "signing": "not base64!"},
            {**body, "scope": ""},
        ):
            response = await client.post(path, json=wrong)
            assert (response.status_code, response.json()) == (400, {"detail": "request_invalid"})
            assert canary not in response.text
            assert console_headed(response)

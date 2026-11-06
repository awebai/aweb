"""Historical labels come from the verified actor, never current names or input."""

import json
from datetime import timedelta
from uuid import uuid4

import pytest
from aweb_naapp.hooks.commitment import CommitmentContext
from aweb_naapp.runtime.team_auth import AWIDTeamCache, authenticate_request
from aweb_naapp_testing import Member
from awid_service.testing import REGISTRY_URL, SERVICE_TOKEN
from fastapi import Request

from aweb_secrets.activity_service import ActivityReads
from aweb_secrets.broker_audit import record_use_refusal
from aweb_secrets.use_context import UseCommitments
from tests.test_admission import NOW, TEAM
from tests.test_broker_audit import INSTALLATION, prepared, source
from tests.test_broker_audit import db as db
from tests.test_broker_audit import fence as fence


async def authenticated(registry, member, *, stable, register=True):
    if register:
        if stable:
            member.extra_cert_fields["member_did_aw"] = await registry.register_did(
                member.member_key
            )
        await registry.add_team(TEAM, member.team_did_key)
    await registry.add_certificate(member.certificate())
    body = b'{"alias":"untrusted-body-name"}'
    headers = member.headers(aud="https://api.localhost", method="POST", path="/v1/use", body=body)

    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

    request = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/v1/use",
            "raw_path": b"/v1/use",
            "query_string": b"",
            "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()],
        },
        receive,
    )
    return await authenticate_request(
        request,
        public_origin="https://api.localhost",
        team_cache=AWIDTeamCache(
            registry_url=REGISTRY_URL,
            ttl_seconds=60,
            service_token=SERVICE_TOKEN,
            transport=registry.transport,
        ),
    )


@pytest.mark.parametrize("stable", [False, True])
@pytest.mark.parametrize("tool", ["request", "run"])
async def test_b1_alias_snapshot_survives_a_new_verified_certificate_without_writes(
    db, fence, registry, stable, tool
):
    _, admission, _, _ = await prepared(db, fence)
    member = Member(team_id=TEAM, alias="db-writer")
    first = await authenticated(registry, member, stable=stable)
    assert first.alias == "db-writer"
    if stable:
        assert first.did_aw_registry_verified
    context = CommitmentContext(
        "secrets", TEAM, INSTALLATION, admission.installation.generation, tool
    )
    async with db.transaction() as tx:
        event_id = await record_use_refusal(
            tx,
            producer=source(INSTALLATION, context.generation),
            principal=first,
            commitments=UseCommitments(context, "a" * 64, None),
            code="grant_missing",
            occurred_at=NOW,
        )
    member.alias, member.certificate_id = "renamed-writer", "cert-2"
    current = await authenticated(registry, member, stable=stable, register=False)
    assert current.alias == "renamed-writer" and current.did_key == first.did_key
    before = [dict(row) for row in await db.fetch_all("SELECT * FROM {{tables.broker_use_events}}")]
    async with db.transaction() as tx:
        await tx.execute("SET TRANSACTION READ ONLY")
        page = await ActivityReads().page(tx, installation_id=INSTALLATION, team_id=TEAM)
    [entry] = [entry for entry in page.entries if entry.event_id == event_id]
    assert entry.principal_alias == "db-writer"
    assert entry.principal_alias != current.alias and entry.principal_alias != "untrusted-body-name"
    assert entry.principal_did == (first.did_aw if stable else first.did_key)
    assert [
        dict(row) for row in await db.fetch_all("SELECT * FROM {{tables.broker_use_events}} ")
    ] == before


@pytest.mark.parametrize(
    "actor",
    [
        {},
        {"alias": "historical"},
        {"did_aw": "did:aw:other", "alias": "other"},
        {"did_key": "did:key:other", "alias": "other"},
        {"did_key": "did:key:canonical", "did_aw": "did:aw:other", "alias": "other"},
        {"did_key": "did:key:canonical", "alias": ""},
        {"did_key": "did:key:canonical", "alias": None},
        {"did_key": "did:key:canonical", "alias": 17},
        [],
    ],
)
async def test_missing_or_mismatched_historical_actor_never_guesses_an_alias(db, fence, actor):
    _, _, dispatch_id, _ = await prepared(db, fence)
    event_id = uuid4()
    # Historical malformed/missing identity data is not repaired from a current
    # alias or key. Seed it directly; immutable production rows are not edited.
    async with db.transaction() as tx:
        await tx.execute(
            "INSERT INTO {{tables.broker_use_events}}"
            " (event_id,installation_id,team_id,install_generation,dispatch_id,occurred_at,action,actor,payload,correlation)"
            " SELECT $1,c.installation_id,c.team_id,c.install_generation,c.dispatch_id,$2,'refused',$3::jsonb,'{}'::jsonb,$4::jsonb"
            " FROM {{tables.use_contexts}} c WHERE dispatch_id=$5",
            event_id,
            NOW + timedelta(seconds=1),
            json.dumps(actor),
            json.dumps({"principal_did": "did:key:canonical"}),
            dispatch_id,
        )
    async with db.transaction() as tx:
        await tx.execute("SET TRANSACTION READ ONLY")
        page = await ActivityReads().page(tx, installation_id=INSTALLATION, team_id=TEAM)
    [entry] = [entry for entry in page.entries if entry.event_id == event_id]
    assert entry.principal_did == "did:key:canonical" and entry.principal_alias is None

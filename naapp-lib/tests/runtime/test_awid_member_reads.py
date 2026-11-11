"""A customer-hosted naapp reads its private team's gated AWID facts with an
ordinary member certificate of its own, path-signing each gated read exactly
as the CLI does; a hosted deployment keeps the service token. Real AWID routes
on real PostgreSQL answer every read.
"""

from __future__ import annotations

import pytest
from aweb_naapp_testing import Member
from awid_service.testing import REGISTRY_URL, SERVICE_TOKEN
from fastapi import HTTPException

from aweb_naapp.runtime.team_auth import AWIDMemberCredential, AWIDTeamCache

TEAM_ID = "backend:example.com"
OTHER_TEAM_ID = "frontend:example.com"


def credential_of(member: Member) -> AWIDMemberCredential:
    return AWIDMemberCredential(
        signing_key=bytes(member.member_key), certificate=member.certificate()
    )


async def private_team(registry, team_id: str = TEAM_ID) -> tuple[Member, Member]:
    """A private team with a member who signs requests, and the service's own
    member certificate, issued by the same team key."""
    caller = Member(team_id=team_id, certificate_id="caller", alias="caller")
    service = Member(
        team_id=team_id,
        team_key=caller.team_key,
        certificate_id="service",
        alias="logs-service",
    )
    await registry.add_team(team_id, caller.team_did_key, visibility="private")
    await registry.add_certificate(caller.certificate())
    await registry.add_certificate(service.certificate())
    return caller, service


def member_cache(registry, *credentials: Member, token: str | None = None) -> AWIDTeamCache:
    return AWIDTeamCache(
        registry_url=REGISTRY_URL,
        ttl_seconds=60,
        service_token=token,
        member_credentials={member.team_id: credential_of(member) for member in credentials},
        transport=registry.transport,
    )


def gated_reads(registry) -> list:
    return [
        request
        for request in registry.transport.calls
        if request.url.path.endswith(("/teams/backend", "/teams/frontend", "/certificates"))
    ]


async def test_a_member_credential_reads_its_private_teams_facts_without_a_token(registry):
    caller, service = await private_team(registry)
    facts = await member_cache(registry, service).get(TEAM_ID, "caller")
    assert facts.team_did_key == caller.team_did_key
    assert {"caller", "service"} <= facts.published_certificate_ids
    reads = gated_reads(registry)
    assert reads
    for request in reads:
        assert "X-AWID-Service-Token" not in request.headers
        assert request.headers["Authorization"].startswith(f"DIDKey {service.did_key} ")
        assert request.headers["X-AWEB-Timestamp"]


async def test_the_owners_team_key_is_read_without_a_caller_certificate(registry):
    """The team-key read an owner act's verifier makes has no certificate id."""
    caller, service = await private_team(registry)
    assert (await member_cache(registry, service).get(TEAM_ID)).team_did_key == caller.team_did_key


async def test_revoking_the_services_certificate_stops_its_reads(registry):
    _, service = await private_team(registry)
    await registry.revoke("service")
    with pytest.raises(HTTPException) as refused:
        await member_cache(registry, service).get(TEAM_ID, "caller")
    assert refused.value.status_code == 403
    assert refused.value.detail["code"] == "team_private_unreadable"


async def test_a_credential_reads_only_its_own_team(registry):
    _, service = await private_team(registry)
    await private_team(registry, OTHER_TEAM_ID)
    cache = member_cache(registry, service)
    assert (await cache.get(TEAM_ID)).team_did_key
    with pytest.raises(HTTPException) as refused:
        await cache.get(OTHER_TEAM_ID)
    assert refused.value.status_code == 403
    assert refused.value.detail["code"] == "team_private_unreadable"
    assert OTHER_TEAM_ID in refused.value.detail["message"]


async def test_the_token_keeps_precedence_over_a_member_credential(registry):
    _, service = await private_team(registry)
    await member_cache(registry, service, token=SERVICE_TOKEN).get(TEAM_ID, "caller")
    for request in gated_reads(registry):
        assert request.headers["X-AWID-Service-Token"] == SERVICE_TOKEN
        assert "Authorization" not in request.headers


async def test_a_public_teams_key_is_a_plain_read_without_token_or_credential(registry):
    member = Member(team_id=TEAM_ID)
    await registry.add_team(TEAM_ID, member.team_did_key, visibility="public")
    cache = AWIDTeamCache(registry_url=REGISTRY_URL, ttl_seconds=60, transport=registry.transport)
    assert (await cache.get(TEAM_ID)).team_did_key == member.team_did_key
    for request in gated_reads(registry):
        assert "Authorization" not in request.headers
        assert "X-AWID-Service-Token" not in request.headers


async def test_a_private_team_with_no_credential_names_the_missing_one(registry):
    await private_team(registry)
    cache = AWIDTeamCache(registry_url=REGISTRY_URL, ttl_seconds=60, transport=registry.transport)
    with pytest.raises(HTTPException) as refused:
        await cache.get(TEAM_ID)
    assert refused.value.status_code == 403
    assert refused.value.detail["code"] == "team_private_unreadable"
    assert f"awid_member_credentials[{TEAM_ID}]" in refused.value.detail["message"]


@pytest.mark.parametrize(
    "mismatch",
    ["certificate of another team", "certificate of another key"],
)
def test_a_credential_that_does_not_belong_together_is_refused(mismatch: str):
    member = Member(team_id=TEAM_ID)
    if mismatch == "certificate of another team":
        certificate = Member(team_id=OTHER_TEAM_ID).certificate()
        signing_key = bytes(member.member_key)
    else:
        certificate = member.certificate()
        signing_key = bytes(Member(team_id=TEAM_ID).member_key)
    with pytest.raises(ValueError):
        AWIDTeamCache(
            registry_url=REGISTRY_URL,
            ttl_seconds=60,
            member_credentials={
                TEAM_ID: AWIDMemberCredential(signing_key=signing_key, certificate=certificate)
            },
        )


async def test_a_fresh_team_key_read_is_signed_and_never_cached(registry):
    """Logs' ingest reads the controller key fresh for each client delivery."""
    caller, service = await private_team(registry)
    cache = member_cache(registry, service)
    assert await cache.current_team_did_key(TEAM_ID) == caller.team_did_key
    assert await cache.current_team_did_key(TEAM_ID) == caller.team_did_key
    team_reads = [r for r in registry.transport.calls if r.url.path.endswith("/teams/backend")]
    assert len(team_reads) == 2
    assert all(r.headers["Authorization"].startswith(f"DIDKey {service.did_key} ") for r in team_reads)


async def test_a_fresh_team_key_read_of_an_unknown_team_is_none(registry):
    await private_team(registry)
    assert await member_cache(registry).current_team_did_key("nobody:example.com") is None


async def test_a_fresh_team_key_read_stops_when_the_certificate_is_revoked(registry):
    _, service = await private_team(registry)
    await registry.revoke("service")
    with pytest.raises(HTTPException) as refused:
        await member_cache(registry, service).current_team_did_key(TEAM_ID)
    assert refused.value.status_code == 403
    assert refused.value.detail["code"] == "team_private_unreadable"

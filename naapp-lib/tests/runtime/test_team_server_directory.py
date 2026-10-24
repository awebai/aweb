"""Team-server discovery against real AWID routes on real PostgreSQL."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import httpx
import pytest
from aweb_naapp_testing import did_key
from awid.dns_verify import DnsVerificationError
from awid.team_server_record import record_signing_bytes
from awid_service.testing import REGISTRY_URL, SERVICE_TOKEN, signed_team_server_record
from nacl.signing import SigningKey

from aweb_naapp.runtime.team_auth import AWIDTeamCache
from aweb_naapp.runtime.team_server import TeamServerDirectory, TeamServerUnavailable

TEAM_ID = "ops:discovery.example"
SERVER_URL = "https://coord.discovery.example/api"


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def _directory(registry, *, clock=None, registry_override=None) -> TeamServerDirectory:
    cache = AWIDTeamCache(
        registry_url=REGISTRY_URL, ttl_seconds=60, service_token=SERVICE_TOKEN, transport=registry.transport
    )

    async def no_override(domain: str) -> str | None:
        return None

    return TeamServerDirectory(
        team_cache=cache,
        transport=registry.transport,
        registry_override=registry_override or no_override,
        clock=clock or Clock(),
    )


async def _refusal(directory: TeamServerDirectory) -> str:
    with pytest.raises(TeamServerUnavailable) as refused:
        await directory.resolve(TEAM_ID)
    return refused.value.code


@pytest.fixture
async def team(registry):
    team_key = SigningKey.generate()
    await registry.add_team(TEAM_ID, did_key(team_key))
    return team_key


async def test_a_published_record_resolves_to_its_server(registry, team):
    await registry.publish_team_server(TEAM_ID, team, server_url=SERVER_URL, issued_at=datetime.now(UTC) - timedelta(minutes=1))

    server = await _directory(registry).resolve(TEAM_ID)

    assert server.server_url == SERVER_URL
    assert server.audience == "https://coord.discovery.example"
    assert server.team_did_key == did_key(team)


async def test_a_team_without_a_record_is_unpublished(registry, team):
    assert await _refusal(_directory(registry)) == "team_server_unpublished"


async def test_a_record_left_by_a_rotated_key_is_a_key_mismatch(registry, team):
    await registry.publish_team_server(TEAM_ID, team, server_url=SERVER_URL, issued_at=datetime.now(UTC) - timedelta(minutes=1))
    await registry.rotate_team_key(TEAM_ID, did_key(SigningKey.generate()))

    assert await _refusal(_directory(registry)) == "team_server_key_mismatch"


async def test_a_far_future_record_held_by_the_registry_is_refused(registry, team):
    future = signed_team_server_record(
        TEAM_ID, team, server_url=SERVER_URL, issued_at=datetime.now(UTC) + timedelta(hours=1)
    )
    await registry.db.execute(
        """
        INSERT INTO {{tables.team_server_records}} (team_uuid, record_json, signature, team_did_key, server_url, issued_at)
        SELECT team_uuid, $3, $4, team_did_key, $5, now() + interval '1 hour'
        FROM {{tables.teams}} WHERE domain = $1 AND name = $2
        """,
        "discovery.example",
        "ops",
        record_signing_bytes(future["record"])[len(b"aweb.team-server/1\n"):].decode(),
        future["signature"],
        SERVER_URL,
    )

    assert await _refusal(_directory(registry)) == "team_server_record_invalid"


async def test_a_domain_whose_awid_record_names_another_registry_is_refused(registry, team):
    await registry.publish_team_server(TEAM_ID, team, server_url=SERVER_URL, issued_at=datetime.now(UTC) - timedelta(minutes=1))

    async def other_registry(domain: str) -> str | None:
        return "https://other-registry.example"

    assert await _refusal(_directory(registry, registry_override=other_registry)) == "registry_mismatch"


async def test_an_answer_is_reused_for_at_most_a_minute_and_never_after(registry, team):
    await registry.publish_team_server(TEAM_ID, team, server_url=SERVER_URL, issued_at=datetime.now(UTC) - timedelta(minutes=1))
    clock = Clock()
    directory = _directory(registry, clock=clock)
    await directory.resolve(TEAM_ID)
    calls = len(registry.transport.calls)

    clock.now += 59
    await directory.resolve(TEAM_ID)
    reused_calls = len(registry.transport.calls)
    clock.now += 2

    def outage(request: httpx.Request, response: httpx.Response) -> None:
        response.status_code = 503

    registry.transport.fault = outage

    assert reused_calls == calls
    assert await _refusal(directory) == "authority_unavailable"


async def test_without_a_service_token_the_member_certificate_reads_a_private_team(registry):
    team_key = SigningKey.generate()
    await registry.add_team(TEAM_ID, did_key(team_key), visibility="private")
    await registry.add_certificate(
        {"team_id": TEAM_ID, "certificate_id": "cert-1", "member_did_key": did_key(SigningKey.generate()), "alias": "alice"}
    )
    await registry.publish_team_server(TEAM_ID, team_key, server_url=SERVER_URL, issued_at=datetime.now(UTC) - timedelta(minutes=1))

    async def no_override(domain: str) -> str | None:
        return None

    directory = TeamServerDirectory(
        team_cache=AWIDTeamCache(registry_url=REGISTRY_URL, ttl_seconds=60, transport=registry.transport),
        transport=registry.transport,
        registry_override=no_override,
    )

    server = await directory.resolve(TEAM_ID, certificate_id="cert-1")

    assert server.server_url == SERVER_URL


async def test_a_malformed_awid_registry_value_fails_closed_with_a_code(registry, team):
    async def malformed(domain: str) -> str | None:
        return "not a url"

    assert await _refusal(_directory(registry, registry_override=malformed)) == "authority_unavailable"


async def test_a_team_awid_does_not_know_is_reported_as_unknown(registry):
    assert await _refusal(_directory(registry)) == "team_unknown"


async def test_a_dns_failure_is_unavailable_and_never_falls_back_to_the_verifier_registry(registry, team):
    await registry.publish_team_server(TEAM_ID, team, server_url=SERVER_URL, issued_at=datetime.now(UTC) - timedelta(minutes=1))
    calls_before = len(registry.transport.calls)

    async def dns_fails(domain: str) -> str | None:
        raise DnsVerificationError("timed out")

    code = await _refusal(_directory(registry, registry_override=dns_fails))

    assert code == "authority_unavailable"
    assert len(registry.transport.calls) == calls_before

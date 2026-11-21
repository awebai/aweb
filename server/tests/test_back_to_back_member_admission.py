"""Registered members connect back to back through real registry/native routes."""

import asyncio
from contextlib import aclosing
from uuid import uuid4

import httpx
import pytest
from awid.dns_verify import DomainAuthority
from awid.registry import CachedRegistryClient
from awid_service.deps import get_domain_verifier
from test_cli_never_grants import registry_listener
from test_dashboard_privacy import privacy_app as privacy_app
from test_messages_http import (
    _encode_certificate,
    _make_certificate,
    _make_keypair,
    _signed_team_headers,
)

__all__ = ["privacy_app"]


@pytest.mark.asyncio
async def test_back_to_back_admissions_are_visible_in_the_authenticated_roster(
    privacy_app, monkeypatch
):
    # B7 bounds signature-verified misses by team, including independent IDs.
    # A suppressed member retries after the actual Redis window; no absence is cached.
    env = privacy_app
    monkeypatch.setenv("AWEB_REQUIRE_REGISTERED_CERTIFICATES", "true")
    async with registry_listener(env) as (writer, origin):

        async def namespace_authority(domain: str) -> DomainAuthority:
            assert domain == "example.test"
            return DomainAuthority(env.namespace_did, origin, "_awid.example.test")

        env.registry_app.dependency_overrides[get_domain_verifier] = lambda: namespace_authority
        name = "join-" + uuid4().hex[:12]
        team_id = name + ":example.test"
        await writer.register_team(
            domain="example.test",
            name=name,
            display_name="Join together",
            team_did_key=env.team_did,
            visibility="public",
            namespace_controller_signing_key=env.namespace_sk,
        )
        async with aclosing(
            CachedRegistryClient(
                registry_url=origin,
                redis_client=env.redis,
                transport=httpx.ASGITransport(app=env.registry_app),
                service_token=writer.service_token,
            )
        ) as reader:
            env.app.state.awid_registry_client = reader
            assert (
                await reader.list_team_certificates("example.test", name, active_only=False) == []
            )

            async def connect_after_miss_window(signing_key, did_key, header):
                body = b"{}"
                headers = {
                    **_signed_team_headers(signing_key, did_key, team_id, header, body),
                    "Content-Type": "application/json",
                }
                response = await env.client.post("/v1/connect", content=body, headers=headers)
                if response.status_code == 503:
                    assert "Retry after five seconds" in response.text
                    assert not await env.db.fetch_value(
                        "SELECT EXISTS(SELECT 1 FROM {{tables.agents}} WHERE team_id=$1 AND did_key=$2)",
                        team_id,
                        did_key,
                    )
                    await asyncio.sleep(5)
                    response = await env.client.post("/v1/connect", content=body, headers=headers)
                return response

            expected_roster = []
            try:
                for alias in ("alice", "bob", "carol"):
                    signing_key, _, did_key = _make_keypair()
                    cert = _make_certificate(
                        env.team_sk,
                        env.team_did,
                        did_key,
                        team_id=team_id,
                        alias=alias,
                        identity_scope="local",
                        certificate_id="join-" + uuid4().hex,
                    )
                    header = _encode_certificate(cert)
                    await writer.register_team_certificate(
                        "example.test",
                        name,
                        team_controller_signing_key=env.team_sk,
                        certificate_id=cert["certificate_id"],
                        member_did_key=did_key,
                        member_did_aw=None,
                        member_address=None,
                        alias=alias,
                        identity_scope="local",
                        certificate=header,
                    )
                    response = await connect_after_miss_window(signing_key, did_key, header)
                    assert response.status_code == 200, response.text
                    agent_id = response.json()["agent_id"]
                    expected_roster.append((alias, agent_id, did_key))
                    row = await env.db.fetch_one(
                        "SELECT certificate_id, accepted_team_did_key FROM {{tables.agents}} "
                        "WHERE agent_id=$1::uuid AND team_id=$2",
                        agent_id,
                        team_id,
                    )
                    assert row["certificate_id"] == cert["certificate_id"]
                    assert row["accepted_team_did_key"] == env.team_did
                # The team roster projects admitted local members even when an
                # exact certificate lookup leaves a cached AWID list untouched.
                roster = await env.client.get(
                    "/v1/agents",
                    headers=_signed_team_headers(signing_key, did_key, team_id, header),
                )
                assert roster.status_code == 200, roster.text
                assert roster.json()["team_id"] == team_id
                assert [
                    (agent["alias"], agent["agent_id"], agent["did_key"])
                    for agent in roster.json()["agents"]
                ] == expected_roster
                # A different, correctly signed but unregistered certificate is
                # a definite refusal, not another member's refresh suppression.
                signing_key, _, did_key = _make_keypair()
                cert = _make_certificate(
                    env.team_sk,
                    env.team_did,
                    did_key,
                    team_id=team_id,
                    alias="unregistered",
                    identity_scope="local",
                    certificate_id="unregistered-" + uuid4().hex,
                )
                header = _encode_certificate(cert)
                refused = await connect_after_miss_window(signing_key, did_key, header)
                assert refused.status_code == 401, refused.text
                assert refused.json()["detail"] == "unregistered"
                assert not await env.db.fetch_value(
                    "SELECT EXISTS(SELECT 1 FROM {{tables.agents}} WHERE team_id=$1 AND did_key=$2)",
                    team_id,
                    did_key,
                )
            finally:
                env.app.state.awid_registry_client = writer

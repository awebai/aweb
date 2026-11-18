# ruff: noqa: F811 -- pytest imports the real shared fixture by name.
"""Federation resolution against real registry HTTP and PostgreSQL budgets."""

import json
from contextlib import asynccontextmanager

import pytest

from aweb.federation.activation import build_federation_authority_activation
from identity_binding_support import register_global_identity
from test_cli_never_grants import registry_listener
from test_dashboard_privacy import TEAM, privacy_app  # noqa: F401
from test_messages_http import _signed_team_headers


@asynccontextmanager
async def _authority(env, monkeypatch):
    async with registry_listener(env) as (_, registry_origin):
        await register_global_identity(env, env.actors["bob"], "foreign.test/bob")
        origin = str(env.client.base_url).rstrip("/")
        await env.registry_db.execute("UPDATE {{tables.dns_namespaces}} SET default_delivery_origin=$1", origin)
        monkeypatch.setenv("APP_ENV", "development")
        monkeypatch.setenv("AWEB_FEDERATION_TEST", "1")
        monkeypatch.setenv("AWEB_FEDERATION_TEST_DEFAULT_REGISTRY", "1")
        monkeypatch.setenv("AWID_REGISTRY_URL", registry_origin)
        authority = build_federation_authority_activation(env.infra, public_origin=origin)
        env.app.state.federation_authority = authority
        try:
            yield authority
        finally:
            await authority.aclose()


@pytest.mark.asyncio
async def test_outbound_resolution_reuses_fresh_cohort_and_refreshes_expired(privacy_app, monkeypatch):
    env = privacy_app
    async with _authority(env, monkeypatch) as authority:
        first = await authority.resolve_contact("foreign.test/bob", source_ip="203.0.113.1")
        second = await authority.resolve_contact("foreign.test/bob", source_ip="203.0.113.2")
        assert second == first
        sources = await env.db.fetch_all(
            "SELECT bucket_key FROM {{tables.federation_authority_token_buckets}} WHERE bucket_kind='source_ip'",
        )
        assert [row["bucket_key"] for row in sources] == ["203.0.113.1"]
        await env.db.execute(
            "UPDATE {{tables.federation_address_authority_cohorts}} SET expires_at=clock_timestamp()-INTERVAL '1 second'",
        )
        refreshed = await authority.resolve_contact("foreign.test/bob", source_ip="203.0.113.3")
        assert refreshed.did_aw == first.did_aw and refreshed.current_did_key == first.current_did_key
        assert await env.db.fetch_value(
            "SELECT count(*) FROM {{tables.federation_authority_token_buckets}} WHERE bucket_kind='source_ip' AND bucket_key='203.0.113.3'",
        ) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("surface", ["mail", "chat", "contact"])
@pytest.mark.parametrize("trusted", [True, False])
async def test_outbound_budget_uses_the_same_configured_client_address(privacy_app, monkeypatch, surface, trusted):
    env = privacy_app
    monkeypatch.setenv("AWEB_CLIENT_ADDRESS_HEADER", "X-Client-IP" if trusted else "")
    paths = {"mail": "/v1/messages", "chat": "/v1/chat/sessions", "contact": "/v1/contacts"}
    actor = env.actors["alice"]
    async with _authority(env, monkeypatch):
        for index in (1, 2):
            address = f"foreign.test/missing-{index}"
            payload = {
                "mail": {"to_address": address, "body": "first contact"},
                "chat": {"to_addresses": [address], "message": "first contact"},
                "contact": {"contact_address": address},
            }[surface]
            body = json.dumps(payload).encode()
            response = await env.client.post(paths[surface], content=body, headers={
                **_signed_team_headers(actor.sk, actor.did, TEAM, actor.certificate, body),
                "Content-Type": "application/json", "X-Client-IP": f"untrusted, 203.0.113.{index}",
            })
            assert response.status_code == 404, response.text
        rows = await env.db.fetch_all(
            "SELECT bucket_key FROM {{tables.federation_authority_token_buckets}} WHERE bucket_kind='source_ip' ORDER BY bucket_key",
        )
        expected = ["203.0.113.1", "203.0.113.2"] if trusted else ["127.0.0.1"]
        assert [row["bucket_key"] for row in rows] == expected

# ruff: noqa: F811 -- pytest imports the real shared fixture by name.
"""Federation resolution against real registry HTTP and PostgreSQL budgets."""

import json
from contextlib import asynccontextmanager

import pytest

from aweb.federation.activation import build_federation_authority_activation
from identity_binding_support import register_global_identity
from test_cli_never_grants import registry_listener
from test_dashboard_privacy import TEAM, privacy_app as privacy_app
from test_messages_http import _signed_team_headers

__all__ = ["privacy_app"]


@asynccontextmanager
async def _authority(env, monkeypatch):
    monkeypatch.setenv("APP_ENV", "development")
    monkeypatch.setenv("AWID_ALLOW_INSECURE_DELIVERY_ORIGIN", "1")
    await register_global_identity(env, env.actors["bob"], "foreign.test/bob")
    origin = str(env.client.base_url).rstrip("/")
    controller = await env.registry.ensure_namespace(domain="foreign.test")
    await env.app.state.awid_registry_client.update_namespace_delivery_origin(
        "foreign.test", controller, origin
    )
    async with registry_listener(env) as (_, registry_origin):
        monkeypatch.setenv("AWEB_FEDERATION_TEST", "1")
        monkeypatch.setenv("AWEB_FEDERATION_TEST_DEFAULT_REGISTRY", "1")
        monkeypatch.setenv("AWID_REGISTRY_URL", registry_origin)
        authority = build_federation_authority_activation(
            env.infra, public_origin=origin
        )
        env.app.state.federation_authority = authority
        try:
            yield authority
        finally:
            await authority.aclose()


@pytest.mark.asyncio
async def test_outbound_resolution_reuses_fresh_cohort_and_refreshes_expired(
    privacy_app, monkeypatch
):
    env = privacy_app
    monkeypatch.setenv("AWEB_FEDERATION_AUTHORITY_REUSE_SECONDS", "5")
    async with _authority(env, monkeypatch) as authority:
        first = await authority.resolve_contact(
            "foreign.test/bob", source_ip="203.0.113.1"
        )
        second = await authority.resolve_contact(
            "foreign.test/bob", source_ip="203.0.113.2"
        )
        assert second == first
        assert (
            await env.db.fetch_value(
                "SELECT count(*) FROM {{tables.federation_authority_leases}}"
            )
            == 0
        )
        sources = await env.db.fetch_all(
            "SELECT bucket_key FROM {{tables.federation_authority_token_buckets}} WHERE bucket_kind='source_ip'",
        )
        assert [row["bucket_key"] for row in sources] == ["203.0.113.1"]
        await env.db.fetch_value(
            "SELECT pg_sleep(GREATEST(0, EXTRACT(EPOCH FROM expires_at - clock_timestamp()))) "
            "FROM {{tables.federation_address_authority_cohorts}} WHERE canonical_address=$1",
            "foreign.test/bob",
        )
        refreshed = await authority.resolve_contact(
            "foreign.test/bob", source_ip="203.0.113.3"
        )
        assert (
            refreshed.did_aw == first.did_aw
            and refreshed.current_did_key == first.current_did_key
        )
        assert (
            await env.db.fetch_value(
                "SELECT count(*) FROM {{tables.federation_authority_token_buckets}} WHERE bucket_kind='source_ip' AND bucket_key='203.0.113.3'",
            )
            == 1
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("failed_cleanup", ["lease", "permit"])
async def test_published_resolution_survives_cleanup_database_failure(
    privacy_app, monkeypatch, caplog, failed_cleanup
):
    env = privacy_app
    table = (
        "federation_authority_leases"
        if failed_cleanup == "lease"
        else "federation_authority_permits"
    )
    await env.db.execute(
        """
        CREATE FUNCTION {{tables.refuse_authority_cleanup}}() RETURNS trigger
        LANGUAGE plpgsql AS $$ BEGIN
            RAISE EXCEPTION 'private cleanup dependency detail';
        END $$
        """
    )
    # Fail the evidence lease only: the following discovery release must still run.
    condition = (
        "WHEN (OLD.scope_key LIKE 'origin:%')" if failed_cleanup == "lease" else ""
    )
    await env.db.execute(
        f"CREATE TRIGGER refuse_authority_cleanup BEFORE DELETE ON {{{{tables.{table}}}}} "
        f"FOR EACH ROW {condition} EXECUTE FUNCTION {{{{tables.refuse_authority_cleanup}}}}()"
    )
    async with _authority(env, monkeypatch) as authority:
        with caplog.at_level("WARNING", logger="aweb.federation.activation"):
            first = await authority.resolve_contact(
                "foreign.test/bob", source_ip="203.0.113.4"
            )
        assert first.canonical_address == "foreign.test/bob"
        assert first.current_did_key == env.actors["bob"].did
        assert authority.resolver._clients == {}
        leases = await env.db.fetch_all(
            "SELECT scope_key, expires_at > clock_timestamp() AS live "
            "FROM {{tables.federation_authority_leases}}"
        )
        if failed_cleanup == "lease":
            assert len(leases) == 1 and leases[0]["scope_key"].startswith("origin:")
            assert leases[0]["live"] is True
            assert (
                await env.db.fetch_value(
                    "SELECT count(*) FROM {{tables.federation_authority_permits}}"
                )
                == 0
            )
        else:
            assert leases == []
            assert (
                await env.db.fetch_value(
                    "SELECT count(*) FROM {{tables.federation_authority_permits}} "
                    "WHERE expires_at > clock_timestamp()"
                )
                == 3
            )
        records = [r for r in caplog.records if r.name == "aweb.federation.activation"]
        assert len(records) == 1
        assert records[0].getMessage() == (
            "federation_authority_cleanup_failed stage="
            + failed_cleanup
            + " failure_type=FederationAuthorityError"
        )
        assert records[0].exc_info is None
        assert "private cleanup dependency detail" not in records[0].getMessage()
        await env.db.execute(
            f"DROP TRIGGER refuse_authority_cleanup ON {{{{tables.{table}}}}}"
        )
        second = await authority.resolve_contact(
            "foreign.test/bob", source_ip="203.0.113.5"
        )
        assert second == first


@pytest.mark.asyncio
@pytest.mark.parametrize("surface", ["mail", "chat", "contact"])
@pytest.mark.parametrize("trusted", [True, False])
async def test_outbound_budget_uses_the_same_configured_client_address(
    privacy_app, monkeypatch, surface, trusted
):
    env = privacy_app
    monkeypatch.setenv("AWEB_CLIENT_ADDRESS_HEADER", "X-Client-IP" if trusted else "")
    paths = {
        "mail": "/v1/messages",
        "chat": "/v1/chat/sessions",
        "contact": "/v1/contacts",
    }
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
            response = await env.client.post(
                paths[surface],
                content=body,
                headers={
                    **_signed_team_headers(
                        actor.sk, actor.did, TEAM, actor.certificate, body
                    ),
                    "Content-Type": "application/json",
                    "X-Client-IP": f"untrusted, 203.0.113.{index}",
                },
            )
            assert response.status_code == 404, response.text
        rows = await env.db.fetch_all(
            "SELECT bucket_key FROM {{tables.federation_authority_token_buckets}} WHERE bucket_kind='source_ip' ORDER BY bucket_key",
        )
        expected = ["203.0.113.1", "203.0.113.2"] if trusted else ["127.0.0.1"]
        assert [row["bucket_key"] for row in rows] == expected


@pytest.mark.asyncio
@pytest.mark.parametrize("surface", ["mail", "chat", "contact"])
@pytest.mark.parametrize("trusted", [True, False])
async def test_mounted_mcp_budget_uses_authenticated_sender_regardless_of_proxy_header(
    privacy_app,
    monkeypatch,
    surface,
    trusted,
):
    from aweb.mcp.server import create_mcp_app

    env = privacy_app
    actor = env.actors["alice"]
    monkeypatch.setenv("AWEB_CLIENT_ADDRESS_HEADER", "X-Client-IP" if trusted else "")
    async with _authority(env, monkeypatch) as authority:
        mcp = create_mcp_app(
            db_infra=env.infra,
            redis=env.redis,
            registry_client=env.app.state.awid_registry_client,
            federation_authority=authority,
            public_origin=str(env.client.base_url).rstrip("/"),
        )
        env.app.mount("/budget-mcp", mcp)
        await mcp.startup()
        try:
            for index in (1, 2):
                address = f"foreign.test/missing-{index}"
                tool, arguments = {
                    "mail": ("send_mail", {"to": address, "body": "first contact"}),
                    "chat": ("send_chat", {"to": address, "message": "first contact"}),
                    "contact": ("add_contact", {"address": address}),
                }[surface]
                body = json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": index,
                        "method": "tools/call",
                        "params": {"name": tool, "arguments": arguments},
                    }
                ).encode()
                response = await env.client.post(
                    "/budget-mcp/",
                    content=body,
                    headers={
                        **_signed_team_headers(
                            actor.sk, actor.did, TEAM, actor.certificate, body
                        ),
                        "Content-Type": "application/json",
                        "Accept": "application/json, text/event-stream",
                        "X-Client-IP": f"untrusted, 203.0.113.{index}",
                    },
                )
                assert response.status_code == 200, response.text
                result = json.loads(response.json()["result"]["content"][0]["text"])
                expected_error = (
                    "recipient_identity_not_found"
                    if surface == "contact"
                    else f"{address} is not a registered address. A local identity has no address and is reachable only from inside its own team, by alias; a global identity is reachable by address once one is assigned. Check the address or use a teammate alias and retry."
                )
                assert result["error"] == expected_error
                if surface in {"mail", "chat"}:
                    assert result["reason"] == "recipient_identity_not_found"
            sources = await env.db.fetch_all(
                "SELECT bucket_key FROM {{tables.federation_authority_token_buckets}} "
                "WHERE bucket_kind='source_ip' ORDER BY bucket_key",
            )
            assert [row["bucket_key"] for row in sources] == [f"mcp:{actor.did}"]
        finally:
            await mcp.shutdown()

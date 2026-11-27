"""Cached verifier recovery requires the admitted pin and a real controller act."""

from __future__ import annotations

import pytest
from awid.registry import CachedRegistryClient
from test_cli_never_grants import registry_listener
from test_dashboard_privacy import TEAM
from test_dashboard_privacy import privacy_app as privacy_app
from test_member_team_key import _certificate, _change_key, _connect, _new_member, _row
from test_messages_http import _signed_team_headers
from test_team_key_pinning import pinning as pinning

__all__ = ["pinning"]


@pytest.mark.asyncio
async def test_cached_key_refresh_admits_only_the_real_controller_rotation(pinning):
    env = pinning
    async with registry_listener(env) as (registry, origin):
        cached = CachedRegistryClient(
            registry_url=origin,
            redis_client=env.redis,
            service_token=registry.service_token,
        )
        env.app.state.awid_registry_client = cached
        try:
            member = _new_member("cachemember")
            original = _certificate(env.team_sk, env.team_did, member, "cache-before")
            admitted = await _connect(env, member, original)
            assert admitted.status_code == 200, admitted.text
            assert (
                await cached.get_team_public_key("example.test", TEAM.split(":", 1)[0])
                == env.team_did
            )
            assert (await _row(env, member))["accepted_team_did_key"] == env.team_did

            next_sk, next_did = await _change_key(env)
            assert (
                await cached.get_team_public_key("example.test", TEAM.split(":", 1)[0])
                == next_did
            )
            pin = await env.db.fetch_one(
                "SELECT team_did_key,team_key_act_at FROM {{tables.teams}} WHERE team_id=$1",
                TEAM,
            )
            assert pin["team_did_key"] == next_did
            assert pin["team_key_act_at"] is not None
            reissued = _certificate(next_sk, next_did, member, "cache-after")
            current = await _connect(env, member, reissued)
            assert current.status_code == 200, current.text
            assert (await _row(env, member))["accepted_team_did_key"] == next_did

            obsolete = await env.client.get(
                "/v1/agents",
                headers=_signed_team_headers(member[0], member[1], TEAM, original),
            )
            assert obsolete.status_code == 401, obsolete.text
            assert obsolete.json()["detail"]["code"] == "team_key_not_current"
            assert (
                await env.db.fetch_value(
                    "SELECT team_did_key FROM {{tables.teams}} WHERE team_id=$1",
                    TEAM,
                )
                == next_did
            )
        finally:
            env.app.state.awid_registry_client = registry
            await cached.aclose()

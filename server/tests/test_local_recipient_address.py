"""Local-address refusals through the real app, registry, PostgreSQL and HTTP."""
import json

import pytest

from aweb.federation.activation import build_federation_authority_activation
from test_dashboard_privacy import TEAM, privacy_app  # noqa: F401
from test_messages_http import _signed_team_headers, _make_certificate, _encode_certificate


@pytest.mark.asyncio
async def test_unknown_local_address_is_not_a_registry_outage(privacy_app):
    env = privacy_app
    team = "default:local"
    await env.db.execute(
        "INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key) VALUES ($1, 'local', 'default', $2)",
        team, env.team_did,
    )
    await env.registry_db.execute(
        "INSERT INTO {{tables.teams}} (domain, name, team_did_key, visibility) VALUES ('local', 'default', $1, 'public')",
        env.team_did,
    )
    await env.registry_db.execute(
        "INSERT INTO {{tables.dns_namespaces}} (domain, controller_did, verification_status) VALUES ('local', $1, 'verified')",
        env.team_did,
    )
    actor = env.actors["alice"]
    await env.db.execute("UPDATE {{tables.agents}} SET team_id = $1 WHERE agent_id = $2", team, actor.id)
    await env.db.execute("UPDATE {{tables.workspaces}} SET team_id = $1 WHERE workspace_id = $2", team, actor.workspace)
    certificate = _encode_certificate(_make_certificate(env.team_sk, env.team_did, actor.did, team_id=team,
                                                       alias="alice", identity_scope="local"))
    activation = build_federation_authority_activation(env.infra, public_origin=env.app.state.public_origin)
    queries = []

    class NoExternalDNS:
        async def lookup_txt(self, name):
            queries.append(name)
            raise RuntimeError("local recipient lookup must not require external DNS")

    activation.txt_resolver = NoExternalDNS()
    env.app.state.federation_authority = activation
    actor = env.actors["alice"]
    body = json.dumps({"to_address": "local/bbo", "subject": "hello", "body": "hello"}).encode()
    headers = _signed_team_headers(actor.sk, actor.did, team, certificate, body)
    headers["Content-Type"] = "application/json"
    try:
        response = await env.client.post("/v1/messages", content=body, headers=headers)
        assert response.status_code == 404, response.text
        assert response.json()["reason"] == "recipient_identity_not_found"
        assert response.json()["retryable"] is False
        assert queries == []
        assert await env.db.fetch_value("SELECT COUNT(*) FROM {{tables.messages}}") == 0
    finally:
        await activation.aclose()

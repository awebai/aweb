"""Team tools require presented membership evidence; identity messaging survives.

Exercise the real MCP middleware/tools and the HTTP team route over a local
listener, with PostgreSQL, Redis and the real AWID app. The two projection
states reproduce F-26: a pre-017 row with no certificate ID and an unregistered
certificate while the existence requirement is off. Authentication is not
overridden, and no AuthContext is supplied by the test.
"""

from __future__ import annotations

import json
from uuid import UUID, uuid4

import pytest

from aweb.config import require_registered_certificates
from aweb.internal_auth import build_internal_auth_header_value
from aweb.mcp.server import create_mcp_app
from test_dashboard_privacy import TEAM, privacy_app  # noqa: F401
from test_messages_http import _signed_identity_headers, _signed_team_headers


TEAM_TOOL_REFUSAL = {
    "error": "This tool requires team context. Use a team certificate."
}
TEAM_TOOLS = (
    "task_list",
    "roles_show",
    "instructions_show",
    "workspace_status",
)


@pytest.mark.asyncio
@pytest.mark.parametrize("projection", ["pre_017", "unregistered_certificate"])
async def test_identity_only_mcp_cannot_use_projection_as_team_evidence(
    privacy_app, monkeypatch, projection,
):
    env = privacy_app
    alice, bob = env.actors["alice"], env.actors["bob"]
    monkeypatch.delenv("AWEB_REQUIRE_REGISTERED_CERTIFICATES", raising=False)
    assert not require_registered_certificates()
    certificate_id = None if projection == "pre_017" else "privacy-alice"
    await env.db.execute(
        "UPDATE {{tables.agents}} SET certificate_id=$1 WHERE agent_id=$2",
        certificate_id, alice.id,
    )
    assert await env.registry_db.fetch_value(
        "SELECT COUNT(*) FROM {{tables.team_certificates}} WHERE certificate_id=$1",
        "privacy-alice",
    ) == 0

    origin = str(env.client.base_url).rstrip("/")
    registry = env.app.state.awid_registry_client
    mcp = create_mcp_app(
        db_infra=env.infra, redis=env.redis,
        registry_client=registry, public_origin=origin,
    )
    env.app.mount("/certificate-evidence-mcp", mcp)
    await mcp.startup()
    try:
        async def call(tool, *, certificate=False, **arguments):
            body = json.dumps({
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": tool, "arguments": arguments},
            }).encode()
            auth = (
                _signed_team_headers(
                    alice.sk, alice.did, TEAM, alice.certificate, body,
                )
                if certificate
                else _signed_identity_headers(alice.sk, alice.did, "", body)
            )
            response = await env.client.post(
                "/certificate-evidence-mcp/", content=body,
                headers={
                    **auth, "Content-Type": "application/json",
                    "Accept": "application/json, text/event-stream",
                },
            )
            assert response.status_code == 200, response.text
            result = response.json()
            assert "error" not in result, result
            tool_result = result["result"]
            assert not tool_result.get("isError"), tool_result
            return json.loads(tool_result["content"][0]["text"])

        # The matching HTTP team route already refuses the bare identity.
        http_identity = await env.client.get(
            "/v1/tasks",
            headers=_signed_identity_headers(alice.sk, alice.did, ""),
        )
        assert http_identity.status_code == 401, http_identity.text

        # Populate real coordination state with a certificate-bearing request.
        task = await call(
            "task_create", certificate=True, title="Certificate-only task",
        )
        assert "error" not in task, task
        task_id = UUID(task["task_id"])
        assert await env.db.fetch_value(
            "SELECT title FROM {{tables.tasks}} WHERE task_id=$1", task_id,
        ) == "Certificate-only task"
        http_certificate = await env.client.get(
            "/v1/tasks",
            headers=_signed_team_headers(
                alice.sk, alice.did, TEAM, alice.certificate,
            ),
        )
        assert http_certificate.status_code == 200, http_certificate.text
        for tool in TEAM_TOOLS:
            control = await call(tool, certificate=True)
            assert "error" not in control, (tool, control)

        # Certificate auth heals a pre-017 projection; restore the observed
        # initial state before exercising identity-only requests.
        await env.db.execute(
            "UPDATE {{tables.agents}} SET certificate_id=$1 WHERE agent_id=$2",
            certificate_id, alice.id,
        )

        # Identity-only MCP must still perform real identity-scoped messaging.
        sent = await call("send_mail", to=bob.did, body="Identity messaging")
        assert "error" not in sent, sent
        delivered = await env.db.fetch_one(
            "SELECT from_did, to_did, body FROM {{tables.messages}} WHERE message_id=$1",
            UUID(sent["message_id"]),
        )
        assert dict(delivered) == {
            "from_did": alice.did, "to_did": bob.did,
            "body": "Identity messaging",
        }
        inbox = await call("check_mail")
        assert "error" not in inbox, inbox

        # Every family must refuse DB-derived team context, even though the
        # projection is unique and the staged existence check is disabled.
        actual = {tool: await call(tool) for tool in TEAM_TOOLS}
        assert actual == {tool: TEAM_TOOL_REFUSAL for tool in TEAM_TOOLS}
    finally:
        await mcp.shutdown()


@pytest.mark.asyncio
async def test_trusted_proxy_mcp_keeps_team_tools_without_certificate(
    privacy_app, monkeypatch,
):
    env = privacy_app
    alice = env.actors["alice"]
    secret = "certificate-evidence-test-proxy-secret"
    monkeypatch.setenv("AWEB_TRUST_PROXY_HEADERS", "1")
    monkeypatch.setenv("AWEB_INTERNAL_AUTH_SECRET", secret)
    user_id = str(uuid4())
    headers = {
        "X-Team-ID": TEAM,
        "X-User-ID": user_id,
        "X-AWEB-Actor-ID": str(alice.id),
        "X-AWEB-Auth": build_internal_auth_header_value(
            secret=secret, team_id=TEAM, principal_type="u",
            principal_id=user_id, actor_id=str(alice.id),
        ),
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    mcp = create_mcp_app(
        db_infra=env.infra, redis=env.redis,
        registry_client=env.app.state.awid_registry_client,
        public_origin=str(env.client.base_url).rstrip("/"),
    )
    env.app.mount("/proxy-evidence-mcp", mcp)
    await mcp.startup()
    try:
        body = json.dumps({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {
                "name": "task_create",
                "arguments": {"title": "Trusted proxy task"},
            },
        }).encode()
        invalid = await env.client.post(
            "/proxy-evidence-mcp/", content=body,
            headers={**headers, "X-AWEB-Auth": headers["X-AWEB-Auth"] + "bad"},
        )
        assert invalid.status_code == 401, invalid.text

        response = await env.client.post(
            "/proxy-evidence-mcp/", content=body, headers=headers,
        )
        assert response.status_code == 200, response.text
        result = response.json()
        assert "error" not in result, result
        tool_result = result["result"]
        assert not tool_result.get("isError"), tool_result
        task = json.loads(tool_result["content"][0]["text"])
        assert "error" not in task, task
        assert await env.db.fetch_value(
            "SELECT title FROM {{tables.tasks}} WHERE task_id=$1",
            UUID(task["task_id"]),
        ) == "Trusted proxy task"
    finally:
        await mcp.shutdown()

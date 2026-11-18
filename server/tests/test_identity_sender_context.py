"""The selected native membership supplies From, never address listing order."""

from __future__ import annotations

import json
from enum import StrEnum
from uuid import UUID, uuid4

import pytest
from aweb.api import _mount_mcp_app, _shutdown_mcp_app
from test_cli_never_grants import registry_listener
from test_dashboard_privacy import TEAM, privacy_app  # noqa: F401
from test_messages_http import (
    _encode_certificate,
    _make_certificate,
    _signed_identity_headers,
    _signed_team_headers,
)
from test_team_key_pinning import register_namespace_controller


class SenderTransport(StrEnum):
    HTTP = "http"
    MCP = "mcp"


async def _send(
    env, *, actor, stable_did: str, certificate: str | None, transport: SenderTransport
):
    if transport is SenderTransport.HTTP:
        path = "/v1/messages"
        payload = {"to_did": env.actors["bob"].did, "body": "Selected sender", "subject": "From"}
    else:
        path = "/mcp/"
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "send_mail",
                "arguments": {
                    "to": env.actors["bob"].did,
                    "body": "Selected sender",
                    "subject": "From",
                    "plaintext": True,
                },
            },
        }
    body = json.dumps(payload).encode()
    headers = (
        _signed_team_headers(actor.sk, actor.did, TEAM, certificate, body)
        if certificate is not None
        else _signed_identity_headers(actor.sk, actor.did, stable_did, body)
    )
    response = await env.client.post(
        path,
        content=body,
        headers={
            **headers,
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        },
    )
    assert response.status_code == 200, response.text
    result = response.json()
    if transport is SenderTransport.MCP:
        assert "error" not in result, result
        assert not result["result"].get("isError"), result
        result = json.loads(result["result"]["content"][0]["text"])
    assert "error" not in result, result
    return UUID(result["message_id"])


@pytest.mark.asyncio
@pytest.mark.parametrize("transport", list(SenderTransport))
async def test_identity_sender_uses_its_single_current_context_not_first_registered_address(
    privacy_app, transport
):
    # trust-model.md:186-191 and identity-messaging-contract.md:381-382.
    # Namespace is a fixture precondition; DID/address creation, native
    # admission and both message transports use real production routes.
    env = privacy_app
    actor = env.actors["alice"]
    async with registry_listener(env) as (registry, _):
        await register_namespace_controller(env, env.team_did)
        stable = (await registry.register_did(actor.did, actor.sk)).did_aw
        prefix = "sender-" + uuid4().hex[:12]
        earlier = await registry.register_address(
            "example.test",
            prefix + "-other",
            stable,
            env.team_sk,
            current_did_key=actor.did,
        )
        selected = await registry.register_address(
            "example.test",
            prefix + "-selected",
            stable,
            env.team_sk,
            current_did_key=actor.did,
        )
        selected_address = f"{selected.domain}/{selected.name}"
        addresses = await registry.list_did_addresses(stable)
        assert f"{addresses[0].domain}/{addresses[0].name}" == f"{earlier.domain}/{earlier.name}"
        certificate = _encode_certificate(
            _make_certificate(
                env.team_sk,
                env.team_did,
                actor.did,
                team_id=TEAM,
                alias="alice",
                identity_scope="global",
                member_did_aw=stable,
                member_address=selected_address,
                certificate_id="selected-address-" + uuid4().hex,
            )
        )
        body = b"{}"
        admitted = await env.client.post(
            "/v1/connect",
            content=body,
            headers={
                **_signed_team_headers(actor.sk, actor.did, TEAM, certificate, body),
                "Content-Type": "application/json",
            },
        )
        assert admitted.status_code == 200, admitted.text
        await _mount_mcp_app(env.app, env.infra, env.redis, registry)
        try:
            positive = await _send(
                env,
                actor=actor,
                stable_did=stable,
                certificate=certificate,
                transport=transport,
            )
            assert (
                await env.db.fetch_value(
                    "SELECT from_address FROM {{tables.messages}} WHERE message_id=$1",
                    positive,
                )
                == selected_address
            )
            identity_only = await _send(
                env,
                actor=actor,
                stable_did=stable,
                certificate=None,
                transport=transport,
            )
            row = await env.db.fetch_one(
                "SELECT from_did,from_address FROM {{tables.messages}} WHERE message_id=$1",
                identity_only,
            )
            assert row["from_did"] == stable
            assert row["from_address"] == selected_address
        finally:
            await _shutdown_mcp_app(env.app)

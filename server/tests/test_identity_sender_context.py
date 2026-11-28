"""The selected native membership supplies From, never address listing order."""

from __future__ import annotations

import json
from enum import StrEnum
from uuid import UUID, uuid4

import pytest
from awid.dns_verify import DomainAuthority
from awid_service.deps import get_domain_verifier
from mcp_runtime_fixtures import mounted_mcp
from test_cli_never_grants import registry_listener
from test_dashboard_privacy import TEAM
from test_dashboard_privacy import privacy_app as privacy_app
from test_messages_http import (
    _encode_certificate,
    _make_certificate,
    _signed_identity_headers,
    _signed_team_headers,
)

__all__ = ["privacy_app"]


class SenderTransport(StrEnum):
    HTTP = "http"
    MCP = "mcp"


async def _send_response(
    env, *, actor, stable_did: str, certificate: str | None, transport: SenderTransport
):
    if transport is SenderTransport.HTTP:
        path = "/v1/messages"
        payload = {
            "to_did": env.actors["bob"].did,
            "body": "Selected sender",
            "subject": "From",
        }
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
    return response


async def _send(
    env, *, actor, stable_did: str, certificate: str | None, transport: SenderTransport
):
    response = await _send_response(
        env,
        actor=actor,
        stable_did=stable_did,
        certificate=certificate,
        transport=transport,
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
    # trust-model.md:186-191 and Receiver-Wide Replay And Contact Compatibility
    # (docs/identity-messaging-contract.md:374-378).
    # Namespace is a fixture precondition; DID/address creation, native
    # admission and both message transports use real production routes.
    env = privacy_app
    actor = env.actors["alice"]
    async with registry_listener(env) as (registry, registry_origin):
        # Supply the external DNS fact to the actual registry route; all
        # signatures, address writes and native admission remain production.
        async def exact_namespace_authority(domain: str) -> DomainAuthority:
            assert domain == "example.test"
            return DomainAuthority(
                env.namespace_did, registry_origin, "_awid.example.test"
            )

        env.registry_app.dependency_overrides[get_domain_verifier] = lambda: (
            exact_namespace_authority
        )
        stable = (await registry.register_did(actor.did, actor.sk)).did_aw
        prefix = "a-" + uuid4().hex[:12]
        earlier = await registry.register_address(
            "example.test",
            prefix + "-other",
            stable,
            env.namespace_sk,
            current_did_key=actor.did,
        )
        selected = await registry.register_address(
            "example.test",
            "alice",
            stable,
            env.namespace_sk,
            current_did_key=actor.did,
        )
        selected_address = f"{selected.domain}/{selected.name}"
        addresses = await registry.list_did_addresses(stable)
        assert (
            f"{addresses[0].domain}/{addresses[0].name}"
            == f"{earlier.domain}/{earlier.name}"
        )
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
        async with mounted_mcp(
            env.app,
            db_infra=env.infra,
            redis=env.redis,
            registry_client=registry,
        ):
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

            # Add another independently verified native member context with a
            # different exact From. Listing order cannot choose between them.
            second_name = "sender-context-" + uuid4().hex[:12]
            await registry.register_team(
                domain="example.test",
                name=second_name,
                display_name="Second sender context",
                team_did_key=env.team_did,
                visibility="public",
                namespace_controller_signing_key=env.namespace_sk,
            )
            second_team = second_name + ":example.test"
            second_certificate = _encode_certificate(
                _make_certificate(
                    env.team_sk,
                    env.team_did,
                    actor.did,
                    team_id=second_team,
                    alias=earlier.name,
                    identity_scope="global",
                    member_did_aw=stable,
                    member_address=f"{earlier.domain}/{earlier.name}",
                    certificate_id="second-context-" + uuid4().hex,
                )
            )
            connected = await env.client.post(
                "/v1/connect",
                content=b"{}",
                headers={
                    **_signed_team_headers(
                        actor.sk, actor.did, second_team, second_certificate, b"{}"
                    ),
                    "Content-Type": "application/json",
                },
            )
            assert connected.status_code == 200, connected.text
            before = await env.db.fetch_value(
                "SELECT count(*) FROM {{tables.messages}} WHERE from_did=$1",
                stable,
            )
            refused = await _send_response(
                env,
                actor=actor,
                stable_did=stable,
                certificate=None,
                transport=transport,
            )
            if transport is SenderTransport.HTTP:
                assert refused.status_code == 409, refused.text
            else:
                assert refused.status_code == 200, refused.text
            # The MCP transport keeps a tool refusal in its result envelope;
            # both shapes retain the same code and exact credential remedy.
            assert "sender_context_required" in refused.text
            assert "X-AWID-Team-Certificate" in refused.text
            assert "pass --team" in refused.text
            assert "aw 1.36.59 or later" in refused.text
            assert (
                await env.db.fetch_value(
                    "SELECT count(*) FROM {{tables.messages}} WHERE from_did=$1",
                    stable,
                )
                == before
            )
            selected_again = await _send(
                env,
                actor=actor,
                stable_did=stable,
                certificate=certificate,
                transport=transport,
            )
            assert (
                await env.db.fetch_value(
                    "SELECT from_address FROM {{tables.messages}} WHERE message_id=$1",
                    selected_again,
                )
                == selected_address
            )

"""Messaging actors admitted by the shared registry and native HTTP owners."""

from dataclasses import dataclass, field
import json
from typing import Protocol
from uuid import UUID, uuid4

from fastapi import FastAPI
import httpx
from nacl.signing import SigningKey

from awid.did import did_from_public_key
from awid.identity_observation import IdentityKind
from awid_service.testing import Registry
from aweb.application_state import application_registry_client
from aweb.routes.connect import ConnectResponse
from test_messages_http import _encode_certificate, _make_certificate, _signed_team_headers


class MessagingFixture(Protocol):
    app: FastAPI
    client: httpx.AsyncClient
    registry: Registry
    team_sk: bytes
    team_did: str


@dataclass(frozen=True, kw_only=True)
class RegisteredMessagingActor:
    alias: str
    signing_key: bytes = field(repr=False)
    did_key: str
    stable_id: str
    address: str
    team_id: str
    agent_id: str
    workspace_id: str
    certificate: str


async def register_messaging_team(env: MessagingFixture, *, team_id: str) -> None:
    """Keep namespace custody separate from team signing (docs/identity.md:86-99)."""
    name, domain = team_id.split(":", 1)
    controller = await env.registry.ensure_namespace(domain=domain)
    registry = application_registry_client(env.app.state)
    existing = await registry.get_team(domain, name)
    if existing is None:
        await registry.register_team(
            domain=domain,
            name=name,
            display_name=name,
            team_did_key=env.team_did,
            visibility="public",
            namespace_controller_signing_key=bytes(controller),
        )
    else:
        assert existing.team_did_key == env.team_did


async def _certify_kind(
    env: MessagingFixture,
    *,
    kind: IdentityKind,
    stable_id: str,
    key: SigningKey,
) -> None:
    """Enroll the subject's own signed kind (docs/id-certificates.md:238-245)."""
    from test_id_chain_request_auth import ROOT, _signed_fixture_certificate

    domain = f"messaging-kind-{uuid4().hex}.test"
    await env.registry.ensure_namespace(
        domain=domain, controller=SigningKey(bytes.fromhex(ROOT["seed_hex"]))
    )
    certificate = _signed_fixture_certificate(
        "alice" if kind is IdentityKind.HUMAN else "root-agent",
        domain=domain,
        identity=stable_id,
        parent={"kind": "namespace", "id": domain},
        issuer="root",
    )
    registry = application_registry_client(env.app.state)
    await registry.register_id_certificate(
        {"v": 1, "type": "aweb.id-chain", "certificates": [certificate]},
        signer=lambda payload: (
            did_from_public_key(bytes(key.verify_key)),
            key.sign(payload).signature,
        ),
        expected_head=None,
        invitation_id=None,
    )


async def admit_messaging_actor(
    env: MessagingFixture,
    *,
    alias: str,
    team_id: str,
    address: str = "",
    kind: IdentityKind = IdentityKind.UNKNOWN,
    signing_key: bytes | None = None,
) -> RegisteredMessagingActor:
    """Register identity facts, then verify a certificate at native connect.

    docs/identity.md:97-99 makes the controller certificate membership authority;
    no row or cached observation is supplied as a substitute.
    """
    if not isinstance(kind, IdentityKind):
        raise TypeError("Pass a named IdentityKind before admitting a messaging actor.")
    key = SigningKey(signing_key) if signing_key is not None else SigningKey.generate()
    did_key = did_from_public_key(bytes(key.verify_key))
    registry = application_registry_client(env.app.state)
    identity = await registry.register_did(did_key, bytes(key))
    if address:
        domain, name = address.split("/", 1)
        controller = await env.registry.ensure_namespace(domain=domain)
        await registry.register_address(
            domain, name, identity.did_aw, bytes(controller), current_did_key=did_key
        )
    if kind is not IdentityKind.UNKNOWN:
        await _certify_kind(env, kind=kind, stable_id=identity.did_aw, key=key)
    certificate_fields = _make_certificate(
        env.team_sk,
        env.team_did,
        did_key,
        team_id=team_id,
        alias=alias,
        identity_scope="global",
        member_did_aw=identity.did_aw,
        member_address=address,
        certificate_id=f"messaging-{uuid4()}",
    )
    certificate = _encode_certificate(certificate_fields)
    team_name, team_domain = team_id.split(":", 1)
    await registry.register_team_certificate(
        team_domain,
        team_name,
        team_controller_signing_key=env.team_sk,
        certificate_id=certificate_fields["certificate_id"],
        member_did_key=did_key,
        member_did_aw=identity.did_aw,
        member_address=address,
        alias=alias,
        identity_scope="global",
        certificate=certificate,
    )
    raw = json.dumps({"agent_type": "agent"}).encode()
    response = await env.client.post(
        "/v1/connect",
        content=raw,
        headers={
            **_signed_team_headers(bytes(key), did_key, team_id, certificate, raw),
            "Content-Type": "application/json",
        },
    )
    assert response.status_code == 200, response.text
    connected = ConnectResponse.model_validate_json(response.content)
    assert connected.alias == alias and connected.team_id == team_id
    if kind is IdentityKind.HUMAN:
        assert connected.agent_type == "human"
    return RegisteredMessagingActor(
        alias=alias,
        signing_key=bytes(key),
        did_key=did_key,
        stable_id=identity.did_aw,
        address=address,
        team_id=team_id,
        agent_id=str(UUID(connected.agent_id)),
        workspace_id=str(UUID(connected.workspace_id)),
        certificate=certificate,
    )

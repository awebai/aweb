"""Messaging actors admitted by the shared registry and native HTTP owners."""

import base64
from dataclasses import dataclass, field, replace
from contextlib import contextmanager
import json
from typing import Protocol
from types import SimpleNamespace
from uuid import UUID, uuid4

from fastapi import FastAPI
import httpx
from nacl.signing import SigningKey

from awid.did import did_from_public_key
from awid.identity_observation import IdentityKind
from awid.registry import RegistryClient
from awid_service.testing import Registry
from aweb.application_state import application_registry_client
from aweb.lifecycle import (
    LifecycleActor,
    LifecycleCascadeRequest,
    apply_lifecycle_cascade,
)
from aweb.routes.connect import ConnectResponse
from test_messages_http import (
    _encode_certificate,
    _make_certificate,
    _signed_team_headers,
)


class MessagingFixture(Protocol):
    app: FastAPI
    client: httpx.AsyncClient
    registry: Registry
    team_sk: bytes
    team_did: str


@dataclass(frozen=True, kw_only=True)
class RegisteredMessagingActor:
    signing_key: bytes = field(repr=False)
    did_key: str
    stable_id: str
    address: str
    team_id: str
    agent_id: str
    certificate: str
    workspace_id: str = ""


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
            namespace_controller_signing_key=controller,
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
        domain=domain, controller=bytes.fromhex(ROOT["seed_hex"])
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
    local: bool = False,
    existing_identity: RegisteredMessagingActor | None = None,
) -> RegisteredMessagingActor:
    """Register identity facts, then verify a certificate at native connect.

    docs/identity.md:97-99 makes the controller certificate membership authority;
    no row or cached observation is supplied as a substitute.
    """
    if not isinstance(kind, IdentityKind):
        raise TypeError("Pass a named IdentityKind before admitting a messaging actor.")
    if existing_identity is not None:
        if local or (
            signing_key is not None and signing_key != existing_identity.signing_key
        ):
            raise ValueError("Reuse a global identity with its existing signing key.")
        signing_key = existing_identity.signing_key
        address = existing_identity.address
    key = SigningKey(signing_key) if signing_key is not None else SigningKey.generate()
    did_key = did_from_public_key(bytes(key.verify_key))
    registry = application_registry_client(env.app.state)
    if local and (address or kind is not IdentityKind.UNKNOWN):
        raise ValueError(
            "Admit a local actor without a global address or ID-tree kind."
        )
    if existing_identity is not None:
        stable_id = existing_identity.stable_id
    elif local:
        stable_id = ""
    else:
        stable_id = (await registry.register_did(did_key, bytes(key))).did_aw
    if address and existing_identity is None:
        domain, name = address.split("/", 1)
        controller = await env.registry.ensure_namespace(domain=domain)
        await registry.register_address(
            domain, name, stable_id, controller, current_did_key=did_key
        )
    if kind is not IdentityKind.UNKNOWN:
        await _certify_kind(env, kind=kind, stable_id=stable_id, key=key)
    certificate_fields = _make_certificate(
        env.team_sk,
        env.team_did,
        did_key,
        team_id=team_id,
        alias=alias,
        identity_scope="local" if local else "global",
        member_did_aw=stable_id,
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
        member_did_aw=stable_id,
        member_address=address,
        alias=alias,
        identity_scope="local" if local else "global",
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
        signing_key=bytes(key),
        did_key=did_key,
        stable_id=stable_id,
        address=address,
        team_id=team_id,
        agent_id=str(UUID(connected.agent_id)),
        workspace_id=str(UUID(connected.workspace_id)),
        certificate=certificate,
    )


async def set_messaging_inbound_mode(
    env: MessagingFixture, actor: RegisteredMessagingActor, mode: str
) -> None:
    """Choose receive policy through the same signed preference route as clients."""
    body = json.dumps({"inbound_mode": mode}).encode()
    response = await env.client.patch(
        "/v1/agents/me/inbound-mode",
        content=body,
        headers=messaging_actor_headers(actor, body=body),
    )
    assert response.status_code == 200, response.text
    assert response.json()["inbound_mode"] == mode


async def archive_messaging_actor(
    db,
    redis,
    *,
    team_id: str,
    agent_id,
    registry_client: RegistryClient | None,
) -> None:
    result = await apply_lifecycle_cascade(
        db,
        redis,
        LifecycleCascadeRequest(
            operation="archive_global_agent",
            actor=LifecycleActor(None, "support", "support"),
            team_id=team_id,
            target_agent_id=str(agent_id),
            workspace_scope="all_for_agent",
            require_identity_scope="global",
        ),
        registry_client=registry_client,
    )
    assert result.identity_archived, result.errors


async def remove_messaging_agent_from_sessions(
    db,
    redis,
    *,
    team_id: str,
    agent_id,
    registry_client: RegistryClient | None,
) -> None:
    result = await apply_lifecycle_cascade(
        db,
        redis,
        LifecycleCascadeRequest(
            operation="cleanup_agent_coordination_state",
            actor=LifecycleActor(None, "support", "support"),
            team_id=team_id,
            target_agent_id=str(agent_id),
            workspace_scope="all_for_agent",
        ),
        registry_client=registry_client,
    )
    assert not result.errors, result.errors
    assert result.chat_participant_cleanup_count == 1


@contextmanager
def record_registry_requests(env):
    """Observe HTTP at the actual registry app and forward every request unchanged."""
    original = (
        env.registry_app.middleware_stack or env.registry_app.build_middleware_stack()
    )
    requests: list[tuple[str, str]] = []

    async def record(scope, receive, send):
        if scope.get("type") == "http":
            requests.append((scope["method"], scope["path"]))
        await original(scope, receive, send)

    env.registry_app.middleware_stack = record
    try:
        yield requests
    finally:
        env.registry_app.middleware_stack = original


async def register_messaging_actors(
    env, *, team_id, aliases, local=False, addressed=True
):
    """Create the named test members through registry writes and signed connect."""
    await register_messaging_team(env, team_id=team_id)
    domain = team_id.split(":", 1)[1]
    return {
        alias: await admit_messaging_actor(
            env,
            alias=alias,
            team_id=team_id,
            address="" if local or not addressed else f"{domain}/{alias}",
            local=local,
        )
        for alias in aliases
    }


async def issue_global_certificate_to_local_member(
    env: MessagingFixture,
    actor: RegisteredMessagingActor,
    *,
    address: str,
) -> RegisteredMessagingActor:
    """Publish the identity and its replacement certificate before native reconnect."""
    registry = application_registry_client(env.app.state)
    mapping = await registry.register_did(actor.did_key, actor.signing_key)
    domain, name = address.split("/", 1)
    controller = await env.registry.ensure_namespace(domain=domain)
    await registry.register_address(
        domain,
        name,
        mapping.did_aw,
        bytes(controller),
        current_did_key=actor.did_key,
    )
    previous = json.loads(base64.b64decode(actor.certificate))
    certificate = _make_certificate(
        env.team_sk,
        env.team_did,
        actor.did_key,
        team_id=actor.team_id,
        alias=previous["alias"],
        identity_scope="global",
        member_did_aw=mapping.did_aw,
        member_address=address,
        certificate_id=f"messaging-global-{uuid4()}",
    )
    team_name, team_domain = actor.team_id.split(":", 1)
    await registry.revoke_team_certificate(
        team_domain,
        team_name,
        team_controller_signing_key=env.team_sk,
        certificate_id=previous["certificate_id"],
    )
    await env.registry.add_certificate(certificate, team_key=SigningKey(env.team_sk))
    return replace(
        actor,
        stable_id=mapping.did_aw,
        address=address,
        certificate=_encode_certificate(certificate),
    )


def messaging_actor_headers(actor, *, body=b"", team=True):
    """Sign exact request bytes with the actor's admitted certificate or identity."""
    from test_messages_http import _signed_identity_headers

    headers = (
        _signed_team_headers(
            actor.signing_key, actor.did_key, actor.team_id, actor.certificate, body
        )
        if team
        else _signed_identity_headers(
            actor.signing_key, actor.did_key, actor.stable_id, body
        )
    )
    return {**headers, "Content-Type": "application/json"}


async def add_messaging_contact(
    env, owner, *, address, key_owner=False, status="active"
):
    """Use the contact service with current SDK address/controller evidence."""
    from aweb.messaging.contacts import add_contact

    domain, alias = address.split("/", 1)
    registry = application_registry_client(env.app.state)
    resolved = await registry.resolve_address(domain, alias)
    namespace = await registry.get_namespace(domain)
    assert resolved is not None and namespace is not None
    return await add_contact(
        env.infra,
        owner_did=owner.did_key if key_owner else owner.stable_id,
        contact_address=address,
        contact_did_aw=resolved.did_aw,
        binding_controller_did=namespace.controller_did,
        label="Alice",
        status=status,
    )


async def send_messaging_mail(env, sender, *, payload):
    """Store a message through authenticated native send, preserving payload bytes."""
    raw = json.dumps(payload).encode()
    response = await env.client.post(
        "/v1/messages",
        content=raw,
        headers=messaging_actor_headers(sender, body=raw),
    )
    assert response.status_code == 200, response.text
    return response


async def admit_privacy_actor(
    env,
    alias,
    *,
    team_id=None,
    address="",
    kind=IdentityKind.UNKNOWN,
    local=False,
    new_identity=False,
    existing_identity=None,
    member_alias=None,
):
    """Port a privacy fixture actor through the existing SDK/native admission builder.

    The returned compatibility view contains only the actual connect response
    and the registered actor's custody; no database or proof projection is seeded.
    """
    from test_dashboard_privacy import TEAM

    original = env.actors[alias]
    team_id = team_id or TEAM
    await register_messaging_team(env, team_id=team_id)
    registered = await admit_messaging_actor(
        env,
        alias=member_alias or alias,
        team_id=team_id,
        address=address,
        kind=kind,
        local=local,
        signing_key=None if new_identity else original.sk,
        existing_identity=existing_identity,
    )
    env.actors[alias] = SimpleNamespace(
        sk=registered.signing_key,
        did=registered.did_key,
        id=UUID(registered.agent_id),
        workspace=UUID(registered.workspace_id),
        certificate=registered.certificate,
        stable_id=registered.stable_id,
        address=registered.address,
        team_id=registered.team_id,
        registered=registered,
    )
    return env.actors[alias]

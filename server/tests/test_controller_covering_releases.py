"""Every controller write the Python client makes, against the AWID release
production runs (the locked production-awid project) and against this
repository's AWID.

Each operation is sent once as signed, and must be accepted; and once with its
body changed after signing, and must be refused. Only a signature that covers
the request's bytes (the covering form) tells the two apart: the legacy form
signs the operation's claims, not its body. Setup goes through the same
releases' own routes; DNS authority is the one answer the tests supply.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable
from uuid import uuid4

import httpx
import pytest
from nacl.signing import SigningKey

from aweb_naapp_contracts_testing.production_registry import running_production_registry
from awid.controller_signing import ControllerDescriptor, parse_controller_request
from awid.did import did_key_from_signing_key
from awid.dns_verify import DnsVerificationError, DomainAuthority
from awid.registry import RegistryClient, RegistryError
from awid_service.deps import get_domain_verifier
from awid_service.testing import REGISTRY_URL, running_registry
from test_messages_http import _encode_certificate, _make_certificate

pytestmark = pytest.mark.asyncio

RELEASES = ("main", "production")


@asynccontextmanager
async def _release(kind: str, database_url: str):
    if kind == "production":
        async with running_production_registry(database_url) as registry:
            yield registry
    else:
        async with running_registry(database_url) as registry:
            yield registry


class _ChangedAfterSigning(httpx.AsyncBaseTransport):
    """Sends each write with its body changed but still valid JSON (a space
    appended; an empty body becomes ``{}``), the request's headers (and so its
    signatures) unchanged."""

    def __init__(self, inner: httpx.AsyncBaseTransport) -> None:
        self._inner = inner

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        if request.method != "GET":
            sent = await request.aread()
            body = sent + b" " if sent else b"{}"
            headers = [(k, v) for k, v in request.headers.raw if k.lower() not in (b"content-length", b"content-type")]
            headers.append((b"content-type", b"application/json"))
            request = httpx.Request(request.method, request.url, headers=headers, content=body)
        return await self._inner.handle_async_request(request)


class _Recorded(httpx.AsyncBaseTransport):
    def __init__(self, inner: httpx.AsyncBaseTransport) -> None:
        self._inner = inner
        self.writes: list[httpx.Request] = []

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        if request.method != "GET":
            self.writes.append(request)
        return await self._inner.handle_async_request(request)


def _did(key: SigningKey) -> str:
    return did_key_from_signing_key(bytes(key))


@dataclass
class World:
    """One namespace with its controller, a team with its key, and the DNS
    answer the release is given for each domain."""

    registry: Any
    domain: str = field(default_factory=lambda: f"cov-{uuid4().hex[:12]}.test")
    namespace_key: SigningKey = field(default_factory=SigningKey.generate)
    team_key: SigningKey = field(default_factory=SigningKey.generate)
    team: str = "team"
    dns: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.dns[self.domain] = _did(self.namespace_key)

        async def verify(domain: str) -> DomainAuthority:
            if domain not in self.dns:
                raise DnsVerificationError(f"No TXT records found for _awid.{domain}")
            return DomainAuthority(self.dns[domain], REGISTRY_URL, "_awid." + domain)

        self.registry.app.dependency_overrides[get_domain_verifier] = lambda: verify

    def client(self, transport: httpx.AsyncBaseTransport | None = None) -> RegistryClient:
        return RegistryClient(registry_url=REGISTRY_URL, transport=transport or self.registry.transport)

    async def namespace(self) -> None:
        await self.client().register_namespace(self.domain, _did(self.namespace_key), bytes(self.namespace_key))

    async def with_team(self) -> None:
        await self.namespace()
        await self.client().register_team(
            domain=self.domain, name=self.team, display_name="Team", team_did_key=_did(self.team_key),
            visibility="public", namespace_controller_signing_key=bytes(self.namespace_key),
        )

    def certificate(self, certificate_id: str) -> str:
        member = SigningKey.generate()
        return _encode_certificate(_make_certificate(
            bytes(self.team_key), _did(self.team_key), _did(member), team_id=f"{self.team}:{self.domain}",
            alias=f"m-{certificate_id[:8]}", identity_scope="local", certificate_id=certificate_id,
        ))

    async def with_certificate(self) -> str:
        await self.with_team()
        certificate_id = str(uuid4())
        await self._register_certificate(self.client(), certificate_id)
        return certificate_id

    async def _register_certificate(self, client: RegistryClient, certificate_id: str) -> None:
        encoded = self.certificate(certificate_id)
        from awid.team_certificate import decode_team_certificate

        cert = decode_team_certificate(encoded)
        await client.register_team_certificate(
            self.domain, self.team, team_controller_signing_key=bytes(self.team_key),
            certificate_id=certificate_id, member_did_key=cert["member_did_key"], member_did_aw=None,
            member_address=None, alias=cert["alias"], identity_scope="local", certificate=encoded,
        )

    async def identity(self) -> tuple[str, str]:
        key = SigningKey.generate()
        mapping = await self.client().register_did(_did(key), bytes(key))
        return mapping.did_aw, _did(key)

    async def with_address(self) -> str:
        await self.namespace()
        did_aw, current = await self.identity()
        await self.client().register_address(self.domain, "alice", did_aw, bytes(self.namespace_key), current)
        return "alice"


# --- the typed controller client -------------------------------------------


def _descriptor(scope: str, domain: str, key: SigningKey, *, team: str | None = None) -> ControllerDescriptor:
    return ControllerDescriptor(scope, domain, _did(key), _did(key), 0, team=team)


async def _typed(client: RegistryClient, world: World, op: str, signers: dict[str, tuple[ControllerDescriptor, SigningKey]],
                 **parameters: Any) -> Any:
    domain = parameters.pop("domain", world.domain)
    keys = {descriptor.key_reference: key for descriptor, key in signers.values()}

    def signer(context):
        key = keys[context.controller.key_reference]
        return _did(key), key.sign(context.signing_bytes()).signature

    return await client.controller_request(
        parse_controller_request({"operation": op, "domain": domain, **parameters}),
        controllers={role: descriptor for role, (descriptor, _) in signers.items()},
        signer=signer,
    )


def _namespace_signer(world: World, key: SigningKey | None = None, domain: str | None = None):
    key = key or world.namespace_key
    return {"controller": (_descriptor("namespace", domain or world.domain, key), key)}


def _team_signer(world: World):
    return {"controller": (_descriptor("team", world.domain, world.team_key, team=world.team), world.team_key)}


Operation = Callable[[World, RegistryClient], Awaitable[Any]]


async def _typed_namespace_register(world, client):
    return await _typed(client, world, "namespace_register", _namespace_signer(world),
                        controller_did=_did(world.namespace_key))


async def _typed_namespace_register_under_parent(world, client):
    await world.namespace()
    child, child_key = f"sub.{world.domain}", SigningKey.generate()
    signers = {**_namespace_signer(world, child_key, child),
               "parent": (_descriptor("namespace", world.domain, world.namespace_key), world.namespace_key)}
    return await _typed(client, world, "namespace_register", signers, domain=child,
                        controller_did=_did(child_key), parent_domain=world.domain)


async def _typed_namespace_update(world, client):
    await world.namespace()
    return await _typed(client, world, "namespace_update", _namespace_signer(world),
                        default_delivery_origin="https://delivery.example.test")


async def _typed_namespace_delete(world, client):
    await world.namespace()
    return await _typed(client, world, "namespace_delete", _namespace_signer(world))


async def _typed_namespace_reset(world, client):
    await world.namespace()
    new_key = SigningKey.generate()
    world.dns[world.domain] = _did(new_key)
    return await _typed(client, world, "namespace_reset", _namespace_signer(world, new_key),
                        new_controller_did=_did(new_key))


async def _typed_team_register(world, client):
    await world.namespace()
    return await _typed(client, world, "team_register", _namespace_signer(world), name=world.team,
                        display_name="Team", team_did_key=_did(world.team_key), visibility="public")


async def _typed_team_rotate(world, client):
    await world.with_team()
    return await _typed(client, world, "team_rotate", _namespace_signer(world), name=world.team,
                        new_team_did_key=_did(SigningKey.generate()))


async def _typed_team_visibility(world, client):
    await world.with_team()
    return await _typed(client, world, "team_visibility", _team_signer(world), name=world.team, visibility="private")


async def _typed_team_delete(world, client):
    await world.with_team()
    return await _typed(client, world, "team_delete", _namespace_signer(world), name=world.team)


async def _typed_certificate_register(world, client):
    await world.with_team()
    return await _typed(client, world, "certificate_register", _team_signer(world), name=world.team,
                        certificate=world.certificate(str(uuid4())))


async def _typed_certificate_revoke(world, client):
    certificate_id = await world.with_certificate()
    return await _typed(client, world, "certificate_revoke", _team_signer(world), name=world.team,
                        certificate_id=certificate_id)


async def _typed_address_register(world, client):
    await world.namespace()
    did_aw, current = await world.identity()
    return await _typed(client, world, "address_register", _namespace_signer(world), name="alice",
                        did_aw=did_aw, current_did_key=current)


async def _typed_address_update(world, client):
    name = await world.with_address()
    return await _typed(client, world, "address_update", _namespace_signer(world), name=name)


async def _typed_address_delete(world, client):
    name = await world.with_address()
    return await _typed(client, world, "address_delete", _namespace_signer(world), name=name)


async def _typed_address_reassign(world, client):
    name = await world.with_address()
    did_aw, current = await world.identity()
    return await _typed(client, world, "address_reassign", _namespace_signer(world), name=name,
                        did_aw=did_aw, current_did_key=current)


TYPED: dict[str, Operation] = {
    "namespace_register": _typed_namespace_register,
    "namespace_register_under_parent": _typed_namespace_register_under_parent,
    "namespace_update": _typed_namespace_update,
    "namespace_delete": _typed_namespace_delete,
    "namespace_reset": _typed_namespace_reset,
    "team_register": _typed_team_register,
    "team_rotate": _typed_team_rotate,
    "team_visibility": _typed_team_visibility,
    "team_delete": _typed_team_delete,
    "certificate_register": _typed_certificate_register,
    "certificate_revoke": _typed_certificate_revoke,
    "address_register": _typed_address_register,
    "address_update": _typed_address_update,
    "address_delete": _typed_address_delete,
    "address_reassign": _typed_address_reassign,
}


async def _check(test_db_factory, release: str, operation: Operation, *, changed: bool) -> None:
    database = await test_db_factory.create_db(suffix="covering")
    async with _release(release, database.config.get_dsn()) as registry:
        world = World(registry)
        recorded = _Recorded(registry.transport)
        transport = _ChangedAfterSigning(recorded) if changed else recorded
        client = world.client(transport)
        try:
            if changed:
                with pytest.raises(RegistryError) as refused:
                    await operation(world, client)
                assert refused.value.status_code == 401, refused.value
            else:
                await operation(world, client)
                assert recorded.writes, "the operation sent no write"
                for write in recorded.writes:
                    signed = [name for name in ("x-aweb-signed-payload", "x-aweb-parent-signed-payload")
                              if name in write.headers]
                    authorizations = [name for name in ("authorization", "x-aweb-parent-authorization")
                                      if name in write.headers]
                    assert len(signed) == len(authorizations), (write.method, write.url, dict(write.headers))
        finally:
            await client.aclose()


@pytest.mark.parametrize("release", RELEASES)
@pytest.mark.parametrize("operation", sorted(TYPED))
@pytest.mark.parametrize("changed", [False, True], ids=["as_signed", "changed_after_signing"])
async def test_typed_controller_write_covers_its_bytes(test_db_factory, release, operation, changed):
    await _check(test_db_factory, release, TYPED[operation], changed=changed)


# --- the RegistryClient methods (Cloud signs through these) -----------------


async def _method_namespace_register(world, client):
    return await client.register_namespace(world.domain, _did(world.namespace_key), bytes(world.namespace_key))


async def _method_namespace_register_under_parent(world, client):
    await world.namespace()
    child_key = SigningKey.generate()
    return await client.register_namespace(
        f"sub.{world.domain}", _did(child_key), bytes(child_key), parent_signing_key=bytes(world.namespace_key),
    )


async def _method_namespace_update(world, client):
    await world.namespace()
    return await client.update_namespace_delivery_origin(
        world.domain, bytes(world.namespace_key), "https://delivery.example.test",
    )


async def _method_namespace_reset(world, client):
    await world.namespace()
    new_key = SigningKey.generate()
    world.dns[world.domain] = _did(new_key)
    return await client.rotate_namespace_controller(world.domain, _did(new_key), bytes(new_key))


async def _method_namespace_reset_under_parent(world, client):
    await world.namespace()
    child, child_key, new_key = f"sub.{world.domain}", SigningKey.generate(), SigningKey.generate()
    await world.client().register_namespace(
        child, _did(child_key), bytes(child_key), parent_signing_key=bytes(world.namespace_key),
    )
    return await client.rotate_namespace_controller(
        child, _did(new_key), bytes(new_key), parent_signing_key=bytes(world.namespace_key),
    )


async def _method_team_register(world, client):
    await world.namespace()
    return await client.register_team(
        domain=world.domain, name=world.team, display_name="Team", team_did_key=_did(world.team_key),
        visibility="public", namespace_controller_signing_key=bytes(world.namespace_key),
    )


async def _method_team_visibility(world, client):
    await world.with_team()
    return await client.set_team_visibility(world.domain, world.team, "private", bytes(world.team_key))


async def _method_team_delete(world, client):
    await world.with_team()
    return await client.delete_team(world.domain, world.team, bytes(world.namespace_key))


async def _method_certificate_register(world, client):
    await world.with_team()
    return await world._register_certificate(client, str(uuid4()))


async def _method_certificate_revoke(world, client):
    certificate_id = await world.with_certificate()
    return await client.revoke_team_certificate(
        world.domain, world.team, team_controller_signing_key=bytes(world.team_key), certificate_id=certificate_id,
    )


async def _method_address_register(world, client):
    await world.namespace()
    did_aw, current = await world.identity()
    return await client.register_address(world.domain, "alice", did_aw, bytes(world.namespace_key), current)


async def _method_address_update(world, client):
    name = await world.with_address()
    return await client.update_address(world.domain, name, bytes(world.namespace_key))


async def _method_address_delete(world, client):
    name = await world.with_address()
    return await client.delete_address(world.domain, name, bytes(world.namespace_key))


async def _method_address_reassign(world, client):
    name = await world.with_address()
    did_aw, _ = await world.identity()
    return await client.reassign_address(world.domain, name, did_aw, bytes(world.namespace_key))


METHODS: dict[str, Operation] = {
    "register_namespace": _method_namespace_register,
    "register_namespace_under_parent": _method_namespace_register_under_parent,
    "update_namespace_delivery_origin": _method_namespace_update,
    "rotate_namespace_controller": _method_namespace_reset,
    "rotate_namespace_controller_under_parent": _method_namespace_reset_under_parent,
    "register_team": _method_team_register,
    "set_team_visibility": _method_team_visibility,
    "delete_team": _method_team_delete,
    "register_team_certificate": _method_certificate_register,
    "revoke_team_certificate": _method_certificate_revoke,
    "register_address": _method_address_register,
    "update_address": _method_address_update,
    "delete_address": _method_address_delete,
    "reassign_address": _method_address_reassign,
}


@pytest.mark.parametrize("release", RELEASES)
@pytest.mark.parametrize("operation", sorted(METHODS))
@pytest.mark.parametrize("changed", [False, True], ids=["as_signed", "changed_after_signing"])
async def test_registry_client_controller_write_covers_its_bytes(test_db_factory, release, operation, changed):
    await _check(test_db_factory, release, METHODS[operation], changed=changed)

"""A human member of a team on the tests' real AWID registry: a registered
did:aw with a human identity certificate under its namespace, and a member
certificate of the team for it."""

from __future__ import annotations

import base64
from collections.abc import AsyncGenerator, Awaitable, Callable
from contextlib import aclosing, asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from awid.dns_verify import DomainAuthority
from awid.id_certificates import id_certificate_signing_bytes
from awid.registry import RegistryClient
from awid_service.deps import get_domain_verifier
from awid_service.testing import REGISTRY_URL, SERVICE_TOKEN, Registry
from nacl.signing import SigningKey

from aweb_naapp_testing import Member, did_key


@dataclass(frozen=True)
class HumanMember:
    """``member``'s certificate names ``principal``, a human did:aw. ``client``
    reads AWID with the namespace's domain authority, as a human-member check
    needs; ``identity`` is the signed human identity certificate."""

    member: Member
    principal: str
    client: RegistryClient
    identity: dict[str, Any]


@dataclass(frozen=True)
class HumanNamespace:
    """A namespace on the tests' AWID registry whose controller certifies its
    members as humans; ``client`` reads AWID with the namespace's authority,
    and ``authority`` is that domain verifier, for an app's own AWID client."""

    registry: Registry
    client: RegistryClient
    controller: SigningKey
    domain: str
    authority: Callable[[str], Awaitable[DomainAuthority]]

    async def register(self, member: Member) -> HumanMember:
        """Register ``member`` as a human member of its team, whose team the
        caller has added to the registry with ``member``'s team key."""
        client, controller = self.client, self.controller
        principal = (await client.register_did(member.did_key, bytes(member.member_key))).did_aw
        member.extra_cert_fields = {"member_did_aw": principal}
        await self.registry.add_certificate(member.certificate())
        fields = {
            "v": 1,
            "type": "aweb.id-certificate",
            "id": principal,
            "domain": self.domain,
            "parent": {"kind": "namespace", "id": self.domain},
            "kind": "human",
            "issuer_key": did_key(controller),
            "issued_at": datetime.now(UTC).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        signature = (
            base64.urlsafe_b64encode(
                controller.sign(id_certificate_signing_bytes(fields)).signature
            )
            .rstrip(b"=")
            .decode()
        )
        identity = {"certificate": fields, "signature": signature}
        await client.register_id_certificate(
            {"v": 1, "type": "aweb.id-chain", "certificates": [identity]},
            signer=lambda payload: (member.did_key, member.member_key.sign(payload).signature),
            expected_head=None,
            invitation_id=None,
        )
        return HumanMember(member, principal, client, identity)


@asynccontextmanager
async def human_namespace(registry: Registry, domain: str) -> AsyncGenerator[HumanNamespace]:
    """Register ``domain``'s namespace once, under a new controller, for the
    humans the caller registers in it."""
    controller = SigningKey.generate()

    async def authority(name: str) -> DomainAuthority:
        assert name == domain
        return DomainAuthority(
            controller_did=did_key(controller),
            registry_url=REGISTRY_URL,
            dns_name=f"_awid.{name}",
        )

    registry.app.dependency_overrides[get_domain_verifier] = lambda: authority
    registry.app.state.awid_public_origins = (REGISTRY_URL,)
    async with aclosing(
        RegistryClient(
            REGISTRY_URL,
            transport=registry.transport,
            service_token=SERVICE_TOKEN,
            domain_verifier=authority,
        )
    ) as client:
        await client.register_namespace(domain, did_key(controller), bytes(controller))
        yield HumanNamespace(registry, client, controller, domain, authority)


@asynccontextmanager
async def registered_human(registry: Registry, member: Member) -> AsyncGenerator[HumanMember]:
    """Register ``member`` as a human member of its team, whose team the caller
    has added to ``registry`` with ``member``'s team key."""
    async with human_namespace(registry, member.team_id.split(":", 1)[1]) as namespace:
        yield await namespace.register(member)

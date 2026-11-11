"""A human member of a team on the tests' real AWID registry: a registered
did:aw with a human identity certificate under its namespace, and a member
certificate of the team for it."""

from __future__ import annotations

import base64
from collections.abc import AsyncGenerator
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


@asynccontextmanager
async def registered_human(registry: Registry, member: Member) -> AsyncGenerator[HumanMember]:
    """Register ``member`` as a human member of its team, whose team the caller
    has added to ``registry`` with ``member``'s team key."""
    domain = member.team_id.split(":", 1)[1]
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
        principal = (await client.register_did(member.did_key, bytes(member.member_key))).did_aw
        member.extra_cert_fields = {"member_did_aw": principal}
        await registry.add_certificate(member.certificate())
        fields = {
            "v": 1,
            "type": "aweb.id-certificate",
            "id": principal,
            "domain": domain,
            "parent": {"kind": "namespace", "id": domain},
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
        yield HumanMember(member, principal, client, identity)

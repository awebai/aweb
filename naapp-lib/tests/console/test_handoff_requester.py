"""requester_parent against real ID chains on the tests' AWID registry.

A human H, an agent Q that H certified, and an agent R that Q certified. Only
Q's chain names a human as the direct parent; R's nearest human is also H, but
H never approved R, so R does not qualify (handoff-wire 1a).
"""

import base64
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from aweb_naapp_testing import did_key
from awid.id_certificates import encode_id_chain_header, id_certificate_signing_bytes
from nacl.signing import SigningKey
from starlette.requests import Request

from aweb_naapp.console.handoff_requester import CHAIN_HEADER, requester_parent
from aweb_naapp.runtime.team_auth import Principal

pytest_plugins = ("tests.runtime.test_human_member",)


@pytest.fixture
def h(human):
    """The registered human H: its client, signed identity, principal and key."""
    member, principal, client, _, identity = human
    return SimpleNamespace(client=client, identity=identity, principal=principal, key=h.key)


def signed(fields, key: SigningKey) -> dict:
    signature = base64.urlsafe_b64encode(key.sign(id_certificate_signing_bytes(fields)).signature)
    return {"certificate": fields, "signature": signature.rstrip(b"=").decode()}


async def issued_agent(h, parent_chain: list[dict], parent_key: SigningKey, parent_id: str):
    """An agent certified by parent_id, registered with its supporting chain."""
    key = SigningKey.generate()
    agent_id = (await h.client.register_did(did_key(key), bytes(key))).did_aw
    fields = {
        "v": 1, "type": "aweb.id-certificate", "id": agent_id,
        "domain": h.identity["certificate"]["domain"],
        "parent": {"kind": "identity", "id": parent_id}, "kind": "agent",
        "issuer_key": did_key(parent_key),
        "issued_at": datetime.now(UTC).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    chain = [*parent_chain, signed(fields, parent_key)]
    bundle = {"v": 1, "type": "aweb.id-chain", "certificates": chain}
    await h.client.register_id_certificate(
        bundle, signer=lambda payload: (did_key(key), key.sign(payload).signature),
        expected_head=None, invitation_id=None,
    )
    return agent_id, key, chain


def request_with(chain: list[dict] | None) -> Request:
    headers = []
    if chain is not None:
        bundle = {"v": 1, "type": "aweb.id-chain", "certificates": chain}
        headers.append((CHAIN_HEADER.lower().encode(), encode_id_chain_header(bundle).encode()))
    return Request({"type": "http", "method": "POST", "path": "/handoffs", "headers": headers})


def signer_for(agent_id: str, key: SigningKey) -> Principal:
    return Principal(
        team_id="people:example.com", did_key=did_key(key), did_aw=agent_id, address=None,
        alias="laptop", certificate_id="c1", team_did_key="did:key:z", did_aw_registry_verified=True,
    )


async def test_a_direct_child_names_its_human_parent(h):
    q_id, q_key, q_chain = await issued_agent(h, [h.identity], h.key, h.principal)
    evidence = await requester_parent(h.client)(request_with(q_chain), signer_for(q_id, q_key))
    assert evidence is not None and evidence.parent == h.principal
    evidence.require_fresh()


async def test_a_grandchild_is_not_a_requester(h):
    q_id, q_key, q_chain = await issued_agent(h, [h.identity], h.key, h.principal)
    r_id, r_key, r_chain = await issued_agent(h, q_chain, q_key, q_id)
    assert await requester_parent(h.client)(request_with(r_chain), signer_for(r_id, r_key)) is None


async def test_a_chain_for_another_key_or_none_names_no_parent(h):
    q_id, q_key, q_chain = await issued_agent(h, [h.identity], h.key, h.principal)
    check = requester_parent(h.client)
    assert await check(request_with(q_chain), signer_for(q_id, SigningKey.generate())) is None
    assert await check(request_with(None), signer_for(q_id, q_key)) is None
    assert await check(request_with([h.identity]), signer_for(h.principal, h.key)) is None

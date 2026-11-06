"""Released AWID routes refuse degenerate Ed25519 keys at admission.

A key AWID stores (a DID's key, a namespace controller, a team or member key,
an address's current key) and a key that signs a request envelope must be a
canonical prime-order point. A mixed-order key can produce signatures that
plain verification accepts, so these refusals cannot rest on signatures.
"""

from __future__ import annotations

from uuid import uuid4

import pytest

from awid.did import did_from_public_key, generate_keypair, stable_id_from_public_key
from awid.log import identity_state_hash, log_entry_payload
from awid_service.deps import get_domain_verifier
from awid.dns_verify import DomainAuthority

from conftest import build_signed_headers
from identity_support import register_identity, request_rotation
from id_tree_support import ORIGIN, MixedOrderController, ed25519_vector_key

from test_certificates import _setup_team, _signed_certificate_blob

# One of each degenerate kind, plus a live mixed-order key that can sign.
DEGENERATE = ["small-order-A-1", "noncanonical-A-identity", "mixed-order-A-k-div-8"]
DOMAIN = "admission.example"


def _degenerate_keys() -> list[str]:
    return [ed25519_vector_key(name) for name in DEGENERATE] + [MixedOrderController().did_key]


def _dns_answers(client, did_key: str) -> None:
    async def _verify(domain: str) -> DomainAuthority:
        return DomainAuthority(controller_did=did_key, registry_url="https://api.awid.ai", dns_name=f"_awid.{domain}")

    client.app.dependency_overrides[get_domain_verifier] = lambda: _verify


@pytest.mark.asyncio
async def test_a_did_with_a_mixed_order_key_cannot_register(clocked_client):
    controller = MixedOrderController()
    did_aw = stable_id_from_public_key(controller.public_key)
    state_hash = identity_state_hash(did_aw=did_aw, current_did_key=controller.did_key)
    timestamp, proof = controller.sign_timed(lambda ts: log_entry_payload(
        did_aw=did_aw, seq=1, operation="register_did", previous_did_key=None, new_did_key=controller.did_key,
        prev_entry_hash=None, state_hash=state_hash, authorized_by=controller.did_key, timestamp=ts,
    ))

    resp = await clocked_client.post("/v1/did", json={
        "did_aw": did_aw, "new_did_key": controller.did_key, "operation": "register_did",
        "previous_did_key": None, "prev_entry_hash": None, "seq": 1, "state_hash": state_hash,
        "authorized_by": controller.did_key, "timestamp": timestamp, "proof": proof,
    })

    assert 400 <= resp.status_code < 500, resp.text
    assert (await clocked_client.get(f"/v1/did/{did_aw}/key")).status_code == 404


@pytest.mark.asyncio
@pytest.mark.parametrize("index", range(4), ids=DEGENERATE + ["mixed-order-controller"])
async def test_a_did_cannot_rotate_to_a_degenerate_key(clocked_client, index):
    signing_key, public = generate_keypair()
    did_key = did_from_public_key(public)
    did_aw = (await register_identity(clocked_client, signing_key, did_key))["did_aw"]

    resp = await request_rotation(clocked_client, signing_key, did_aw, did_key, _degenerate_keys()[index])

    assert 400 <= resp.status_code < 500, resp.text
    assert (await clocked_client.get(f"/v1/did/{did_aw}/key")).json()["current_did_key"] == did_key


@pytest.mark.asyncio
@pytest.mark.parametrize("envelope", ["legacy", "covering"])
async def test_a_mixed_order_controller_cannot_register_a_namespace(clocked_client, envelope):
    controller = MixedOrderController()
    _dns_answers(clocked_client, controller.did_key)
    clocked_client.app.state.awid_public_origins = (ORIGIN,)
    body = b'{"domain":"' + DOMAIN.encode() + b'"}'
    if envelope == "legacy":
        headers = controller.signed_headers(domain=DOMAIN, operation="register")
    else:
        headers = controller.covering_headers(
            method="POST", path="/v1/namespaces", body=body, domain=DOMAIN, operation="register",
        )

    resp = await clocked_client.post("/v1/namespaces", content=body, headers={**headers, "Content-Type": "application/json"})

    assert 400 <= resp.status_code < 500, resp.text
    assert (await clocked_client.get(f"/v1/namespaces/{DOMAIN}")).status_code == 404


@pytest.mark.asyncio
async def test_a_namespace_cannot_move_to_a_mixed_order_controller(clocked_client, controller_identity):
    signing_key, did_key = controller_identity
    _dns_answers(clocked_client, did_key)
    resp = await clocked_client.post(
        "/v1/namespaces", json={"domain": DOMAIN},
        headers=build_signed_headers(signing_key, did_key, domain=DOMAIN, operation="register"),
    )
    assert resp.status_code == 200, resp.text
    controller = MixedOrderController()
    _dns_answers(clocked_client, controller.did_key)

    resp = await clocked_client.put(
        f"/v1/namespaces/{DOMAIN}", json={"new_controller_did": controller.did_key},
        headers=controller.signed_headers(
            domain=DOMAIN, operation="rotate_controller", new_controller_did=controller.did_key,
        ),
    )

    assert 400 <= resp.status_code < 500, resp.text
    assert (await clocked_client.get(f"/v1/namespaces/{DOMAIN}")).json()["controller_did"] == did_key


@pytest.mark.asyncio
@pytest.mark.parametrize("index", range(4), ids=DEGENERATE + ["mixed-order-controller"])
async def test_a_team_cannot_be_created_with_a_degenerate_key(client, controller_identity, index):
    ns_key, ns_did = controller_identity
    resp = await client.post(
        "/v1/namespaces", json={"domain": "team.example"},
        headers=build_signed_headers(ns_key, ns_did, domain="team.example", operation="register"),
    )
    assert resp.status_code == 200, resp.text

    resp = await client.post(
        "/v1/namespaces/team.example/teams",
        json={"name": "backend", "team_did_key": _degenerate_keys()[index], "visibility": "public"},
        headers=build_signed_headers(ns_key, ns_did, domain="team.example", operation="create_team", name="backend"),
    )

    assert 400 <= resp.status_code < 500, resp.text
    assert (await client.get("/v1/namespaces/team.example/teams/backend")).status_code == 404


@pytest.mark.asyncio
@pytest.mark.parametrize("index", range(4), ids=DEGENERATE + ["mixed-order-controller"])
async def test_a_member_certificate_cannot_carry_a_degenerate_key(client, controller_identity, index):
    ns_key, ns_did = controller_identity
    team_key, team_did, _ = await _setup_team(client, ns_key, ns_did, "member.example", "backend")
    member_did_key = _degenerate_keys()[index]
    cert_id = str(uuid4())

    resp = await client.post(
        "/v1/namespaces/member.example/teams/backend/certificates",
        json={
            "certificate": _signed_certificate_blob(
                team_key, certificate_id=cert_id, team_id="backend:member.example", team_did_key=team_did,
                member_did_key=member_did_key, alias="mallory", lifetime="ephemeral",
            ),
            "certificate_id": cert_id,
            "member_did_key": member_did_key,
            "alias": "mallory",
            "identity_scope": "ephemeral",
        },
        headers=build_signed_headers(
            team_key, team_did, domain="member.example", operation="register_certificate",
            team_name="backend", certificate_id=cert_id,
        ),
    )

    assert 400 <= resp.status_code < 500, resp.text

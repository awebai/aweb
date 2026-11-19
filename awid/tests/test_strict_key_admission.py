"""Released AWID routes refuse degenerate Ed25519 keys at admission.

A key AWID stores (a DID's key, a namespace controller, a team or member key,
an address's current key) and a key that signs a request envelope must be a
canonical prime-order point. A mixed-order key can produce signatures that
plain verification accepts, so these refusals cannot rest on signatures.
The admitted-key rule is docs/signature-primitives.md:13-25.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum, auto
from uuid import uuid4

import httpx
import pytest
from awid.did import did_from_public_key, generate_keypair, stable_id_from_public_key
from awid.dns_verify import DomainAuthority
from awid.log import identity_state_hash, log_entry_payload
from awid_service.deps import get_domain_verifier
from conftest import build_signed_headers
from id_tree_support import (
    ORIGIN,
    MixedOrderController,
    covering_headers,
    ed25519_vector_key,
)
from id_tree_support import did_key as vector_did_key
from id_tree_support import seed as vector_seed
from identity_support import register_identity, request_rotation
from test_certificates import _setup_team, _signed_certificate_blob

# One of each degenerate kind, plus a live mixed-order key that can sign.
DEGENERATE = ["small-order-A-1", "noncanonical-A-identity", "mixed-order-A-k-div-8"]
DOMAIN = "admission.example"


class NamespaceProof(Enum):
    CONTEXT_FIELDS = auto()
    REQUEST_COVERING = auto()


@dataclass(frozen=True)
class AdmissionState:
    record: Mapping[str, object] | None
    history: list[Mapping[str, object]]


async def _identity_admission_state(db, *, did_aw: str) -> AdmissionState:
    """Read identity/key-log effects of the act in docs/awid-sot.md:546-574."""
    return AdmissionState(
        record=await db.fetch_one(
            "SELECT * FROM {{tables.did_aw_mappings}} WHERE did_aw = $1", did_aw
        ),
        history=await db.fetch_all(
            "SELECT * FROM {{tables.did_aw_log}} WHERE did_aw = $1 ORDER BY seq",
            did_aw,
        ),
    )


async def _namespace_admission_state(db, *, domain: str) -> AdmissionState:
    """Include the root epochs protected by docs/awid-sot.md:293-309."""
    return AdmissionState(
        record=await db.fetch_one(
            "SELECT * FROM {{tables.dns_namespaces}} WHERE domain = $1", domain
        ),
        history=await db.fetch_all(
            "SELECT * FROM {{tables.id_namespace_epochs}} WHERE domain = $1 ORDER BY seq",
            domain,
        ),
    )


def _assert_key_field_refusal(
    response: httpx.Response, *, field: str, supplied_key: str
) -> None:
    """Identify field admission, separately from request authentication."""
    assert response.status_code == 422, response.text
    errors = response.json()["detail"]
    assert len(errors) == 1, response.text
    error = errors[0]
    assert error["loc"] == ["body", field]
    assert error["type"] == "value_error"
    assert error["msg"] == "Value error, must be a valid did:key Ed25519 identifier"
    assert error["input"] == supplied_key


def _degenerate_keys() -> list[str]:
    return [ed25519_vector_key(name) for name in DEGENERATE] + [
        MixedOrderController().did_key
    ]


def _dns_answers(client, did_key: str) -> None:
    async def _verify(domain: str) -> DomainAuthority:
        return DomainAuthority(
            controller_did=did_key,
            registry_url="https://api.awid.ai",
            dns_name=f"_awid.{domain}",
        )

    client.app.dependency_overrides[get_domain_verifier] = lambda: _verify


@pytest.mark.asyncio
async def test_a_did_with_a_mixed_order_key_cannot_register(
    clocked_client, awid_db_infra
):
    controller = MixedOrderController()
    did_aw = stable_id_from_public_key(controller.public_key)
    state_hash = identity_state_hash(did_aw=did_aw, current_did_key=controller.did_key)
    timestamp, proof = controller.sign_timed(
        lambda ts: log_entry_payload(
            did_aw=did_aw,
            seq=1,
            operation="register_did",
            previous_did_key=None,
            new_did_key=controller.did_key,
            prev_entry_hash=None,
            state_hash=state_hash,
            authorized_by=controller.did_key,
            timestamp=ts,
        )
    )

    db = awid_db_infra.get_manager("aweb")
    before = await _identity_admission_state(db, did_aw=did_aw)
    assert before == AdmissionState(record=None, history=[])
    resp = await clocked_client.post(
        "/v1/did",
        json={
            "did_aw": did_aw,
            "new_did_key": controller.did_key,
            "operation": "register_did",
            "previous_did_key": None,
            "prev_entry_hash": None,
            "seq": 1,
            "state_hash": state_hash,
            "authorized_by": controller.did_key,
            "timestamp": timestamp,
            "proof": proof,
        },
    )

    assert resp.status_code == 400, resp.text
    assert resp.json() == {
        "detail": "did:key must be a canonical Ed25519 key of prime order"
    }
    assert await _identity_admission_state(db, did_aw=did_aw) == before, (
        "refused key changed the identity mapping or signed log"
    )
    assert (await clocked_client.get(f"/v1/did/{did_aw}/key")).status_code == 404

    honest_key, honest_public = generate_keypair()
    honest_did = did_from_public_key(honest_public)
    registered = await register_identity(clocked_client, honest_key, honest_did)
    assert registered["registered"] is True
    public_key = await clocked_client.get(f"/v1/did/{registered['did_aw']}/key")
    assert public_key.status_code == 200, public_key.text
    assert public_key.json()["current_did_key"] == honest_did


@pytest.mark.asyncio
@pytest.mark.parametrize("index", range(4), ids=DEGENERATE + ["mixed-order-controller"])
async def test_a_did_cannot_rotate_to_a_degenerate_key(
    clocked_client, awid_db_infra, index
):
    signing_key, public = generate_keypair()
    did_key = did_from_public_key(public)
    did_aw = (await register_identity(clocked_client, signing_key, did_key))["did_aw"]
    db = awid_db_infra.get_manager("aweb")
    before = await _identity_admission_state(db, did_aw=did_aw)
    key_before = (await clocked_client.get(f"/v1/did/{did_aw}/key")).json()

    resp = await request_rotation(
        clocked_client, signing_key, did_aw, did_key, _degenerate_keys()[index]
    )

    assert resp.status_code == 400, resp.text
    assert resp.json() == {
        "detail": "did:key must be a canonical Ed25519 key of prime order"
    }
    assert await _identity_admission_state(db, did_aw=did_aw) == before, (
        "refused key changed the identity mapping or signed log"
    )
    assert (await clocked_client.get(f"/v1/did/{did_aw}/key")).json() == key_before

    _, next_public = generate_keypair()
    next_did = did_from_public_key(next_public)
    rotated = await request_rotation(
        clocked_client, signing_key, did_aw, did_key, next_did
    )
    assert rotated.status_code == 200, rotated.text
    current = await clocked_client.get(f"/v1/did/{did_aw}/key")
    assert current.status_code == 200, current.text
    assert current.json()["current_did_key"] == next_did
    assert current.json()["log_head"]["seq"] == key_before["log_head"]["seq"] + 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "envelope",
    [NamespaceProof.CONTEXT_FIELDS, NamespaceProof.REQUEST_COVERING],
    ids=["legacy", "covering"],
)
async def test_a_mixed_order_controller_cannot_register_a_namespace(
    clocked_client, awid_db_infra, envelope
):
    controller = MixedOrderController()
    _dns_answers(clocked_client, controller.did_key)
    clocked_client.app.state.awid_public_origins = (ORIGIN,)
    body = b'{"domain":"' + DOMAIN.encode() + b'"}'
    if envelope is NamespaceProof.CONTEXT_FIELDS:
        headers = controller.signed_headers(domain=DOMAIN, operation="register")
    else:
        headers = controller.covering_headers(
            method="POST",
            path="/v1/namespaces",
            body=body,
            domain=DOMAIN,
            operation="register",
        )

    db = awid_db_infra.get_manager("aweb")
    before = await _namespace_admission_state(db, domain=DOMAIN)
    assert before == AdmissionState(record=None, history=[])
    resp = await clocked_client.post(
        "/v1/namespaces",
        content=body,
        headers={**headers, "Content-Type": "application/json"},
    )

    assert resp.status_code == 401, resp.text
    assert resp.json() == {"detail": "Invalid signature"}
    assert await _namespace_admission_state(db, domain=DOMAIN) == before, (
        "refused controller changed the namespace or root epochs"
    )
    assert (await clocked_client.get(f"/v1/namespaces/{DOMAIN}")).status_code == 404

    honest_did = vector_did_key("root")
    _dns_answers(clocked_client, honest_did)
    if envelope is NamespaceProof.CONTEXT_FIELDS:
        valid_headers = build_signed_headers(
            vector_seed("root"), honest_did, domain=DOMAIN, operation="register"
        )
    else:
        valid_headers = covering_headers(
            "root",
            method="POST",
            path="/v1/namespaces",
            body=body,
            domain=DOMAIN,
            operation="register",
        )
    retried = await clocked_client.post(
        "/v1/namespaces",
        content=body,
        headers={**valid_headers, "Content-Type": "application/json"},
    )
    assert retried.status_code == 200, retried.text
    namespace = await clocked_client.get(f"/v1/namespaces/{DOMAIN}")
    assert namespace.status_code == 200, namespace.text
    assert namespace.json()["controller_did"] == honest_did
    assert len((await _namespace_admission_state(db, domain=DOMAIN)).history) == 1


@pytest.mark.asyncio
async def test_a_namespace_cannot_move_to_a_mixed_order_controller(
    clocked_client, controller_identity, awid_db_infra
):
    signing_key, did_key = controller_identity
    _dns_answers(clocked_client, did_key)
    resp = await clocked_client.post(
        "/v1/namespaces",
        json={"domain": DOMAIN},
        headers=build_signed_headers(
            signing_key, did_key, domain=DOMAIN, operation="register"
        ),
    )
    assert resp.status_code == 200, resp.text
    db = awid_db_infra.get_manager("aweb")
    before = await _namespace_admission_state(db, domain=DOMAIN)
    namespace_before = (await clocked_client.get(f"/v1/namespaces/{DOMAIN}")).json()
    controller = MixedOrderController()
    _dns_answers(clocked_client, controller.did_key)

    resp = await clocked_client.put(
        f"/v1/namespaces/{DOMAIN}",
        json={"new_controller_did": controller.did_key},
        headers=controller.signed_headers(
            domain=DOMAIN,
            operation="rotate_controller",
            new_controller_did=controller.did_key,
        ),
    )

    _assert_key_field_refusal(
        resp, field="new_controller_did", supplied_key=controller.did_key
    )
    assert await _namespace_admission_state(db, domain=DOMAIN) == before, (
        "refused controller changed the namespace or root epochs"
    )
    assert (
        await clocked_client.get(f"/v1/namespaces/{DOMAIN}")
    ).json() == namespace_before

    next_key, next_public = generate_keypair()
    next_did = did_from_public_key(next_public)
    _dns_answers(clocked_client, next_did)
    recovered = await clocked_client.put(
        f"/v1/namespaces/{DOMAIN}",
        json={"new_controller_did": next_did},
        headers=build_signed_headers(
            next_key,
            next_did,
            domain=DOMAIN,
            operation="rotate_controller",
            new_controller_did=next_did,
        ),
    )
    assert recovered.status_code == 200, recovered.text
    assert (await clocked_client.get(f"/v1/namespaces/{DOMAIN}")).json()[
        "controller_did"
    ] == next_did


@pytest.mark.asyncio
@pytest.mark.parametrize("index", range(4), ids=DEGENERATE + ["mixed-order-controller"])
async def test_a_team_cannot_be_created_with_a_degenerate_key(
    client, controller_identity, awid_db_infra, index
):
    ns_key, ns_did = controller_identity
    resp = await client.post(
        "/v1/namespaces",
        json={"domain": "team.example"},
        headers=build_signed_headers(
            ns_key, ns_did, domain="team.example", operation="register"
        ),
    )
    assert resp.status_code == 200, resp.text

    bad_key = _degenerate_keys()[index]
    db = awid_db_infra.get_manager("aweb")
    resp = await client.post(
        "/v1/namespaces/team.example/teams",
        json={
            "name": "backend",
            "team_did_key": bad_key,
            "visibility": "public",
        },
        headers=build_signed_headers(
            ns_key,
            ns_did,
            domain="team.example",
            operation="create_team",
            name="backend",
        ),
    )

    _assert_key_field_refusal(resp, field="team_did_key", supplied_key=bad_key)
    assert await db.fetch_all("SELECT * FROM {{tables.teams}}") == []
    assert (
        await client.get("/v1/namespaces/team.example/teams/backend")
    ).status_code == 404

    _, team_public = generate_keypair()
    team_did = did_from_public_key(team_public)
    created = await client.post(
        "/v1/namespaces/team.example/teams",
        json={"name": "backend", "team_did_key": team_did, "visibility": "public"},
        headers=build_signed_headers(
            ns_key,
            ns_did,
            domain="team.example",
            operation="create_team",
            name="backend",
        ),
    )
    assert created.status_code == 200, created.text
    team = await client.get("/v1/namespaces/team.example/teams/backend")
    assert team.status_code == 200, team.text
    assert team.json()["team_did_key"] == team_did


@pytest.mark.asyncio
@pytest.mark.parametrize("index", range(4), ids=DEGENERATE + ["mixed-order-controller"])
async def test_a_member_certificate_cannot_carry_a_degenerate_key(
    client, controller_identity, awid_db_infra, index
):
    ns_key, ns_did = controller_identity
    team_key, team_did, _ = await _setup_team(
        client, ns_key, ns_did, "member.example", "backend"
    )
    member_did_key = _degenerate_keys()[index]
    cert_id = str(uuid4())

    resp = await client.post(
        "/v1/namespaces/member.example/teams/backend/certificates",
        json={
            "certificate": _signed_certificate_blob(
                team_key,
                certificate_id=cert_id,
                team_id="backend:member.example",
                team_did_key=team_did,
                member_did_key=member_did_key,
                alias="mallory",
                lifetime="ephemeral",
            ),
            "certificate_id": cert_id,
            "member_did_key": member_did_key,
            "alias": "mallory",
            "identity_scope": "ephemeral",
        },
        headers=build_signed_headers(
            team_key,
            team_did,
            domain="member.example",
            operation="register_certificate",
            team_name="backend",
            certificate_id=cert_id,
        ),
    )

    _assert_key_field_refusal(resp, field="member_did_key", supplied_key=member_did_key)
    db = awid_db_infra.get_manager("aweb")
    assert await db.fetch_all("SELECT * FROM {{tables.team_certificates}}") == []
    root = "/v1/namespaces/member.example/teams/backend"
    assert (
        await client.get(f"{root}/certificates/{cert_id}/status")
    ).status_code == 404
    assert (await client.get(f"{root}/members/mallory")).status_code == 404

    _, member_public = generate_keypair()
    valid_member_did = did_from_public_key(member_public)
    registered = await client.post(
        f"{root}/certificates",
        json={
            "certificate": _signed_certificate_blob(
                team_key,
                certificate_id=cert_id,
                team_id="backend:member.example",
                team_did_key=team_did,
                member_did_key=valid_member_did,
                alias="mallory",
                lifetime="ephemeral",
            ),
            "certificate_id": cert_id,
            "member_did_key": valid_member_did,
            "alias": "mallory",
            "identity_scope": "ephemeral",
        },
        headers=build_signed_headers(
            team_key,
            team_did,
            domain="member.example",
            operation="register_certificate",
            team_name="backend",
            certificate_id=cert_id,
        ),
    )
    assert registered.status_code == 200, registered.text
    assert registered.json() == {"registered": True, "certificate_id": cert_id}
    status = await client.get(f"{root}/certificates/{cert_id}/status")
    assert status.status_code == 200, status.text
    assert status.json()["status"] == "active"
    member = await client.get(f"{root}/members/mallory")
    assert member.status_code == 200, member.text
    assert member.json()["member_did_key"] == valid_member_did
    assert member.json()["certificate_id"] == cert_id

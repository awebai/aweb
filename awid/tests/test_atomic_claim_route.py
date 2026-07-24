from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi import HTTPException

import awid_service.routes.did as did_routes
import awid_service.routes.dns_addresses as dns_addresses_routes
from awid.atomic_claim import (
    AtomicAddressClaimFields,
    atomic_address_claim_identity_canonical,
    atomic_address_claim_identity_proof_hash,
    atomic_address_claim_namespace_canonical,
)
from awid.did import did_from_public_key, generate_keypair, stable_id_from_did_key
from awid.log import identity_state_hash, log_entry_payload
from awid.signing import sign_message

from conftest import build_signed_headers


_TS = "2026-06-06T09:30:00Z"
_REGISTRY_URL = "https://API.AWID.AI/"
_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(autouse=True)
def _allow_static_atomic_claim_timestamp(monkeypatch):
    monkeypatch.setattr(dns_addresses_routes, "enforce_timestamp_skew", lambda _timestamp: None)
    monkeypatch.setattr(did_routes, "enforce_timestamp_skew", lambda _timestamp: None)


def test_atomic_claim_conflict_codes_match_shared_vector():
    vector = json.loads(
        (_ROOT / "docs" / "vectors" / "atomic-address-claim-conflict-codes-v1.json").read_text(
            encoding="utf-8",
        )
    )
    assert vector["codes"] == list(dns_addresses_routes._ATOMIC_CLAIM_CONFLICT_CODES)


async def _register_namespace(client, signing_key, controller_did, domain="example.com"):
    headers = build_signed_headers(signing_key, controller_did, domain=domain, operation="register")
    resp = await client.post("/v1/namespaces", json={"domain": domain}, headers=headers)
    assert resp.status_code == 200, resp.text
    return resp.json()


def _register_did_log_proof(signing_key, did_aw: str, did_key: str, *, timestamp: str = _TS) -> dict:
    state_hash = identity_state_hash(did_aw=did_aw, current_did_key=did_key)
    payload = log_entry_payload(
        did_aw=did_aw,
        seq=1,
        operation="register_did",
        previous_did_key=None,
        new_did_key=did_key,
        prev_entry_hash=None,
        state_hash=state_hash,
        authorized_by=did_key,
        timestamp=timestamp,
    )
    return {
        "did_aw": did_aw,
        "seq": 1,
        "operation": "register_did",
        "previous_did_key": None,
        "new_did_key": did_key,
        "prev_entry_hash": None,
        "state_hash": state_hash,
        "authorized_by": did_key,
        "timestamp": timestamp,
        "signature": sign_message(signing_key, payload),
    }


def _claim_body(
    *,
    identity_signing_key,
    identity_did_key,
    controller_signing_key,
    domain="example.com",
    address_name="alice",
    dry_run=False,
    identity_custody="self",
    namespace_custody="self",
    include_did_log_proof=True,
    did_aw=None,
    did_log_proof=None,
) -> dict:
    did_aw = did_aw or stable_id_from_did_key(identity_did_key)
    fields = AtomicAddressClaimFields(
        operation="claim_identity_address",
        domain=domain,
        address_name=address_name,
        did_aw=did_aw,
        current_did_key=identity_did_key,
        registry_url=_REGISTRY_URL,
        timestamp=_TS,
        dry_run=dry_run,
        identity_custody=identity_custody,
        namespace_custody=namespace_custody,
    )
    identity_canonical = atomic_address_claim_identity_canonical(fields)
    identity_signature = sign_message(identity_signing_key, identity_canonical)
    identity_proof_hash = atomic_address_claim_identity_proof_hash(
        identity_canonical,
        identity_signature,
    )
    namespace_signature = sign_message(
        controller_signing_key,
        atomic_address_claim_namespace_canonical(fields, identity_proof_hash),
    )
    body = {
        "operation": "claim_identity_address",
        "address_name": address_name,
        "did_aw": did_aw,
        "current_did_key": identity_did_key,
        "registry_url": _REGISTRY_URL,
        "timestamp": _TS,
        "dry_run": dry_run,
        "identity_custody": identity_custody,
        "namespace_custody": namespace_custody,
        "identity_signature": identity_signature,
        "namespace_signature": namespace_signature,
    }
    if include_did_log_proof:
        body["did_log_proof"] = did_log_proof or _register_did_log_proof(
            identity_signing_key,
            did_aw,
            identity_did_key,
        )
    return body


async def _register_and_rotate_identity(client, *, rotations=2):
    signing_key, public_key = generate_keypair()
    did_key = did_from_public_key(public_key)
    did_aw = stable_id_from_did_key(did_key)
    register_proof = _register_did_log_proof(signing_key, did_aw, did_key)
    register_body = {**register_proof, "proof": register_proof["signature"]}
    del register_body["signature"]
    response = await client.post("/v1/did", json=register_body)
    assert response.status_code == 200, response.text

    head_response = await client.get(f"/v1/did/{did_aw}/key")
    assert head_response.status_code == 200, head_response.text
    log_head = head_response.json()["log_head"]
    for _ in range(rotations):
        next_signing_key, next_public_key = generate_keypair()
        next_did_key = did_from_public_key(next_public_key)
        state_hash = identity_state_hash(did_aw=did_aw, current_did_key=next_did_key)
        payload = log_entry_payload(
            did_aw=did_aw,
            seq=log_head["seq"] + 1,
            operation="rotate_key",
            previous_did_key=did_key,
            new_did_key=next_did_key,
            prev_entry_hash=log_head["entry_hash"],
            state_hash=state_hash,
            authorized_by=did_key,
            timestamp=_TS,
        )
        rotation = {
            "operation": "rotate_key",
            "new_did_key": next_did_key,
            "seq": log_head["seq"] + 1,
            "prev_entry_hash": log_head["entry_hash"],
            "state_hash": state_hash,
            "authorized_by": did_key,
            "timestamp": _TS,
            "signature": sign_message(signing_key, payload),
        }
        response = await client.put(f"/v1/did/{did_aw}", json=rotation)
        assert response.status_code == 200, response.text
        signing_key = next_signing_key
        did_key = next_did_key
        head_response = await client.get(f"/v1/did/{did_aw}/key")
        assert head_response.status_code == 200, head_response.text
        log_head = head_response.json()["log_head"]
    return signing_key, did_key, did_aw, log_head


async def _counts(awid_db_infra, did_aw: str, name: str, domain="example.com") -> tuple[int, int, int]:
    db = awid_db_infra.get_manager("aweb")
    did_count = await db.fetch_one(
        "SELECT COUNT(*) AS count FROM {{tables.did_aw_mappings}} WHERE did_aw = $1",
        did_aw,
    )
    log_count = await db.fetch_one(
        "SELECT COUNT(*) AS count FROM {{tables.did_aw_log}} WHERE did_aw = $1",
        did_aw,
    )
    addr_count = await db.fetch_one(
        """
        SELECT COUNT(*) AS count
        FROM {{tables.public_addresses}} pa
        JOIN {{tables.dns_namespaces}} ns ON ns.namespace_id = pa.namespace_id
        WHERE ns.domain = $1 AND pa.name = $2 AND pa.deleted_at IS NULL
        """,
        domain,
        name,
    )
    return did_count["count"], log_count["count"], addr_count["count"]


@pytest.mark.asyncio
async def test_atomic_claim_dry_run_validates_without_writing(client, awid_db_infra, controller_identity):
    controller_signing_key, controller_did = controller_identity
    await _register_namespace(client, controller_signing_key, controller_did)
    identity_signing_key, identity_public_key = generate_keypair()
    identity_did_key = did_from_public_key(identity_public_key)
    body = _claim_body(
        identity_signing_key=identity_signing_key,
        identity_did_key=identity_did_key,
        controller_signing_key=controller_signing_key,
        dry_run=True,
    )

    resp = await client.post("/v1/namespaces/example.com/addresses/claims", json=body)

    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "available"
    assert resp.json()["dry_run"] is True
    assert await _counts(awid_db_infra, body["did_aw"], body["address_name"]) == (0, 0, 0)


@pytest.mark.asyncio
async def test_atomic_claim_apply_creates_compatible_did_log_and_address(
    client,
    awid_db_infra,
    controller_identity,
):
    controller_signing_key, controller_did = controller_identity
    await _register_namespace(client, controller_signing_key, controller_did)
    identity_signing_key, identity_public_key = generate_keypair()
    identity_did_key = did_from_public_key(identity_public_key)
    body = _claim_body(
        identity_signing_key=identity_signing_key,
        identity_did_key=identity_did_key,
        controller_signing_key=controller_signing_key,
    )

    resp = await client.post("/v1/namespaces/example.com/addresses/claims", json=body)

    assert resp.status_code == 200, resp.text
    payload = resp.json()
    assert payload["status"] == "claimed"
    assert payload["did_status"] == "created"
    assert payload["address_status"] == "created"
    assert payload["address"]["name"] == body["address_name"]
    assert await _counts(awid_db_infra, body["did_aw"], body["address_name"]) == (1, 1, 1)

    key_response = await client.get(f"/v1/did/{body['did_aw']}/key")
    assert key_response.status_code == 200, key_response.text
    key_payload = key_response.json()
    assert key_payload["current_did_key"] == identity_did_key
    assert key_payload["log_head"]["operation"] == "register_did"
    assert key_payload["log_head"]["signature"] == body["did_log_proof"]["signature"]

    address_response = await client.get("/v1/namespaces/example.com/addresses/alice")
    assert address_response.status_code == 200, address_response.text
    assert address_response.json()["did_aw"] == body["did_aw"]


@pytest.mark.asyncio
async def test_atomic_claim_existing_multi_rotated_identity_accepts_rotation_log_head(
    client,
    awid_db_infra,
    controller_identity,
):
    controller_signing_key, controller_did = controller_identity
    await _register_namespace(client, controller_signing_key, controller_did)
    identity_signing_key, identity_did_key, did_aw, log_head = await _register_and_rotate_identity(
        client,
        rotations=2,
    )
    assert log_head["seq"] == 3
    body = _claim_body(
        identity_signing_key=identity_signing_key,
        identity_did_key=identity_did_key,
        controller_signing_key=controller_signing_key,
        did_aw=did_aw,
        did_log_proof={
            "did_aw": did_aw,
            **{key: value for key, value in log_head.items() if key != "entry_hash"},
        },
    )

    resp = await client.post("/v1/namespaces/example.com/addresses/claims", json=body)

    assert resp.status_code == 200, resp.text
    assert resp.json()["did_status"] == "existing"
    assert resp.json()["address_status"] == "created"
    assert await _counts(awid_db_infra, did_aw, body["address_name"]) == (1, 3, 1)


@pytest.mark.asyncio
async def test_atomic_claim_rotation_log_head_requires_previous_key_signature(
    client,
    awid_db_infra,
    controller_identity,
):
    controller_signing_key, controller_did = controller_identity
    await _register_namespace(client, controller_signing_key, controller_did)
    identity_signing_key, identity_did_key, did_aw, log_head = await _register_and_rotate_identity(
        client,
        rotations=2,
    )
    proof = {
        "did_aw": did_aw,
        **{key: value for key, value in log_head.items() if key != "entry_hash"},
        "signature": "invalid",
    }
    body = _claim_body(
        identity_signing_key=identity_signing_key,
        identity_did_key=identity_did_key,
        controller_signing_key=controller_signing_key,
        address_name="bad-rotation-proof",
        did_aw=did_aw,
        did_log_proof=proof,
    )

    resp = await client.post("/v1/namespaces/example.com/addresses/claims", json=body)

    assert resp.status_code == 401, resp.text
    assert resp.json()["detail"]["code"] == "did_log_proof_invalid"
    assert await _counts(awid_db_infra, did_aw, body["address_name"]) == (1, 3, 0)


@pytest.mark.asyncio
async def test_atomic_claim_rotation_proof_must_match_registered_log_head(
    client,
    awid_db_infra,
    controller_identity,
):
    controller_signing_key, controller_did = controller_identity
    await _register_namespace(client, controller_signing_key, controller_did)
    identity_signing_key, identity_did_key, did_aw, log_head = await _register_and_rotate_identity(
        client,
        rotations=2,
    )
    fake_previous_key, fake_previous_public = generate_keypair()
    fake_previous_did = did_from_public_key(fake_previous_public)
    state_hash = identity_state_hash(did_aw=did_aw, current_did_key=identity_did_key)
    fake_prev_hash = "c" * 64
    payload = log_entry_payload(
        did_aw=did_aw,
        seq=log_head["seq"],
        operation="rotate_key",
        previous_did_key=fake_previous_did,
        new_did_key=identity_did_key,
        prev_entry_hash=fake_prev_hash,
        state_hash=state_hash,
        authorized_by=fake_previous_did,
        timestamp=_TS,
    )
    fake_log_head = {
        "did_aw": did_aw,
        "seq": log_head["seq"],
        "operation": "rotate_key",
        "previous_did_key": fake_previous_did,
        "new_did_key": identity_did_key,
        "prev_entry_hash": fake_prev_hash,
        "state_hash": state_hash,
        "authorized_by": fake_previous_did,
        "timestamp": _TS,
        "signature": sign_message(fake_previous_key, payload),
    }
    body = _claim_body(
        identity_signing_key=identity_signing_key,
        identity_did_key=identity_did_key,
        controller_signing_key=controller_signing_key,
        address_name="fake-head",
        did_aw=did_aw,
        did_log_proof=fake_log_head,
    )

    resp = await client.post("/v1/namespaces/example.com/addresses/claims", json=body)

    assert resp.status_code == 409, resp.text
    assert resp.json()["detail"]["code"] == "did_log_proof_invalid"
    assert await _counts(awid_db_infra, did_aw, body["address_name"]) == (1, 3, 0)


@pytest.mark.asyncio
async def test_atomic_claim_rotated_spoof_still_rejects_registry_key_mismatch(
    client,
    awid_db_infra,
    controller_identity,
):
    controller_signing_key, controller_did = controller_identity
    await _register_namespace(client, controller_signing_key, controller_did)
    _, _, victim_did_aw, _ = await _register_and_rotate_identity(client, rotations=2)

    attacker_previous_key, attacker_previous_public = generate_keypair()
    attacker_previous_did = did_from_public_key(attacker_previous_public)
    attacker_key, attacker_public = generate_keypair()
    attacker_did = did_from_public_key(attacker_public)
    state_hash = identity_state_hash(did_aw=victim_did_aw, current_did_key=attacker_did)
    prev_entry_hash = "a" * 64
    payload = log_entry_payload(
        did_aw=victim_did_aw,
        seq=3,
        operation="rotate_key",
        previous_did_key=attacker_previous_did,
        new_did_key=attacker_did,
        prev_entry_hash=prev_entry_hash,
        state_hash=state_hash,
        authorized_by=attacker_previous_did,
        timestamp=_TS,
    )
    fake_log_head = {
        "did_aw": victim_did_aw,
        "seq": 3,
        "operation": "rotate_key",
        "previous_did_key": attacker_previous_did,
        "new_did_key": attacker_did,
        "prev_entry_hash": prev_entry_hash,
        "state_hash": state_hash,
        "authorized_by": attacker_previous_did,
        "timestamp": _TS,
        "signature": sign_message(attacker_previous_key, payload),
    }
    body = _claim_body(
        identity_signing_key=attacker_key,
        identity_did_key=attacker_did,
        controller_signing_key=controller_signing_key,
        address_name="spoof",
        did_aw=victim_did_aw,
        did_log_proof=fake_log_head,
    )

    resp = await client.post("/v1/namespaces/example.com/addresses/claims", json=body)

    assert resp.status_code == 409, resp.text
    assert resp.json()["detail"]["code"] == "did_taken_different_key"
    assert await _counts(awid_db_infra, victim_did_aw, body["address_name"]) == (1, 3, 0)


@pytest.mark.asyncio
async def test_atomic_claim_rotation_tail_cannot_register_an_unregistered_did(
    client,
    awid_db_infra,
    controller_identity,
):
    controller_signing_key, controller_did = controller_identity
    await _register_namespace(client, controller_signing_key, controller_did)
    root_key, root_public = generate_keypair()
    root_did = did_from_public_key(root_public)
    did_aw = stable_id_from_did_key(root_did)
    current_key, current_public = generate_keypair()
    current_did = did_from_public_key(current_public)
    state_hash = identity_state_hash(did_aw=did_aw, current_did_key=current_did)
    prev_entry_hash = "b" * 64
    payload = log_entry_payload(
        did_aw=did_aw,
        seq=2,
        operation="rotate_key",
        previous_did_key=root_did,
        new_did_key=current_did,
        prev_entry_hash=prev_entry_hash,
        state_hash=state_hash,
        authorized_by=root_did,
        timestamp=_TS,
    )
    log_head = {
        "did_aw": did_aw,
        "seq": 2,
        "operation": "rotate_key",
        "previous_did_key": root_did,
        "new_did_key": current_did,
        "prev_entry_hash": prev_entry_hash,
        "state_hash": state_hash,
        "authorized_by": root_did,
        "timestamp": _TS,
        "signature": sign_message(root_key, payload),
    }
    body = _claim_body(
        identity_signing_key=current_key,
        identity_did_key=current_did,
        controller_signing_key=controller_signing_key,
        did_aw=did_aw,
        did_log_proof=log_head,
    )

    resp = await client.post("/v1/namespaces/example.com/addresses/claims", json=body)

    assert resp.status_code == 409, resp.text
    assert resp.json()["detail"]["code"] == "did_log_proof_required"
    assert await _counts(awid_db_infra, did_aw, body["address_name"]) == (0, 0, 0)


@pytest.mark.asyncio
async def test_atomic_claim_self_did_hosted_namespace_custody_is_supported(
    client,
    awid_db_infra,
    controller_identity,
):
    controller_signing_key, controller_did = controller_identity
    await _register_namespace(client, controller_signing_key, controller_did)
    identity_signing_key, identity_public_key = generate_keypair()
    identity_did_key = did_from_public_key(identity_public_key)
    body = _claim_body(
        identity_signing_key=identity_signing_key,
        identity_did_key=identity_did_key,
        controller_signing_key=controller_signing_key,
        identity_custody="self",
        namespace_custody="hosted_custodial",
    )

    resp = await client.post("/v1/namespaces/example.com/addresses/claims", json=body)

    assert resp.status_code == 200, resp.text
    payload = resp.json()
    assert payload["status"] == "claimed"
    assert payload["identity_custody"] == "self"
    assert payload["namespace_custody"] == "hosted_custodial"
    assert await _counts(awid_db_infra, body["did_aw"], body["address_name"]) == (1, 1, 1)


@pytest.mark.asyncio
async def test_atomic_claim_apply_is_idempotent_for_same_payload(
    client,
    awid_db_infra,
    controller_identity,
):
    controller_signing_key, controller_did = controller_identity
    await _register_namespace(client, controller_signing_key, controller_did)
    identity_signing_key, identity_public_key = generate_keypair()
    identity_did_key = did_from_public_key(identity_public_key)
    body = _claim_body(
        identity_signing_key=identity_signing_key,
        identity_did_key=identity_did_key,
        controller_signing_key=controller_signing_key,
    )

    first = await client.post("/v1/namespaces/example.com/addresses/claims", json=body)
    second = await client.post("/v1/namespaces/example.com/addresses/claims", json=body)

    assert first.status_code == 200, first.text
    assert second.status_code == 200, second.text
    assert second.json()["status"] == "already_applied"
    assert await _counts(awid_db_infra, body["did_aw"], body["address_name"]) == (1, 1, 1)


@pytest.mark.asyncio
async def test_atomic_claim_missing_did_log_proof_fails_before_writes(
    client,
    awid_db_infra,
    controller_identity,
):
    controller_signing_key, controller_did = controller_identity
    await _register_namespace(client, controller_signing_key, controller_did)
    identity_signing_key, identity_public_key = generate_keypair()
    identity_did_key = did_from_public_key(identity_public_key)
    body = _claim_body(
        identity_signing_key=identity_signing_key,
        identity_did_key=identity_did_key,
        controller_signing_key=controller_signing_key,
        include_did_log_proof=False,
    )

    resp = await client.post("/v1/namespaces/example.com/addresses/claims", json=body)

    assert resp.status_code == 409, resp.text
    assert resp.json()["detail"]["code"] == "did_log_proof_required"
    assert await _counts(awid_db_infra, body["did_aw"], body["address_name"]) == (0, 0, 0)


@pytest.mark.asyncio
async def test_atomic_claim_missing_namespace_fails_before_writes(
    client,
    awid_db_infra,
    controller_identity,
):
    controller_signing_key, _ = controller_identity
    identity_signing_key, identity_public_key = generate_keypair()
    identity_did_key = did_from_public_key(identity_public_key)
    body = _claim_body(
        identity_signing_key=identity_signing_key,
        identity_did_key=identity_did_key,
        controller_signing_key=controller_signing_key,
        domain="missing.example.com",
    )

    resp = await client.post("/v1/namespaces/missing.example.com/addresses/claims", json=body)

    assert resp.status_code == 404, resp.text
    assert resp.json()["detail"]["code"] == "namespace_not_registered"
    assert await _counts(awid_db_infra, body["did_aw"], body["address_name"], "missing.example.com") == (
        0,
        0,
        0,
    )


@pytest.mark.asyncio
async def test_atomic_claim_stale_timestamp_fails_before_writes(
    client,
    awid_db_infra,
    controller_identity,
    monkeypatch,
):
    controller_signing_key, controller_did = controller_identity
    await _register_namespace(client, controller_signing_key, controller_did)
    identity_signing_key, identity_public_key = generate_keypair()
    identity_did_key = did_from_public_key(identity_public_key)
    body = _claim_body(
        identity_signing_key=identity_signing_key,
        identity_did_key=identity_did_key,
        controller_signing_key=controller_signing_key,
    )

    def stale_timestamp(_timestamp):
        raise HTTPException(status_code=401, detail="stale timestamp")

    monkeypatch.setattr(dns_addresses_routes, "enforce_timestamp_skew", stale_timestamp)

    resp = await client.post("/v1/namespaces/example.com/addresses/claims", json=body)

    assert resp.status_code == 401, resp.text
    assert resp.json()["detail"]["code"] == "timestamp_stale"
    assert await _counts(awid_db_infra, body["did_aw"], body["address_name"]) == (0, 0, 0)


@pytest.mark.asyncio
async def test_atomic_claim_bad_namespace_signature_fails_before_writes(
    client,
    awid_db_infra,
    controller_identity,
):
    controller_signing_key, controller_did = controller_identity
    await _register_namespace(client, controller_signing_key, controller_did)
    identity_signing_key, identity_public_key = generate_keypair()
    identity_did_key = did_from_public_key(identity_public_key)
    other_signing_key, _ = generate_keypair()
    body = _claim_body(
        identity_signing_key=identity_signing_key,
        identity_did_key=identity_did_key,
        controller_signing_key=other_signing_key,
    )

    resp = await client.post("/v1/namespaces/example.com/addresses/claims", json=body)

    assert resp.status_code == 403, resp.text
    assert resp.json()["detail"]["code"] == "namespace_authority_invalid"
    assert await _counts(awid_db_infra, body["did_aw"], body["address_name"]) == (0, 0, 0)


@pytest.mark.asyncio
async def test_atomic_claim_invalid_did_fields_use_structured_codes(
    client,
    awid_db_infra,
    controller_identity,
):
    controller_signing_key, controller_did = controller_identity
    await _register_namespace(client, controller_signing_key, controller_did)
    identity_signing_key, identity_public_key = generate_keypair()
    identity_did_key = did_from_public_key(identity_public_key)
    body = _claim_body(
        identity_signing_key=identity_signing_key,
        identity_did_key=identity_did_key,
        controller_signing_key=controller_signing_key,
    )
    did_aw = body["did_aw"]
    body["did_aw"] = "did:aw:not-base58!"

    resp = await client.post("/v1/namespaces/example.com/addresses/claims", json=body)

    assert resp.status_code == 422, resp.text
    assert resp.json()["detail"]["code"] == "payload_canonicalization_mismatch"
    assert await _counts(awid_db_infra, did_aw, body["address_name"]) == (0, 0, 0)


@pytest.mark.asyncio
async def test_atomic_claim_invalid_did_log_proof_uses_structured_code(
    client,
    awid_db_infra,
    controller_identity,
):
    controller_signing_key, controller_did = controller_identity
    await _register_namespace(client, controller_signing_key, controller_did)
    identity_signing_key, identity_public_key = generate_keypair()
    identity_did_key = did_from_public_key(identity_public_key)
    body = _claim_body(
        identity_signing_key=identity_signing_key,
        identity_did_key=identity_did_key,
        controller_signing_key=controller_signing_key,
    )
    body["did_log_proof"]["new_did_key"] = "did:key:not-base58!"

    resp = await client.post("/v1/namespaces/example.com/addresses/claims", json=body)

    assert resp.status_code == 422, resp.text
    assert resp.json()["detail"]["code"] == "did_log_proof_invalid"
    assert await _counts(awid_db_infra, body["did_aw"], body["address_name"]) == (0, 0, 0)


@pytest.mark.asyncio
async def test_atomic_claim_same_did_can_claim_multiple_addresses(client, controller_identity):
    controller_signing_key, controller_did = controller_identity
    await _register_namespace(client, controller_signing_key, controller_did)
    identity_signing_key, identity_public_key = generate_keypair()
    identity_did_key = did_from_public_key(identity_public_key)
    first = _claim_body(
        identity_signing_key=identity_signing_key,
        identity_did_key=identity_did_key,
        controller_signing_key=controller_signing_key,
        address_name="alice",
    )
    second = _claim_body(
        identity_signing_key=identity_signing_key,
        identity_did_key=identity_did_key,
        controller_signing_key=controller_signing_key,
        address_name="bob",
    )

    first_resp = await client.post("/v1/namespaces/example.com/addresses/claims", json=first)
    second_resp = await client.post("/v1/namespaces/example.com/addresses/claims", json=second)

    assert first_resp.status_code == 200, first_resp.text
    assert second_resp.status_code == 200, second_resp.text
    assert second_resp.json()["did_status"] == "existing"


@pytest.mark.asyncio
async def test_atomic_claim_feature_flag_disabled(client, controller_identity, monkeypatch):
    controller_signing_key, controller_did = controller_identity
    await _register_namespace(client, controller_signing_key, controller_did)
    identity_signing_key, identity_public_key = generate_keypair()
    identity_did_key = did_from_public_key(identity_public_key)
    body = _claim_body(
        identity_signing_key=identity_signing_key,
        identity_did_key=identity_did_key,
        controller_signing_key=controller_signing_key,
    )
    monkeypatch.setenv("AWID_ENABLE_ATOMIC_CLAIM", "0")

    resp = await client.post("/v1/namespaces/example.com/addresses/claims", json=body)

    assert resp.status_code == 404, resp.text
    assert resp.json()["detail"]["code"] == "primitive_disabled"

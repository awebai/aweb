from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi import HTTPException

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
) -> dict:
    did_aw = stable_id_from_did_key(identity_did_key)
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
        body["did_log_proof"] = _register_did_log_proof(identity_signing_key, did_aw, identity_did_key)
    return body


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

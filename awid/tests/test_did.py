from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from awid.log import identity_state_hash, log_entry_payload
from awid.e2ee_keys import encryption_key_id
from awid.signing import canonical_json_bytes, sign_message
from awid_service.routes import did as did_routes


_ROOT = Path(__file__).resolve().parents[2]
_IDENTITY_VECTOR = _ROOT / "docs" / "vectors" / "identity-log-v1.json"


@pytest.fixture(autouse=True)
def _allow_static_vector_timestamps(monkeypatch):
    monkeypatch.setattr(did_routes, "enforce_timestamp_skew", lambda _timestamp: None)
    monkeypatch.setattr(
        did_routes,
        "_now",
        lambda: datetime(2026, 5, 26, 12, 0, 0, tzinfo=timezone.utc),
    )


@pytest.fixture
def identity_vectors():
    return json.loads(_IDENTITY_VECTOR.read_text(encoding="utf-8"))


@pytest.fixture
def register_vector(identity_vectors):
    return next(entry for entry in identity_vectors["entries"] if entry["name"] == "register_did")


def _register_body(register_vector: dict) -> dict:
    return {**register_vector["entry_payload"], "proof": register_vector["signature_b64"]}


def _signed_get_headers(identity_vectors: dict, path: str) -> dict[str, str]:
    seed = bytes.fromhex(identity_vectors["key_seeds"]["initial_seed_hex"])
    did_key = identity_vectors["mapping"]["initial_did_key"]
    timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    payload = f"{timestamp}\nGET\n{path}".encode("utf-8")
    return {
        "Authorization": f"DIDKey {did_key} {sign_message(seed, payload)}",
        "X-AWEB-Timestamp": timestamp,
    }


def _encryption_assertion_body(identity_vectors: dict, *, expired: bool = False) -> dict:
    seed = bytes.fromhex(identity_vectors["key_seeds"]["initial_seed_hex"])
    did_aw = identity_vectors["mapping"]["did_aw"]
    did_key = identity_vectors["mapping"]["initial_did_key"]
    public_key = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA"
    body = {
        "operation": "publish_encryption_key",
        "version": "aweb-e2ee-key-v1",
        "identity_did": did_key,
        "identity_stable_id": did_aw,
        "encryption_key_id": encryption_key_id(public_key),
        "encryption_public_key": public_key,
        "algorithm": "x25519",
        "created_at": "2026-05-26T00:00:00Z",
        "not_before": "2026-05-26T00:00:00Z",
        "expires_at": "2026-05-27T00:00:00Z",
    }
    if expired:
        body["created_at"] = "2020-01-01T00:00:00Z"
        body["not_before"] = "2020-01-01T00:00:00Z"
        body["expires_at"] = "2020-01-02T00:00:00Z"
    body["signature"] = sign_message(seed, canonical_json_bytes(body))
    return body


@pytest.mark.asyncio
async def test_register_did_accepts_identity_only_vector(
    client,
    awid_db_infra,
    identity_vectors,
    register_vector,
):
    body = _register_body(register_vector)

    expected_entry_payload = log_entry_payload(
        did_aw=body["did_aw"],
        seq=body["seq"],
        operation=body["operation"],
        previous_did_key=body["previous_did_key"],
        new_did_key=body["new_did_key"],
        prev_entry_hash=body["prev_entry_hash"],
        state_hash=body["state_hash"],
        authorized_by=body["authorized_by"],
        timestamp=body["timestamp"],
    )
    assert expected_entry_payload.decode("utf-8") == register_vector["canonical_entry_payload"]
    assert hashlib.sha256(expected_entry_payload).hexdigest() == register_vector["entry_hash"]

    response = await client.post("/v1/did", json=body)
    assert response.status_code == 200, response.text
    assert response.json() == {
        "registered": True,
        "did_aw": body["did_aw"],
        "current_did_key": body["new_did_key"],
    }

    db = awid_db_infra.get_manager("aweb")
    mapping = await db.fetch_one(
        """
        SELECT did_aw, current_did_key
        FROM {{tables.did_aw_mappings}}
        WHERE did_aw = $1
        """,
        body["did_aw"],
    )
    assert mapping["did_aw"] == body["did_aw"]
    assert mapping["current_did_key"] == body["new_did_key"]

    expected_state_hash = identity_state_hash(did_aw=body["did_aw"], current_did_key=body["new_did_key"])
    assert expected_state_hash == register_vector["state_hash"]

    log_entry = await db.fetch_one(
        """
        SELECT did_aw, seq, operation, previous_did_key, new_did_key,
               prev_entry_hash, entry_hash, state_hash, authorized_by, signature,
               timestamp
        FROM {{tables.did_aw_log}}
        WHERE did_aw = $1
        """,
        body["did_aw"],
    )
    assert log_entry["operation"] == "register_did"
    assert log_entry["previous_did_key"] is None
    assert log_entry["new_did_key"] == body["new_did_key"]
    assert log_entry["prev_entry_hash"] is None
    assert log_entry["entry_hash"] == register_vector["entry_hash"]
    assert log_entry["state_hash"] == expected_state_hash
    assert log_entry["authorized_by"] == body["authorized_by"]
    assert log_entry["signature"] == body["proof"]
    assert log_entry["timestamp"] == body["timestamp"]

    key_response = await client.get(f"/v1/did/{body['did_aw']}/key")
    assert key_response.status_code == 200, key_response.text
    key_payload = key_response.json()
    assert key_payload["current_did_key"] == body["new_did_key"]
    assert key_payload["log_head"]["operation"] == "register_did"
    assert key_payload["log_head"]["state_hash"] == expected_state_hash

    log_response = await client.get(f"/v1/did/{body['did_aw']}/log")
    assert log_response.status_code == 200, log_response.text
    log_payload = log_response.json()
    assert len(log_payload) == 1
    assert log_payload[0]["operation"] == "register_did"

    full_path = f"/v1/did/{body['did_aw']}/full"
    full_response = await client.get(
        full_path,
        headers=_signed_get_headers(identity_vectors, full_path),
    )
    assert full_response.status_code == 200, full_response.text
    full_payload = full_response.json()
    assert full_payload["did_aw"] == body["did_aw"]
    assert full_payload["current_did_key"] == body["new_did_key"]
    assert "server" not in full_payload
    assert "address" not in full_payload
    assert "handle" not in full_payload


@pytest.mark.asyncio
async def test_register_did_is_idempotent_for_same_pair(client, awid_db_infra, register_vector):
    body = _register_body(register_vector)

    first = await client.post("/v1/did", json=body)
    second = await client.post("/v1/did", json=body)

    assert first.status_code == 200, first.text
    assert second.status_code == 200, second.text
    assert second.json() == first.json()

    db = awid_db_infra.get_manager("aweb")
    count_row = await db.fetch_one(
        "SELECT COUNT(*) AS count FROM {{tables.did_aw_log}} WHERE did_aw = $1",
        body["did_aw"],
    )
    assert count_row["count"] == 1


@pytest.mark.asyncio
async def test_register_did_conflicts_for_existing_did_aw_with_different_key(
    client,
    identity_vectors,
    register_vector,
):
    body = _register_body(register_vector)
    response = await client.post("/v1/did", json=body)
    assert response.status_code == 200, response.text

    conflict_body = dict(body)
    conflict_body["new_did_key"] = identity_vectors["mapping"]["rotated_did_key"]
    conflict_body["authorized_by"] = identity_vectors["mapping"]["rotated_did_key"]
    conflict_body["state_hash"] = next(
        entry["state_hash"] for entry in identity_vectors["entries"] if entry["name"] == "rotate_key"
    )
    conflict_body["proof"] = "not-checked-for-conflict"

    conflict = await client.post("/v1/did", json=conflict_body)
    assert conflict.status_code == 409, conflict.text
    assert conflict.json()["detail"] == "did_aw already registered"


@pytest.mark.asyncio
async def test_register_did_rejects_legacy_did_key_payload(client, register_vector):
    body = _register_body(register_vector)
    body["did_key"] = body["new_did_key"]

    response = await client.post("/v1/did", json=body)

    assert response.status_code == 422, response.text
    assert "awid-sot.md" in response.text


@pytest.mark.asyncio
async def test_register_did_rejects_non_null_previous_did_key(client, register_vector):
    body = _register_body(register_vector)
    body["previous_did_key"] = body["new_did_key"]

    response = await client.post("/v1/did", json=body)

    assert response.status_code == 422, response.text
    assert "awid-sot.md" in response.text


@pytest.mark.asyncio
async def test_register_did_state_hash_tamper_breaks_signature(client, register_vector):
    body = _register_body(register_vector)
    body["state_hash"] = "0" * 64

    response = await client.post("/v1/did", json=body)

    assert response.status_code == 401, response.text
    assert response.json()["detail"] == "invalid proof"


@pytest.mark.asyncio
async def test_did_delivery_origin_endpoint_is_not_exposed(client, register_vector):
    body = _register_body(register_vector)
    register = await client.post("/v1/did", json=body)
    assert register.status_code == 200, register.text

    response = await client.put(
        f"/v1/did/{body['did_aw']}/delivery-origin",
        json={"delivery_origin": "https://identity-origin.example"},
    )
    assert response.status_code == 404

    key_response = await client.get(f"/v1/did/{body['did_aw']}/key")
    assert key_response.status_code == 200, key_response.text
    assert "delivery_origin" not in key_response.json()


@pytest.mark.asyncio
async def test_publish_identity_encryption_key_and_resolve_from_key_endpoint(
    client,
    identity_vectors,
    register_vector,
):
    register = await client.post("/v1/did", json=_register_body(register_vector))
    assert register.status_code == 200, register.text

    body = _encryption_assertion_body(identity_vectors)
    publish = await client.post(f"/v1/did/{body['identity_stable_id']}/encryption-key", json=body)
    assert publish.status_code == 200, publish.text
    assert publish.json() == body

    key_response = await client.get(f"/v1/did/{body['identity_stable_id']}/key")
    assert key_response.status_code == 200, key_response.text
    key_payload = key_response.json()
    assert key_payload["encryption_key"]["encryption_key_id"] == body["encryption_key_id"]
    assert key_payload["encryption_key"]["identity_did"] == body["identity_did"]
    assert key_payload["encryption_key"]["signature"] == body["signature"]


@pytest.mark.asyncio
async def test_publish_identity_encryption_key_rejects_controller_substitution(
    client,
    identity_vectors,
    register_vector,
):
    register = await client.post("/v1/did", json=_register_body(register_vector))
    assert register.status_code == 200, register.text

    body = _encryption_assertion_body(identity_vectors)
    body["identity_did"] = identity_vectors["mapping"]["rotated_did_key"]
    body["signature"] = "invalid"

    publish = await client.post(f"/v1/did/{body['identity_stable_id']}/encryption-key", json=body)
    assert publish.status_code == 422, publish.text
    assert "identity_did must match current did:key" in publish.text


@pytest.mark.asyncio
async def test_publish_identity_encryption_key_rejects_key_id_mismatch(
    client,
    identity_vectors,
    register_vector,
):
    register = await client.post("/v1/did", json=_register_body(register_vector))
    assert register.status_code == 200, register.text

    body = _encryption_assertion_body(identity_vectors)
    body["encryption_key_id"] = "sha256:wrong"
    body["signature"] = sign_message(
        bytes.fromhex(identity_vectors["key_seeds"]["initial_seed_hex"]),
        canonical_json_bytes({k: v for k, v in body.items() if k != "signature"}),
    )

    publish = await client.post(f"/v1/did/{body['identity_stable_id']}/encryption-key", json=body)
    assert publish.status_code == 422, publish.text
    assert "encryption_key_id does not match" in publish.text


@pytest.mark.asyncio
async def test_publish_identity_encryption_key_rejects_expired_assertion(
    client,
    identity_vectors,
    register_vector,
):
    register = await client.post("/v1/did", json=_register_body(register_vector))
    assert register.status_code == 200, register.text

    body = _encryption_assertion_body(identity_vectors, expired=True)
    publish = await client.post(f"/v1/did/{body['identity_stable_id']}/encryption-key", json=body)
    assert publish.status_code == 422, publish.text
    assert "expired" in publish.text

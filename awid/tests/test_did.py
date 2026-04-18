from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from awid.log import identity_state_hash, register_did_entry_payload
from awid.signing import sign_message
from awid_service.routes import did as did_routes


_ROOT = Path(__file__).resolve().parents[2]
_IDENTITY_VECTOR = _ROOT / "docs" / "vectors" / "identity-log-v1.json"


@pytest.fixture(autouse=True)
def _allow_static_vector_timestamps(monkeypatch):
    monkeypatch.setattr(did_routes, "enforce_timestamp_skew", lambda _timestamp: None)


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


@pytest.mark.asyncio
async def test_register_did_accepts_identity_only_vector(
    client,
    awid_db_infra,
    identity_vectors,
    register_vector,
):
    body = _register_body(register_vector)

    expected_entry_payload = register_did_entry_payload(
        did_aw=body["did_aw"],
        did_key=body["did_key"],
        prev_entry_hash=body["prev_entry_hash"],
        seq=body["seq"],
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
        "current_did_key": body["did_key"],
    }

    db = awid_db_infra.get_manager("aweb")
    mapping = await db.fetch_one(
        """
        SELECT did_aw, current_did_key, server_url, address, handle
        FROM {{tables.did_aw_mappings}}
        WHERE did_aw = $1
        """,
        body["did_aw"],
    )
    assert mapping["did_aw"] == body["did_aw"]
    assert mapping["current_did_key"] == body["did_key"]
    assert mapping["server_url"] == ""
    assert mapping["address"] == ""
    assert mapping["handle"] is None

    expected_state_hash = identity_state_hash(did_aw=body["did_aw"], current_did_key=body["did_key"])
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
    assert log_entry["new_did_key"] == body["did_key"]
    assert log_entry["prev_entry_hash"] is None
    assert log_entry["entry_hash"] == register_vector["entry_hash"]
    assert log_entry["state_hash"] == expected_state_hash
    assert log_entry["authorized_by"] == body["authorized_by"]
    assert log_entry["signature"] == body["proof"]
    assert log_entry["timestamp"] == body["timestamp"]

    key_response = await client.get(f"/v1/did/{body['did_aw']}/key")
    assert key_response.status_code == 200, key_response.text
    key_payload = key_response.json()
    assert key_payload["current_did_key"] == body["did_key"]
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
    assert full_payload["current_did_key"] == body["did_key"]
    assert full_payload["server"] == ""
    assert full_payload["address"] == ""
    assert full_payload["handle"] is None


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
    conflict_body["did_key"] = identity_vectors["mapping"]["rotated_did_key"]
    conflict_body["authorized_by"] = identity_vectors["mapping"]["rotated_did_key"]
    conflict_body["proof"] = "not-checked-for-conflict"

    conflict = await client.post("/v1/did", json=conflict_body)
    assert conflict.status_code == 409, conflict.text
    assert conflict.json()["detail"] == "did_aw already registered"


@pytest.mark.asyncio
async def test_register_did_rejects_legacy_bundled_address_payload(client, register_vector):
    body = _register_body(register_vector)
    body["address"] = "example.com/alice"

    response = await client.post("/v1/did", json=body)

    assert response.status_code == 422, response.text
    assert "awid-sot.md" in response.text

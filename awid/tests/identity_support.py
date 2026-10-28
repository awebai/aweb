"""did:aw registration and rotation through the real AWID routes, for tests."""

from __future__ import annotations

from datetime import datetime, timezone

from awid.did import stable_id_from_did_key
from awid.log import identity_state_hash, log_entry_payload
from awid.signing import sign_message


async def register_identity(client, signing_key, did_key):
    did_aw = stable_id_from_did_key(did_key)
    timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    state_hash = identity_state_hash(did_aw=did_aw, current_did_key=did_key)
    proof = sign_message(
        signing_key,
        log_entry_payload(
            did_aw=did_aw,
            seq=1,
            operation="register_did",
            previous_did_key=None,
            new_did_key=did_key,
            prev_entry_hash=None,
            state_hash=state_hash,
            authorized_by=did_key,
            timestamp=timestamp,
        ),
    )
    resp = await client.post(
        "/v1/did",
        json={
            "did_aw": did_aw,
            "new_did_key": did_key,
            "operation": "register_did",
            "previous_did_key": None,
            "prev_entry_hash": None,
            "seq": 1,
            "state_hash": state_hash,
            "authorized_by": did_key,
            "timestamp": timestamp,
            "proof": proof,
        },
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


async def rotate_identity(client, old_signing_key, did_aw, old_did_key, new_did_key):
    resp = await request_rotation(client, old_signing_key, did_aw, old_did_key, new_did_key)
    assert resp.status_code == 200, resp.text
    return resp.json()


async def request_rotation(client, old_signing_key, did_aw, old_did_key, new_did_key):
    """Sign a rotation from the current log head and send it."""
    key_resp = await client.get(f"/v1/did/{did_aw}/key")
    assert key_resp.status_code == 200, key_resp.text
    head = key_resp.json()["log_head"]

    timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    state_hash = identity_state_hash(did_aw=did_aw, current_did_key=new_did_key)
    seq = head["seq"] + 1
    signature = sign_message(
        old_signing_key,
        log_entry_payload(
            did_aw=did_aw,
            seq=seq,
            operation="rotate_key",
            previous_did_key=old_did_key,
            new_did_key=new_did_key,
            prev_entry_hash=head["entry_hash"],
            state_hash=state_hash,
            authorized_by=old_did_key,
            timestamp=timestamp,
        ),
    )
    return await client.put(
        f"/v1/did/{did_aw}",
        json={
            "operation": "rotate_key",
            "new_did_key": new_did_key,
            "seq": seq,
            "prev_entry_hash": head["entry_hash"],
            "state_hash": state_hash,
            "authorized_by": old_did_key,
            "timestamp": timestamp,
            "signature": signature,
        },
    )

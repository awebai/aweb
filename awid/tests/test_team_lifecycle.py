"""End-to-end team lifecycle integration test.

Covers the full flow that aweb and aweb-cloud depend on:
namespace → team → certificates → revocation → rotation → deletion.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from uuid import uuid4

import pytest

from awid.did import did_from_public_key, generate_keypair, stable_id_from_did_key
from awid.log import identity_state_hash, log_entry_payload
from awid.signing import sign_message

from conftest import build_signed_headers as _sign


async def _register_identity(client, signing_key, did_key):
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
    return did_aw


async def _register_member_address(client, ns_key, ns_did, domain, name, member_key, member_did_key):
    did_aw = await _register_identity(client, member_key, member_did_key)
    headers = _sign(ns_key, ns_did, domain=domain, operation="register_address", name=name)
    resp = await client.post(
        f"/v1/namespaces/{domain}/addresses",
        json={
            "name": name,
            "did_aw": did_aw,
            "current_did_key": member_did_key,
            "reachability": "public",
        },
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    return did_aw


@pytest.mark.asyncio
async def test_full_team_lifecycle(client, controller_identity):
    ns_key, ns_did = controller_identity
    domain = "lifecycle.example"

    # ---------------------------------------------------------------
    # 1. Create namespace
    # ---------------------------------------------------------------
    headers = _sign(ns_key, ns_did, domain=domain, operation="register")
    resp = await client.post("/v1/namespaces", json={"domain": domain}, headers=headers)
    assert resp.status_code == 200, resp.text

    # ---------------------------------------------------------------
    # 2. Create team
    # ---------------------------------------------------------------
    team_key, team_pub = generate_keypair()
    team_did = did_from_public_key(team_pub)

    headers = _sign(ns_key, ns_did, domain=domain, operation="create_team", name="platform")
    resp = await client.post(
        f"/v1/namespaces/{domain}/teams",
        json={"name": "platform", "display_name": "Platform Team", "team_did_key": team_did},
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    team = resp.json()
    assert team["name"] == "platform"
    assert team["team_did_key"] == team_did

    # ---------------------------------------------------------------
    # 3. Register two certificates (alice and bob)
    # ---------------------------------------------------------------
    alice_key, alice_pub = generate_keypair()
    alice_did_key = did_from_public_key(alice_pub)
    alice_did_aw = await _register_member_address(
        client, ns_key, ns_did, domain, "alice", alice_key, alice_did_key,
    )
    alice_cert_id = str(uuid4())

    headers = _sign(
        team_key, team_did, domain=domain,
        operation="register_certificate", team_name="platform",
        certificate_id=alice_cert_id,
    )
    resp = await client.post(
        f"/v1/namespaces/{domain}/teams/platform/certificates",
        json={
            "certificate_id": alice_cert_id,
            "member_did_key": alice_did_key,
            "member_did_aw": alice_did_aw,
            "member_address": f"{domain}/alice",
            "alias": "alice",
            "lifetime": "persistent",
        },
        headers=headers,
    )
    assert resp.status_code == 200, resp.text

    _, bob_pub = generate_keypair()
    bob_did_key = did_from_public_key(bob_pub)
    bob_cert_id = str(uuid4())

    headers = _sign(
        team_key, team_did, domain=domain,
        operation="register_certificate", team_name="platform",
        certificate_id=bob_cert_id,
    )
    resp = await client.post(
        f"/v1/namespaces/{domain}/teams/platform/certificates",
        json={
            "certificate_id": bob_cert_id,
            "member_did_key": bob_did_key,
            "alias": "bob",
            "lifetime": "ephemeral",
        },
        headers=headers,
    )
    assert resp.status_code == 200, resp.text

    # ---------------------------------------------------------------
    # 4. List certificates (active_only) — both appear
    # ---------------------------------------------------------------
    resp = await client.get(f"/v1/namespaces/{domain}/teams/platform/certificates?active_only=true")
    assert resp.status_code == 200
    certs = resp.json()["certificates"]
    assert len(certs) == 2
    cert_ids = {c["certificate_id"] for c in certs}
    assert cert_ids == {alice_cert_id, bob_cert_id}

    # Verify certificate fields
    alice_cert = next(c for c in certs if c["alias"] == "alice")
    assert alice_cert["member_did_key"] == alice_did_key
    assert alice_cert["member_did_aw"] == alice_did_aw
    assert alice_cert["member_address"] == f"{domain}/alice"
    assert alice_cert["lifetime"] == "persistent"
    assert alice_cert["revoked_at"] is None

    bob_cert = next(c for c in certs if c["alias"] == "bob")
    assert bob_cert["lifetime"] == "ephemeral"
    assert bob_cert["member_did_aw"] is None

    # Record timestamp before revocation for incremental sync test
    time.sleep(0.01)  # ensure revoked_at > this timestamp
    before_revoke = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    # ---------------------------------------------------------------
    # 5. Revoke bob's certificate
    # ---------------------------------------------------------------
    headers = _sign(
        team_key, team_did, domain=domain,
        operation="revoke_certificate", team_name="platform",
        certificate_id=bob_cert_id,
    )
    resp = await client.post(
        f"/v1/namespaces/{domain}/teams/platform/certificates/revoke",
        json={"certificate_id": bob_cert_id},
        headers=headers,
    )
    assert resp.status_code == 200
    assert resp.json()["revoked"] is True

    # ---------------------------------------------------------------
    # 6. List certificates (active_only) — only alice
    # ---------------------------------------------------------------
    resp = await client.get(f"/v1/namespaces/{domain}/teams/platform/certificates?active_only=true")
    assert resp.status_code == 200
    active_certs = resp.json()["certificates"]
    assert len(active_certs) == 1
    assert active_certs[0]["certificate_id"] == alice_cert_id

    # List all — both still exist, bob has revoked_at
    resp = await client.get(f"/v1/namespaces/{domain}/teams/platform/certificates")
    assert resp.status_code == 200
    all_certs = resp.json()["certificates"]
    assert len(all_certs) == 2
    revoked_bob = next(c for c in all_certs if c["certificate_id"] == bob_cert_id)
    assert revoked_bob["revoked_at"] is not None

    # ---------------------------------------------------------------
    # 7. List revocations — bob appears
    # ---------------------------------------------------------------
    resp = await client.get(f"/v1/namespaces/{domain}/teams/platform/revocations")
    assert resp.status_code == 200
    revocations = resp.json()["revocations"]
    assert len(revocations) == 1
    assert revocations[0]["certificate_id"] == bob_cert_id
    assert revocations[0]["revoked_at"] is not None

    # ---------------------------------------------------------------
    # 8. List revocations with since= — incremental sync
    # ---------------------------------------------------------------
    resp = await client.get(
        f"/v1/namespaces/{domain}/teams/platform/revocations?since={before_revoke}"
    )
    assert resp.status_code == 200, resp.text
    incremental = resp.json()["revocations"]
    assert len(incremental) == 1
    assert incremental[0]["certificate_id"] == bob_cert_id

    # Future timestamp should return empty
    future = "2099-01-01T00:00:00Z"
    resp = await client.get(
        f"/v1/namespaces/{domain}/teams/platform/revocations?since={future}"
    )
    assert resp.status_code == 200
    assert resp.json()["revocations"] == []

    # ---------------------------------------------------------------
    # 9. Rotate team key
    # ---------------------------------------------------------------
    new_team_key, new_team_pub = generate_keypair()
    new_team_did = did_from_public_key(new_team_pub)

    headers = _sign(
        ns_key, ns_did, domain=domain,
        operation="rotate_team_key", name="platform",
        new_team_did_key=new_team_did,
    )
    resp = await client.post(
        f"/v1/namespaces/{domain}/teams/platform/rotate",
        json={"new_team_did_key": new_team_did},
        headers=headers,
    )
    assert resp.status_code == 200
    rotate_body = resp.json()
    assert rotate_body["team_did_key"] == new_team_did
    assert rotate_body["key_changed"] is True

    # ---------------------------------------------------------------
    # 10. Certificate rows persist after key rotation
    # ---------------------------------------------------------------
    resp = await client.get(f"/v1/namespaces/{domain}/teams/platform/certificates")
    assert resp.status_code == 200
    post_rotate_certs = resp.json()["certificates"]
    assert len(post_rotate_certs) == 2  # rows still exist

    # Confirm the team's public key is now the new one
    resp = await client.get(f"/v1/namespaces/{domain}/teams/platform")
    assert resp.status_code == 200
    assert resp.json()["team_did_key"] == new_team_did

    # ---------------------------------------------------------------
    # 11. Revoke the remaining active certificate, then delete team
    # ---------------------------------------------------------------
    headers = _sign(
        new_team_key, new_team_did, domain=domain,
        operation="revoke_certificate", team_name="platform",
        certificate_id=alice_cert_id,
    )
    resp = await client.post(
        f"/v1/namespaces/{domain}/teams/platform/certificates/revoke",
        json={"certificate_id": alice_cert_id},
        headers=headers,
    )
    assert resp.status_code == 200

    headers = _sign(ns_key, ns_did, domain=domain, operation="delete_team", team_name="platform")
    resp = await client.delete(f"/v1/namespaces/{domain}/teams/platform", headers=headers)
    assert resp.status_code == 200

    # Team is gone
    resp = await client.get(f"/v1/namespaces/{domain}/teams/platform")
    assert resp.status_code == 404

    # Team list is empty
    resp = await client.get(f"/v1/namespaces/{domain}/teams")
    assert resp.status_code == 200
    assert resp.json()["teams"] == []

    # Certificates inaccessible after team deletion
    resp = await client.get(f"/v1/namespaces/{domain}/teams/platform/certificates")
    assert resp.status_code == 404

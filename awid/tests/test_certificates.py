from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from uuid import uuid4

import pytest

from awid.did import did_from_public_key, generate_keypair, stable_id_from_did_key
from awid.log import identity_state_hash, log_entry_payload
from awid.signing import canonical_json_bytes, sign_message

from conftest import build_signed_headers as _sign


def _path_signed_headers(signing_key, did_key, *, method: str, path: str):
    ts = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    payload = f"{ts}\n{method}\n{path}".encode("utf-8")
    sig = sign_message(signing_key, payload)
    return {
        "Authorization": f"DIDKey {did_key} {sig}",
        "X-AWEB-Timestamp": ts,
    }


def _signed_certificate_blob(
    team_key,
    *,
    certificate_id: str,
    team_id: str,
    team_did_key: str,
    member_did_key: str,
    alias: str,
    lifetime: str = "persistent",
    member_did_aw: str | None = None,
    member_address: str | None = None,
) -> str:
    cert = {
        "version": 1,
        "certificate_id": certificate_id,
        "team_id": team_id,
        "team_did_key": team_did_key,
        "member_did_key": member_did_key,
        "alias": alias,
        "lifetime": lifetime,
        "issued_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    }
    if member_did_aw:
        cert["member_did_aw"] = member_did_aw
    if member_address:
        cert["member_address"] = member_address
    cert["signature"] = sign_message(team_key, canonical_json_bytes(cert))
    data = json.dumps(cert, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return base64.b64encode(data).decode("ascii")


async def _setup_team(client, ns_signing_key, ns_controller_did, domain, team_name):
    """Register a namespace and create a team. Returns (team_signing_key, team_did_key, team_json)."""
    # Register namespace
    headers = _sign(ns_signing_key, ns_controller_did, domain=domain, operation="register")
    resp = await client.post("/v1/namespaces", json={"domain": domain}, headers=headers)
    assert resp.status_code == 200, resp.text

    # Create team with its own keypair
    team_signing_key, team_pub = generate_keypair()
    team_did_key = did_from_public_key(team_pub)
    headers = _sign(
        ns_signing_key, ns_controller_did,
        domain=domain, operation="create_team", name=team_name,
    )
    resp = await client.post(
        f"/v1/namespaces/{domain}/teams",
        json={"name": team_name, "team_did_key": team_did_key},
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    return team_signing_key, team_did_key, resp.json()


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


# ---------------------------------------------------------------------------
# POST /v1/namespaces/{domain}/teams/{name}/certificates — register cert
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_register_certificate(client, controller_identity):
    ns_key, ns_did = controller_identity
    team_key, team_did, _ = await _setup_team(client, ns_key, ns_did, "cert.com", "backend")

    member_key, member_pub = generate_keypair()
    member_did_key = did_from_public_key(member_pub)
    member_did_aw = await _register_member_address(
        client, ns_key, ns_did, "cert.com", "alice", member_key, member_did_key,
    )
    cert_id = str(uuid4())

    headers = _sign(
        team_key, team_did,
        domain="cert.com", operation="register_certificate",
        team_name="backend", certificate_id=cert_id,
    )
    resp = await client.post(
        "/v1/namespaces/cert.com/teams/backend/certificates",
        json={
            "certificate_id": cert_id,
            "member_did_key": member_did_key,
            "member_did_aw": member_did_aw,
            "member_address": "cert.com/alice",
            "alias": "alice",
            "lifetime": "persistent",
        },
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["registered"] is True
    assert body["certificate_id"] == cert_id


@pytest.mark.asyncio
async def test_register_certificate_with_blob_can_be_fetched_by_subject(client, controller_identity):
    ns_key, ns_did = controller_identity
    team_key, team_did, _ = await _setup_team(client, ns_key, ns_did, "blob.cert.com", "backend")

    member_key, member_pub = generate_keypair()
    member_did_key = did_from_public_key(member_pub)
    member_did_aw = await _register_member_address(
        client, ns_key, ns_did, "blob.cert.com", "alice", member_key, member_did_key,
    )
    cert_id = str(uuid4())
    certificate = _signed_certificate_blob(
        team_key,
        certificate_id=cert_id,
        team_id="backend:blob.cert.com",
        team_did_key=team_did,
        member_did_key=member_did_key,
        member_did_aw=member_did_aw,
        member_address="blob.cert.com/alice",
        alias="alice",
    )

    headers = _sign(
        team_key, team_did,
        domain="blob.cert.com", operation="register_certificate",
        team_name="backend", certificate_id=cert_id,
    )
    resp = await client.post(
        "/v1/namespaces/blob.cert.com/teams/backend/certificates",
        json={
            "certificate_id": cert_id,
            "member_did_key": member_did_key,
            "member_did_aw": member_did_aw,
            "member_address": "blob.cert.com/alice",
            "alias": "alice",
            "lifetime": "persistent",
            "certificate": certificate,
        },
        headers=headers,
    )
    assert resp.status_code == 200, resp.text

    path = f"/v1/namespaces/blob.cert.com/teams/backend/certificates/{cert_id}"
    resp = await client.get(
        path,
        headers=_path_signed_headers(member_key, member_did_key, method="GET", path=path),
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["team_id"] == "backend:blob.cert.com"
    assert body["certificate_id"] == cert_id
    assert body["member_did_key"] == member_did_key
    assert body["member_did_aw"] == member_did_aw
    assert body["member_address"] == "blob.cert.com/alice"
    assert body["certificate"] == certificate


@pytest.mark.asyncio
async def test_fetch_certificate_rejects_other_did(client, controller_identity):
    ns_key, ns_did = controller_identity
    team_key, team_did, _ = await _setup_team(client, ns_key, ns_did, "otherfetch.cert.com", "backend")

    member_key, member_pub = generate_keypair()
    member_did_key = did_from_public_key(member_pub)
    cert_id = str(uuid4())
    certificate = _signed_certificate_blob(
        team_key,
        certificate_id=cert_id,
        team_id="backend:otherfetch.cert.com",
        team_did_key=team_did,
        member_did_key=member_did_key,
        alias="alice",
        lifetime="ephemeral",
    )

    headers = _sign(
        team_key, team_did,
        domain="otherfetch.cert.com", operation="register_certificate",
        team_name="backend", certificate_id=cert_id,
    )
    resp = await client.post(
        "/v1/namespaces/otherfetch.cert.com/teams/backend/certificates",
        json={
            "certificate_id": cert_id,
            "member_did_key": member_did_key,
            "alias": "alice",
            "lifetime": "ephemeral",
            "certificate": certificate,
        },
        headers=headers,
    )
    assert resp.status_code == 200, resp.text

    other_key, other_pub = generate_keypair()
    other_did = did_from_public_key(other_pub)
    path = f"/v1/namespaces/otherfetch.cert.com/teams/backend/certificates/{cert_id}"
    resp = await client.get(
        path,
        headers=_path_signed_headers(other_key, other_did, method="GET", path=path),
    )
    assert resp.status_code == 403, resp.text


@pytest.mark.asyncio
async def test_fetch_certificate_metadata_only_record_has_explicit_error(client, controller_identity):
    ns_key, ns_did = controller_identity
    team_key, team_did, _ = await _setup_team(client, ns_key, ns_did, "legacyfetch.cert.com", "backend")

    member_key, member_pub = generate_keypair()
    member_did_key = did_from_public_key(member_pub)
    cert_id = str(uuid4())

    headers = _sign(
        team_key, team_did,
        domain="legacyfetch.cert.com", operation="register_certificate",
        team_name="backend", certificate_id=cert_id,
    )
    resp = await client.post(
        "/v1/namespaces/legacyfetch.cert.com/teams/backend/certificates",
        json={
            "certificate_id": cert_id,
            "member_did_key": member_did_key,
            "alias": "alice",
            "lifetime": "ephemeral",
        },
        headers=headers,
    )
    assert resp.status_code == 200, resp.text

    path = f"/v1/namespaces/legacyfetch.cert.com/teams/backend/certificates/{cert_id}"
    resp = await client.get(
        path,
        headers=_path_signed_headers(member_key, member_did_key, method="GET", path=path),
    )
    assert resp.status_code == 409, resp.text
    assert "reissue" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_register_certificate_rejects_member_address_for_different_did_aw(client, controller_identity):
    ns_key, ns_did = controller_identity
    team_key, team_did, _ = await _setup_team(client, ns_key, ns_did, "mismatch.cert.com", "backend")

    member_key, member_pub = generate_keypair()
    member_did_key = did_from_public_key(member_pub)
    await _register_member_address(
        client, ns_key, ns_did, "mismatch.cert.com", "alice", member_key, member_did_key,
    )
    other_did_aw = "did:aw:other"
    cert_id = str(uuid4())

    headers = _sign(
        team_key, team_did,
        domain="mismatch.cert.com", operation="register_certificate",
        team_name="backend", certificate_id=cert_id,
    )
    resp = await client.post(
        "/v1/namespaces/mismatch.cert.com/teams/backend/certificates",
        json={
            "certificate_id": cert_id,
            "member_did_key": member_did_key,
            "member_did_aw": other_did_aw,
            "member_address": "mismatch.cert.com/alice",
            "alias": "alice",
            "lifetime": "persistent",
        },
        headers=headers,
    )
    assert resp.status_code == 422, resp.text
    assert "member_address belongs to" in resp.json()["detail"]
    assert other_did_aw in resp.json()["detail"]


@pytest.mark.asyncio
async def test_register_certificate_rejects_member_address_without_did_aw(client, controller_identity):
    ns_key, ns_did = controller_identity
    team_key, team_did, _ = await _setup_team(client, ns_key, ns_did, "missingdid.cert.com", "backend")

    _, member_pub = generate_keypair()
    member_did_key = did_from_public_key(member_pub)
    cert_id = str(uuid4())

    headers = _sign(
        team_key, team_did,
        domain="missingdid.cert.com", operation="register_certificate",
        team_name="backend", certificate_id=cert_id,
    )
    resp = await client.post(
        "/v1/namespaces/missingdid.cert.com/teams/backend/certificates",
        json={
            "certificate_id": cert_id,
            "member_did_key": member_did_key,
            "member_address": "missingdid.cert.com/alice",
            "alias": "alice",
            "lifetime": "persistent",
        },
        headers=headers,
    )
    assert resp.status_code == 422, resp.text
    assert resp.json()["detail"] == "member_did_aw is required when member_address is set"


@pytest.mark.asyncio
async def test_register_certificate_ephemeral(client, controller_identity):
    ns_key, ns_did = controller_identity
    team_key, team_did, _ = await _setup_team(client, ns_key, ns_did, "eph.com", "ops")

    _, member_pub = generate_keypair()
    member_did_key = did_from_public_key(member_pub)
    cert_id = str(uuid4())

    headers = _sign(
        team_key, team_did,
        domain="eph.com", operation="register_certificate",
        team_name="ops", certificate_id=cert_id,
    )
    resp = await client.post(
        "/v1/namespaces/eph.com/teams/ops/certificates",
        json={
            "certificate_id": cert_id,
            "member_did_key": member_did_key,
            "alias": "bot1",
            "lifetime": "ephemeral",
        },
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["registered"] is True


@pytest.mark.asyncio
async def test_register_certificate_duplicate_returns_409(client, controller_identity):
    ns_key, ns_did = controller_identity
    team_key, team_did, _ = await _setup_team(client, ns_key, ns_did, "dup.cert.com", "infra")

    _, member_pub = generate_keypair()
    member_did_key = did_from_public_key(member_pub)
    cert_id = str(uuid4())

    headers = _sign(
        team_key, team_did,
        domain="dup.cert.com", operation="register_certificate",
        team_name="infra", certificate_id=cert_id,
    )
    resp = await client.post(
        "/v1/namespaces/dup.cert.com/teams/infra/certificates",
        json={
            "certificate_id": cert_id,
            "member_did_key": member_did_key,
            "alias": "alice",
        },
        headers=headers,
    )
    assert resp.status_code == 200

    # Second registration with same certificate_id must be rejected
    headers = _sign(
        team_key, team_did,
        domain="dup.cert.com", operation="register_certificate",
        team_name="infra", certificate_id=cert_id,
    )
    resp = await client.post(
        "/v1/namespaces/dup.cert.com/teams/infra/certificates",
        json={
            "certificate_id": cert_id,
            "member_did_key": member_did_key,
            "alias": "alice",
        },
        headers=headers,
    )
    assert resp.status_code == 409


@pytest.mark.asyncio
async def test_register_certificate_deleted_team_returns_404(client, controller_identity):
    ns_key, ns_did = controller_identity
    team_key, team_did, _ = await _setup_team(client, ns_key, ns_did, "del.cert.com", "gone")

    # Delete the team
    headers = _sign(ns_key, ns_did, domain="del.cert.com", operation="delete_team", team_name="gone")
    resp = await client.delete("/v1/namespaces/del.cert.com/teams/gone", headers=headers)
    assert resp.status_code == 200

    # Try to register a cert on the deleted team
    _, member_pub = generate_keypair()
    cert_id = str(uuid4())
    headers = _sign(
        team_key, team_did,
        domain="del.cert.com", operation="register_certificate",
        team_name="gone", certificate_id=cert_id,
    )
    resp = await client.post(
        "/v1/namespaces/del.cert.com/teams/gone/certificates",
        json={
            "certificate_id": cert_id,
            "member_did_key": did_from_public_key(member_pub),
            "alias": "orphan",
        },
        headers=headers,
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_register_certificate_wrong_key_returns_403(client, controller_identity):
    ns_key, ns_did = controller_identity
    team_key, team_did, _ = await _setup_team(client, ns_key, ns_did, "auth.cert.com", "sec")

    wrong_key, wrong_pub = generate_keypair()
    wrong_did = did_from_public_key(wrong_pub)

    _, member_pub = generate_keypair()
    cert_id = str(uuid4())
    headers = _sign(
        wrong_key, wrong_did,
        domain="auth.cert.com", operation="register_certificate",
        team_name="sec", certificate_id=cert_id,
    )
    resp = await client.post(
        "/v1/namespaces/auth.cert.com/teams/sec/certificates",
        json={
            "certificate_id": cert_id,
            "member_did_key": did_from_public_key(member_pub),
            "alias": "intruder",
        },
        headers=headers,
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_register_certificate_no_auth_returns_401(client, controller_identity):
    ns_key, ns_did = controller_identity
    team_key, team_did, _ = await _setup_team(client, ns_key, ns_did, "noauth.cert.com", "web")

    _, member_pub = generate_keypair()
    resp = await client.post(
        "/v1/namespaces/noauth.cert.com/teams/web/certificates",
        json={
            "certificate_id": str(uuid4()),
            "member_did_key": did_from_public_key(member_pub),
            "alias": "anon",
        },
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_register_certificate_nonexistent_team_returns_404(client, controller_identity):
    ns_key, ns_did = controller_identity
    # Register namespace but no team
    headers = _sign(ns_key, ns_did, domain="noteam.cert.com", operation="register")
    resp = await client.post("/v1/namespaces", json={"domain": "noteam.cert.com"}, headers=headers)
    assert resp.status_code == 200

    _, member_pub = generate_keypair()
    # Use the namespace controller key (will fail on team lookup, not auth)
    cert_id = str(uuid4())
    headers = _sign(
        ns_key, ns_did,
        domain="noteam.cert.com", operation="register_certificate",
        team_name="nope", certificate_id=cert_id,
    )
    resp = await client.post(
        "/v1/namespaces/noteam.cert.com/teams/nope/certificates",
        json={
            "certificate_id": cert_id,
            "member_did_key": did_from_public_key(member_pub),
            "alias": "ghost",
        },
        headers=headers,
    )
    assert resp.status_code == 404

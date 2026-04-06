from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

import pytest

from aweb.awid import sign_message
from aweb.awid.did import did_from_public_key, generate_keypair, stable_id_from_did_key
from aweb.awid.signing import canonical_json_bytes


def _sign(signing_key, did_key, *, domain, operation, **extra):
    """Build Authorization header and timestamp for a signed request."""
    ts = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    payload = {"domain": domain, "operation": operation, "timestamp": ts}
    payload.update(extra)
    sig = sign_message(signing_key, canonical_json_bytes(payload))
    return {
        "Authorization": f"DIDKey {did_key} {sig}",
        "X-AWEB-Timestamp": ts,
    }


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


# ---------------------------------------------------------------------------
# POST /v1/namespaces/{domain}/teams/{name}/certificates — register cert
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_register_certificate(client, controller_identity):
    ns_key, ns_did = controller_identity
    team_key, team_did, _ = await _setup_team(client, ns_key, ns_did, "cert.com", "backend")

    _, member_pub = generate_keypair()
    member_did_key = did_from_public_key(member_pub)
    member_did_aw = stable_id_from_did_key(member_did_key)
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
            "lifetime": "permanent",
        },
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["registered"] is True
    assert body["certificate_id"] == cert_id


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
    headers = _sign(ns_key, ns_did, domain="del.cert.com", operation="delete_team", name="gone")
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

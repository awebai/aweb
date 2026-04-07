from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

import pytest

from awid.did import did_from_public_key, generate_keypair

from conftest import build_signed_headers as _sign


async def _setup_team(client, ns_key, ns_did, domain, team_name):
    headers = _sign(ns_key, ns_did, domain=domain, operation="register")
    resp = await client.post("/v1/namespaces", json={"domain": domain}, headers=headers)
    assert resp.status_code == 200, resp.text

    team_key, team_pub = generate_keypair()
    team_did = did_from_public_key(team_pub)
    headers = _sign(ns_key, ns_did, domain=domain, operation="create_team", name=team_name)
    resp = await client.post(
        f"/v1/namespaces/{domain}/teams",
        json={"name": team_name, "team_did_key": team_did},
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    return team_key, team_did


async def _register_cert(client, team_key, team_did, domain, team_name, alias, *, lifetime="persistent"):
    _, member_pub = generate_keypair()
    member_did_key = did_from_public_key(member_pub)
    cert_id = str(uuid4())
    headers = _sign(
        team_key, team_did,
        domain=domain, operation="register_certificate",
        team_name=team_name, certificate_id=cert_id,
    )
    resp = await client.post(
        f"/v1/namespaces/{domain}/teams/{team_name}/certificates",
        json={
            "certificate_id": cert_id,
            "member_did_key": member_did_key,
            "alias": alias,
            "lifetime": lifetime,
        },
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    return cert_id, member_did_key


# ---------------------------------------------------------------------------
# GET /v1/namespaces/{domain}/teams/{name}/certificates
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_certificates(client, controller_identity):
    ns_key, ns_did = controller_identity
    team_key, team_did = await _setup_team(client, ns_key, ns_did, "lc.com", "ops")

    cert1, _ = await _register_cert(client, team_key, team_did, "lc.com", "ops", "alice")
    cert2, _ = await _register_cert(client, team_key, team_did, "lc.com", "ops", "bob")

    resp = await client.get("/v1/namespaces/lc.com/teams/ops/certificates")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["certificates"]) == 2
    ids = {c["certificate_id"] for c in body["certificates"]}
    assert ids == {cert1, cert2}


@pytest.mark.asyncio
async def test_list_certificates_active_only(client, controller_identity):
    ns_key, ns_did = controller_identity
    team_key, team_did = await _setup_team(client, ns_key, ns_did, "active.com", "svc")

    cert1, _ = await _register_cert(client, team_key, team_did, "active.com", "svc", "alice")
    cert2, _ = await _register_cert(client, team_key, team_did, "active.com", "svc", "bob")

    # Revoke cert1
    headers = _sign(
        team_key, team_did,
        domain="active.com", operation="revoke_certificate",
        team_name="svc", certificate_id=cert1,
    )
    resp = await client.post(
        "/v1/namespaces/active.com/teams/svc/certificates/revoke",
        json={"certificate_id": cert1},
        headers=headers,
    )
    assert resp.status_code == 200, resp.text

    # List active only
    resp = await client.get("/v1/namespaces/active.com/teams/svc/certificates?active_only=true")
    assert resp.status_code == 200
    certs = resp.json()["certificates"]
    assert len(certs) == 1
    assert certs[0]["certificate_id"] == cert2

    # List all (includes revoked)
    resp = await client.get("/v1/namespaces/active.com/teams/svc/certificates")
    assert resp.status_code == 200
    assert len(resp.json()["certificates"]) == 2


@pytest.mark.asyncio
async def test_list_certificates_empty(client, controller_identity):
    ns_key, ns_did = controller_identity
    await _setup_team(client, ns_key, ns_did, "empty.lc.com", "web")

    resp = await client.get("/v1/namespaces/empty.lc.com/teams/web/certificates")
    assert resp.status_code == 200
    assert resp.json()["certificates"] == []


# ---------------------------------------------------------------------------
# POST /v1/namespaces/{domain}/teams/{name}/certificates/revoke
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_revoke_certificate(client, controller_identity):
    ns_key, ns_did = controller_identity
    team_key, team_did = await _setup_team(client, ns_key, ns_did, "rev.com", "api")

    cert_id, _ = await _register_cert(client, team_key, team_did, "rev.com", "api", "alice")

    headers = _sign(
        team_key, team_did,
        domain="rev.com", operation="revoke_certificate",
        team_name="api", certificate_id=cert_id,
    )
    resp = await client.post(
        "/v1/namespaces/rev.com/teams/api/certificates/revoke",
        json={"certificate_id": cert_id},
        headers=headers,
    )
    assert resp.status_code == 200
    assert resp.json()["revoked"] is True


@pytest.mark.asyncio
async def test_revoke_certificate_not_found(client, controller_identity):
    ns_key, ns_did = controller_identity
    team_key, team_did = await _setup_team(client, ns_key, ns_did, "revnf.com", "api")

    headers = _sign(
        team_key, team_did,
        domain="revnf.com", operation="revoke_certificate",
        team_name="api", certificate_id="nonexistent",
    )
    resp = await client.post(
        "/v1/namespaces/revnf.com/teams/api/certificates/revoke",
        json={"certificate_id": "nonexistent"},
        headers=headers,
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_revoke_certificate_already_revoked_returns_409(client, controller_identity):
    ns_key, ns_did = controller_identity
    team_key, team_did = await _setup_team(client, ns_key, ns_did, "revdup.com", "api")

    cert_id, _ = await _register_cert(client, team_key, team_did, "revdup.com", "api", "alice")

    headers = _sign(
        team_key, team_did,
        domain="revdup.com", operation="revoke_certificate",
        team_name="api", certificate_id=cert_id,
    )
    resp = await client.post(
        "/v1/namespaces/revdup.com/teams/api/certificates/revoke",
        json={"certificate_id": cert_id},
        headers=headers,
    )
    assert resp.status_code == 200

    headers = _sign(
        team_key, team_did,
        domain="revdup.com", operation="revoke_certificate",
        team_name="api", certificate_id=cert_id,
    )
    resp = await client.post(
        "/v1/namespaces/revdup.com/teams/api/certificates/revoke",
        json={"certificate_id": cert_id},
        headers=headers,
    )
    assert resp.status_code == 409


@pytest.mark.asyncio
async def test_revoke_certificate_wrong_key_returns_403(client, controller_identity):
    ns_key, ns_did = controller_identity
    team_key, team_did = await _setup_team(client, ns_key, ns_did, "revauth.com", "api")

    cert_id, _ = await _register_cert(client, team_key, team_did, "revauth.com", "api", "alice")

    wrong_key, wrong_pub = generate_keypair()
    wrong_did = did_from_public_key(wrong_pub)
    headers = _sign(
        wrong_key, wrong_did,
        domain="revauth.com", operation="revoke_certificate",
        team_name="api", certificate_id=cert_id,
    )
    resp = await client.post(
        "/v1/namespaces/revauth.com/teams/api/certificates/revoke",
        json={"certificate_id": cert_id},
        headers=headers,
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_revoke_certificate_no_auth_returns_401(client, controller_identity):
    ns_key, ns_did = controller_identity
    team_key, team_did = await _setup_team(client, ns_key, ns_did, "revnoauth.com", "api")

    cert_id, _ = await _register_cert(client, team_key, team_did, "revnoauth.com", "api", "alice")

    resp = await client.post(
        "/v1/namespaces/revnoauth.com/teams/api/certificates/revoke",
        json={"certificate_id": cert_id},
    )
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# GET /v1/namespaces/{domain}/teams/{name}/revocations
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_revocations(client, controller_identity):
    ns_key, ns_did = controller_identity
    team_key, team_did = await _setup_team(client, ns_key, ns_did, "revlist.com", "svc")

    cert1, _ = await _register_cert(client, team_key, team_did, "revlist.com", "svc", "alice")
    cert2, _ = await _register_cert(client, team_key, team_did, "revlist.com", "svc", "bob")

    # Revoke cert1 only
    headers = _sign(
        team_key, team_did,
        domain="revlist.com", operation="revoke_certificate",
        team_name="svc", certificate_id=cert1,
    )
    await client.post(
        "/v1/namespaces/revlist.com/teams/svc/certificates/revoke",
        json={"certificate_id": cert1},
        headers=headers,
    )

    resp = await client.get("/v1/namespaces/revlist.com/teams/svc/revocations")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["revocations"]) == 1
    assert body["revocations"][0]["certificate_id"] == cert1
    assert body["revocations"][0]["revoked_at"] is not None


@pytest.mark.asyncio
async def test_list_revocations_empty(client, controller_identity):
    ns_key, ns_did = controller_identity
    await _setup_team(client, ns_key, ns_did, "revempty.com", "web")

    resp = await client.get("/v1/namespaces/revempty.com/teams/web/revocations")
    assert resp.status_code == 200
    assert resp.json()["revocations"] == []

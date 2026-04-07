from __future__ import annotations

from uuid import uuid4

import pytest

from awid.did import did_from_public_key, generate_keypair, stable_id_from_did_key
from awid.signing import canonical_json_bytes, sign_message

from conftest import build_signed_headers as _sign


async def _register_namespace(client, signing_key, controller_did, domain):
    headers = _sign(signing_key, controller_did, domain=domain, operation="register")
    resp = await client.post("/v1/namespaces", json={"domain": domain}, headers=headers)
    assert resp.status_code == 200, resp.text
    return resp.json()


async def _create_team(client, signing_key, controller_did, domain, team_name):
    team_signing_key, team_pub = generate_keypair()
    team_did_key = did_from_public_key(team_pub)
    headers = _sign(
        signing_key, controller_did, domain=domain, operation="create_team", name=team_name,
    )
    resp = await client.post(
        f"/v1/namespaces/{domain}/teams",
        json={"name": team_name, "team_did_key": team_did_key},
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    return team_signing_key, team_did_key, resp.json()


async def _register_address(client, signing_key, controller_did, domain, name):
    _, member_pub = generate_keypair()
    member_did_key = did_from_public_key(member_pub)
    headers = _sign(
        signing_key, controller_did, domain=domain, operation="register_address", name=name,
    )
    resp = await client.post(
        f"/v1/namespaces/{domain}/addresses",
        json={
            "name": name,
            "did_aw": stable_id_from_did_key(member_did_key),
            "current_did_key": member_did_key,
            "reachability": "public",
        },
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


async def _register_certificate(client, team_key, team_did, domain, team_name, certificate_id):
    _, member_pub = generate_keypair()
    headers = _sign(
        team_key, team_did,
        domain=domain, operation="register_certificate",
        team_name=team_name, certificate_id=certificate_id,
    )
    resp = await client.post(
        f"/v1/namespaces/{domain}/teams/{team_name}/certificates",
        json={
            "certificate_id": certificate_id,
            "member_did_key": did_from_public_key(member_pub),
            "alias": "alice",
            "lifetime": "persistent",
        },
        headers=headers,
    )
    assert resp.status_code == 200, resp.text


async def _register_persistent_certificate_for_address(
    client,
    team_key,
    team_did,
    domain,
    team_name,
    certificate_id,
    member_address,
):
    _, member_pub = generate_keypair()
    member_did_key = did_from_public_key(member_pub)
    headers = _sign(
        team_key, team_did,
        domain=domain, operation="register_certificate",
        team_name=team_name, certificate_id=certificate_id,
    )
    resp = await client.post(
        f"/v1/namespaces/{domain}/teams/{team_name}/certificates",
        json={
            "certificate_id": certificate_id,
            "member_did_key": member_did_key,
            "member_did_aw": stable_id_from_did_key(member_did_key),
            "member_address": member_address,
            "alias": "alice",
            "lifetime": "persistent",
        },
        headers=headers,
    )
    assert resp.status_code == 200, resp.text


async def _revoke_certificate(client, team_key, team_did, domain, team_name, certificate_id):
    headers = _sign(
        team_key, team_did,
        domain=domain, operation="revoke_certificate",
        team_name=team_name, certificate_id=certificate_id,
    )
    resp = await client.post(
        f"/v1/namespaces/{domain}/teams/{team_name}/certificates/revoke",
        json={"certificate_id": certificate_id},
        headers=headers,
    )
    assert resp.status_code == 200, resp.text


def _bad_signature_headers(signing_key, header_did, *, domain, operation, **extra):
    payload = {"domain": domain, "operation": operation, **extra}
    headers = _sign(signing_key, header_did, domain=domain, operation=operation, **extra)
    headers["Authorization"] = f"DIDKey {header_did} {sign_message(signing_key, canonical_json_bytes(payload | {'timestamp': headers['X-AWEB-Timestamp']}))}"
    return headers


@pytest.mark.asyncio
async def test_delete_namespace_happy_path_cascades(client, controller_identity, awid_db_infra):
    ns_key, ns_did = controller_identity
    domain = "delete-ns.example"
    namespace = await _register_namespace(client, ns_key, ns_did, domain)
    _, _, team = await _create_team(client, ns_key, ns_did, domain, "backend")
    address = await _register_address(client, ns_key, ns_did, domain, "alice")

    team_key, team_pub = generate_keypair()
    team_did = did_from_public_key(team_pub)
    headers = _sign(ns_key, ns_did, domain=domain, operation="create_team", name="ops")
    resp = await client.post(
        f"/v1/namespaces/{domain}/teams",
        json={"name": "ops", "team_did_key": team_did},
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    cert_id = str(uuid4())
    await _register_certificate(client, team_key, team_did, domain, "ops", cert_id)
    await _revoke_certificate(client, team_key, team_did, domain, "ops", cert_id)

    headers = _sign(ns_key, ns_did, domain=domain, operation="delete_namespace")
    resp = await client.request(
        "DELETE",
        f"/v1/namespaces/{domain}",
        headers=headers,
        json={"reason": "rollback after downstream failure"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["deleted"] is True
    assert body["namespace_id"] == namespace["namespace_id"]

    resp = await client.get(f"/v1/namespaces/{domain}")
    assert resp.status_code == 404

    resp = await client.get(f"/v1/namespaces/{domain}/teams")
    assert resp.status_code == 200
    assert resp.json()["teams"] == []

    resp = await client.get(f"/v1/namespaces/{domain}/addresses")
    assert resp.status_code == 404

    db = awid_db_infra.get_manager("aweb")
    ns_row = await db.fetch_one(
        "SELECT deleted_at FROM {{tables.dns_namespaces}} WHERE namespace_id = $1",
        namespace["namespace_id"],
    )
    team_row = await db.fetch_one(
        "SELECT deleted_at FROM {{tables.teams}} WHERE team_id = $1",
        team["team_id"],
    )
    address_row = await db.fetch_one(
        "SELECT deleted_at FROM {{tables.public_addresses}} WHERE address_id = $1",
        address["address_id"],
    )
    cert_row = await db.fetch_one(
        "SELECT 1 FROM {{tables.team_certificates}} WHERE certificate_id = $1",
        cert_id,
    )
    assert ns_row["deleted_at"] is not None
    assert team_row["deleted_at"] is not None
    assert address_row["deleted_at"] is not None
    assert cert_row is None


@pytest.mark.asyncio
async def test_delete_namespace_with_active_certificates_returns_409(client, controller_identity):
    ns_key, ns_did = controller_identity
    domain = "active-ns.example"
    await _register_namespace(client, ns_key, ns_did, domain)
    team_key, team_did, _ = await _create_team(client, ns_key, ns_did, domain, "backend")
    await _register_certificate(client, team_key, team_did, domain, "backend", str(uuid4()))

    headers = _sign(ns_key, ns_did, domain=domain, operation="delete_namespace")
    resp = await client.delete(f"/v1/namespaces/{domain}", headers=headers)
    assert resp.status_code == 409
    assert "active certificates" in resp.text


@pytest.mark.asyncio
async def test_delete_namespace_already_deleted_returns_404(client, controller_identity):
    ns_key, ns_did = controller_identity
    domain = "deleted-ns.example"
    await _register_namespace(client, ns_key, ns_did, domain)

    headers = _sign(ns_key, ns_did, domain=domain, operation="delete_namespace")
    resp = await client.delete(f"/v1/namespaces/{domain}", headers=headers)
    assert resp.status_code == 200

    headers = _sign(ns_key, ns_did, domain=domain, operation="delete_namespace")
    resp = await client.delete(f"/v1/namespaces/{domain}", headers=headers)
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_delete_namespace_bad_signature_returns_401(client, controller_identity):
    ns_key, ns_did = controller_identity
    wrong_key, _ = generate_keypair()
    domain = "bad-sig-ns.example"
    await _register_namespace(client, ns_key, ns_did, domain)

    headers = _bad_signature_headers(
        wrong_key, ns_did, domain=domain, operation="delete_namespace",
    )
    resp = await client.delete(f"/v1/namespaces/{domain}", headers=headers)
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_delete_namespace_wrong_operation_returns_401(client, controller_identity):
    ns_key, ns_did = controller_identity
    domain = "wrong-op-ns.example"
    await _register_namespace(client, ns_key, ns_did, domain)

    headers = _sign(ns_key, ns_did, domain=domain, operation="delete")
    resp = await client.delete(f"/v1/namespaces/{domain}", headers=headers)
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_delete_address_happy_path(client, controller_identity, awid_db_infra):
    ns_key, ns_did = controller_identity
    domain = "delete-address.example"
    await _register_namespace(client, ns_key, ns_did, domain)
    address = await _register_address(client, ns_key, ns_did, domain, "alice")

    headers = _sign(ns_key, ns_did, domain=domain, operation="delete_address", name="alice")
    resp = await client.request(
        "DELETE",
        f"/v1/namespaces/{domain}/addresses/alice",
        headers=headers,
        json={"reason": "rollback after downstream failure"},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json() == {
        "deleted": True,
        "address_id": address["address_id"],
        "domain": domain,
        "name": "alice",
    }

    resp = await client.get(f"/v1/namespaces/{domain}/addresses/alice")
    assert resp.status_code == 404

    db = awid_db_infra.get_manager("aweb")
    row = await db.fetch_one(
        "SELECT deleted_at FROM {{tables.public_addresses}} WHERE address_id = $1",
        address["address_id"],
    )
    assert row["deleted_at"] is not None


@pytest.mark.asyncio
async def test_delete_address_with_active_certificates_returns_409(client, controller_identity):
    ns_key, ns_did = controller_identity
    domain = "active-address.example"
    await _register_namespace(client, ns_key, ns_did, domain)
    await _register_address(client, ns_key, ns_did, domain, "alice")
    team_key, team_did, _ = await _create_team(client, ns_key, ns_did, domain, "backend")
    await _register_persistent_certificate_for_address(
        client,
        team_key,
        team_did,
        domain,
        "backend",
        str(uuid4()),
        f"{domain}/alice",
    )

    headers = _sign(ns_key, ns_did, domain=domain, operation="delete_address", name="alice")
    resp = await client.delete(f"/v1/namespaces/{domain}/addresses/alice", headers=headers)
    assert resp.status_code == 409
    assert "active certificates" in resp.text


@pytest.mark.asyncio
async def test_delete_address_already_deleted_returns_404(client, controller_identity):
    ns_key, ns_did = controller_identity
    domain = "deleted-address.example"
    await _register_namespace(client, ns_key, ns_did, domain)
    await _register_address(client, ns_key, ns_did, domain, "alice")

    headers = _sign(ns_key, ns_did, domain=domain, operation="delete_address", name="alice")
    resp = await client.delete(f"/v1/namespaces/{domain}/addresses/alice", headers=headers)
    assert resp.status_code == 200

    headers = _sign(ns_key, ns_did, domain=domain, operation="delete_address", name="alice")
    resp = await client.delete(f"/v1/namespaces/{domain}/addresses/alice", headers=headers)
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_delete_address_bad_signature_returns_401(client, controller_identity):
    ns_key, ns_did = controller_identity
    wrong_key, _ = generate_keypair()
    domain = "bad-sig-address.example"
    await _register_namespace(client, ns_key, ns_did, domain)
    await _register_address(client, ns_key, ns_did, domain, "alice")

    headers = _bad_signature_headers(
        wrong_key, ns_did, domain=domain, operation="delete_address", name="alice",
    )
    resp = await client.delete(f"/v1/namespaces/{domain}/addresses/alice", headers=headers)
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_delete_address_wrong_operation_returns_401(client, controller_identity):
    ns_key, ns_did = controller_identity
    domain = "wrong-op-address.example"
    await _register_namespace(client, ns_key, ns_did, domain)
    await _register_address(client, ns_key, ns_did, domain, "alice")

    headers = _sign(ns_key, ns_did, domain=domain, operation="delete", name="alice")
    resp = await client.delete(f"/v1/namespaces/{domain}/addresses/alice", headers=headers)
    assert resp.status_code == 401

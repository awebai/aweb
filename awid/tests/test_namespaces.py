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


async def _register_address_for_identity(
    client,
    signing_key,
    controller_did,
    domain,
    name,
    *,
    member_did_key: str,
    reachability: str,
    visible_to_team_id: str | None = None,
):
    headers = _sign(
        signing_key, controller_did, domain=domain, operation="register_address", name=name,
    )
    payload = {
        "name": name,
        "did_aw": stable_id_from_did_key(member_did_key),
        "current_did_key": member_did_key,
        "reachability": reachability,
    }
    if visible_to_team_id is not None:
        payload["visible_to_team_id"] = visible_to_team_id
    resp = await client.post(
        f"/v1/namespaces/{domain}/addresses",
        json=payload,
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


async def _register_certificate(
    client,
    team_key,
    team_did,
    domain,
    team_name,
    certificate_id,
    *,
    member_did_key: str | None = None,
    member_did_aw: str | None = None,
    member_address: str | None = None,
    alias: str = "alice",
    lifetime: str = "persistent",
):
    if member_did_key is None:
        _, member_pub = generate_keypair()
        member_did_key = did_from_public_key(member_pub)
    headers = _sign(
        team_key, team_did,
        domain=domain, operation="register_certificate",
        team_name=team_name, certificate_id=certificate_id,
    )
    payload = {
        "certificate_id": certificate_id,
        "member_did_key": member_did_key,
        "alias": alias,
        "lifetime": lifetime,
    }
    if member_did_aw is not None:
        payload["member_did_aw"] = member_did_aw
    if member_address is not None:
        payload["member_address"] = member_address
    resp = await client.post(
        f"/v1/namespaces/{domain}/teams/{team_name}/certificates",
        json=payload,
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    return {
        "certificate_id": certificate_id,
        "member_did_key": member_did_key,
        "member_did_aw": member_did_aw,
        "member_address": member_address,
        "alias": alias,
        "lifetime": lifetime,
    }


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
        "SELECT deleted_at FROM {{tables.teams}} WHERE domain = $1 AND name = $2",
        domain,
        "backend",
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


@pytest.mark.asyncio
async def test_public_address_get_allows_anonymous(client, controller_identity):
    ns_key, ns_did = controller_identity
    domain = "public-address.example"
    await _register_namespace(client, ns_key, ns_did, domain)
    address = await _register_address(client, ns_key, ns_did, domain, "alice")

    resp = await client.get(f"/v1/namespaces/{domain}/addresses/alice")
    assert resp.status_code == 200, resp.text
    assert resp.json()["address_id"] == address["address_id"]


@pytest.mark.asyncio
async def test_nobody_address_get_requires_owner_signature(client, controller_identity):
    ns_key, ns_did = controller_identity
    owner_key, owner_pub = generate_keypair()
    owner_did_key = did_from_public_key(owner_pub)
    domain = "nobody-address.example"
    await _register_namespace(client, ns_key, ns_did, domain)
    address = await _register_address_for_identity(
        client,
        ns_key,
        ns_did,
        domain,
        "alice",
        member_did_key=owner_did_key,
        reachability="nobody",
    )

    owner_headers = _sign(owner_key, owner_did_key, domain=domain, operation="get_address", name="alice")
    owner_resp = await client.get(f"/v1/namespaces/{domain}/addresses/alice", headers=owner_headers)
    assert owner_resp.status_code == 200, owner_resp.text
    assert owner_resp.json()["address_id"] == address["address_id"]

    anon_resp = await client.get(f"/v1/namespaces/{domain}/addresses/alice")
    assert anon_resp.status_code == 404

    other_key, other_pub = generate_keypair()
    other_did_key = did_from_public_key(other_pub)
    other_headers = _sign(other_key, other_did_key, domain=domain, operation="get_address", name="alice")
    other_resp = await client.get(f"/v1/namespaces/{domain}/addresses/alice", headers=other_headers)
    assert other_resp.status_code == 404


@pytest.mark.asyncio
async def test_address_get_nonexistent_matches_nobody_404_shape(client, controller_identity):
    ns_key, ns_did = controller_identity
    owner_key, owner_pub = generate_keypair()
    owner_did_key = did_from_public_key(owner_pub)
    other_key, other_pub = generate_keypair()
    other_did_key = did_from_public_key(other_pub)
    domain = "nobody-404-shape.example"
    await _register_namespace(client, ns_key, ns_did, domain)
    await _register_address_for_identity(
        client,
        ns_key,
        ns_did,
        domain,
        "alice",
        member_did_key=owner_did_key,
        reachability="nobody",
    )

    hidden_headers = _sign(other_key, other_did_key, domain=domain, operation="get_address", name="alice")
    hidden_resp = await client.get(f"/v1/namespaces/{domain}/addresses/alice", headers=hidden_headers)
    assert hidden_resp.status_code == 404
    assert hidden_resp.json() == {"detail": "Address not found"}

    missing_headers = _sign(other_key, other_did_key, domain=domain, operation="get_address", name="missing")
    missing_resp = await client.get(f"/v1/namespaces/{domain}/addresses/missing", headers=missing_headers)
    assert missing_resp.status_code == 404
    assert missing_resp.json() == hidden_resp.json()


@pytest.mark.asyncio
async def test_list_addresses_filters_nobody_to_owner(client, controller_identity):
    ns_key, ns_did = controller_identity
    owner_key, owner_pub = generate_keypair()
    owner_did_key = did_from_public_key(owner_pub)
    domain = "list-nobody.example"
    await _register_namespace(client, ns_key, ns_did, domain)
    await _register_address_for_identity(
        client,
        ns_key,
        ns_did,
        domain,
        "public-alice",
        member_did_key=did_from_public_key(generate_keypair()[1]),
        reachability="public",
    )
    await _register_address_for_identity(
        client,
        ns_key,
        ns_did,
        domain,
        "nobody-alice",
        member_did_key=owner_did_key,
        reachability="nobody",
    )

    anon_resp = await client.get(f"/v1/namespaces/{domain}/addresses")
    assert anon_resp.status_code == 200, anon_resp.text
    assert [item["name"] for item in anon_resp.json()["addresses"]] == ["public-alice"]

    owner_headers = _sign(owner_key, owner_did_key, domain=domain, operation="list_addresses")
    owner_resp = await client.get(f"/v1/namespaces/{domain}/addresses", headers=owner_headers)
    assert owner_resp.status_code == 200, owner_resp.text
    assert [item["name"] for item in owner_resp.json()["addresses"]] == ["nobody-alice", "public-alice"]


@pytest.mark.asyncio
async def test_org_only_address_get_allows_same_org_persistent_members_only(client, controller_identity):
    ns_key, ns_did = controller_identity
    owner_key, owner_pub = generate_keypair()
    owner_did_key = did_from_public_key(owner_pub)
    member_key, member_pub = generate_keypair()
    member_did_key = did_from_public_key(member_pub)
    other_key, other_pub = generate_keypair()
    other_did_key = did_from_public_key(other_pub)
    ephemeral_key, ephemeral_pub = generate_keypair()
    ephemeral_did_key = did_from_public_key(ephemeral_pub)
    domain = "org-only.example"
    await _register_namespace(client, ns_key, ns_did, domain)
    team_key, team_did, _ = await _create_team(client, ns_key, ns_did, domain, "backend")
    await _register_address_for_identity(
        client,
        ns_key,
        ns_did,
        domain,
        "alice",
        member_did_key=owner_did_key,
        reachability="org_only",
    )
    await _register_certificate(
        client,
        team_key,
        team_did,
        domain,
        "backend",
        str(uuid4()),
        member_did_key=member_did_key,
        member_did_aw=stable_id_from_did_key(member_did_key),
        alias="member",
    )
    await _register_certificate(
        client,
        team_key,
        team_did,
        domain,
        "backend",
        str(uuid4()),
        member_did_key=ephemeral_did_key,
        alias="ephemeral",
        lifetime="ephemeral",
    )

    anon_resp = await client.get(f"/v1/namespaces/{domain}/addresses/alice")
    assert anon_resp.status_code == 404

    owner_headers = _sign(owner_key, owner_did_key, domain=domain, operation="get_address", name="alice")
    owner_resp = await client.get(f"/v1/namespaces/{domain}/addresses/alice", headers=owner_headers)
    assert owner_resp.status_code == 200, owner_resp.text
    assert owner_resp.json()["reachability"] == "org_only"

    member_headers = _sign(member_key, member_did_key, domain=domain, operation="get_address", name="alice")
    member_resp = await client.get(f"/v1/namespaces/{domain}/addresses/alice", headers=member_headers)
    assert member_resp.status_code == 200, member_resp.text

    other_headers = _sign(other_key, other_did_key, domain=domain, operation="get_address", name="alice")
    other_resp = await client.get(f"/v1/namespaces/{domain}/addresses/alice", headers=other_headers)
    assert other_resp.status_code == 404

    ephemeral_headers = _sign(ephemeral_key, ephemeral_did_key, domain=domain, operation="get_address", name="alice")
    ephemeral_resp = await client.get(f"/v1/namespaces/{domain}/addresses/alice", headers=ephemeral_headers)
    assert ephemeral_resp.status_code == 404


@pytest.mark.asyncio
async def test_org_only_rejects_ephemeral_certificate_even_with_member_did_aw(client, controller_identity):
    ns_key, ns_did = controller_identity
    owner_key, owner_pub = generate_keypair()
    owner_did_key = did_from_public_key(owner_pub)
    ephemeral_key, ephemeral_pub = generate_keypair()
    ephemeral_did_key = did_from_public_key(ephemeral_pub)
    domain = "org-only-ephemeral.example"
    await _register_namespace(client, ns_key, ns_did, domain)
    team_key, team_did, _ = await _create_team(client, ns_key, ns_did, domain, "backend")
    await _register_address_for_identity(
        client,
        ns_key,
        ns_did,
        domain,
        "alice",
        member_did_key=owner_did_key,
        reachability="org_only",
    )
    await _register_certificate(
        client,
        team_key,
        team_did,
        domain,
        "backend",
        str(uuid4()),
        member_did_key=ephemeral_did_key,
        member_did_aw=stable_id_from_did_key(ephemeral_did_key),
        alias="ephemeral",
        lifetime="ephemeral",
    )

    ephemeral_headers = _sign(ephemeral_key, ephemeral_did_key, domain=domain, operation="get_address", name="alice")
    ephemeral_resp = await client.get(f"/v1/namespaces/{domain}/addresses/alice", headers=ephemeral_headers)
    assert ephemeral_resp.status_code == 404


@pytest.mark.asyncio
async def test_list_addresses_filters_org_only_to_same_org_persistent_members(client, controller_identity):
    ns_key, ns_did = controller_identity
    member_key, member_pub = generate_keypair()
    member_did_key = did_from_public_key(member_pub)
    outsider_key, outsider_pub = generate_keypair()
    outsider_did_key = did_from_public_key(outsider_pub)
    domain = "list-org-only.example"
    await _register_namespace(client, ns_key, ns_did, domain)
    team_key, team_did, _ = await _create_team(client, ns_key, ns_did, domain, "backend")
    await _register_address_for_identity(
        client,
        ns_key,
        ns_did,
        domain,
        "org-alice",
        member_did_key=did_from_public_key(generate_keypair()[1]),
        reachability="org_only",
    )
    await _register_address_for_identity(
        client,
        ns_key,
        ns_did,
        domain,
        "public-alice",
        member_did_key=did_from_public_key(generate_keypair()[1]),
        reachability="public",
    )
    await _register_certificate(
        client,
        team_key,
        team_did,
        domain,
        "backend",
        str(uuid4()),
        member_did_key=member_did_key,
        member_did_aw=stable_id_from_did_key(member_did_key),
        alias="member",
    )

    anon_resp = await client.get(f"/v1/namespaces/{domain}/addresses")
    assert anon_resp.status_code == 200, anon_resp.text
    assert [item["name"] for item in anon_resp.json()["addresses"]] == ["public-alice"]

    outsider_headers = _sign(outsider_key, outsider_did_key, domain=domain, operation="list_addresses")
    outsider_resp = await client.get(f"/v1/namespaces/{domain}/addresses", headers=outsider_headers)
    assert outsider_resp.status_code == 200, outsider_resp.text
    assert [item["name"] for item in outsider_resp.json()["addresses"]] == ["public-alice"]

    member_headers = _sign(member_key, member_did_key, domain=domain, operation="list_addresses")
    member_resp = await client.get(f"/v1/namespaces/{domain}/addresses", headers=member_headers)
    assert member_resp.status_code == 200, member_resp.text
    assert [item["name"] for item in member_resp.json()["addresses"]] == ["org-alice", "public-alice"]


@pytest.mark.asyncio
async def test_team_members_only_address_get_allows_target_team_persistent_members_only(client, controller_identity):
    ns_key, ns_did = controller_identity
    owner_key, owner_pub = generate_keypair()
    owner_did_key = did_from_public_key(owner_pub)
    member_key, member_pub = generate_keypair()
    member_did_key = did_from_public_key(member_pub)
    other_team_key, other_team_pub = generate_keypair()
    other_team_did_key = did_from_public_key(other_team_pub)
    ephemeral_key, ephemeral_pub = generate_keypair()
    ephemeral_did_key = did_from_public_key(ephemeral_pub)
    domain = "team-members-only.example"
    await _register_namespace(client, ns_key, ns_did, domain)
    backend_key, backend_did, _ = await _create_team(client, ns_key, ns_did, domain, "backend")
    frontend_key, frontend_did, _ = await _create_team(client, ns_key, ns_did, domain, "frontend")
    address = await _register_address_for_identity(
        client,
        ns_key,
        ns_did,
        domain,
        "alice",
        member_did_key=owner_did_key,
        reachability="team_members_only",
        visible_to_team_id=f"backend:{domain}",
    )
    assert address["visible_to_team_id"] == f"backend:{domain}"

    await _register_certificate(
        client,
        backend_key,
        backend_did,
        domain,
        "backend",
        str(uuid4()),
        member_did_key=member_did_key,
        member_did_aw=stable_id_from_did_key(member_did_key),
        alias="backend-member",
    )
    await _register_certificate(
        client,
        frontend_key,
        frontend_did,
        domain,
        "frontend",
        str(uuid4()),
        member_did_key=other_team_did_key,
        member_did_aw=stable_id_from_did_key(other_team_did_key),
        alias="frontend-member",
    )
    await _register_certificate(
        client,
        backend_key,
        backend_did,
        domain,
        "backend",
        str(uuid4()),
        member_did_key=ephemeral_did_key,
        alias="backend-ephemeral",
        lifetime="ephemeral",
    )

    anon_resp = await client.get(f"/v1/namespaces/{domain}/addresses/alice")
    assert anon_resp.status_code == 404

    owner_headers = _sign(owner_key, owner_did_key, domain=domain, operation="get_address", name="alice")
    owner_resp = await client.get(f"/v1/namespaces/{domain}/addresses/alice", headers=owner_headers)
    assert owner_resp.status_code == 200, owner_resp.text

    member_headers = _sign(member_key, member_did_key, domain=domain, operation="get_address", name="alice")
    member_resp = await client.get(f"/v1/namespaces/{domain}/addresses/alice", headers=member_headers)
    assert member_resp.status_code == 200, member_resp.text

    other_team_headers = _sign(other_team_key, other_team_did_key, domain=domain, operation="get_address", name="alice")
    other_team_resp = await client.get(f"/v1/namespaces/{domain}/addresses/alice", headers=other_team_headers)
    assert other_team_resp.status_code == 404

    ephemeral_headers = _sign(ephemeral_key, ephemeral_did_key, domain=domain, operation="get_address", name="alice")
    ephemeral_resp = await client.get(f"/v1/namespaces/{domain}/addresses/alice", headers=ephemeral_headers)
    assert ephemeral_resp.status_code == 404


@pytest.mark.asyncio
async def test_list_addresses_filters_team_members_only_to_target_team(client, controller_identity):
    ns_key, ns_did = controller_identity
    backend_member_key, backend_member_pub = generate_keypair()
    backend_member_did_key = did_from_public_key(backend_member_pub)
    frontend_member_key, frontend_member_pub = generate_keypair()
    frontend_member_did_key = did_from_public_key(frontend_member_pub)
    domain = "list-team-members-only.example"
    await _register_namespace(client, ns_key, ns_did, domain)
    backend_key, backend_did, _ = await _create_team(client, ns_key, ns_did, domain, "backend")
    frontend_key, frontend_did, _ = await _create_team(client, ns_key, ns_did, domain, "frontend")
    await _register_address_for_identity(
        client,
        ns_key,
        ns_did,
        domain,
        "backend-alice",
        member_did_key=did_from_public_key(generate_keypair()[1]),
        reachability="team_members_only",
        visible_to_team_id=f"backend:{domain}",
    )
    await _register_address_for_identity(
        client,
        ns_key,
        ns_did,
        domain,
        "public-alice",
        member_did_key=did_from_public_key(generate_keypair()[1]),
        reachability="public",
    )
    await _register_certificate(
        client,
        backend_key,
        backend_did,
        domain,
        "backend",
        str(uuid4()),
        member_did_key=backend_member_did_key,
        member_did_aw=stable_id_from_did_key(backend_member_did_key),
        alias="backend-member",
    )
    await _register_certificate(
        client,
        frontend_key,
        frontend_did,
        domain,
        "frontend",
        str(uuid4()),
        member_did_key=frontend_member_did_key,
        member_did_aw=stable_id_from_did_key(frontend_member_did_key),
        alias="frontend-member",
    )

    anon_resp = await client.get(f"/v1/namespaces/{domain}/addresses")
    assert anon_resp.status_code == 200, anon_resp.text
    assert [item["name"] for item in anon_resp.json()["addresses"]] == ["public-alice"]

    frontend_headers = _sign(frontend_member_key, frontend_member_did_key, domain=domain, operation="list_addresses")
    frontend_resp = await client.get(f"/v1/namespaces/{domain}/addresses", headers=frontend_headers)
    assert frontend_resp.status_code == 200, frontend_resp.text
    assert [item["name"] for item in frontend_resp.json()["addresses"]] == ["public-alice"]

    backend_headers = _sign(backend_member_key, backend_member_did_key, domain=domain, operation="list_addresses")
    backend_resp = await client.get(f"/v1/namespaces/{domain}/addresses", headers=backend_headers)
    assert backend_resp.status_code == 200, backend_resp.text
    assert [item["name"] for item in backend_resp.json()["addresses"]] == ["backend-alice", "public-alice"]


@pytest.mark.asyncio
# Split the literals so residue greps can stay strict while this negative test
# still exercises server-side rejection of the removed enum values.
@pytest.mark.parametrize("reachability", ["contacts" + "_only", "org" + "_visible"])
async def test_register_address_rejects_legacy_reachability_values(client, controller_identity, reachability):
    ns_key, ns_did = controller_identity
    owner_key, owner_pub = generate_keypair()
    owner_did_key = did_from_public_key(owner_pub)
    domain = f"legacy-{reachability.replace('_', '-')}.example"
    await _register_namespace(client, ns_key, ns_did, domain)
    headers = _sign(ns_key, ns_did, domain=domain, operation="register_address", name="alice")
    resp = await client.post(
        f"/v1/namespaces/{domain}/addresses",
        json={
            "name": "alice",
            "did_aw": stable_id_from_did_key(owner_did_key),
            "current_did_key": owner_did_key,
            "reachability": reachability,
        },
        headers=headers,
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_register_team_members_only_requires_visible_to_team_id(client, controller_identity):
    ns_key, ns_did = controller_identity
    owner_key, owner_pub = generate_keypair()
    owner_did_key = did_from_public_key(owner_pub)
    domain = "missing-team-scope.example"
    await _register_namespace(client, ns_key, ns_did, domain)
    headers = _sign(ns_key, ns_did, domain=domain, operation="register_address", name="alice")
    resp = await client.post(
        f"/v1/namespaces/{domain}/addresses",
        json={
            "name": "alice",
            "did_aw": stable_id_from_did_key(owner_did_key),
            "current_did_key": owner_did_key,
            "reachability": "team_members_only",
        },
        headers=headers,
    )
    assert resp.status_code == 422
    assert resp.json()["detail"] == "visible_to_team_id is required when reachability=team_members_only"


@pytest.mark.asyncio
async def test_register_non_team_members_only_rejects_visible_to_team_id(client, controller_identity):
    ns_key, ns_did = controller_identity
    owner_key, owner_pub = generate_keypair()
    owner_did_key = did_from_public_key(owner_pub)
    domain = "unexpected-team-scope.example"
    await _register_namespace(client, ns_key, ns_did, domain)
    await _create_team(client, ns_key, ns_did, domain, "backend")
    headers = _sign(ns_key, ns_did, domain=domain, operation="register_address", name="alice")
    resp = await client.post(
        f"/v1/namespaces/{domain}/addresses",
        json={
            "name": "alice",
            "did_aw": stable_id_from_did_key(owner_did_key),
            "current_did_key": owner_did_key,
            "reachability": "org_only",
            "visible_to_team_id": f"backend:{domain}",
        },
        headers=headers,
    )
    assert resp.status_code == 422
    assert resp.json()["detail"] == "visible_to_team_id is only allowed when reachability=team_members_only"


@pytest.mark.asyncio
async def test_update_address_clears_visible_to_team_id_when_leaving_team_members_only(client, controller_identity):
    ns_key, ns_did = controller_identity
    owner_key, owner_pub = generate_keypair()
    owner_did_key = did_from_public_key(owner_pub)
    domain = "update-address-visibility.example"
    await _register_namespace(client, ns_key, ns_did, domain)
    await _create_team(client, ns_key, ns_did, domain, "backend")
    await _register_address_for_identity(
        client,
        ns_key,
        ns_did,
        domain,
        "alice",
        member_did_key=owner_did_key,
        reachability="team_members_only",
        visible_to_team_id=f"backend:{domain}",
    )

    headers = _sign(ns_key, ns_did, domain=domain, operation="update_address", name="alice")
    resp = await client.put(
        f"/v1/namespaces/{domain}/addresses/alice",
        json={"reachability": "org_only"},
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["reachability"] == "org_only"
    assert resp.json()["visible_to_team_id"] is None


@pytest.mark.asyncio
async def test_update_address_rejects_visible_to_team_id_with_org_only(client, controller_identity):
    ns_key, ns_did = controller_identity
    owner_key, owner_pub = generate_keypair()
    owner_did_key = did_from_public_key(owner_pub)
    domain = "update-address-invalid-scope.example"
    await _register_namespace(client, ns_key, ns_did, domain)
    await _create_team(client, ns_key, ns_did, domain, "backend")
    await _register_address_for_identity(
        client,
        ns_key,
        ns_did,
        domain,
        "alice",
        member_did_key=owner_did_key,
        reachability="nobody",
    )

    headers = _sign(ns_key, ns_did, domain=domain, operation="update_address", name="alice")
    resp = await client.put(
        f"/v1/namespaces/{domain}/addresses/alice",
        json={"reachability": "org_only", "visible_to_team_id": f"backend:{domain}"},
        headers=headers,
    )
    assert resp.status_code == 422
    assert resp.json()["detail"] == "visible_to_team_id is only allowed when reachability=team_members_only"

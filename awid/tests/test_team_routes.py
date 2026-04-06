from __future__ import annotations

import pytest

from aweb.awid.did import did_from_public_key, generate_keypair

from conftest import build_signed_headers as _sign


async def _register_namespace(client, signing_key, controller_did, domain):
    """Register a namespace so team operations can verify the controller."""
    headers = _sign(signing_key, controller_did, domain=domain, operation="register")
    resp = await client.post(
        "/v1/namespaces",
        json={"domain": domain},
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


# ---------------------------------------------------------------------------
# POST /v1/namespaces/{domain}/teams — create team
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_team(client, controller_identity):
    signing_key, controller_did = controller_identity
    await _register_namespace(client, signing_key, controller_did, "acme.com")

    _, team_pub = generate_keypair()
    team_did_key = did_from_public_key(team_pub)

    headers = _sign(signing_key, controller_did, domain="acme.com", operation="create_team", name="backend")
    resp = await client.post(
        "/v1/namespaces/acme.com/teams",
        json={"name": "backend", "display_name": "Backend Team", "team_did_key": team_did_key},
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["domain"] == "acme.com"
    assert body["name"] == "backend"
    assert body["display_name"] == "Backend Team"
    assert body["team_did_key"] == team_did_key
    assert "team_id" in body
    assert "created_at" in body


@pytest.mark.asyncio
async def test_create_team_duplicate_returns_409(client, controller_identity):
    signing_key, controller_did = controller_identity
    await _register_namespace(client, signing_key, controller_did, "dup.com")

    _, team_pub = generate_keypair()
    team_did_key = did_from_public_key(team_pub)

    headers = _sign(signing_key, controller_did, domain="dup.com", operation="create_team", name="ops")
    await client.post(
        "/v1/namespaces/dup.com/teams",
        json={"name": "ops", "team_did_key": team_did_key},
        headers=headers,
    )

    headers = _sign(signing_key, controller_did, domain="dup.com", operation="create_team", name="ops")
    resp = await client.post(
        "/v1/namespaces/dup.com/teams",
        json={"name": "ops", "team_did_key": team_did_key},
        headers=headers,
    )
    assert resp.status_code == 409


@pytest.mark.asyncio
async def test_create_team_wrong_key_returns_403(client, controller_identity):
    signing_key, controller_did = controller_identity
    await _register_namespace(client, signing_key, controller_did, "auth.com")

    wrong_key, wrong_pub = generate_keypair()
    wrong_did = did_from_public_key(wrong_pub)

    _, team_pub = generate_keypair()
    team_did_key = did_from_public_key(team_pub)

    headers = _sign(wrong_key, wrong_did, domain="auth.com", operation="create_team", name="x")
    resp = await client.post(
        "/v1/namespaces/auth.com/teams",
        json={"name": "x", "team_did_key": team_did_key},
        headers=headers,
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_create_team_nonexistent_namespace_returns_404(client, controller_identity):
    signing_key, controller_did = controller_identity

    _, team_pub = generate_keypair()
    team_did_key = did_from_public_key(team_pub)

    headers = _sign(signing_key, controller_did, domain="noexist.com", operation="create_team", name="x")
    resp = await client.post(
        "/v1/namespaces/noexist.com/teams",
        json={"name": "x", "team_did_key": team_did_key},
        headers=headers,
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_create_team_no_auth_returns_401(client):
    _, pub = generate_keypair()
    resp = await client.post(
        "/v1/namespaces/acme.com/teams",
        json={"name": "x", "team_did_key": did_from_public_key(pub)},
    )
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# GET /v1/namespaces/{domain}/teams — list teams
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_teams(client, controller_identity):
    signing_key, controller_did = controller_identity
    await _register_namespace(client, signing_key, controller_did, "list.com")

    for name in ["alpha", "beta"]:
        _, pub = generate_keypair()
        headers = _sign(signing_key, controller_did, domain="list.com", operation="create_team", name=name)
        await client.post(
            "/v1/namespaces/list.com/teams",
            json={"name": name, "team_did_key": did_from_public_key(pub)},
            headers=headers,
        )

    resp = await client.get("/v1/namespaces/list.com/teams")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["teams"]) == 2
    names = {t["name"] for t in body["teams"]}
    assert names == {"alpha", "beta"}


@pytest.mark.asyncio
async def test_list_teams_empty_namespace(client, controller_identity):
    signing_key, controller_did = controller_identity
    await _register_namespace(client, signing_key, controller_did, "empty.com")

    resp = await client.get("/v1/namespaces/empty.com/teams")
    assert resp.status_code == 200
    assert resp.json()["teams"] == []


# ---------------------------------------------------------------------------
# GET /v1/namespaces/{domain}/teams/{name} — get team
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_team(client, controller_identity):
    signing_key, controller_did = controller_identity
    await _register_namespace(client, signing_key, controller_did, "get.com")

    _, pub = generate_keypair()
    team_did_key = did_from_public_key(pub)
    headers = _sign(signing_key, controller_did, domain="get.com", operation="create_team", name="infra")
    await client.post(
        "/v1/namespaces/get.com/teams",
        json={"name": "infra", "team_did_key": team_did_key},
        headers=headers,
    )

    resp = await client.get("/v1/namespaces/get.com/teams/infra")
    assert resp.status_code == 200
    body = resp.json()
    assert body["name"] == "infra"
    assert body["team_did_key"] == team_did_key


@pytest.mark.asyncio
async def test_get_team_not_found(client, controller_identity):
    signing_key, controller_did = controller_identity
    await _register_namespace(client, signing_key, controller_did, "miss.com")

    resp = await client.get("/v1/namespaces/miss.com/teams/nope")
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# DELETE /v1/namespaces/{domain}/teams/{name} — soft-delete team
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_delete_team(client, controller_identity):
    signing_key, controller_did = controller_identity
    await _register_namespace(client, signing_key, controller_did, "del.com")

    _, pub = generate_keypair()
    headers = _sign(signing_key, controller_did, domain="del.com", operation="create_team", name="old")
    await client.post(
        "/v1/namespaces/del.com/teams",
        json={"name": "old", "team_did_key": did_from_public_key(pub)},
        headers=headers,
    )

    headers = _sign(signing_key, controller_did, domain="del.com", operation="delete_team", name="old")
    resp = await client.delete("/v1/namespaces/del.com/teams/old", headers=headers)
    assert resp.status_code == 200

    # Should be gone from GET
    resp = await client.get("/v1/namespaces/del.com/teams/old")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_delete_team_wrong_key_returns_403(client, controller_identity):
    signing_key, controller_did = controller_identity
    await _register_namespace(client, signing_key, controller_did, "delfail.com")

    _, pub = generate_keypair()
    headers = _sign(signing_key, controller_did, domain="delfail.com", operation="create_team", name="x")
    await client.post(
        "/v1/namespaces/delfail.com/teams",
        json={"name": "x", "team_did_key": did_from_public_key(pub)},
        headers=headers,
    )

    wrong_key, wrong_pub = generate_keypair()
    wrong_did = did_from_public_key(wrong_pub)
    headers = _sign(wrong_key, wrong_did, domain="delfail.com", operation="delete_team", name="x")
    resp = await client.delete("/v1/namespaces/delfail.com/teams/x", headers=headers)
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_delete_team_no_auth_returns_401(client, controller_identity):
    signing_key, controller_did = controller_identity
    await _register_namespace(client, signing_key, controller_did, "delnoauth.com")

    resp = await client.delete("/v1/namespaces/delnoauth.com/teams/x")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_delete_team_not_found(client, controller_identity):
    signing_key, controller_did = controller_identity
    await _register_namespace(client, signing_key, controller_did, "delnf.com")

    headers = _sign(signing_key, controller_did, domain="delnf.com", operation="delete_team", name="nope")
    resp = await client.delete("/v1/namespaces/delnf.com/teams/nope", headers=headers)
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# POST /v1/namespaces/{domain}/teams/{name}/rotate — rotate team key
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_rotate_team_key(client, controller_identity):
    signing_key, controller_did = controller_identity
    await _register_namespace(client, signing_key, controller_did, "rot.com")

    _, pub = generate_keypair()
    old_did_key = did_from_public_key(pub)
    headers = _sign(signing_key, controller_did, domain="rot.com", operation="create_team", name="svc")
    await client.post(
        "/v1/namespaces/rot.com/teams",
        json={"name": "svc", "team_did_key": old_did_key},
        headers=headers,
    )

    _, new_pub = generate_keypair()
    new_did_key = did_from_public_key(new_pub)
    headers = _sign(
        signing_key, controller_did,
        domain="rot.com", operation="rotate_team_key",
        name="svc", new_team_did_key=new_did_key,
    )
    resp = await client.post(
        "/v1/namespaces/rot.com/teams/svc/rotate",
        json={"new_team_did_key": new_did_key},
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["team_did_key"] == new_did_key
    assert body["key_changed"] is True

    # Confirm the key persisted
    resp = await client.get("/v1/namespaces/rot.com/teams/svc")
    assert resp.json()["team_did_key"] == new_did_key


@pytest.mark.asyncio
async def test_rotate_team_key_wrong_controller_returns_403(client, controller_identity):
    signing_key, controller_did = controller_identity
    await _register_namespace(client, signing_key, controller_did, "rotfail.com")

    _, pub = generate_keypair()
    headers = _sign(signing_key, controller_did, domain="rotfail.com", operation="create_team", name="x")
    await client.post(
        "/v1/namespaces/rotfail.com/teams",
        json={"name": "x", "team_did_key": did_from_public_key(pub)},
        headers=headers,
    )

    wrong_key, wrong_pub = generate_keypair()
    wrong_did = did_from_public_key(wrong_pub)
    _, new_pub = generate_keypair()
    new_did_key = did_from_public_key(new_pub)
    headers = _sign(wrong_key, wrong_did, domain="rotfail.com", operation="rotate_team_key", name="x", new_team_did_key=new_did_key)
    resp = await client.post(
        "/v1/namespaces/rotfail.com/teams/x/rotate",
        json={"new_team_did_key": new_did_key},
        headers=headers,
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_rotate_team_key_no_auth_returns_401(client, controller_identity):
    signing_key, controller_did = controller_identity
    await _register_namespace(client, signing_key, controller_did, "rotnoauth.com")

    _, pub = generate_keypair()
    resp = await client.post(
        "/v1/namespaces/rotnoauth.com/teams/x/rotate",
        json={"new_team_did_key": did_from_public_key(pub)},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_rotate_team_key_not_found(client, controller_identity):
    signing_key, controller_did = controller_identity
    await _register_namespace(client, signing_key, controller_did, "rotnf.com")

    _, new_pub = generate_keypair()
    new_did_key = did_from_public_key(new_pub)
    headers = _sign(
        signing_key, controller_did,
        domain="rotnf.com", operation="rotate_team_key",
        name="nope", new_team_did_key=new_did_key,
    )
    resp = await client.post(
        "/v1/namespaces/rotnf.com/teams/nope/rotate",
        json={"new_team_did_key": new_did_key},
        headers=headers,
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_rotate_same_key_reports_no_invalidation(client, controller_identity):
    signing_key, controller_did = controller_identity
    await _register_namespace(client, signing_key, controller_did, "same.com")

    _, pub = generate_keypair()
    team_did_key = did_from_public_key(pub)
    headers = _sign(signing_key, controller_did, domain="same.com", operation="create_team", name="x")
    await client.post(
        "/v1/namespaces/same.com/teams",
        json={"name": "x", "team_did_key": team_did_key},
        headers=headers,
    )

    headers = _sign(
        signing_key, controller_did,
        domain="same.com", operation="rotate_team_key",
        name="x", new_team_did_key=team_did_key,
    )
    resp = await client.post(
        "/v1/namespaces/same.com/teams/x/rotate",
        json={"new_team_did_key": team_did_key},
        headers=headers,
    )
    assert resp.status_code == 200
    assert resp.json()["key_changed"] is False

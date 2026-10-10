"""Anonymous, minimal certificate status against the real registry and database."""
import json
from pathlib import Path
from datetime import datetime
from uuid import uuid4

import pytest

from awid.did import did_from_public_key, generate_keypair
from conftest import build_signed_headers as _sign
from test_team_visibility_enforcement import (
    _assert_team_private, _create_team, _register_member, _revoke_member, _setup_namespace,
)


@pytest.mark.asyncio
@pytest.mark.parametrize("visibility", ["public", "private"])
async def test_status_active_revoked_and_private_read_boundary(client, controller_identity, visibility):
    ns_key, ns_did = controller_identity
    domain = "status.example"
    await _setup_namespace(client, ns_key, ns_did, domain)
    key, did, team = await _create_team(client, ns_key, ns_did, domain, "ops", visibility=visibility)
    _, _, cert = await _register_member(client, key, did, domain, "ops", "alice")
    base = f"/v1/namespaces/{domain}/teams/ops"
    path = f"{base}/certificates/{cert}/status"
    response = await client.get(path)
    assert response.status_code == 200, response.text
    assert response.json() == {
        "team_id": team["team_id"], "team_did_key": did, "status": "active", "revoked_at": None,
    }
    if visibility == "private":
        for suffix in ("", "/certificates", "/revocations", "/members/alice"):
            _assert_team_private(await client.get(base + suffix))
    await _revoke_member(client, key, did, domain, "ops", cert)
    response = await client.get(path)
    assert response.status_code == 200, response.text
    body = response.json()
    assert set(body) == {"team_id", "team_did_key", "status", "revoked_at"}
    assert body["team_id"] == team["team_id"]
    assert body["team_did_key"] == did
    assert body["status"] == "revoked"
    assert body["revoked_at"] is not None


@pytest.mark.asyncio
async def test_unknown_team_certificate_and_other_team_have_identical_404(client, controller_identity):
    ns_key, ns_did = controller_identity
    domain = "unknown-status.example"
    await _setup_namespace(client, ns_key, ns_did, domain)
    key, did, _ = await _create_team(client, ns_key, ns_did, domain, "ops")
    _, _, cert = await _register_member(client, key, did, domain, "ops", "alice")
    await _create_team(client, ns_key, ns_did, domain, "other")
    responses = [await client.get(f"/v1/namespaces/{d}/teams/{name}/certificates/{cid}/status")
                 for d, name, cid in [(domain, "missing", cert), (domain, "ops", str(uuid4())),
                                      (domain, "other", cert), ("missing.example", "ops", cert)]]
    assert all(response.status_code == 404 for response in responses)
    assert len({response.content for response in responses}) == 1
    assert responses[0].json() == {"detail": "Certificate not found"}


@pytest.mark.asyncio
async def test_rotation_returns_current_key_even_for_active_old_certificate(client, controller_identity):
    ns_key, ns_did = controller_identity
    domain = "rotate-status.example"
    await _setup_namespace(client, ns_key, ns_did, domain)
    key, did, _ = await _create_team(client, ns_key, ns_did, domain, "ops")
    _, _, cert = await _register_member(client, key, did, domain, "ops", "alice")
    _, pub = generate_keypair()
    new_did = did_from_public_key(pub)
    response = await client.post(
        f"/v1/namespaces/{domain}/teams/ops/rotate", json={"new_team_did_key": new_did},
        headers=_sign(ns_key, ns_did, domain=domain, operation="rotate_team_key",
                      name="ops", new_team_did_key=new_did),
    )
    assert response.status_code == 200, response.text
    response = await client.get(f"/v1/namespaces/{domain}/teams/ops/certificates/{cert}/status")
    assert response.status_code == 200, response.text
    assert response.json()["team_did_key"] == new_did
    assert response.json()["team_did_key"] != did
    assert response.json()["status"] == "active"
    assert response.json()["revoked_at"] is None


@pytest.mark.asyncio
async def test_status_conformance_vector_and_deleted_team(client, controller_identity, awid_db_infra):
    vector = json.loads((Path(__file__).parents[2] / "docs" / "vectors" / "team-certificate-status-v1.json").read_text())
    ns_key, ns_did = controller_identity
    domain = "vector-status.example"
    await _setup_namespace(client, ns_key, ns_did, domain)
    key, did, _ = await _create_team(client, ns_key, ns_did, domain, "ops")
    _, _, cert = await _register_member(client, key, did, domain, "ops", "alice")
    db = awid_db_infra.get_manager("aweb")
    path = f"/v1/namespaces/{domain}/teams/ops/certificates/{cert}/status"
    for case in vector["cases"]:
        expected = case["response"]
        await db.execute("UPDATE {{tables.teams}} SET team_did_key = $1", expected["team_did_key"])
        stamp = expected["revoked_at"]
        await db.execute("UPDATE {{tables.team_certificates}} SET revoked_at = $1",
                         datetime.fromisoformat(stamp) if stamp else None)
        response = await client.get(path)
        assert response.status_code == case["http_status"]
        assert response.json() == expected
    await db.execute("UPDATE {{tables.teams}} SET deleted_at = now()")
    response = await client.get(path)
    assert response.status_code == vector["not_found"]["http_status"]
    assert response.json() == vector["not_found"]["response"]

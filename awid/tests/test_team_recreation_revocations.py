"""A team's revocations outlive the team.

The aweb server checks a presented certificate against the revocation list it
reads by team_id (domain and name). Deleting a team, or its namespace, and
creating the team again under the same name must not empty that list: a
certificate revoked before the deletion stays revoked, whatever key the team is
created with again. Revocation is one-way.
"""
from __future__ import annotations

from uuid import uuid4

import pytest

from awid.did import did_from_public_key, generate_keypair
from conftest import build_signed_headers as _sign
from test_namespaces import (
    _register_certificate,
    _register_namespace,
    _revoke_certificate,
)


async def _create_team_with_key(client, ns_key, ns_did, domain, name, team_did):
    headers = _sign(ns_key, ns_did, domain=domain, operation="create_team", name=name)
    resp = await client.post(
        f"/v1/namespaces/{domain}/teams",
        json={"name": name, "team_did_key": team_did, "visibility": "public"},
        headers=headers,
    )
    assert resp.status_code == 200, resp.text


async def _delete_team(client, ns_key, ns_did, domain, name):
    headers = _sign(ns_key, ns_did, domain=domain, operation="delete_team", team_name=name)
    resp = await client.delete(f"/v1/namespaces/{domain}/teams/{name}", headers=headers)
    assert resp.status_code == 200, resp.text


async def _delete_namespace(client, ns_key, ns_did, domain):
    headers = _sign(ns_key, ns_did, domain=domain, operation="delete_namespace")
    resp = await client.request("DELETE", f"/v1/namespaces/{domain}", headers=headers, json={})
    assert resp.status_code == 200, resp.text


async def _revoked_ids(client, domain, name) -> set[str]:
    resp = await client.get(f"/v1/namespaces/{domain}/teams/{name}/revocations")
    assert resp.status_code == 200, resp.text
    return {entry["certificate_id"] for entry in resp.json()["revocations"]}


async def _team_with_revoked_certificate(client, ns_key, ns_did, domain, name):
    """A live team holding one revoked certificate. Returns (team_key, team_did, cert_id)."""
    team_key, team_pub = generate_keypair()
    team_did = did_from_public_key(team_pub)
    await _create_team_with_key(client, ns_key, ns_did, domain, name, team_did)
    cert_id = str(uuid4())
    await _register_certificate(client, team_key, team_did, domain, name, cert_id)
    await _revoke_certificate(client, team_key, team_did, domain, name, cert_id)
    assert await _revoked_ids(client, domain, name) == {cert_id}
    return team_key, team_did, cert_id


@pytest.mark.asyncio
async def test_revocation_survives_team_recreation_with_the_same_key(client, controller_identity):
    ns_key, ns_did = controller_identity
    domain = "recreate-same.example"
    await _register_namespace(client, ns_key, ns_did, domain)
    _, team_did, cert_id = await _team_with_revoked_certificate(client, ns_key, ns_did, domain, "ops")

    await _delete_team(client, ns_key, ns_did, domain, "ops")
    await _create_team_with_key(client, ns_key, ns_did, domain, "ops", team_did)

    assert cert_id in await _revoked_ids(client, domain, "ops")


@pytest.mark.asyncio
async def test_revocation_survives_team_recreation_with_a_new_key(client, controller_identity):
    ns_key, ns_did = controller_identity
    domain = "recreate-new.example"
    await _register_namespace(client, ns_key, ns_did, domain)
    _, _, cert_id = await _team_with_revoked_certificate(client, ns_key, ns_did, domain, "ops")

    await _delete_team(client, ns_key, ns_did, domain, "ops")
    _, new_pub = generate_keypair()
    await _create_team_with_key(client, ns_key, ns_did, domain, "ops", did_from_public_key(new_pub))

    assert cert_id in await _revoked_ids(client, domain, "ops")


@pytest.mark.asyncio
async def test_revocation_survives_namespace_deletion_and_team_recreation(client, controller_identity):
    ns_key, ns_did = controller_identity
    domain = "recreate-ns.example"
    await _register_namespace(client, ns_key, ns_did, domain)
    _, team_did, cert_id = await _team_with_revoked_certificate(client, ns_key, ns_did, domain, "ops")

    await _delete_namespace(client, ns_key, ns_did, domain)
    await _register_namespace(client, ns_key, ns_did, domain)
    await _create_team_with_key(client, ns_key, ns_did, domain, "ops", team_did)

    assert cert_id in await _revoked_ids(client, domain, "ops")


@pytest.mark.asyncio
async def test_recreated_team_lists_its_own_revocations_and_no_other_teams(client, controller_identity):
    ns_key, ns_did = controller_identity
    domain = "recreate-scope.example"
    await _register_namespace(client, ns_key, ns_did, domain)
    team_key, team_did, earlier = await _team_with_revoked_certificate(client, ns_key, ns_did, domain, "ops")
    _, _, other_team = await _team_with_revoked_certificate(client, ns_key, ns_did, domain, "web")

    await _delete_team(client, ns_key, ns_did, domain, "ops")
    await _create_team_with_key(client, ns_key, ns_did, domain, "ops", team_did)
    current = str(uuid4())
    await _register_certificate(client, team_key, team_did, domain, "ops", current)
    await _revoke_certificate(client, team_key, team_did, domain, "ops", current)
    active = str(uuid4())
    await _register_certificate(client, team_key, team_did, domain, "ops", active, alias="bob")

    assert await _revoked_ids(client, domain, "ops") == {earlier, current}
    assert await _revoked_ids(client, domain, "web") == {other_team}

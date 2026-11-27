"""A team's revocations outlive the team.

The aweb server checks a presented certificate against the revocation list it
reads by team_id (domain and name). Deleting a team, or its namespace, and
creating the team again under the same name must not empty that list: a
certificate revoked before the deletion stays revoked, whatever key the team is
created with again. Revocation is one-way.
"""

from __future__ import annotations

from pathlib import Path
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
    headers = _sign(
        ns_key, ns_did, domain=domain, operation="delete_team", team_name=name
    )
    resp = await client.delete(f"/v1/namespaces/{domain}/teams/{name}", headers=headers)
    assert resp.status_code == 200, resp.text


async def _delete_namespace(client, ns_key, ns_did, domain):
    headers = _sign(ns_key, ns_did, domain=domain, operation="delete_namespace")
    resp = await client.request(
        "DELETE", f"/v1/namespaces/{domain}", headers=headers, json={}
    )
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
async def test_revocation_survives_team_recreation_with_the_same_key(
    client, controller_identity
):
    ns_key, ns_did = controller_identity
    domain = "recreate-same.example"
    await _register_namespace(client, ns_key, ns_did, domain)
    _, team_did, cert_id = await _team_with_revoked_certificate(
        client, ns_key, ns_did, domain, "ops"
    )

    await _delete_team(client, ns_key, ns_did, domain, "ops")
    for path in ("ops", "ops/revocations"):
        response = await client.get(f"/v1/namespaces/{domain}/teams/{path}")
        assert response.status_code == 404
        assert response.json() == {"detail": "Team not found"}
    await _create_team_with_key(client, ns_key, ns_did, domain, "ops", team_did)

    assert cert_id in await _revoked_ids(client, domain, "ops")


@pytest.mark.asyncio
async def test_revocation_survives_team_recreation_with_a_new_key(
    client, controller_identity
):
    ns_key, ns_did = controller_identity
    domain = "recreate-new.example"
    await _register_namespace(client, ns_key, ns_did, domain)
    _, _, cert_id = await _team_with_revoked_certificate(
        client, ns_key, ns_did, domain, "ops"
    )

    await _delete_team(client, ns_key, ns_did, domain, "ops")
    _, new_pub = generate_keypair()
    await _create_team_with_key(
        client, ns_key, ns_did, domain, "ops", did_from_public_key(new_pub)
    )

    assert cert_id in await _revoked_ids(client, domain, "ops")


@pytest.mark.asyncio
async def test_revocation_survives_namespace_deletion_and_team_recreation(
    client, controller_identity
):
    ns_key, ns_did = controller_identity
    domain = "recreate-ns.example"
    await _register_namespace(client, ns_key, ns_did, domain)
    _, team_did, cert_id = await _team_with_revoked_certificate(
        client, ns_key, ns_did, domain, "ops"
    )

    await _delete_namespace(client, ns_key, ns_did, domain)
    await _register_namespace(client, ns_key, ns_did, domain)
    await _create_team_with_key(client, ns_key, ns_did, domain, "ops", team_did)

    assert cert_id in await _revoked_ids(client, domain, "ops")


@pytest.mark.asyncio
async def test_recreated_team_lists_its_own_revocations_and_no_other_teams(
    client, controller_identity
):
    ns_key, ns_did = controller_identity
    domain = "recreate-scope.example"
    await _register_namespace(client, ns_key, ns_did, domain)
    team_key, team_did, earlier = await _team_with_revoked_certificate(
        client, ns_key, ns_did, domain, "ops"
    )
    _, _, other_team = await _team_with_revoked_certificate(
        client, ns_key, ns_did, domain, "web"
    )

    await _delete_team(client, ns_key, ns_did, domain, "ops")
    await _create_team_with_key(client, ns_key, ns_did, domain, "ops", team_did)
    current = str(uuid4())
    await _register_certificate(client, team_key, team_did, domain, "ops", current)
    await _revoke_certificate(client, team_key, team_did, domain, "ops", current)
    active = str(uuid4())
    await _register_certificate(
        client, team_key, team_did, domain, "ops", active, alias="bob"
    )

    assert await _revoked_ids(client, domain, "ops") == {earlier, current}
    assert await _revoked_ids(client, domain, "web") == {other_team}


# The statement of awid/ops/team-recreation-census.sql, which the test reads
# back from that file and compares, so the SQL the test runs is the SQL in the
# file and the test-state scan can read it.
CENSUS_STATEMENT = """
WITH deleted AS (
    SELECT team_uuid, domain, name, team_did_key, deleted_at
    FROM awid.teams
    WHERE deleted_at IS NOT NULL
), recreated AS (
    SELECT d.team_uuid AS deleted_team,
           later.team_uuid AS later_team,
           later.deleted_at IS NULL AS later_is_live,
           later.team_did_key = d.team_did_key AS same_key
    FROM deleted d
    JOIN awid.teams later
      ON later.domain = d.domain
     AND later.name = d.name
     AND later.team_uuid <> d.team_uuid
     AND later.created_at >= d.deleted_at
)
SELECT
    (SELECT count(*) FROM deleted) AS deleted_teams,
    (SELECT count(*) FROM deleted d
      WHERE EXISTS (SELECT 1 FROM awid.team_certificates c WHERE c.team_uuid = d.team_uuid))
        AS deleted_teams_with_certificate_rows,
    (SELECT count(DISTINCT deleted_team) FROM recreated) AS deleted_teams_recreated,
    (SELECT count(DISTINCT deleted_team) FROM recreated WHERE same_key)
        AS deleted_teams_recreated_with_same_key,
    (SELECT count(DISTINCT later_team) FROM recreated WHERE same_key AND later_is_live)
        AS live_teams_recreated_with_same_key;
"""


def _census_file_statement() -> str:
    script = (
        Path(__file__).resolve().parents[1] / "ops" / "team-recreation-census.sql"
    ).read_text()
    _before, begin, tail = script.partition("BEGIN READ ONLY;")
    statement, rollback, after = tail.rpartition("ROLLBACK;")
    assert begin and rollback and not after.strip()
    return statement.strip()


async def _read_only_census(pool) -> dict:
    """Run the statement of awid/ops/team-recreation-census.sql in its own
    read-only transaction, as it runs in production."""
    assert _census_file_statement() == CENSUS_STATEMENT.strip()
    async with pool.acquire() as conn:
        await conn.execute("BEGIN READ ONLY")
        try:
            assert await conn.fetchval("SHOW transaction_read_only") == "on"
            return dict(await conn.fetchrow(CENSUS_STATEMENT))
        finally:
            await conn.execute("ROLLBACK")


@pytest.mark.asyncio
async def test_recreation_census_counts_teams_recreated_with_the_same_key(
    client,
    controller_identity,
    shared_test_pool,
):
    ns_key, ns_did = controller_identity
    domain = "census.example"
    await _register_namespace(client, ns_key, ns_did, domain)
    _, same_did, _ = await _team_with_revoked_certificate(
        client, ns_key, ns_did, domain, "same"
    )
    await _team_with_revoked_certificate(client, ns_key, ns_did, domain, "fresh")
    await _team_with_revoked_certificate(client, ns_key, ns_did, domain, "gone")
    await _team_with_revoked_certificate(client, ns_key, ns_did, domain, "live")
    # A deleted team that never held a certificate has no certificate rows,
    # the shape every team deleted before acxc.101 left.
    _, empty_pub = generate_keypair()
    await _create_team_with_key(
        client, ns_key, ns_did, domain, "empty", did_from_public_key(empty_pub)
    )
    for name in ("same", "fresh", "gone", "empty"):
        await _delete_team(client, ns_key, ns_did, domain, name)
    await _create_team_with_key(client, ns_key, ns_did, domain, "same", same_did)
    _, new_pub = generate_keypair()
    await _create_team_with_key(
        client, ns_key, ns_did, domain, "fresh", did_from_public_key(new_pub)
    )

    assert await _read_only_census(shared_test_pool) == {
        "deleted_teams": 4,
        "deleted_teams_with_certificate_rows": 3,
        "deleted_teams_recreated": 2,
        "deleted_teams_recreated_with_same_key": 1,
        "live_teams_recreated_with_same_key": 1,
    }


async def _certificate_status(client, domain, name, cert_id) -> dict:
    resp = await client.get(
        f"/v1/namespaces/{domain}/teams/{name}/certificates/{cert_id}/status"
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


@pytest.mark.asyncio
async def test_a_revoked_certificate_id_registered_again_after_recreation_reads_revoked(
    client, controller_identity
):
    # One certificate has one answer: the status read and the revocation list
    # both read the revocation history of every team ever created under the
    # name, so registering a revoked id again in the recreated team does not
    # make it active.
    ns_key, ns_did = controller_identity
    domain = "recreate-status.example"
    await _register_namespace(client, ns_key, ns_did, domain)
    team_key, team_did, cert_id = await _team_with_revoked_certificate(
        client, ns_key, ns_did, domain, "ops"
    )

    await _delete_team(client, ns_key, ns_did, domain, "ops")
    await _create_team_with_key(client, ns_key, ns_did, domain, "ops", team_did)
    await _register_certificate(client, team_key, team_did, domain, "ops", cert_id)
    fresh = str(uuid4())
    await _register_certificate(
        client, team_key, team_did, domain, "ops", fresh, alias="bob"
    )

    status = await _certificate_status(client, domain, "ops", cert_id)
    assert status["status"] == "revoked"
    assert status["revoked_at"]
    assert status["team_did_key"] == team_did
    assert cert_id in await _revoked_ids(client, domain, "ops")
    # The recreated team's own certificate is active.
    assert (await _certificate_status(client, domain, "ops", fresh))[
        "status"
    ] == "active"

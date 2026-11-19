"""A certificate registration racing a team-key change is checked against the
key the change leaves current.

The change is held open on its own connection with the team row locked, as
rotate_team_key holds it; the registration runs through the real AWID app.
"""

from __future__ import annotations

import asyncio
from uuid import uuid4

import pytest

from awid.did import did_from_public_key, generate_keypair

from conftest import build_signed_headers as _sign
from test_certificates import (
    _register_member_address,
    _setup_team,
    _signed_certificate_blob,
)

DOMAIN = "race.cert.com"


async def _registration(client, ns_key, ns_did, team_key, team_did):
    member_key, member_pub = generate_keypair()
    member_did_key = did_from_public_key(member_pub)
    member_did_aw = await _register_member_address(
        client,
        ns_key,
        ns_did,
        DOMAIN,
        "alice",
        member_key,
        member_did_key,
    )
    cert_id = str(uuid4())
    headers = _sign(
        team_key,
        team_did,
        domain=DOMAIN,
        operation="register_certificate",
        team_name="backend",
        certificate_id=cert_id,
    )
    body = {
        "certificate": _signed_certificate_blob(
            team_key,
            certificate_id=cert_id,
            team_id=f"backend:{DOMAIN}",
            team_did_key=team_did,
            member_did_key=member_did_key,
            alias="alice",
            lifetime="global",
            member_did_aw=member_did_aw,
            member_address=f"{DOMAIN}/alice",
        ),
        "certificate_id": cert_id,
        "member_did_key": member_did_key,
        "member_did_aw": member_did_aw,
        "member_address": f"{DOMAIN}/alice",
        "alias": "alice",
        "identity_scope": "global",
    }
    return cert_id, lambda: client.post(
        f"/v1/namespaces/{DOMAIN}/teams/backend/certificates",
        json=body,
        headers=headers,
    )


async def _registered(db, cert_id) -> bool:
    row = await db.fetch_one(
        "SELECT 1 AS found FROM {{tables.team_certificates}} WHERE certificate_id = $1",
        cert_id,
    )
    return row is not None


async def _wait_until_a_backend_waits_on_a_lock(db):
    async with asyncio.timeout(10):
        while True:
            row = await db.fetch_one(
                "SELECT count(*) AS waiting FROM pg_locks WHERE NOT granted"
            )
            if row["waiting"]:
                return
            await asyncio.sleep(0.01)


@pytest.mark.asyncio
async def test_registration_under_a_key_rotated_out_meanwhile_is_refused(
    client, controller_identity, awid_db_infra
):
    ns_key, ns_did = controller_identity
    team_key, team_did, _ = await _setup_team(client, ns_key, ns_did, DOMAIN, "backend")
    cert_id, register = await _registration(client, ns_key, ns_did, team_key, team_did)
    db = awid_db_infra.get_manager()
    _, new_pub = generate_keypair()

    async with db.transaction() as rotation:
        await rotation.fetch_one(
            "SELECT team_uuid FROM {{tables.teams}} WHERE domain = $1 AND name = 'backend' FOR UPDATE",
            DOMAIN,
        )
        await rotation.execute(
            "UPDATE {{tables.teams}} SET team_did_key = $2 WHERE domain = $1 AND name = 'backend'",
            DOMAIN,
            did_from_public_key(new_pub),
        )
        pending = asyncio.create_task(register())
        await _wait_until_a_backend_waits_on_a_lock(db)
    response = await pending

    assert response.status_code == 409, response.text
    assert response.json()["detail"]["code"] == "team_key_not_current"
    assert not await _registered(db, cert_id)


@pytest.mark.asyncio
async def test_registration_with_no_rotation_meanwhile_is_registered(
    client, controller_identity, awid_db_infra
):
    ns_key, ns_did = controller_identity
    team_key, team_did, _ = await _setup_team(client, ns_key, ns_did, DOMAIN, "backend")
    cert_id, register = await _registration(client, ns_key, ns_did, team_key, team_did)

    response = await register()

    assert response.status_code == 200, response.text
    assert await _registered(awid_db_infra.get_manager(), cert_id)

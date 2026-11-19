"""Certificate registration races the actual team-key rotation route."""

from uuid import uuid4

import pytest
from awid.did import did_from_public_key, generate_keypair
from rotation_race_harness import paused_rotation
from test_certificates import _register_member_address
from test_controller_request_v2_http import certificate_body, keypair, send

BASE = "/v1/namespaces/local/teams/base"


async def _registration(env):
    member_key, member_pub = generate_keypair()
    member_did = did_from_public_key(member_pub)
    alias = f"m{uuid4().hex[:8]}"
    did_aw = await _register_member_address(
        env.client, *env.controller, "local", alias, member_key, member_did
    )
    body = certificate_body(
        env,
        alias=alias,
        member=(member_key, member_did),
        did_aw=did_aw,
        address=f"local/{alias}",
    )
    claims = {
        "domain": "local",
        "operation": "register_certificate",
        "team_name": "base",
        "certificate_id": body["certificate_id"],
    }
    return body["certificate_id"], lambda: send(
        env, "POST", f"{BASE}/certificates", claims, body, signer=env.team
    )


async def _rotate(env, new_did):
    return await send(
        env,
        "POST",
        f"{BASE}/rotate",
        {
            "domain": "local",
            "operation": "rotate_team_key",
            "name": "base",
            "new_team_did_key": new_did,
        },
        {"new_team_did_key": new_did},
    )


@pytest.mark.asyncio
async def test_registration_under_a_key_rotated_out_meanwhile_is_refused(
    controller_app,
):
    env = controller_app
    cert_id, register = await _registration(env)
    new = keypair()
    async with paused_rotation(
        env.db, domain="local", name="base", rotate=lambda: _rotate(env, new[1])
    ) as barrier:
        pending = await barrier.start_competing(register)
    rotation, registration = barrier.rotation.result(), pending.result()
    assert rotation.status_code == 200, rotation.text
    assert rotation.json()["team_did_key"] == new[1]
    assert registration.status_code == 409, registration.text
    assert registration.json()["detail"]["code"] == "team_key_not_current"
    team = await env.client.get(BASE)
    assert team.status_code == 200, team.text
    assert team.json()["team_did_key"] == new[1]
    status = await env.client.get(f"{BASE}/certificates/{cert_id}/status")
    assert status.status_code == 404, status.text
    assert status.json() == {"detail": "Certificate not found"}


@pytest.mark.asyncio
async def test_registration_with_no_rotation_meanwhile_is_registered(controller_app):
    env = controller_app
    cert_id, register = await _registration(env)
    response = await register()
    assert response.status_code == 200, response.text
    assert response.json() == {"registered": True, "certificate_id": cert_id}
    status = await env.client.get(f"{BASE}/certificates/{cert_id}/status")
    assert status.status_code == 200, status.text
    assert status.json() == {
        "team_id": "base:local",
        "team_did_key": env.team[1],
        "status": "active",
        "revoked_at": None,
    }

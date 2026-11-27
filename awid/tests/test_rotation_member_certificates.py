"""A team-key change carries each kept member's new certificate and records.

The rotate request may name, for each active member certificate, its
replacement under the new key and the member's custody and person records for
it. AWID revokes the old certificate, registers the new one and records them in
the rotation's own transaction, or changes nothing.
"""

from __future__ import annotations

from uuid import uuid4

import pytest

from test_attestation_record_routes import (
    BASE,
    _custody,
    _person,
    _resign,
    _signed,
    _team_key,
    _team_with_records,
    _now,
)
from test_certificates import _signed_certificate_blob
from test_controller_request_v2_http import keypair, send  # noqa: F401


async def _old_certificate(env):
    return await env.db.fetch_one(
        "SELECT certificate_id, member_did_key, alias FROM {{tables.team_certificates}} WHERE revoked_at IS NULL",
    )


def _replacement(old, signer, *, member_did_key=None):
    """old's member certificate signed by signer (key, did), with its records."""
    cert_id = str(uuid4())
    member = member_did_key or old["member_did_key"]
    blob = _signed_certificate_blob(
        signer[0],
        certificate_id=cert_id,
        team_id="base:local",
        team_did_key=signer[1],
        member_did_key=member,
        alias=old["alias"],
        lifetime="local",
    )
    record_cert = {"certificate_id": cert_id, "member_did_key": member}
    env_key = type("Env", (), {"team": signer})()
    return {
        "old_certificate_id": old["certificate_id"],
        "certificate": blob,
        "custody": _signed(signer[0], _custody(env_key, record_cert, issued_at=_now())),
        "person": _signed(signer[0], _person(env_key, record_cert, issued_at=_now())),
    }


async def _rotate_with(env, new, custodian, custody, person, members):
    resigned = {
        "team_custodians": [_signed(new[0], _resign(custodian, new))],
        "member_custody": [_signed(new[0], _resign(custody, new))],
        "member_person": [_signed(new[0], _resign(person, new))],
    }
    body = {
        "new_team_did_key": new[1],
        "resigned_records": resigned,
        "member_certificates": members,
    }
    claims = {
        "domain": "local",
        "operation": "rotate_team_key",
        "name": "base",
        "new_team_did_key": new[1],
    }
    return await send(env, "POST", f"{BASE}/rotate", claims, body)


async def _active(env):
    rows = await env.db.fetch_all(
        "SELECT certificate_id FROM {{tables.team_certificates}} WHERE revoked_at IS NULL"
    )
    return {row["certificate_id"] for row in rows}


@pytest.mark.asyncio
async def test_rotation_replaces_each_named_member_certificate_and_records_it(
    controller_app,
):
    env = controller_app
    custodian, custody, person = await _team_with_records(env)
    old = await _old_certificate(env)
    new = keypair()
    member = _replacement(old, new)

    response = await _rotate_with(env, new, custodian, custody, person, [member])

    assert response.status_code == 200, response.text
    assert await _team_key(env) == new[1]
    new_id = member["custody"]["record"]["certificate_id"]
    assert await _active(env) == {new_id}
    for kind in ("custody", "person"):
        read = await env.client.get(f"{BASE}/certificates/{new_id}/{kind}")
        assert read.json() == member[kind]


@pytest.mark.parametrize(
    "change", ["old_key", "other_member", "unknown_old", "record_for_other_certificate"]
)
@pytest.mark.asyncio
async def test_a_member_change_that_does_not_hold_changes_nothing(
    controller_app, change
):
    env = controller_app
    custodian, custody, person = await _team_with_records(env)
    old = await _old_certificate(env)
    old_key = await _team_key(env)
    new = keypair()
    if change == "old_key":
        member = _replacement(old, env.team)
    elif change == "other_member":
        member = _replacement(old, new, member_did_key=keypair()[1])
    elif change == "unknown_old":
        member = dict(_replacement(old, new), old_certificate_id=str(uuid4()))
    else:
        member = _replacement(old, new)
        other = {
            "certificate_id": old["certificate_id"],
            "member_did_key": old["member_did_key"],
        }
        env_key = type("Env", (), {"team": new})()
        member["person"] = _signed(new[0], _person(env_key, other, issued_at=_now()))

    response = await _rotate_with(env, new, custodian, custody, person, [member])

    expected = {
        "old_key": (422, "certificate team_did_key does not match registration"),
        "other_member": (422, "certificate member_did_key does not match registration"),
        "unknown_old": (409, "member_certificate_not_active"),
        "record_for_other_certificate": (422, "record_invalid"),
    }[change]
    detail = response.json()["detail"]
    assert (
        response.status_code,
        detail["code"] if isinstance(detail, dict) else detail,
    ) == expected, response.text
    assert await _team_key(env) == old_key
    assert await _active(env) == {old["certificate_id"]}

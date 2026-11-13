"""Protected-team cutover must change verifier behavior, not controller identity.

These native HTTP cases retain the real team/namespace keys and valid signatures
on both sides of cutover. The authoritative protection row is the only change.
The detached proof mechanism is intentionally absent: these are legacy callers.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from awid.signing import sign_message
from awid.team_server_record import record_signing_bytes
from test_controller_request_v2_http import (
    certificate_body,
    controller_app as controller_app,  # Real PostgreSQL and Redis fixture.
    keypair,
    send,
)

TEAM_PATH = "/v1/namespaces/local/teams/base"


async def protect_team(env):
    # Model the recorded registry-host provisioning action. No worker endpoint
    # or client profile may turn protection on/off, or select its proof key.
    await env.db.execute(
        "INSERT INTO {{tables.team_protection}} "
        "(domain, name, service_id, service_did_key, generation) "
        "VALUES ($1, $2, $3, $4, $5)",
        "local",
        "base",
        "independent-signer",
        keypair()[1],
        1,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("protected", [False, True], ids=["legacy", "protected"])
@pytest.mark.parametrize(
    "covering", [False, True], ids=["released-legacy-envelope", "covering-envelope"]
)
@pytest.mark.parametrize(
    "operation",
    [
        "register_certificate",
        "revoke_certificate",
        "set_team_visibility",
        "delete_team",
        "rotate_team_key",
    ],
)
async def test_key_file_controller_mutations_obey_authoritative_protection(
    controller_app,
    operation,
    covering,
    protected,
):
    env = controller_app
    before_key = env.team[1]
    cert = certificate_body(env)
    if operation == "revoke_certificate":
        admitted = await send(
            env,
            "POST",
            TEAM_PATH + "/certificates",
            {
                "domain": "local",
                "team_name": "base",
                "operation": "register_certificate",
                "certificate_id": cert["certificate_id"],
            },
            cert,
            signer=env.team,
        )
        assert admitted.status_code == 200, admitted.text
    if protected:
        await protect_team(env)

    claims = {"domain": "local", "operation": operation, "team_name": "base"}
    signer = env.team
    method = "POST"
    if operation == "register_certificate":
        path, body = TEAM_PATH + "/certificates", cert
        claims["certificate_id"] = cert["certificate_id"]
    elif operation == "revoke_certificate":
        path = TEAM_PATH + "/certificates/revoke"
        body = {"certificate_id": cert["certificate_id"]}
        claims["certificate_id"] = cert["certificate_id"]
    elif operation == "set_team_visibility":
        path, body = TEAM_PATH + "/visibility", {"visibility": "private"}
        claims["visibility"] = "private"
    elif operation == "delete_team":
        method, path, body, signer = "DELETE", TEAM_PATH, None, env.controller
    elif operation == "rotate_team_key":
        path, body, signer = (
            TEAM_PATH + "/rotate",
            {"new_team_did_key": keypair()[1]},
            env.controller,
        )
        claims = {"domain": "local", "operation": operation, "name": "base", **body}
    response = await send(
        env, method, path, claims, body, signer=signer, covering=covering
    )
    if not protected:
        assert response.status_code == 200, response.text
        return

    assert response.status_code == 403, response.text
    expected = (
        "protected_admission_required"
        if operation == "register_certificate"
        else "protected_controller_required"
    )
    assert response.json()["detail"]["code"] == expected
    row = await env.db.fetch_one(
        "SELECT team_did_key, visibility, deleted_at FROM {{tables.teams}} WHERE domain='local' AND name='base'",
    )
    assert row["team_did_key"] == before_key
    assert row["visibility"] == "public"
    assert row["deleted_at"] is None
    certificates = await env.db.fetch_all(
        "SELECT certificate_id, revoked_at FROM {{tables.team_certificates}}"
    )
    if operation == "revoke_certificate":
        assert len(certificates) == 1
        assert certificates[0]["certificate_id"] == cert["certificate_id"]
        assert certificates[0]["revoked_at"] is None
    else:
        assert not certificates


@pytest.mark.asyncio
@pytest.mark.parametrize("protected", [False, True], ids=["legacy", "protected"])
async def test_key_file_team_server_publication_obeys_authoritative_protection(
    controller_app, protected
):
    env = controller_app
    if protected:
        await protect_team(env)
    record = {
        "v": 1,
        "type": "aweb.team-server",
        "team_id": "base:local",
        "team_did_key": env.team[1],
        "server_url": "https://coord.example/api",
        "issued_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    body = {
        "record": record,
        "signature": sign_message(env.team[0], record_signing_bytes(record)),
    }
    # Publication is authorized by the record itself, independently of HTTP auth.
    response = await env.client.put(TEAM_PATH + "/server", json=body)
    if protected:
        assert response.status_code == 403, response.text
        assert response.json()["detail"]["code"] == "protected_controller_required"
        assert (
            await env.db.fetch_value(
                "SELECT count(*) FROM {{tables.team_server_records}}"
            )
            == 0
        )
    else:
        assert response.status_code == 200, response.text


@pytest.mark.asyncio
@pytest.mark.parametrize("protected", [False, True], ids=["legacy", "protected"])
@pytest.mark.parametrize(
    "covering", [False, True], ids=["legacy-envelope", "covering-envelope"]
)
async def test_namespace_delete_cannot_cascade_a_protected_team_with_revoked_members(
    controller_app,
    protected,
    covering,
):
    env = controller_app
    cert = certificate_body(env)
    claims = {
        "domain": "local",
        "team_name": "base",
        "certificate_id": cert["certificate_id"],
    }
    admitted = await send(
        env,
        "POST",
        TEAM_PATH + "/certificates",
        {**claims, "operation": "register_certificate"},
        cert,
        signer=env.team,
    )
    assert admitted.status_code == 200, admitted.text
    revoked = await send(
        env,
        "POST",
        TEAM_PATH + "/certificates/revoke",
        {**claims, "operation": "revoke_certificate"},
        {"certificate_id": cert["certificate_id"]},
        signer=env.team,
    )
    assert revoked.status_code == 200, revoked.text
    if protected:
        await protect_team(env)
    response = await send(
        env,
        "DELETE",
        "/v1/namespaces/local",
        {"domain": "local", "operation": "delete_namespace"},
        covering=covering,
    )
    if not protected:
        assert response.status_code == 200, response.text
        return
    assert response.status_code == 403, response.text
    assert response.json()["detail"]["code"] == "protected_controller_required"
    assert (
        await env.db.fetch_value(
            "SELECT deleted_at FROM {{tables.teams}} WHERE name='base'"
        )
        is None
    )
    assert (
        await env.db.fetch_value(
            "SELECT deleted_at FROM {{tables.dns_namespaces}} WHERE domain='local'"
        )
        is None
    )
    assert (
        await env.db.fetch_value(
            "SELECT count(*) FROM {{tables.team_certificates}} WHERE revoked_at IS NOT NULL"
        )
        == 1
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("protected", [False, True], ids=["legacy", "protected"])
@pytest.mark.parametrize("kind", ["custodian", "custody", "person"])
async def test_attestation_publication_needs_protected_controller_authority(
    controller_app, protected, kind
):
    from test_attestation_record_routes import (
        _custodian,
        _custody,
        _person,
        publish_custodian,
        publish_custody,
        publish_person,
        register_certificate,
    )

    env = controller_app
    cert = await register_certificate(env)
    if kind == "custody":
        setup = await publish_custodian(env, _custodian(env))
        assert setup.status_code == 200, setup.text
    if protected:
        await protect_team(env)
    if kind == "custodian":
        response = await publish_custodian(env, _custodian(env))
        table = "team_custodians"
    elif kind == "custody":
        response = await publish_custody(env, _custody(env, cert))
        table = "member_custody"
    else:
        response = await publish_person(env, _person(env, cert))
        table = "member_person"
    if not protected:
        assert response.status_code == 200, response.text
        return
    assert response.status_code == 403, response.text
    assert response.json()["detail"]["code"] == "protected_controller_required"
    assert await env.db.fetch_value(f"SELECT count(*) FROM {{{{tables.{table}}}}}") == 0

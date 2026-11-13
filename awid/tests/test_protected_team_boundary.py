"""Protected-team cutover must change verifier behavior, not controller identity.

These native HTTP cases retain the real team/namespace keys and valid signatures
on both sides of cutover. The authoritative protection row is the only change.
The detached proof mechanism is intentionally absent: these are legacy callers.
"""

from __future__ import annotations

import base64
import json
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
@pytest.mark.parametrize("malformed", [[], "not-an-object"])
async def test_protected_register_refuses_nonobject_artifact_without_a_server_error(controller_app, malformed):
    env = controller_app
    await protect_team(env)
    body = certificate_body(env)
    body["certificate"] = base64.b64encode(json.dumps(malformed).encode()).decode()
    response = await send(
        env, "POST", TEAM_PATH + "/certificates",
        {"domain": "local", "team_name": "base", "operation": "register_certificate",
         "certificate_id": body["certificate_id"]},
        body, signer=env.team,
    )
    assert response.status_code == 403, response.text
    assert response.json()["detail"]["code"] == "protected_admission_required"
    assert await env.db.fetch_value("SELECT count(*) FROM {{tables.team_certificates}}") == 0


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


@pytest.mark.asyncio
@pytest.mark.parametrize("protected", [False, True], ids=["legacy", "protected"])
async def test_team_read_projects_authoritative_protection_explicitly(
    controller_app, protected
):
    env = controller_app
    if protected:
        await protect_team(env)
    response = await env.client.get(TEAM_PATH)
    assert response.status_code == 200, response.text
    binding = response.json()["protection"]
    if protected:
        assert binding["mode"] == "protected"
        assert binding["service_id"] == "independent-signer"
        assert binding["generation"] == 1
        assert binding["history_id"]
    else:
        assert binding == {"mode": "legacy"}


@pytest.mark.asyncio
async def test_operator_protection_transition_preserves_history_and_requires_generation(
    controller_app,
):
    from awid_service.protected_teams import provision_team_protection

    env = controller_app
    service_did = keypair()[1]
    async with env.db.transaction() as tx:
        first = await provision_team_protection(
            tx,
            domain="local",
            name="base",
            service_id="independent-signer",
            service_did_key=service_did,
            expected_generation=0,
            approval_ref="operator-reviewed-initial-cutover",
        )
    async with env.db.transaction() as tx:
        second = await provision_team_protection(
            tx,
            domain="local",
            name="base",
            service_id="independent-signer",
            service_did_key=keypair()[1],
            expected_generation=1,
            approval_ref="operator-reviewed-key-replacement",
        )
    assert first["history_id"] == second["history_id"]
    assert second["generation"] == 2
    with pytest.raises(ValueError, match="protection_generation_changed"):
        async with env.db.transaction() as tx:
            await provision_team_protection(
                tx,
                domain="local",
                name="base",
                service_id="independent-signer",
                service_did_key=service_did,
                expected_generation=1,
                approval_ref="stale-transition",
            )
    async with env.db.transaction() as tx:
        await provision_team_protection(
            tx,
            domain="local",
            name="base",
            service_id="independent-signer",
            service_did_key=service_did,
            expected_generation=2,
            approval_ref="operator-reviewed-deprotection",
            mode="legacy",
        )
    row = await env.db.fetch_one(
        "SELECT history_id,generation,mode FROM {{tables.team_protection}}"
    )
    assert str(row["history_id"]) == first["history_id"]
    assert row["generation"] == 3 and row["mode"] == "legacy"
    assert (await env.client.get(TEAM_PATH)).json()["protection"] == {"mode": "legacy"}


@pytest.mark.asyncio
async def test_operator_cannot_reuse_a_controller_or_member_key_for_attestation(
    controller_app,
):
    from awid_service.protected_teams import provision_team_protection

    env = controller_app
    for reused in (env.controller[1], env.team[1]):
        with pytest.raises(ValueError, match="service_key_not_distinct"):
            async with env.db.transaction() as tx:
                await provision_team_protection(
                    tx,
                    domain="local",
                    name="base",
                    service_id="independent-signer",
                    service_did_key=reused,
                    expected_generation=0,
                    approval_ref="operator-record",
                )
    assert (
        await env.db.fetch_value("SELECT count(*) FROM {{tables.team_protection}}") == 0
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("protected", [False, True], ids=["legacy", "protected"])
async def test_new_team_uuid_does_not_reset_canonical_protection(
    controller_app, protected
):
    env = controller_app
    if protected:
        await protect_team(env)
    # Represents an explicitly retired old incarnation; its canonical binding
    # is independent of this disposable UUID and cannot be erased by create.
    await env.db.execute(
        "UPDATE {{tables.teams}} SET deleted_at=now() WHERE domain='local' AND name='base'"
    )
    response = await send(
        env,
        "POST",
        "/v1/namespaces/local/teams",
        {"domain": "local", "operation": "create_team", "name": "base"},
        {"name": "base", "team_did_key": keypair()[1], "visibility": "public"},
    )
    assert response.status_code == (403 if protected else 200), response.text
    if protected:
        assert response.json()["detail"]["code"] == "protected_controller_required"
        assert (
            await env.db.fetch_value(
                "SELECT count(*) FROM {{tables.teams}} WHERE deleted_at IS NULL"
            )
            == 0
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("protected", [False, True], ids=["legacy", "protected"])
async def test_private_public_status_negotiates_protection_without_changing_released_shape(
    controller_app, protected
):
    from awid.registry import RegistryClient
    from awid.protected_membership import (
        observe_team_protection,
        verify_registered_membership,
    )
    from awid.team_certificate import TeamCertificateError
    import base64
    import json

    env = controller_app
    cert = certificate_body(env)
    await send(
        env,
        "POST",
        TEAM_PATH + "/certificates",
        {
            "domain": "local",
            "operation": "register_certificate",
            "team_name": "base",
            "certificate_id": cert["certificate_id"],
        },
        cert,
        signer=env.team,
    )
    hidden = await send(
        env,
        "POST",
        TEAM_PATH + "/visibility",
        {
            "domain": "local",
            "operation": "set_team_visibility",
            "team_name": "base",
            "visibility": "private",
        },
        {"visibility": "private"},
        signer=env.team,
    )
    assert hidden.status_code == 200, hidden.text
    if protected:
        await protect_team(env)
    assert (await env.client.get(TEAM_PATH)).status_code == 403
    path = TEAM_PATH + "/certificates/" + cert["certificate_id"] + "/status"
    old = await env.client.get(path)
    assert old.status_code == 200, old.text
    assert set(old.json()) == {"team_id", "team_did_key", "status", "revoked_at"}
    current = await env.client.get(path + "?protection=1")
    assert current.status_code == 200, current.text
    assert current.json()["protection"]["mode"] == (
        "protected" if protected else "legacy"
    )
    assert current.json()["certificate_sha256"]
    registry = RegistryClient(
        registry_url="http://registry.test", transport=env.client._transport
    )
    try:
        observation = await observe_team_protection(
            registry, "base:local", certificate_id=cert["certificate_id"]
        )
        decoded = json.loads(base64.b64decode(cert["certificate"]))
        await verify_registered_membership(registry, observation, decoded)
        changed = {**decoded, "alias": "different-member"}
        from awid.signing import canonical_json_bytes

        changed["signature"] = sign_message(
            env.team[0],
            canonical_json_bytes(
                {k: v for k, v in changed.items() if k != "signature"}
            ),
        )
        if protected:
            with pytest.raises(
                TeamCertificateError, match="certificate_binding_mismatch"
            ):
                await verify_registered_membership(registry, observation, changed)
    finally:
        await registry.aclose()


@pytest.mark.asyncio
async def test_controller_write_serializes_with_activation_before_reading_absent_binding(
    controller_app,
):
    import asyncio
    from awid_service.protected_teams import provision_team_protection

    env = controller_app
    pending = None
    try:
        async with env.db.transaction() as operator:
            operator_pid = await operator.fetch_value("SELECT pg_backend_pid()")
            await provision_team_protection(
                operator,
                domain="local",
                name="base",
                service_id="independent-signer",
                service_did_key=keypair()[1],
                expected_generation=0,
                approval_ref="operator-reviewed-cutover",
            )
            pending = asyncio.create_task(
                send(
                    env,
                    "POST",
                    TEAM_PATH + "/visibility",
                    {
                        "domain": "local",
                        "operation": "set_team_visibility",
                        "team_name": "base",
                        "visibility": "private",
                    },
                    {"visibility": "private"},
                    signer=env.team,
                )
            )
            # Observe a real database lock wait, rather than assuming a sleeping
            # HTTP task reached the authority fence. All PIDs belong to this test DB.
            for _ in range(200):
                if pending.done():
                    pytest.fail(
                        "controller write escaped the uncommitted activation fence"
                    )
                blocked = await env.db.fetch_value(
                    "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() "
                    "AND $1=ANY(pg_blocking_pids(pid)))",
                    operator_pid,
                )
                if blocked:
                    break
                await asyncio.sleep(0.01)
            else:
                pytest.fail(
                    "controller write never reached the canonical authority lock"
                )
        response = await asyncio.wait_for(pending, 5)
        assert response.status_code == 403, response.text
        assert response.json()["detail"]["code"] == "protected_controller_required"
        assert (
            await env.db.fetch_value(
                "SELECT visibility FROM {{tables.teams}} WHERE name='base'"
            )
            == "public"
        )
    finally:
        if pending is not None and not pending.done():
            pending.cancel()
            await asyncio.gather(pending, return_exceptions=True)

"""Operator-only standalone grants against real HTTP, Postgres and local CLI."""

import asyncio
import json
import os
import sys

import pytest
import pytest_asyncio
import test_app_manifest_fetch as manifest_fixture
import test_dashboard_privacy as services
from aweb.install_admins import (
    INSTALL_ADMIN_SETUP_MESSAGE,
    InstallAdminGrantError,
    grant_install_admin_on,
    install_admin_setup_message,
    revoke_install_admin_on,
    standalone_install_admin_policy,
)
from aweb.install_authority import CertificateInstallAdminSubject
from test_agent_status_host_http import _team_request

TEAM = services.TEAM
privacy_app = services.privacy_app
origin = manifest_fixture.origin
pytestmark = pytest.mark.asyncio


@pytest_asyncio.fixture
async def standalone(privacy_app, origin):
    env = privacy_app
    env.app.state.manifest_fetcher = origin.fetcher
    data = origin.manifest()
    origin.publish(data)
    return env, {"app_id": "fixture", "origin": origin.url, "digest": manifest_fixture.digest(data), "granted_scopes": ["fixture:read"]}


def subject(env, name="alice"):
    actor = env.actors[name]
    return CertificateInstallAdminSubject(team_id=TEAM, agent_id=str(actor.id), did_key=actor.did, certificate_id="privacy-"+name)


async def grant(env, name="alice", role="admin"):
    async with env.db.transaction() as tx:
        return await grant_install_admin_on(tx, team_id=TEAM, principal_did=env.actors[name].did, role=role)


async def permitted(env):
    async with env.db.transaction() as tx:
        return await standalone_install_admin_policy(tx, subject(env), action="apps.install", app_id="fixture")


async def test_no_grant_fails_closed_and_member_cannot_self_promote(standalone):
    env, pin = standalone
    assert await install_admin_setup_message(env.db) == INSTALL_ADMIN_SETUP_MESSAGE
    refused = await _team_request(env, "alice", "POST", "/v1/apps/install", pin)
    assert refused.status_code == 403 and refused.json()["detail"]["code"] == "admin_required", refused.text
    # These are member-writable coordination labels, never install authority.
    changed = await _team_request(env, "alice", "PATCH", f"/v1/workspaces/{env.actors['alice'].workspace}", {"role": "admin"})
    assert changed.status_code == 200, changed.text
    for path in ("/v1/apps/install-admin/grant", "/v1/apps/install-admins"):
        request = await _team_request(env, "alice", "POST", path, {"principal_did": env.actors["alice"].did, "role": "owner"})
        assert request.status_code in (404, 405), request.text
    refused = await _team_request(env, "alice", "POST", "/v1/apps/install", pin)
    assert refused.status_code == 403, refused.text
    request = await _team_request(env, "alice", "POST", "/v1/apps/requests", {
        "app_id": pin["app_id"], "origin": pin["origin"], "digest": pin["digest"], "requested_scopes": pin["granted_scopes"],
    })
    assert request.status_code == 201, request.text
    assert await env.db.fetch_value("SELECT count(*) FROM {{tables.team_app_install_admins}}") == 0
    assert await env.db.fetch_value("SELECT count(*) FROM {{tables.team_app_installs}}") == 0


async def test_standalone_admin_can_install_and_revocation_stops_further_writes(standalone):
    env, pin = standalone
    await grant(env)
    assert await install_admin_setup_message(env.db) is None
    accepted = await _team_request(env, "alice", "POST", "/v1/apps/install", pin)
    assert accepted.status_code == 200, accepted.text
    before = accepted.json()
    member = await _team_request(env, "bob", "POST", "/v1/apps/install", {**pin, "expected_generation": before["generation"]})
    assert member.status_code == 403, member.text
    async with env.db.transaction() as tx:
        assert await revoke_install_admin_on(tx, team_id=TEAM, principal_did=env.actors["alice"].did)
    refused = await _team_request(env, "alice", "POST", "/v1/apps/install", {**pin, "expected_generation": before["generation"]})
    assert refused.status_code == 403, refused.text
    assert await env.db.fetch_value("SELECT generation FROM {{tables.team_app_installs}}") == before["generation"]
    assert await env.db.fetch_value("SELECT count(*) FROM {{tables.app_install_admin_audit}}") == 2


async def test_grant_and_revoke_roll_back_with_their_audit(standalone):
    env, _ = standalone
    with pytest.raises(RuntimeError):
        async with env.db.transaction() as tx:
            await grant_install_admin_on(tx, team_id=TEAM, principal_did=env.actors["alice"].did)
            assert await standalone_install_admin_policy(tx, subject(env), action="apps.install", app_id="fixture")
            assert await env.db.fetch_value("SELECT count(*) FROM {{tables.team_app_install_admins}}") == 0
            raise RuntimeError("operator transaction rolls back")
    assert not await permitted(env)
    assert await env.db.fetch_value("SELECT count(*) FROM {{tables.app_install_admin_audit}}") == 0
    await grant(env)
    with pytest.raises(RuntimeError):
        async with env.db.transaction() as tx:
            await revoke_install_admin_on(tx, team_id=TEAM, principal_did=env.actors["alice"].did)
            assert not await standalone_install_admin_policy(tx, subject(env), action="apps.install", app_id="fixture")
            assert await env.db.fetch_value("SELECT revoked_at IS NULL FROM {{tables.team_app_install_admins}}")
            raise RuntimeError("revoke rolls back")
    assert await permitted(env)
    assert await env.db.fetch_value("SELECT count(*) FROM {{tables.app_install_admin_audit}}") == 1


async def test_admin_authority_is_held_until_the_install_transaction_ends(standalone):
    env, _ = standalone
    await grant(env)
    async def revoke():
        async with env.db.transaction() as tx:
            return await revoke_install_admin_on(tx, team_id=TEAM, principal_did=env.actors["alice"].did)
    async with env.db.transaction() as tx:
        assert await standalone_install_admin_policy(tx, subject(env), action="apps.install", app_id="fixture")
        revoking = asyncio.create_task(revoke())
        try:
            await asyncio.sleep(0.05)
            assert not revoking.done()
        except BaseException:
            revoking.cancel()
            await asyncio.gather(revoking, return_exceptions=True)
            raise
    assert await asyncio.wait_for(revoking, 5)
    assert not await permitted(env)


async def test_last_owner_cannot_be_revoked_or_demoted_without_force(standalone):
    env, _ = standalone
    await grant(env, role="owner")
    for action in ("revoke", "demote"):
        with pytest.raises(InstallAdminGrantError) as refused:
            async with env.db.transaction() as tx:
                if action == "revoke":
                    await revoke_install_admin_on(tx, team_id=TEAM, principal_did=env.actors["alice"].did)
                else:
                    await grant_install_admin_on(tx, team_id=TEAM, principal_did=env.actors["alice"].did, role="admin")
        assert refused.value.code == "last_owner"
    assert await permitted(env)
    async with env.db.transaction() as tx:
        assert await revoke_install_admin_on(tx, team_id=TEAM, principal_did=env.actors["alice"].did, force=True)
    assert not await permitted(env)
    assert await env.db.fetch_value("SELECT forced FROM {{tables.app_install_admin_audit}} WHERE action='revoke'") is True


async def test_host_policy_denial_is_final_even_with_a_local_owner_grant(standalone):
    env, pin = standalone
    await grant(env, role="owner")
    async def deny(tx, subject, **kwargs):
        return False
    env.app.state.install_admin_policy = deny
    response = await _team_request(env, "alice", "POST", "/v1/apps/install", pin)
    assert response.status_code == 403, response.text
    async def allow(tx, subject, **kwargs):
        return True
    env.app.state.install_admin_policy = allow
    response = await _team_request(env, "bob", "POST", "/v1/apps/install", pin)
    assert response.status_code == 200, response.text  # Bob has no local grant.


async def test_local_operator_cli_grant_list_revoke_and_forced_last_owner(standalone):
    env, _ = standalone
    process_env = {**os.environ, "AWEB_DATABASE_URL": env.db.config.get_dsn()}
    async def cli(*args):
        process = await asyncio.create_subprocess_exec(
            sys.executable, "-c", "from aweb.cli import app; app()", "install-admin", *args,
            env=process_env, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        out, error = await asyncio.wait_for(process.communicate(), 20)
        return process.returncode, out.decode(), error.decode()
    selector = ("--team-id", TEAM, "--principal-did", env.actors["alice"].did)
    code, out, error = await cli("grant", *selector, "--role", "owner")
    assert code == 0, error
    assert json.loads(out)["role"] == "owner"
    code, out, error = await cli("list", "--team-id", TEAM)
    assert code == 0 and json.loads(out)[0]["principal_did"] == env.actors["alice"].did, error
    code, _, error = await cli("revoke", *selector)
    assert code != 0 and "last_owner" in error
    code, out, error = await cli("revoke", *selector, "--force")
    assert code == 0 and json.loads(out)["revoked"], error
    assert not await permitted(env)
    assert await env.db.fetch_value("SELECT count(*) FROM {{tables.app_install_admin_audit}}") == 2

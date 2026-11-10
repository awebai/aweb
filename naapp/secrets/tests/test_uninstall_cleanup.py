"""Sensitive installation state leaves through the real fenced retirement hook."""

import json
import secrets
from uuid import uuid4

import asyncpg
import pytest
from aweb_naapp.roles import PrincipalKey

from aweb_secrets.app import installation_fence
from aweb_secrets.custody import encode_value
from aweb_secrets.owners import owner_scope, record_owner
from tests.test_change_sets import ALICE, enrol_owner
from tests.test_change_sets import world as world
from tests.test_console_changes import clients, sign_in, token_draft
from tests.test_reinstall import TeamServer, _grant


async def staged(world):
    scope = await enrol_owner(world, ALICE, "alice@acme.com")
    async with clients(world) as (human, _):
        headers = await sign_in(world, human, scope)
        await token_draft(world, human, headers)
    assert await world.db.fetch_value("SELECT count(*) FROM {{tables.sealed_versions}}") > 0
    assert await world.db.fetch_value("SELECT count(*) FROM {{tables.passkey_credentials}}") > 0
    authority = TeamServer()
    authority.grant = _grant(
        world.admitted.installation_id, world.admitted.generation, world.admitted.team_id
    )
    fence = installation_fence(world.db, app_id="secrets", grants=authority)
    return fence, authority


@pytest.mark.parametrize("retirement", ["uninstall", "replacement"])
async def test_confirmed_uninstall_purges_sealed_credentials_and_passkeys_with_audit(
    world, retirement
):
    fence, authority = await staged(world)
    if retirement == "uninstall":
        authority.state = "uninstalled"
    else:
        authority.grant = _grant("replacement-installation", 2, world.admitted.team_id)
    await fence.refresh(world.admitted.team_id)
    assert await world.db.fetch_value("SELECT count(*) FROM {{tables.sealed_versions}}") == 0
    assert await world.db.fetch_value("SELECT count(*) FROM {{tables.passkey_credentials}}") == 0
    assert await world.db.fetch_value("SELECT count(*) FROM {{tables.console_sessions}}") == 0
    events = await world.db.fetch_all("SELECT * FROM {{tables.installation_retirement_events}}")
    assert len(events) == 1
    assert events[0]["team_id"] == world.admitted.team_id
    assert events[0]["installation_id"] == world.admitted.installation_id
    destroyed = json.loads(events[0]["destroyed"])
    assert destroyed["sealed_versions"] > 0
    assert destroyed["passkey_credentials"] > 0
    assert all(type(count) is int for count in destroyed.values())
    # Repeated observations do not duplicate an installation retirement receipt.
    await fence.refresh(world.admitted.team_id)
    assert (
        await world.db.fetch_value("SELECT count(*) FROM {{tables.installation_retirement_events}}")
        == 1
    )


@pytest.mark.parametrize("state", ["pending", "unknown", "disabled"])
async def test_unconfirmed_retirement_retains_credential_material(world, state):
    fence, authority = await staged(world)
    authority.state = state
    await fence.refresh(world.admitted.team_id)
    assert await world.db.fetch_value("SELECT count(*) FROM {{tables.sealed_versions}}") > 0
    assert await world.db.fetch_value("SELECT count(*) FROM {{tables.passkey_credentials}}") > 0
    assert (
        await world.db.fetch_value("SELECT count(*) FROM {{tables.installation_retirement_events}}")
        == 0
    )


async def test_retirement_receipt_failure_rolls_back_credential_destruction(world):
    fence, authority = await staged(world)
    await world.db.execute(
        "ALTER TABLE {{tables.installation_retirement_events}}"
        " ADD CONSTRAINT refuse_receipt CHECK (false) NOT VALID"
    )
    authority.state = "uninstalled"
    with pytest.raises(asyncpg.CheckViolationError):
        await fence.refresh(world.admitted.team_id)
    assert await world.db.fetch_value("SELECT count(*) FROM {{tables.sealed_versions}}") > 0
    assert await world.db.fetch_value("SELECT count(*) FROM {{tables.passkey_credentials}}") > 0
    assert (
        await world.db.fetch_value("SELECT count(*) FROM {{tables.retired_installation_fences}}")
        == 0
    )


async def test_retirement_keeps_another_installations_sealed_value_and_passkey(world):
    fence, authority = await staged(world)
    other = PrincipalKey(team_id="other:example.com", principal_did=ALICE.principal_did)
    scope = owner_scope("other-installation", other.team_id, other.principal_did)
    subject = str(uuid4())
    credential_id = secrets.token_bytes(32)
    async with world.db.transaction() as tx:
        await world.custody.stage_backend_credential(
            tx,
            installation_id="other-installation",
            team_id=other.team_id,
            value=encode_value("bearer", {"value": secrets.token_urlsafe(32)}),
        )
        await record_owner(tx, installation_id="other-installation", principal=other)
        # An unrelated stored credential, copied from the real enrolled key's
        # valid public material. It is fixture state, never used to authenticate.
        await tx.execute(
            "INSERT INTO {{tables.passkey_approvers}}"
            " (subject,scope,contact,designated_by,designated_at,effective_at)"
            " SELECT $1,$2,contact,designated_by,designated_at,effective_at"
            " FROM {{tables.passkey_approvers}} LIMIT 1",
            subject,
            scope,
        )
        await tx.execute(
            "INSERT INTO {{tables.passkey_credentials}}"
            " (credential_id,subject,public_key,sign_count,created_at)"
            " SELECT $1,$2,public_key,sign_count,created_at FROM {{tables.passkey_credentials}} LIMIT 1",
            credential_id,
            subject,
        )
    authority.state = "uninstalled"
    await fence.refresh(world.admitted.team_id)
    assert await world.db.fetch_value("SELECT count(*) FROM {{tables.sealed_versions}}") == 1
    assert (
        await world.db.fetch_value(
            "SELECT 1 FROM {{tables.passkey_credentials}} WHERE credential_id=$1", credential_id
        )
        == 1
    )
    assert await world.db.fetch_value("SELECT count(*) FROM {{tables.passkey_credentials}}") == 1

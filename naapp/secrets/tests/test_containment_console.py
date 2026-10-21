"""Console authority uses enrolled passkeys and live scoped records in PostgreSQL."""

from datetime import UTC, datetime, timedelta

import pytest
from aweb_naapp.console import ConsoleSession

from aweb_secrets.containment import ContainmentRefused
from aweb_secrets.owners import approver_scope
from tests.test_change_sets import TEAM, world  # noqa: F401
from tests.test_containment_service import service
from tests.test_use_approval_lineage import child, seed
from tests.test_use_approvals import SECRET_ID
from tests.test_use_approvals import uses as _uses

uses = _uses


async def finance_session(context):
    w = context.world
    scope = approver_scope(w.admitted.installation_id, TEAM, "finance")
    logged_in = await w.passkeys.verify_login(
        scope,
        w.devices["finance@acme.com"].get(await w.passkeys.login_options(scope)),
    )
    return ConsoleSession(
        subject=logged_in.subject,
        scope=scope,
        evidence_ref=logged_in.evidence_ref,
        expires_at=datetime.now(UTC) + timedelta(minutes=15),
        token_sha256=b"",
    )


async def authorize(svc, context, session, action, target=None):
    async with context.world.db.transaction() as tx:
        await context.world.fence.admit(tx, context.grant)
        return await svc.authorize_console(
            tx,
            admitted=context.world.admitted,
            session=session,
            action=action,
            target=target,
        )


async def test_approver_covers_descendants_but_cannot_kill_installation(uses):
    await seed(uses)
    svc = await service(uses)
    first, _ = await child(uses)
    session = await finance_session(uses)
    assert not await authorize(svc, uses, session, "disable-secret", first.secret_id)
    with pytest.raises(ContainmentRefused) as refused:
        await authorize(svc, uses, session, "disable-installation")
    assert refused.value.code == "owner_required"
    with pytest.raises(ContainmentRefused) as refused:
        await authorize(svc, uses, session, "deregister-runner", "runner-1")
    assert refused.value.code == "owner_required"


@pytest.mark.parametrize("covered", [False, True])
async def test_current_coverage_is_required_at_action_time(uses, covered):
    await seed(uses)
    svc = await service(uses)
    session = await finance_session(uses)
    async with uses.world.db.transaction() as tx:
        await tx.execute(
            "UPDATE {{tables.approvers}} SET covers=$1::jsonb WHERE approver_ref='finance'",
            '["sec_19ab42"]' if covered else "[]",
        )
    if covered:
        assert not await authorize(svc, uses, session, "disable-secret", SECRET_ID)
    else:
        with pytest.raises(ContainmentRefused) as refused:
            await authorize(svc, uses, session, "disable-secret", SECRET_ID)
        assert refused.value.code == "coverage_denied"


async def test_approver_credential_target_is_self_only(uses):
    await seed(uses)
    svc = await service(uses)
    session = await finance_session(uses)
    assert not await authorize(svc, uses, session, "revoke-approver", "finance")
    with pytest.raises(ContainmentRefused):
        await authorize(svc, uses, session, "revoke-approver", "other-approver")


async def test_same_team_owner_scope_of_another_installation_is_refused(uses):
    from dataclasses import replace

    await seed(uses)
    svc = await service(uses)
    session = await finance_session(uses)
    async with uses.world.db.transaction() as tx:
        await uses.world.fence.admit(tx, uses.grant)
        with pytest.raises(ContainmentRefused):
            await svc.authorize_console(
                tx,
                admitted=replace(uses.world.admitted, installation_id="other-installation"),
                session=session,
                action="disable-secret",
                target=SECRET_ID,
            )


async def test_designated_approver_can_open_the_shared_s4_console_session(uses):
    from tests.test_console import clients

    await seed(uses)
    scope = approver_scope(uses.world.admitted.installation_id, TEAM, "finance")
    async with clients(uses.world) as (human, _):
        options = await human.post("/login/options", json={"scope": scope})
        assert options.status_code == 200
        logged_in = await human.post(
            "/login",
            json={
                "scope": scope,
                "assertion": uses.world.devices["finance@acme.com"].get(options.json()),
            },
        )
        assert logged_in.status_code == 200
        assert (await human.get("/session")).json()["scope"] == scope

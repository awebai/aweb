"""Owner actions share real team roles, PostgreSQL, custody and hook outbox."""

import os
from datetime import UTC, datetime, timedelta
from functools import partial

import pytest
from aweb_naapp.hooks.envelope import verify
from aweb_naapp.hooks.producer import HookProducer, ServerProducer
from aweb_naapp.outbox import apply_outbox_migrations
from aweb_naapp.roles import assign, principal_key
from aweb_naapp_testing.owner_acts import INSTALLATION_ID

from aweb_secrets.containment import Containment, ContainmentRefused
from aweb_secrets.owners import OWNER_ROLE
from aweb_secrets.tokens import ProcessTokenCache, TokenKey
from tests.test_change_sets import TEAM, world  # noqa: F401
from tests.test_use_approval_lineage import child, seed
from tests.test_use_approvals import REQUESTER, SECRET_ID
from tests.test_use_approvals import uses as _uses

uses = _uses


async def service(uses):  # noqa: F811
    w = uses.world
    await apply_outbox_migrations(w.db)
    async with w.db.transaction() as tx:
        await assign(tx, principal_key(REQUESTER), OWNER_ROLE)
    producer = HookProducer(
        ServerProducer.app(
            origin="https://api.secrets.example.com",
            app_id="secrets",
            installation_id=INSTALLATION_ID,
            generation=1,
            kid="test-key",
            seed=os.urandom(32),
        )
    )
    tokens = ProcessTokenCache()
    return Containment(
        db=w.db,
        fence=w.fence,
        approvals=uses.approvals,
        custody=w.custody,
        passkeys=w.passkeys,
        directory=w.directory,
        tokens=tokens,
        governance=partial(producer.enqueue, hook="post-governance-hook"),
    )


async def act(svc, uses, action="disable-secret", target=SECRET_ID, request_id="contain-1"):  # noqa: F811
    return await svc.by_member(
        grant=uses.grant,
        principal=REQUESTER,
        request_id=request_id,
        action=action,
        target=target,
    )


@pytest.mark.parametrize("stalled", [False, True])
async def test_team_auth_containment_succeeds_without_audit_target_and_with_stalled_delivery(
    uses, stalled
):  # noqa: F811
    await seed(uses)
    svc = await service(uses)
    if stalled:
        await act(svc, uses, "disable-installation", None, "earlier-event")
        event_id = await uses.world.db.fetch_value("SELECT event_id FROM {{tables.outbox_events}}")
        await uses.world.db.execute(
            "INSERT INTO {{tables.outbox_deliveries}} (event_id,target_id,state,attempts)"
            " VALUES ($1,'stalled-target','stalled',40)",
            event_id,
        )
    first, _ = await child(uses)
    result = await act(svc, uses)
    assert set(result.affected_secret_ids) == {SECRET_ID, first.secret_id}
    rows = await uses.world.db.fetch_all(
        "SELECT payload,signature FROM {{tables.outbox_events}} ORDER BY position"
    )
    envelope = verify(bytes(rows[-1]["payload"]), rows[-1]["signature"], team_id=TEAM)
    assert envelope.fields["payload"]["act"] == "resource.disabled"
    assert envelope.fields["payload"]["direction"] == "narrowing"
    assert envelope.fields["payload"]["authority"] == "team_cert"


async def test_role_and_team_are_checked_before_containment(uses):  # noqa: F811
    from dataclasses import replace

    from aweb_naapp.roles import unassign

    await seed(uses)
    svc = await service(uses)
    async with uses.world.db.transaction() as tx:
        await unassign(tx, principal_key(REQUESTER), OWNER_ROLE)
    with pytest.raises(ContainmentRefused) as refused:
        await act(svc, uses)
    assert refused.value.code == "owner_required"
    with pytest.raises(ContainmentRefused) as refused:
        await svc.by_member(
            grant=uses.grant,
            principal=replace(REQUESTER, team_id="other:example.com"),
            request_id="bad-team",
            action="disable-secret",
            target=SECRET_ID,
        )
    assert refused.value.code == "owner_required"
    assert (
        await uses.world.db.fetch_value(
            "SELECT state FROM {{tables.secrets}} WHERE secret_id=$1", SECRET_ID
        )
        == "active"
    )
    assert await uses.world.db.fetch_value("SELECT count(*) FROM {{tables.outbox_events}}") == 0


async def test_receipt_replays_without_duplicate_event_and_conflicting_id_refuses(uses):  # noqa: F811
    await seed(uses)
    svc = await service(uses)
    first = await act(svc, uses)
    assert await act(svc, uses) == first
    assert await uses.world.db.fetch_value("SELECT count(*) FROM {{tables.outbox_events}}") == 1
    with pytest.raises(ContainmentRefused) as refused:
        await act(svc, uses, "disable-installation", None)
    assert refused.value.code == "idempotency_conflict"


@pytest.mark.parametrize("action", ["disable-secret", "disable-installation"])
async def test_successful_commit_evicts_all_cached_versions(uses, action):  # noqa: F811
    await seed(uses)
    svc = await service(uses)
    keys = [
        TokenKey(INSTALLATION_ID, TEAM, SECRET_ID, version, "https://api.example.com/token", "")
        for version in (3, 4)
    ]
    for key in keys:
        await svc.tokens.put(key, os.urandom(24).hex(), datetime.now(UTC) + timedelta(hours=1))
    await act(svc, uses, action, SECRET_ID if action == "disable-secret" else None)
    assert all([await svc.tokens.get(key) is None for key in keys])


async def test_reenable_is_not_a_team_auth_containment_action(uses):  # noqa: F811
    await seed(uses)
    svc = await service(uses)
    await act(svc, uses)
    with pytest.raises(ContainmentRefused) as refused:
        await act(svc, uses, "reenable", SECRET_ID, "enable-1")
    assert refused.value.code == "containment_action_invalid"


async def test_approval_revoke_is_scoped_and_stops_consumption(uses):  # noqa: F811
    from aweb_naapp.runtime.approvals import ApprovalState

    from tests.test_use_approval_lineage import admit, request_child
    from tests.test_use_approvals import approve

    await seed(uses)
    first, _ = await child(uses)
    admission, dispatch_id, pending = await request_child(uses, first)
    await approve(uses, pending, "finance@acme.com")
    svc = await service(uses)
    approval_id = pending.pending.approval.approval_id
    await act(svc, uses, "revoke-approvals", approval_id)
    assert (await uses.approvals.get(approval_id)).state == ApprovalState.REVOKED
    assert (await admit(uses, admission, dispatch_id)).refusal == "approval_revoked"
    with pytest.raises(ContainmentRefused) as refused:
        await act(svc, uses, "revoke-approvals", "another-installations-approval", "other")
    assert refused.value.code == "approval_unknown"


async def test_confirmed_reenable_restores_only_named_root(uses):  # noqa: F811
    from aweb_secrets.custody import CustodyUnavailable
    from tests.test_containment import seal

    await seed(uses)
    svc = await service(uses)
    first, _ = await child(uses)
    root_context = await seal(uses, SECRET_ID)
    child_context = await seal(uses, first.secret_id)
    await act(svc, uses)
    async with uses.world.db.transaction() as tx:
        await uses.world.fence.admit(tx, uses.grant)
        await svc.prepare_replacements(
            tx,
            installation_id=INSTALLATION_ID,
            team_id=TEAM,
            secret_ids=(SECRET_ID,),
        )
        await svc.reenable(
            tx,
            installation_id=INSTALLATION_ID,
            team_id=TEAM,
            target_kind="secret",
            target_ref="staging-api",
        )
    assert await uses.world.custody.opener.open(root_context) is not None
    with pytest.raises(CustodyUnavailable):
        await uses.world.custody.opener.open(child_context)
    assert (
        await uses.world.db.fetch_value(
            "SELECT state FROM {{tables.secrets}} WHERE secret_id=$1",
            first.secret_id,
        )
        == "disabled"
    )

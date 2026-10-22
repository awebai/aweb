"""Confirmed empty-root recovery never restores an invalidated value or child."""

from datetime import timedelta

import pytest
from aweb_naapp.roles import hold_role, principal_key
from aweb_naapp_testing.owner_acts import INSTALLATION_ID

from aweb_secrets import records
from aweb_secrets.admission import AdmissionRefused, admit_use
from aweb_secrets.containment import ContainmentRefused
from aweb_secrets.custody import CustodyUnavailable
from aweb_secrets.owners import OWNER_ROLE
from tests.test_change_sets import TEAM, world  # noqa: F401
from tests.test_containment import seal
from tests.test_containment_service import act, service
from tests.test_use_approval_lineage import child, seed
from tests.test_use_approvals import REQUESTER, SECRET_ID, use_request
from tests.test_use_approvals import uses as _uses

uses = _uses


async def recover(uses, svc, secret_id, ref, *, rollback=False):
    async with uses.world.db.transaction() as tx:
        await uses.world.fence.admit(tx, uses.grant)
        assert await hold_role(tx, principal_key(REQUESTER), OWNER_ROLE)
        await svc.prepare_replacements(
            tx, installation_id=INSTALLATION_ID, team_id=TEAM, secret_ids=(secret_id,)
        )
        await svc.reenable(
            tx,
            installation_id=INSTALLATION_ID,
            team_id=TEAM,
            target_kind="secret",
            target_ref=ref,
        )
        if rollback:
            raise RuntimeError("abort confirmation")


@pytest.mark.parametrize("previous_value", [False, True])
@pytest.mark.parametrize("rollback", [False, True])
async def test_confirmed_empty_root_can_restage_without_resurrecting_value_or_children(
    uses, previous_value, rollback
):  # noqa: F811
    await seed(uses)
    svc = await service(uses)
    descendant, _ = await child(uses)
    child_context = await seal(uses, descendant.secret_id)
    old = await seal(uses, SECRET_ID) if previous_value else None
    if old is None:
        async with uses.world.db.transaction() as tx:
            root = await records.secret_by_ref(tx, INSTALLATION_ID, TEAM, "staging-api")
            assert await uses.world.custody.bind_shape(
                tx, installation_id=INSTALLATION_ID, team_id=TEAM, record=root.record
            )
    await act(svc, uses)
    async with uses.world.db.transaction() as tx:
        await tx.execute(
            "UPDATE {{tables.secrets}} SET active_version=NULL WHERE secret_id=$1", SECRET_ID
        )
        if old is not None:
            await uses.world.custody.destroy(tx, old)
    # Disabled custody must still refuse staging before confirmed recovery.
    with pytest.raises(CustodyUnavailable):
        await seal(uses, SECRET_ID)
    if rollback:
        with pytest.raises(RuntimeError, match="abort confirmation"):
            await recover(uses, svc, SECRET_ID, "staging-api", rollback=True)
    else:
        await recover(uses, svc, SECRET_ID, "staging-api")
    async with uses.world.db.transaction() as tx:
        root = await records.secret_by_ref(tx, INSTALLATION_ID, TEAM, "staging-api")
        assert root.state == ("disabled" if rollback else "active")
        assert root.active_version is None
        below = await records.secret_by_ref(tx, INSTALLATION_ID, TEAM, descendant.ref)
        assert below.state == "disabled"
    if old is not None:
        with pytest.raises(CustodyUnavailable):
            await uses.world.custody.opener.open(old)
    with pytest.raises(CustodyUnavailable):
        await uses.world.custody.opener.open(child_context)
    if rollback:
        with pytest.raises(CustodyUnavailable):
            await seal(uses, SECRET_ID)
        return
    # Recovery permits a new draft; it neither activates it nor admits use.
    staged = await seal(uses, SECRET_ID)
    if old is not None:
        assert staged.version > old.version
    with pytest.raises(AdmissionRefused) as refused:
        async with uses.world.db.transaction() as tx:
            await admit_use(
                tx,
                fence=uses.world.fence,
                grant=uses.grant,
                principal=REQUESTER,
                request=use_request("empty-root-after-recovery"),
                attestation=None,
                now=uses.clock(),
                clock=uses.clock,
            )
    assert refused.value.code == "secret_disabled"
    assert (
        await uses.world.db.fetch_value(
            "SELECT active_version FROM {{tables.secrets}} WHERE secret_id=$1", SECRET_ID
        )
        is None
    )


@pytest.mark.parametrize("broken", ["empty", "parent_version", "expired", "grant_revoked"])
async def test_derived_reenable_keeps_full_ancestry_checks_and_rolls_back(uses, broken):  # noqa: F811
    await seed(uses)
    svc = await service(uses)
    now = uses.clock.now
    if broken == "expired":
        uses.clock.now -= timedelta(hours=1)
    derived, _ = await child(uses)
    uses.clock.now = now
    context = await seal(uses, derived.secret_id)
    await act(svc, uses, target=derived.secret_id)
    async with uses.world.db.transaction() as tx:
        if broken == "empty":
            await tx.execute(
                "UPDATE {{tables.secrets}} SET active_version=NULL WHERE secret_id=$1",
                derived.secret_id,
            )
        elif broken == "parent_version":
            await records.set_active_version(tx, INSTALLATION_ID, TEAM, SECRET_ID, 5)
        elif broken == "grant_revoked":
            await tx.execute(
                "UPDATE {{tables.grants}} SET revoked_at=NOW() WHERE grant_id="
                "(SELECT source_grant_id FROM {{tables.derived_secrets}} WHERE secret_id=$1)",
                derived.secret_id,
            )
    with pytest.raises(ContainmentRefused):
        await recover(uses, svc, derived.secret_id, derived.ref)
    assert (
        await uses.world.db.fetch_value(
            "SELECT state FROM {{tables.secrets}} WHERE secret_id=$1", derived.secret_id
        )
        == "disabled"
    )
    with pytest.raises(CustodyUnavailable):
        await uses.world.custody.opener.open(context)
    with pytest.raises(CustodyUnavailable):
        await seal(uses, derived.secret_id)

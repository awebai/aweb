"""Containment setup and its owner actor follow the real holder lifecycle."""

import pytest

from aweb_secrets.containment import ContainmentRefused
from aweb_secrets.owners import has_owner
from tests.test_change_sets import ALICE, Installations, enrol_owner
from tests.test_change_sets import world as world
from tests.test_containment_service import act, service
from tests.test_use_approval_lineage import seed
from tests.test_use_approvals import REQUESTER, SECRET_ID, Clock, Uses
from tests.test_use_approvals import uses as uses


async def test_browser_containment_is_composed_before_its_holder_is_designated(world):
    context = Uses(world, world.approvals, Clock(), Installations().grant)
    assert not await has_owner(world.db, ALICE, installation_id=world.admitted.installation_id)
    before = await world.db.fetch_value("SELECT count(*) FROM {{tables.role_holdings}}")
    await service(context)
    assert await world.db.fetch_value("SELECT count(*) FROM {{tables.role_holdings}}") == before
    await enrol_owner(world, ALICE, "alice@acme.com")
    assert await has_owner(world.db, ALICE, installation_id=world.admitted.installation_id)


async def test_use_requester_does_not_inherit_the_containment_owners_authority(uses):
    await seed(uses)
    svc = await service(uses)
    before = await uses.world.db.fetch_value("SELECT count(*) FROM {{tables.outbox_events}}")
    with pytest.raises(ContainmentRefused) as refused:
        await svc.by_member(
            grant=uses.grant,
            principal=REQUESTER,
            request_id="requester-is-not-owner",
            action="disable-secret",
            target=SECRET_ID,
        )
    assert refused.value.code == "owner_required"
    assert (
        await uses.world.db.fetch_value("SELECT count(*) FROM {{tables.outbox_events}}") == before
    )
    await act(svc, uses)
    assert (
        await uses.world.db.fetch_value(
            "SELECT state FROM {{tables.secrets}} WHERE secret_id=$1", SECRET_ID
        )
        == "disabled"
    )

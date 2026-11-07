"""Activity names each agent with the shared escaped principal display."""

from dataclasses import replace
from datetime import UTC, datetime

from aweb_naapp.hooks.commitment import CommitmentContext
from aweb_naapp_testing.owner_acts import INSTALLATION_ID

from aweb_secrets.broker_audit import record_broker_refusal
from aweb_secrets.use_context import UseCommitments
from tests.test_broker_audit import source
from tests.test_change_sets import ALICE, TEAM, enrol_owner
from tests.test_console_activity import clients
from tests.test_console_activity import world as _world
from tests.test_console_changes import sign_in
from tests.test_use_approvals import REQUESTER

world = _world


async def refused_as(w, principal):
    async with w.db.transaction() as tx:
        await record_broker_refusal(
            tx,
            producer=source(INSTALLATION_ID, 1),
            principal=principal,
            commitments=UseCommitments(
                CommitmentContext("secrets", TEAM, INSTALLATION_ID, 1, "request"), None, None
            ),
            code="grant_missing",
            occurred_at=datetime.now(UTC),
        )


async def test_activity_shows_the_recorded_name_in_its_team_beside_the_did(world):
    scope = await enrol_owner(world, ALICE, "alice@acme.com")
    named = replace(REQUESTER, alias="ops-bot", did_aw_registry_verified=True)
    async with clients(world) as (human, _):
        await sign_in(world, human, scope)
        await refused_as(world, named)
        page = (await human.get("/activity")).text
    assert '<span class="principal-name">ops-bot</span>' in page
    assert f'<span class="principal-team">{TEAM}</span>' in page
    assert f'<code class="principal-did">{REQUESTER.did_aw}</code>' in page


async def test_activity_shows_only_the_did_when_the_name_is_not_bound_to_it(world):
    scope = await enrol_owner(world, ALICE, "alice@acme.com")
    async with clients(world) as (human, _):
        await sign_in(world, human, scope)
        # An unverified did:aw is not carried in the actor, so its alias names nothing.
        await refused_as(world, REQUESTER)
        page = (await human.get("/activity")).text
    assert f'<code class="principal-did">{REQUESTER.did_aw}</code>' in page
    assert 'class="principal-name"' not in page

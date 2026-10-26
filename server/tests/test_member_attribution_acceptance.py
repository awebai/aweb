"""Caller-owned acceptance and host policy on real PostgreSQL transactions."""
from __future__ import annotations

import asyncio
from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest
import pytest_asyncio

from aweb.member_attribution import (
    AttributionAcceptanceContext, AttributionError, LocalControllerSigner,
    MemberReference, ValidatedHuman, accept_member_attribution,
)
from aweb.routes.connect import connect_agent
from test_messages_http import _build_test_app, _insert_agent, _insert_team, _make_keypair


@pytest_asyncio.fixture
async def attribution_env(aweb_cloud_db):
    db = aweb_cloud_db.aweb_db
    team = "attribution:example.test"
    seed, _, team_key = _make_keypair()
    await _insert_team(db, team)
    await db.execute("UPDATE {{tables.teams}} SET team_did_key=$1 WHERE team_id=$2", team_key, team)
    members = []
    for alias in ("parent", "child"):
        _, _, member_key = _make_keypair()
        agent_id = await _insert_agent(db, team_id=team, alias=alias, did_key=member_key, did_aw=None, address=None)
        certificate_id = str(uuid4())
        await db.execute("UPDATE {{tables.agents}} SET certificate_id=$1,identity_scope='local' WHERE agent_id=$2", certificate_id, UUID(agent_id))
        members.append(MemberReference(team_id=team, agent_id=agent_id, certificate_id=certificate_id, member_did_key=member_key))
    now = datetime.now(UTC).replace(microsecond=0)
    await db.execute("UPDATE {{tables.agents}} SET created_at=$1 WHERE team_id=$2", now - timedelta(minutes=2), team)
    return SimpleNamespace(
        db=db, infra=_build_test_app(db, None).state.db, parent=members[0], child=members[1],
        signer=LocalControllerSigner(seed, root_member_did_key=members[0].member_did_key),
        human=ValidatedHuman(" Alice@EXAMPLE.test ", "email", now - timedelta(seconds=1)),
    )


async def accept(env, tx, member=None, event="birth", **kwargs):
    return await accept_member_attribution(
        env.infra, tx.connection, member=member or env.parent, event=event,
        signer=env.signer, **kwargs,
    )


@pytest.mark.asyncio
async def test_fresh_none_and_observed_unknown_are_distinct(attribution_env):
    env = attribution_env
    async with env.db.transaction() as tx:
        unknown = await accept(env, tx, event="observe")
        assert unknown.publications == ()
        born = await accept(env, tx)
        assert born.publications[0].record["human"] is None
        assert born.publications[0].record["how"] == "none"
        assert await env.db.fetch_value("SELECT count(*) FROM {{tables.member_attributions}}") == 0
    assert await env.db.fetch_value("SELECT count(*) FROM {{tables.member_attributions}}") == 1


@pytest.mark.asyncio
async def test_claim_and_spawn_use_private_email_but_publish_only_the_fingerprint(attribution_env):
    env = attribution_env
    async with env.db.transaction() as tx:
        await accept(env, tx, event="claim", validated_human=env.human)
        result = await accept(env, tx, member=env.child, event="spawn", parent=env.parent)
        record = result.publications[0].record
        assert set(record["human"]) == {"domain", "fingerprint"}
        assert record["human"]["domain"] == "example.test"
        assert record["parent"] == {"certificate_id": env.parent.certificate_id, "member_did_key": env.parent.member_did_key}
        assert record["how"] == "inherited"
    rows = await env.db.fetch_all("SELECT human_email,record_json,published_at FROM {{tables.member_attributions}}")
    assert len(rows) == 2
    assert all(row["human_email"] == "alice@example.test" for row in rows)
    assert all("alice@" not in row["record_json"] and row["published_at"] is None for row in rows)


@pytest.mark.asyncio
async def test_host_rollback_removes_acceptance_and_publication_intent(attribution_env):
    env = attribution_env
    with pytest.raises(RuntimeError):
        async with env.db.transaction() as tx:
            await accept(env, tx, event="claim", validated_human=env.human)
            await tx.execute("SELECT 1")
            raise RuntimeError("host rollback")
    assert await env.db.fetch_value("SELECT count(*) FROM {{tables.member_attributions}}") == 0


@pytest.mark.asyncio
async def test_fresh_child_can_be_inserted_after_the_human_policy_on_the_same_transaction(attribution_env):
    env = attribution_env
    child = MemberReference(team_id=env.parent.team_id, certificate_id=str(uuid4()), member_did_key=_make_keypair()[2])
    checked = []
    async def policy(context, connection):
        checked.append(context)
        assert await connection.fetchval("SELECT count(*) FROM aweb.agents WHERE certificate_id=$1", child.certificate_id) == 0
    async with env.db.transaction() as tx:
        await accept(env, tx, event="claim", validated_human=env.human)
        result = await accept(env, tx, member=child, event="spawn", parent=env.parent, lock_human_policy=policy)
        connected = await connect_agent(
            db=tx, cert_info={"team_id": child.team_id, "did_key": child.member_did_key,
                              "certificate_id": child.certificate_id, "alias": "new-child", "identity_scope": "local"},
            team_did_key=env.signer.team_did_key, hostname="", workspace_path="", repo_origin="",
            role="", human_name="", agent_type="agent",
        )
    assert len(checked) == 1
    assert result.publications[0].record["parent"]["member_did_key"] == env.parent.member_did_key
    assert await env.db.fetch_value("SELECT count(*) FROM {{tables.member_attributions}}") == 2
    assert str(await env.db.fetch_value(
        "SELECT agent_id FROM {{tables.member_attributions}} WHERE certificate_id=$1", child.certificate_id,
    )) == connected["agent_id"]


@pytest.mark.asyncio
async def test_claim_is_monotonic_and_retry_does_not_rewrite_provenance(attribution_env):
    env = attribution_env
    async with env.db.transaction() as tx:
        first = await accept(env, tx, event="claim", validated_human=env.human)
        retry = await accept(env, tx, event="claim", validated_human=env.human)
        assert retry == first
    with pytest.raises(AttributionError):
        async with env.db.transaction() as tx:
            await accept(env, tx, event="claim", validated_human=replace(env.human, email="other@example.test"))
    async with env.db.transaction() as tx:
        reused = await accept(env, tx, event="observe")
        assert reused == first


@pytest.mark.asyncio
async def test_host_policy_sees_the_parent_epoch_once_and_can_refuse_before_any_write(attribution_env):
    env = attribution_env
    async with env.db.transaction() as tx:
        await accept(env, tx, event="claim", validated_human=env.human)
    seen = []
    class DepartedHuman(Exception):
        pass
    async def policy(context, connection):
        assert isinstance(context, AttributionAcceptanceContext)
        assert connection.is_in_transaction()
        assert context.parent == env.parent
        assert context.human_email == "alice@example.test"
        assert context.source_since == env.human.accepted_at
        with pytest.raises(FrozenInstanceError):
            context.human_email = "other@example.test"
        seen.append(connection)
        raise DepartedHuman()
    with pytest.raises(DepartedHuman):
        async with env.db.transaction() as tx:
            await accept(env, tx, member=env.child, event="spawn", parent=env.parent, lock_human_policy=policy)
    assert len(seen) == 1
    assert await env.db.fetch_value("SELECT count(*) FROM {{tables.member_attributions}}") == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["key", "certificate", "retired", "deleted"])
async def test_spawn_refuses_stale_or_inactive_parent(attribution_env, change):
    env = attribution_env
    async with env.db.transaction() as tx:
        await accept(env, tx, event="claim", validated_human=env.human)
    columns = {
        "key": ("did_key", _make_keypair()[2]), "certificate": ("certificate_id", str(uuid4())),
        "retired": ("status", "retired"), "deleted": ("deleted_at", datetime.now(UTC)),
    }
    column, value = columns[change]
    await env.db.execute("UPDATE {{tables.agents}} SET " + column + "=$1 WHERE agent_id=$2", value, UUID(env.parent.agent_id))
    with pytest.raises(AttributionError):
        async with env.db.transaction() as tx:
            await accept(env, tx, member=env.child, event="spawn", parent=env.parent)
    assert await env.db.fetch_value("SELECT count(*) FROM {{tables.member_attributions}}") == 1


@pytest.mark.asyncio
async def test_first_cohort_claim_requires_configured_root_and_covers_existing_members(attribution_env):
    env = attribution_env
    with pytest.raises(AttributionError):
        async with env.db.transaction() as tx:
            await accept(env, tx, member=env.child, event="claim", validated_human=env.human, whole_team=True)
    async with env.db.transaction() as tx:
        result = await accept(env, tx, event="claim", validated_human=env.human, whole_team=True)
        assert {item.record["certificate_id"] for item in result.publications} == {env.parent.certificate_id, env.child.certificate_id}


@pytest.mark.asyncio
async def test_policy_runs_before_waiting_for_member_row_and_locks_last_through_commit(attribution_env):
    env = attribution_env
    reached = asyncio.Event()
    async def policy(context, connection):
        reached.set()
    async def claim():
        async with env.db.transaction() as tx:
            return await accept(env, tx, event="claim", validated_human=env.human, lock_human_policy=policy)
    task = None
    try:
        async with env.db.transaction() as blocker:
            await blocker.fetch_one("SELECT agent_id FROM {{tables.agents}} WHERE agent_id=$1 FOR UPDATE", UUID(env.parent.agent_id))
            task = asyncio.create_task(claim())
            await asyncio.wait_for(reached.wait(), 5)
            assert not task.done()
        result = await asyncio.wait_for(task, 5)
        assert result.publications[0].record["human"] is not None
    finally:
        if task is not None and not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

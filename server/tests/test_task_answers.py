"""Conditional answer commits compose with a caller's real transaction."""

import asyncio
import hashlib
from dataclasses import replace
from uuid import UUID

import pytest

from aweb.coordination import tasks_service
from aweb.service_errors import ConflictError, ForbiddenError
from aweb.team_auth_deps import TeamIdentity
from test_task_human_assignment_events import _member
from test_tasks_http import TEAM_ID, _DbShim, _seed_team


async def _question(db):
    await _seed_team(db)
    member_id = await _member(db, "requester", human=True)
    await db.execute("UPDATE {{tables.agents}} SET certificate_id = 'cert-human' WHERE agent_id = $1", member_id)
    actor = TeamIdentity(team_id=TEAM_ID, alias="requester", did_key=f"did:key:{member_id}", did_aw="", address="", agent_id=str(member_id), identity_scope="local", certificate_id="cert-human")
    service = _DbShim(db)
    task = await tasks_service.create_task(service, team_id=TEAM_ID, created_by_alias="alice", title="Review app request", assignee_alias="requester")
    return service, task, actor


def _answer(task, actor, *, key="answer-1", digest=None):
    return dict(team_id=TEAM_ID, task_id=UUID(task["task_id"]), actor=actor,
                expected_task_rev=task["rev"], answer_key=key,
                answer_sha256=digest or hashlib.sha256(b"private answer").hexdigest())


async def _commit(db, **kwargs):
    async with db.transaction() as tx:
        return await tasks_service.answer_task_on(tx, **kwargs)


@pytest.mark.asyncio
async def test_answer_replay_is_immutable_and_reopen_allows_another_answer(aweb_cloud_db):
    db = aweb_cloud_db.aweb_db
    service, task, actor = await _question(db)
    first = await _commit(db, **_answer(task, actor))
    assert first["current"] is True
    assert first["question_rev"] == 1
    assert first["answered_by"] == {"principal_did": actor.did_key, "certificate_id": actor.certificate_id}
    assert await _commit(db, **_answer(task, actor)) == first
    async with db.transaction() as tx:
        assert await tasks_service.get_task_answer_on(tx, team_id=TEAM_ID, task_id=UUID(task["task_id"]), answer_key="answer-1") == first
    reopened = await tasks_service.update_task(service, team_id=TEAM_ID, ref=task["task_id"], actor_alias="alice", status="open")
    historical = await _commit(db, **_answer(task, actor))
    assert historical == {**first, "current": False}
    async with db.transaction() as tx:
        assert await tasks_service.get_task_answer_on(tx, team_id=TEAM_ID, task_id=UUID(task["task_id"]), answer_key="answer-1") == historical
    assert (await tasks_service.get_task(service, team_id=TEAM_ID, ref=task["task_id"]))["status"] == "open"
    second = await _commit(db, **_answer(reopened, actor, key="answer-2"))
    assert second["question_rev"] == 2
    assert second["receipt_id"] != first["receipt_id"]
    with pytest.raises(ConflictError, match="idempotency_conflict"):
        await _commit(db, **_answer(task, actor, digest="0" * 64))
    comments = await tasks_service.list_comments(service, team_id=TEAM_ID, ref=task["task_id"])
    assert len(comments) == 2
    assert all("private answer" not in c["body"] and "cert-human" not in c["body"] for c in comments)


@pytest.mark.asyncio
async def test_wrong_actor_and_stale_revision_have_no_effect(aweb_cloud_db):
    db = aweb_cloud_db.aweb_db
    service, task, actor = await _question(db)
    with pytest.raises(ForbiddenError, match="target_mismatch"):
        await _commit(db, **_answer(task, replace(actor, did_key="did:key:someone-else")))
    edited = await tasks_service.update_task(service, team_id=TEAM_ID, ref=task["task_id"], actor_alias="alice", notes="Changed")
    with pytest.raises(ConflictError, match="revision_conflict"):
        await _commit(db, **_answer(task, actor))
    assert (await tasks_service.get_task(service, team_id=TEAM_ID, ref=task["task_id"]))["rev"] == edited["rev"]
    assert not await tasks_service.list_comments(service, team_id=TEAM_ID, ref=task["task_id"])


@pytest.mark.asyncio
async def test_concurrent_answers_commit_one_receipt(aweb_cloud_db):
    db = aweb_cloud_db.aweb_db
    service, task, actor = await _question(db)
    results = await asyncio.gather(
        _commit(db, **_answer(task, actor, key="tab-a")),
        _commit(db, **_answer(task, actor, key="tab-b")),
        return_exceptions=True,
    )
    assert sum(isinstance(r, dict) for r in results) == 1
    assert sum(isinstance(r, ConflictError) for r in results) == 1
    assert len(await tasks_service.list_comments(service, team_id=TEAM_ID, ref=task["task_id"])) == 1


@pytest.mark.asyncio
async def test_concurrent_identical_retries_return_the_same_receipt(aweb_cloud_db):
    db = aweb_cloud_db.aweb_db
    service, task, actor = await _question(db)
    first, retry = await asyncio.gather(
        _commit(db, **_answer(task, actor)), _commit(db, **_answer(task, actor)),
    )
    assert first == retry
    assert len(await tasks_service.list_comments(service, team_id=TEAM_ID, ref=task["task_id"])) == 1


@pytest.mark.asyncio
async def test_answer_rolls_back_with_callers_delivery_transaction(aweb_cloud_db):
    db = aweb_cloud_db.aweb_db
    service, task, actor = await _question(db)
    with pytest.raises(RuntimeError, match="delivery failed"):
        async with db.transaction() as tx:
            await tasks_service.answer_task_on(tx, **_answer(task, actor))
            raise RuntimeError("delivery failed")
    read = await tasks_service.get_task(service, team_id=TEAM_ID, ref=task["task_id"])
    assert (read["rev"], read["status"]) == (1, "open")
    assert not await tasks_service.list_comments(service, team_id=TEAM_ID, ref=task["task_id"])


@pytest.mark.asyncio
async def test_alias_reuse_and_replaced_certificate_cannot_answer(aweb_cloud_db):
    db = aweb_cloud_db.aweb_db
    service, task, actor = await _question(db)
    with pytest.raises(ForbiddenError, match="target_mismatch"):
        await _commit(db, **_answer(task, replace(actor, certificate_id="replaced-certificate")))
    await db.execute("UPDATE {{tables.agents}} SET deleted_at = NOW() WHERE agent_id = $1", UUID(actor.agent_id))
    replacement_id = await _member(db, "requester", human=True)
    replacement = replace(actor, agent_id=str(replacement_id), did_key=f"did:key:{replacement_id}")
    with pytest.raises(ForbiddenError, match="target_mismatch"):
        await _commit(db, **_answer(task, replacement))
    with pytest.raises(ForbiddenError, match="target_mismatch"):
        await _commit(db, **_answer(task, actor))

"""Conditional answer commits compose with a caller's real transaction."""

import asyncio
import hashlib
import base64
import json
from datetime import datetime, timezone
from dataclasses import replace
from uuid import UUID

import pytest

from aweb.coordination import tasks_service
from aweb.service_errors import ConflictError, ForbiddenError
from aweb.team_auth_deps import TeamIdentity
from test_task_human_assignment_events import _member
from test_tasks_http import TEAM_ID, _DbShim, _seed_team
from test_dashboard_privacy import privacy_app, TEAM as LIVE_TEAM  # noqa: F401
from awid.signing import canonical_json_bytes, sign_message


async def _question(db):
    await _seed_team(db)
    member_id = await _member(db, "requester", human=True)
    await db.execute("UPDATE {{tables.agents}} SET certificate_id = 'cert-human' WHERE agent_id = $1", member_id)
    actor = TeamIdentity(team_id=TEAM_ID, alias="requester", did_key=f"did:key:{member_id}", did_aw="", address="", agent_id=str(member_id), identity_scope="local", certificate_id="cert-human")
    service = _DbShim(db)
    task = await tasks_service.create_task(service, team_id=TEAM_ID, created_by_alias="alice", title="Review app request", assignee_alias="requester")
    return service, task, actor


def _answer(task, actor, *, key="answer-1", digest=None, text="Full answer"):
    return dict(team_id=TEAM_ID, task_id=UUID(task["task_id"]), actor=actor,
                expected_task_rev=task["rev"], answer_key=key,
                answer_sha256=digest or hashlib.sha256(b"Full answer").hexdigest(),
                body_md=text)


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
    assert second["task_answer_ref"] != first["task_answer_ref"]
    with pytest.raises(ConflictError, match="idempotency_conflict"):
        await _commit(db, **_answer(task, actor, digest=hashlib.sha256(b"Changed answer").hexdigest(), text="Changed answer"))
    comments = await tasks_service.list_comments(service, team_id=TEAM_ID, ref=task["task_id"])
    assert len(comments) == 2
    assert all(c["body"] == "Full answer" and "cert-human" not in c["body"] for c in comments)


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


@pytest.mark.asyncio
async def test_plain_answer_keeps_full_text_and_checks_its_digest(aweb_cloud_db):
    db = aweb_cloud_db.aweb_db
    service, task, actor = await _question(db)
    text = "Sí, endavant."
    answer = {**_answer(task, actor), "body_md": text}
    from aweb.service_errors import ValidationError
    with pytest.raises(ValidationError, match="schema_invalid"):
        await _commit(db, **answer)
    answer["answer_sha256"] = hashlib.sha256(text.encode()).hexdigest()
    receipt = await _commit(db, **answer)
    comments = await tasks_service.list_comments(service, team_id=TEAM_ID, ref=task["task_id"])
    assert [c["body"] for c in comments] == [text]
    current = await tasks_service.get_task(service, team_id=TEAM_ID, ref=task["task_id"])
    assert receipt["task_rev"] == current["rev"]


async def _v2_request(env, alias, method, path, body=None):
    actor = env.actors[alias]
    content = canonical_json_bytes(body) if body is not None else b""
    timestamp = datetime.now(timezone.utc).isoformat()
    origin = str(env.client.base_url).rstrip("/")
    env.app.state.public_origin = origin
    signed = canonical_json_bytes(dict(v=2, aud=origin, method=method, path=path,
        team_id=LIVE_TEAM, timestamp=timestamp, body_sha256=hashlib.sha256(content).hexdigest()))
    headers = {
        "Authorization": f"DIDKey {actor.did} {sign_message(actor.sk, signed)}",
        "X-AWID-Team-Certificate": actor.certificate,
        "X-AWEB-Signed-Payload": base64.urlsafe_b64encode(signed).decode().rstrip("="),
        "X-AWEB-Timestamp": timestamp, "Content-Type": "application/json",
    }
    return await env.client.request(method, path, content=content, headers=headers)


@pytest.mark.asyncio
async def test_signed_answer_and_receipt_through_real_http_registry_and_database(privacy_app):
    env = privacy_app
    made = await _v2_request(env, "alice", "POST", "/v1/tasks", {"title": "Decide", "assignee_alias": "bob"})
    assert made.status_code == 200, made.text
    task = made.json()
    text = "Keep the full Waiting-on-you answer."
    body = {"expected_task_rev": task["rev"], "answer_key": "real-answer",
            "answer_sha256": hashlib.sha256(text.encode()).hexdigest(), "choice": None,
            "proposal_rev": None, "proposal_sha256": None, "body_md": text}
    path = f'/v1/tasks/{task["task_ref"]}/answer'
    wrong = await _v2_request(env, "alice", "POST", path, body)
    assert wrong.status_code == 403, wrong.text
    missing = await _v2_request(env, "bob", "POST", path, {k: v for k, v in body.items() if k != "expected_task_rev"})
    assert missing.status_code == 428, missing.text
    answered = await _v2_request(env, "bob", "POST", path, body)
    assert answered.status_code == 201, answered.text
    receipt = answered.json()
    retry = await _v2_request(env, "bob", "POST", path, body)
    assert retry.status_code == 200 and retry.json() == receipt, retry.text
    read = await _v2_request(env, "alice", "GET", path + "?answer_key=real-answer")
    assert read.status_code == 200 and read.json() == receipt, read.text
    comments = await _v2_request(env, "alice", "GET", f'/v1/tasks/{task["task_ref"]}/comments')
    assert [c["body"] for c in comments.json()["comments"]] == [text]
    assert text not in json.dumps(env.dispatched)
    reopened = await _v2_request(env, "alice", "PATCH", f'/v1/tasks/{task["task_ref"]}', {"status": "open"})
    assert reopened.status_code == 200, reopened.text
    history = await _v2_request(env, "bob", "POST", path, body)
    assert history.status_code == 200 and history.json() == {**receipt, "current": False}, history.text
    changed = await _v2_request(env, "bob", "POST", path, {**body, "answer_key": "new-question", "expected_task_rev": reopened.json()["rev"]})
    assert changed.status_code == 201 and changed.json()["question_rev"] == 2, changed.text

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
    for alias, actor in env.actors.items():
        cert = json.loads(base64.b64decode(actor.certificate))
        await env.app.state.awid_registry_client.register_team_certificate(
            "example.test", LIVE_TEAM.split(":", 1)[0], team_controller_signing_key=env.team_sk,
            certificate_id=cert["certificate_id"], member_did_key=actor.did,
            member_did_aw=None, member_address=None, alias=alias, identity_scope="local", certificate=actor.certificate)
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


async def _decision_question(db):
    service, ordinary, owner = await _question(db)
    from test_app_task_requests import _verified_install
    from nacl.signing import SigningKey
    from awid.did import did_from_public_key
    service.stage_key = SigningKey.generate()
    service.stage_did = did_from_public_key(bytes(service.stage_key.verify_key))
    await _verified_install(db, team_id=TEAM_ID, app_id="fixture", did_key=service.stage_did)
    backup_id = await _member(db, "backup", human=True)
    await db.execute("UPDATE {{tables.agents}} SET certificate_id='cert-backup' WHERE agent_id=$1", backup_id)
    backup = replace(owner, agent_id=str(backup_id), alias="backup", did_key=f"did:key:{backup_id}", certificate_id="cert-backup")
    outsider_id = await _member(db, "outsider", human=True)
    await db.execute("UPDATE {{tables.agents}} SET certificate_id='cert-outsider' WHERE agent_id=$1", outsider_id)
    outsider = replace(owner, agent_id=str(outsider_id), alias="outsider", did_key=f"did:key:{outsider_id}", certificate_id="cert-outsider")
    metadata = {"eligible_dids": sorted([owner.did_key, backup.did_key]),
                "external_request_id": "decision-set", "resource_ref": "page-1", "action_ref": "decide",
                "proposal_rev": 2, "proposal_sha256": "sha256:" + "d" * 64, "choices": [{"value": "approve", "label": "Approve"}, {"value": "reject", "label": "Reject"}], "role": None, "fields": [{"field": "price", "label": "Price", "format": "number"}]}
    # Seed immutable request metadata at INSERT. Signed ingress shape/authority
    # is tested separately against the shared contract's HTTP vectors.
    row = await db.fetch_one(
        """INSERT INTO {{tables.tasks}}
           (team_id, task_number, root_task_seq, task_ref_suffix, title, assignee_alias, assignee_did, app_request)
           VALUES ($1,$2,$3,'aaab','Approve prices','requester',$4,$5::jsonb) RETURNING task_id""",
        TEAM_ID, await tasks_service._allocate_task_number_on(db, team_id=TEAM_ID),
        await tasks_service._allocate_root_task_seq_on(db, team_id=TEAM_ID), owner.did_key, json.dumps(metadata),
    )
    await db.execute("""INSERT INTO {{tables.task_app_requests}}
        (task_id,team_id,app_id,installation_id,installation_generation,originator_did,external_request_id,
         task_body_sha256,task_authorization,receipt) VALUES ($1,$2,'fixture','install-fixture',1,$3,'decision-set',$4,'{}','{}')""",
        row["task_id"], TEAM_ID, owner.did_key, "0"*64)
    task = await tasks_service.get_task(service, team_id=TEAM_ID, ref=str(row["task_id"]))
    return service, ordinary, task, owner, backup, outsider


def _decision_answer(service, task, actor, *, key="decision-answer"):
    from aweb_naapp.runtime.task_requests import sign_stage_receipt
    from datetime import timedelta
    from uuid import uuid4
    answer = {**_answer(task, actor, key=key), "choice": "approve", "proposal_rev": 2,
              "proposal_sha256": "sha256:" + "d" * 64}
    now = datetime.now(timezone.utc).replace(microsecond=0)
    payload = dict(v=1, type="aweb.app-answer-stage", team_id=TEAM_ID, app_id="fixture",
        installation_id="install-fixture", installation_generation=1, kid="requests-1", did_key=service.stage_did,
        task_id=task["task_id"], question_rev=task["question_rev"], answer_key=key, answer_sha256=answer["answer_sha256"],
        answerer_did=actor.did_aw or actor.did_key, choice=answer["choice"], proposal_rev=answer["proposal_rev"],
        proposal_sha256=answer["proposal_sha256"], issued_at=now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        expires_at=(now+timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ"), nonce=uuid4().hex)
    return {**answer, "stage_receipt": {"payload": payload, "signature": sign_stage_receipt(payload, service.stage_key)}}


@pytest.mark.asyncio
async def test_eligible_backup_answers_and_other_candidate_reads_the_winner(aweb_cloud_db):
    db = aweb_cloud_db.aweb_db
    service, _, task, owner, backup, outsider = await _decision_question(db)
    with pytest.raises(ForbiddenError, match="target_mismatch"):
        await _commit(db, **_decision_answer(service, task, outsider))
    winner = await _commit(db, **_decision_answer(service, task, backup))
    assert winner["answered_by"]["principal_did"] == backup.did_key
    with pytest.raises(ConflictError, match="revision_conflict"):
        await _commit(db, **_decision_answer(service, task, owner, key="other-answer"))
    read = await tasks_service.get_task(service, team_id=TEAM_ID, ref=task["task_ref"])
    assert read["answer"] == winner and read["assignee_did"] == owner.did_key
    assert read["app_request"]["eligible_dids"] == task["app_request"]["eligible_dids"]
    assert await _commit(db, **_decision_answer(service, task, backup)) == winner
    assert len(await tasks_service.list_comments(service, team_id=TEAM_ID, ref=task["task_ref"])) == 1
    reopened = await tasks_service.update_task(service, team_id=TEAM_ID, ref=task["task_ref"], actor_alias="alice", status="open")
    assert reopened["app_request"]["eligible_dids"] == task["app_request"]["eligible_dids"]
    assert await _commit(db, **_decision_answer(service, task, backup)) == {**winner, "current": False}
    next_answer = await _commit(db, **_decision_answer(service, reopened, owner, key="reopened-answer"))
    assert next_answer["question_rev"] == 2 and next_answer["answered_by"]["principal_did"] == owner.did_key


@pytest.mark.asyncio
async def test_two_eligible_people_racing_commit_one_answer(aweb_cloud_db):
    db = aweb_cloud_db.aweb_db
    service, _, task, owner, backup, _ = await _decision_question(db)
    results = await asyncio.gather(
        _commit(db, **_decision_answer(service, task, owner, key="owner-answer")),
        _commit(db, **_decision_answer(service, task, backup, key="backup-answer")), return_exceptions=True,
    )
    assert sum(isinstance(r, dict) for r in results) == 1
    assert sum(isinstance(r, ConflictError) and str(r) == "revision_conflict" for r in results) == 1
    assert len(await tasks_service.list_comments(service, team_id=TEAM_ID, ref=task["task_ref"])) == 1


@pytest.mark.asyncio
async def test_removed_eligible_member_is_refused_and_another_can_answer(aweb_cloud_db):
    db = aweb_cloud_db.aweb_db
    service, _, task, owner, backup, _ = await _decision_question(db)
    await db.execute("UPDATE {{tables.agents}} SET status='retired' WHERE agent_id=$1", UUID(owner.agent_id))
    with pytest.raises(ForbiddenError, match="target_mismatch"):
        await _commit(db, **_decision_answer(service, task, owner))
    assert (await _commit(db, **_decision_answer(service, task, backup)))["answered_by"]["principal_did"] == backup.did_key


@pytest.mark.asyncio
async def test_all_eligible_members_removed_leaves_question_unanswered(aweb_cloud_db):
    db = aweb_cloud_db.aweb_db
    service, _, task, owner, backup, _ = await _decision_question(db)
    await db.execute("UPDATE {{tables.agents}} SET status='retired' WHERE agent_id=ANY($1::uuid[])",
                     [UUID(owner.agent_id), UUID(backup.agent_id)])
    for actor in (owner, backup):
        with pytest.raises(ForbiddenError, match="target_mismatch"):
            await _commit(db, **_decision_answer(service, task, actor))
    current = await tasks_service.get_task(service, team_id=TEAM_ID, ref=task["task_ref"])
    assert current["status"] == "open" and current["answer"] is None
    assert not await tasks_service.list_comments(service, team_id=TEAM_ID, ref=task["task_ref"])


@pytest.mark.asyncio
async def test_list_by_eligible_uses_principals_and_preserves_ordinary_assignment(aweb_cloud_db):
    db = aweb_cloud_db.aweb_db
    service, ordinary, task, owner, backup, outsider = await _decision_question(db)
    for list_fn in (tasks_service.list_tasks, tasks_service.list_tasks_paginated):
        owner_tasks = await list_fn(service, team_id=TEAM_ID, eligible_did=owner.did_key, status="open")
        assert {t["task_id"] for t in owner_tasks} == {ordinary["task_id"], task["task_id"]}
        backup_tasks = await list_fn(service, team_id=TEAM_ID, eligible_did=backup.did_key, status="open")
        assert [t["task_id"] for t in backup_tasks] == [task["task_id"]]
        assert not await list_fn(service, team_id=TEAM_ID, eligible_did=outsider.did_key)
        assert not await list_fn(service, team_id=TEAM_ID, eligible_did="backup")
    winner = await _commit(db, **_decision_answer(service, task, backup))
    assert not await tasks_service.list_tasks(service, team_id=TEAM_ID, eligible_did=backup.did_key, status="open")
    closed = await tasks_service.list_tasks(service, team_id=TEAM_ID, eligible_did=owner.did_key, status="closed")
    assert [t["task_id"] for t in closed] == [task["task_id"]]
    assert (await tasks_service.get_task(service, team_id=TEAM_ID, ref=closed[0]["task_ref"]))["answer"] == winner

"""An app's own role store decides who may stage an answer to its role task.

The owning app (here the naapp runtime's role store, aweb_naapp.roles) reads
its current role holders before it signs a stage receipt; the server sees only
the bound receipt.
"""

import hashlib

import pytest
from awid.signing import canonical_json_bytes

from test_app_task_requests import (  # noqa: F401
    _app_http,
    _body,
    _sign,
    _stage,
    app_request_context,
)
from test_dashboard_privacy import TEAM, privacy_app  # noqa: F401
from test_task_answers import _v2_request

__all__ = ["app_request_context", "privacy_app"]


@pytest.mark.asyncio
@pytest.mark.parametrize("remove_all", [False, True])
async def test_app_role_removal_withholds_stage_while_remaining_holder_can_answer(
    app_request_context, shared_test_pool, remove_all
):
    from pgdbm import AsyncDatabaseManager
    from aweb_naapp.roles import PrincipalKey, apply_roles_migrations, assign, has_role, unassign

    env, *_ = app_request_context
    app_db = AsyncDatabaseManager(pool=shared_test_pool, schema="c2_role_app")
    await app_db.execute("CREATE SCHEMA IF NOT EXISTS c2_role_app")
    await apply_roles_migrations(app_db)
    role = "fixture.approver"
    async with app_db.transaction() as tx:
        for actor in ("bob", "carol"):
            await assign(tx, PrincipalKey(TEAM, env.actors[actor].did), role)
    body = _body(env)
    body["task"]["app_request"].update(
        eligible_dids=sorted([env.actors["bob"].did, env.actors["carol"].did]), role=role
    )
    body["task_authorization"]["payload"].update(
        target_dids=body["task"]["app_request"]["eligible_dids"],
        task_body_sha256=hashlib.sha256(canonical_json_bytes(body["task"])).hexdigest(),
    )
    made = await _app_http(app_request_context, "POST", "/v1/tasks/app-requests", _sign(env, body))
    assert made.status_code == 201, made.text
    ref = f"/v1/tasks/{made.json()['task_ref']}"
    task = (await _v2_request(env, "alice", "GET", ref)).json()
    text = "Approve prices"
    answer = dict(
        expected_task_rev=task["rev"],
        answer_key="role-answer",
        body_md=text,
        answer_sha256=hashlib.sha256(text.encode()).hexdigest(),
        choice="approve",
        proposal_rev=2,
        proposal_sha256="sha256:" + "d" * 64,
    )
    async with app_db.transaction() as tx:
        await unassign(tx, PrincipalKey(TEAM, env.actors["bob"].did), role)
        if remove_all:
            await unassign(tx, PrincipalKey(TEAM, env.actors["carol"].did), role)
    responses = {}
    for actor in ("bob", "carol"):
        # The owning app reads S5's real role map before it signs. Core sees
        # only the bound stage receipt, never a copy of that role store.
        async with app_db.transaction() as tx:
            current_holder = await has_role(tx, PrincipalKey(TEAM, env.actors[actor].did), role)
            proof = _stage(app_request_context, task, actor, answer) if current_holder else None
        responses[actor] = await _v2_request(
            env, actor, "POST", ref + "/answer", {**answer, "stage_receipt": proof}
        )
    assert responses["bob"].status_code == 403, responses["bob"].text
    assert responses["carol"].status_code == (403 if remove_all else 201), responses["carol"].text
    state = (await _v2_request(env, "alice", "GET", ref)).json()
    assert state["status"] == ("open" if remove_all else "closed")
    assert (state["answer"] is None) == remove_all

"""Task membership never promotes an unverified global claim to its principal."""

from __future__ import annotations

import hashlib
from enum import StrEnum
from uuid import UUID

import pytest
from aweb.coordination.tasks_service import answer_task_on, update_task
from aweb.identity_binding import verified_principal_did_sql
from aweb.team_auth_deps import get_team_identity
from starlette.requests import Request
from test_cli_never_grants import registry_listener
from test_dashboard_privacy import TEAM
from test_dashboard_privacy import privacy_app as privacy_app
from test_member_team_key import _connect
from test_messages_http import (
    _encode_certificate,
    _make_certificate,
    _signed_team_headers,
)
from test_task_answers import _v2_request

__all__ = ["privacy_app"]


class SubjectProjection(StrEnum):
    LOCAL = "local"
    VERIFIED_GLOBAL = "verified-global"


async def _connected_subject(env, registry, *, projection: SubjectProjection):
    actor = env.actors["bob"]
    expected = actor.did
    if projection is SubjectProjection.VERIFIED_GLOBAL:
        expected = (await registry.register_did(actor.did, actor.sk)).did_aw
        actor.certificate = _encode_certificate(
            _make_certificate(
                env.team_sk,
                env.team_did,
                actor.did,
                team_id=TEAM,
                alias="bob",
                identity_scope="global",
                member_did_aw=expected,
                certificate_id="task-global-bob",
            )
        )
    assert (await _connect(env, (actor.sk, actor.did, "bob"), actor.certificate)).status_code == 200
    return expected


async def _capture_verified_actor(env):
    actor = env.actors["bob"]
    headers = _signed_team_headers(actor.sk, actor.did, TEAM, actor.certificate)
    request = Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/v1/tasks",
            "app": env.app,
            "headers": [(key.lower().encode(), value.encode()) for key, value in headers.items()],
        }
    )
    return await get_team_identity(request, env.infra)


@pytest.mark.asyncio
@pytest.mark.parametrize("projection", list(SubjectProjection))
async def test_task_assignment_uses_the_verified_member_principal(privacy_app, projection):
    # docs/identity.md:566-585 makes registry-verified marker evidence the
    # condition for global principal projection. The local key remains valid.
    env = privacy_app
    async with registry_listener(env) as (registry, _):
        principal = await _connected_subject(env, registry, projection=projection)
        response = await _v2_request(
            env,
            "alice",
            "POST",
            "/v1/tasks",
            {"title": "Verified assignee", "assignee_alias": "bob"},
        )
        assert response.status_code == 200, response.text
        assert response.json()["assignee_did"] == principal


@pytest.mark.asyncio
async def test_historical_unverified_claim_keeps_the_literal_local_principal(privacy_app):
    env = privacy_app
    async with registry_listener(env) as (registry, _):
        principal = await _connected_subject(env, registry, projection=SubjectProjection.LOCAL)
        other = env.actors["carol"]
        unrelated = (await registry.register_did(other.did, other.sk)).did_aw
        # The current admission path cannot store this historical projection.
        # Feed it to the exact SQL owner shared by task writes.
        row = await env.db.fetch_one(
            f"""SELECT {verified_principal_did_sql()} AS principal_did
                FROM (VALUES ($1::text, $2::text, NULL::text))
                   AS history(did_key, did_aw, did_aw_verified_key)""",
            principal,
            unrelated,
        )
        assert row["principal_did"] == principal


@pytest.mark.asyncio
async def test_task_claim_uses_the_verified_local_principal(privacy_app):
    env = privacy_app
    async with registry_listener(env) as (registry, _):
        principal = await _connected_subject(env, registry, projection=SubjectProjection.LOCAL)
        actor = await _capture_verified_actor(env)
        made = await _v2_request(
            env, "alice", "POST", "/v1/tasks", {"title": "Claim by exact actor"}
        )
        assert made.status_code == 200, made.text
        claimed = await update_task(
            env.infra,
            actor=actor,
            on_mutation=None,
            ref=made.json()["task_ref"],
            status="in_progress",
        )
        assert claimed["assignee_did"] == principal


@pytest.mark.asyncio
async def test_task_answer_uses_the_verified_local_principal(privacy_app):
    env = privacy_app
    async with registry_listener(env) as (registry, _):
        principal = await _connected_subject(env, registry, projection=SubjectProjection.LOCAL)
        actor = await _capture_verified_actor(env)
        made = await _v2_request(
            env,
            "alice",
            "POST",
            "/v1/tasks",
            {"title": "Answer by exact actor", "assignee_alias": "bob"},
        )
        assert made.status_code == 200, made.text
        task = made.json()
        text = "Answer from the same authenticated local key"
        async with env.db.transaction() as transaction:
            receipt = await answer_task_on(
                transaction,
                team_id=TEAM,
                task_id=UUID(task["task_id"]),
                actor=actor,
                expected_task_rev=task["rev"],
                answer_key="verified-principal",
                answer_sha256=hashlib.sha256(text.encode()).hexdigest(),
                body_md=text,
            )
        assert receipt["answered_by"]["principal_did"] == principal

"""C2 service tests with real registry, signatures and database.

The caller supplies a verified installation/transport snapshot. F6's actual
installation-lock/HTTP integration is covered separately once F6 is available.
"""

import base64
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import json
from uuid import UUID

import pytest
import pytest_asyncio
from fastapi import HTTPException
from starlette.requests import Request

from awid.signing import canonical_json_bytes, sign_message
from aweb.app_credentials import APP_REQUEST, AppCredential
from aweb.coordination.app_tasks import (
    AUTHORIZATION_PREFIX, cancel_app_task_on, cancel_installation_requests_on,
    create_app_task_on, read_app_request_on,
)
from aweb.service_errors import ConflictError, ForbiddenError, ValidationError
from test_dashboard_privacy import privacy_app, TEAM  # noqa: F401
from test_task_answers import _v2_request


@pytest_asyncio.fixture
async def app_request_context(privacy_app):
    env = privacy_app
    env.app.state.public_origin = str(env.client.base_url).rstrip("/")
    for alias, actor in env.actors.items():
        cert = json.loads(base64.b64decode(actor.certificate))
        await env.app.state.awid_registry_client.register_team_certificate(
            "example.test", TEAM.split(":", 1)[0], team_controller_signing_key=env.team_sk,
            certificate_id=cert["certificate_id"], member_did_key=actor.did,
            member_did_aw=None, member_address=None, alias=alias, identity_scope="local",
            certificate=actor.certificate,
        )
    installation = dict(installation_id="install-fixture", generation=1, state="active",
                        origin="https://fixture.example.test", granted_scopes=["requests.create", "requests.read"])
    credential = AppCredential(purpose=APP_REQUEST, team_id=TEAM, app_id="fixture", kid="requests-1",
                               did_key=env.actors["alice"].did, installation_id="install-fixture", installation_generation=1)
    request = Request({"type": "http", "method": "POST", "path": "/v1/tasks/app-requests",
                       "headers": [], "app": env.app})
    return env, request, credential, installation


def _body(env, *, request_id="action-1", expired=False):
    task = dict(title="Review a page request", description=None, assignee_did=env.actors["bob"].did,
        app_request=dict(external_request_id=request_id, resource_ref="opaque-page", action_ref="decide",
                         proposal_rev=2, proposal_sha256="sha256:" + "d" * 64, choices=["approve", "reject"]))
    now = datetime.now(timezone.utc).replace(microsecond=0)
    if expired:
        now -= timedelta(days=2)
    payload = dict(v=1, type="aweb.app-task-authorization", aud=env.app.state.public_origin,
        app_origin="https://fixture.example.test", team_id=TEAM, app_id="fixture",
        installation_id="install-fixture", installation_generation=1, external_request_id=request_id,
        actor_did_key=env.actors["alice"].did, certificate_id="privacy-alice", target_did=task["assignee_did"],
        task_body_sha256=hashlib.sha256(canonical_json_bytes(task)).hexdigest(), action_id="decide",
        proposal_rev=2, proposal_sha256=task["app_request"]["proposal_sha256"],
        issued_at=now.strftime("%Y-%m-%dT%H:%M:%SZ"), expires_at=(now+timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"), nonce="1"*32)
    return _sign(env, dict(task=task, task_authorization=dict(payload=payload, signature="", certificate=env.actors["alice"].certificate)))


def _sign(env, body):
    signature = sign_message(env.actors["alice"].sk, AUTHORIZATION_PREFIX + canonical_json_bytes(body["task_authorization"]["payload"]))
    body["task_authorization"]["signature"] = signature.replace("+", "-").replace("/", "_")
    return body


async def _create(context, body):
    env, request, credential, installation = context
    async with env.db.transaction() as tx:
        return await create_app_task_on(request, tx, credential=credential, installation=installation, body=body)


@pytest.mark.asyncio
async def test_app_create_replay_expiry_and_lost_receipt_reconcile(app_request_context):
    env, request, credential, installation = app_request_context
    body = _body(env)
    first, created = await _create(app_request_context, body)
    assert created and first["originator"]["principal_did"] == env.actors["alice"].did
    assert first["transport_app"]["installation_id"] == "install-fixture"
    assert await _create(app_request_context, body) == (first, False)
    expired = _body(env, expired=True)
    assert await _create(app_request_context, expired) == (first, False)
    with pytest.raises(HTTPException) as caught:
        await _create(app_request_context, _body(env, request_id="not-created", expired=True))
    assert caught.value.status_code == 401 and caught.value.detail == "authorization_expired"
    changed = deepcopy(body)
    changed["task"]["title"] = "A changed request"
    changed["task_authorization"]["payload"]["task_body_sha256"] = hashlib.sha256(canonical_json_bytes(changed["task"])).hexdigest()
    with pytest.raises(ConflictError, match="idempotency_conflict"):
        await _create(app_request_context, _sign(env, changed))
    async with env.db.transaction() as tx:
        state = await read_app_request_on(tx, credential=credential, installation=installation,
            external_request_id="action-1", originator=env.actors["alice"].did)
    assert state["receipt"] == first and state["task"]["answer"] is None
    assert await env.db.fetch_value("SELECT count(*) FROM {{tables.task_app_requests}}") == 1
    installation["granted_scopes"] = []
    with pytest.raises(ForbiddenError, match="scope_denied"):
        await _create(app_request_context, expired)


@pytest.mark.asyncio
async def test_app_request_binding_and_authorization_are_independent(app_request_context):
    env, *_ = app_request_context
    body = _body(env)
    body["task_authorization"]["payload"]["target_did"] = env.actors["carol"].did
    with pytest.raises(ForbiddenError, match="target_mismatch"):
        await _create(app_request_context, _sign(env, body))
    body = _body(env)
    body["task_authorization"]["signature"] = "A" * 86
    with pytest.raises(HTTPException) as caught:
        await _create(app_request_context, body)
    assert caught.value.status_code == 401
    body = _body(env)
    body["task"]["unrecognized_security_field"] = True
    with pytest.raises(ValidationError, match="schema_invalid"):
        await _create(app_request_context, body)


@pytest.mark.asyncio
async def test_app_decision_answer_checks_proposal_and_choice_then_cancellation(app_request_context):
    env, request, credential, installation = app_request_context
    receipt, _ = await _create(app_request_context, _body(env))
    path = f'/v1/tasks/{receipt["task_ref"]}/answer'
    text = "Approve the proposal"
    answer = dict(expected_task_rev=1, answer_key="decision-1", body_md=text,
                  answer_sha256=hashlib.sha256(text.encode()).hexdigest(), choice="approve",
                  proposal_rev=2, proposal_sha256="sha256:"+"d"*64)
    changed = await _v2_request(env, "bob", "POST", path, {**answer, "proposal_sha256": "sha256:"+"e"*64})
    assert changed.status_code == 409 and changed.json()["detail"] == "approval_changed", changed.text
    invalid = await _v2_request(env, "bob", "POST", path, {**answer, "choice": "not-an-option"})
    assert invalid.status_code == 422, invalid.text
    accepted = await _v2_request(env, "bob", "POST", path, answer)
    assert accepted.status_code == 201, accepted.text
    async with env.db.transaction() as tx:
        state = await read_app_request_on(tx, credential=credential, installation=installation,
            external_request_id="action-1", originator=env.actors["alice"].did)
        assert state["task"]["answer"] == accepted.json()
        cancellation = await cancel_app_task_on(tx, team_id=TEAM, task_id=UUID(receipt["task_id"]), external_request_id="action-1", reason="requested")
        assert await cancel_app_task_on(tx, team_id=TEAM, task_id=UUID(receipt["task_id"]), external_request_id="action-1", reason="requested") == cancellation
    historical = await _v2_request(env, "bob", "POST", path, answer)
    assert historical.status_code == 200 and historical.json()["current"] is False, historical.text
    comments = await _v2_request(env, "alice", "GET", f'/v1/tasks/{receipt["task_ref"]}/comments')
    assert [c["body"] for c in comments.json()["comments"]] == [text, "Request cancelled · action-1"]


@pytest.mark.asyncio
async def test_f6_cancellation_hook_rolls_back_with_installation_transaction(app_request_context):
    env, *_ = app_request_context
    receipt, _ = await _create(app_request_context, _body(env))
    with pytest.raises(RuntimeError):
        async with env.db.transaction() as tx:
            assert await cancel_installation_requests_on(tx, team_id=TEAM, app_id="fixture", installation_id="install-fixture") == 1
            raise RuntimeError("uninstall rolls back")
    row = await env.db.fetch_one("SELECT status, cancellation FROM {{tables.tasks}} WHERE task_id=$1", UUID(receipt["task_id"]))
    assert row["status"] == "open" and row["cancellation"] is None
    async with env.db.transaction() as tx:
        assert await cancel_installation_requests_on(tx, team_id=TEAM, app_id="fixture", installation_id="install-fixture") == 1

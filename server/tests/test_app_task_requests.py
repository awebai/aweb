"""C2 services and signed HTTP paths with real registry, signatures and database."""

import base64
import asyncio
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import json
from uuid import UUID, uuid4

import pytest
import pytest_asyncio
from fastapi import HTTPException
from starlette.requests import Request
from nacl.signing import SigningKey
from awid.did import did_from_public_key
from awid.registry import CachedRegistryClient
import awid.registry as registry_module
import httpx
from aweb.app_registry import get_installation_on
from aweb_naapp.runtime.task_requests import app_request_credential

from awid.signing import canonical_json_bytes, sign_message
from aweb.app_credentials import APP_REQUEST, AppCredential
from aweb.coordination.app_tasks import (
    AUTHORIZATION_PREFIX, cancel_app_task_on, cancel_installation_requests_on,
    create_app_task_on, prepare_app_task, read_app_request_on,
)
from aweb.service_errors import ConflictError, ForbiddenError, ValidationError
from aweb.task_contracts import validate_app_task, strict_json_bytes
from test_dashboard_privacy import privacy_app, TEAM  # noqa: F401
from test_task_answers import _v2_request


async def _verified_install(db, *, team_id, app_id, did_key, kid="requests-1", installation_id="install-fixture", generation=1,
                            origin="https://fixture.example.test"):
    """Provision disposable verified registry state; F6 owns the install flow."""
    manifest = canonical_json_bytes({"manifest_version": 2, "app": {"id": app_id, "origin": origin, "version": "1.0.0"},
        "app_keys": [{"kid": kid, "did_key": did_key, "purposes": ["app-request"]}]})
    digest = "sha256:" + hashlib.sha256(manifest).hexdigest()
    await db.execute("INSERT INTO {{tables.app_registry_apps}} (app_id,origin) VALUES ($1,$2) ON CONFLICT DO NOTHING", app_id, origin)
    await db.execute("""INSERT INTO {{tables.app_registry_entries}} (app_id,origin,digest,app_version,manifest_version)
        VALUES ($1,$2,$3,'1.0.0',2) ON CONFLICT DO NOTHING""", app_id, origin, digest)
    await db.execute("""INSERT INTO {{tables.team_app_installs}}
        (team_id,app_id,origin,digest,app_version,manifest_version,granted_scopes,installation_id,generation,state,origin_verified,manifest_bytes)
        VALUES ($1,$2,$3,$4,'1.0.0',2,ARRAY['requests.create','requests.read'],$5,$6,'active',TRUE,$7)""",
        team_id, app_id, origin, digest, installation_id, generation, manifest)
    await db.execute("""INSERT INTO {{tables.team_app_keys}} (team_id,app_id,origin,digest,key_id,did_key,purposes)
        VALUES ($1,$2,$3,$4,$5,$6,ARRAY['app-request'])""", team_id, app_id, origin, digest, kid, did_key)
    return dict(await get_installation_on(db, team_id=team_id, app_id=app_id))


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
    env.app_signing_key = SigningKey.generate()
    app_did = did_from_public_key(bytes(env.app_signing_key.verify_key))
    installation = await _verified_install(env.db, team_id=TEAM, app_id="fixture", did_key=app_did)
    credential = AppCredential(purpose=APP_REQUEST, team_id=TEAM, app_id="fixture", kid="requests-1",
                               did_key=app_did, installation_id="install-fixture", installation_generation=1)
    request = Request({"type": "http", "method": "POST", "path": "/v1/tasks/app-requests",
                       "headers": [(b"x-aweb-team-id", TEAM.encode()), (b"x-aweb-app-id", b"fixture")], "app": env.app})
    return env, request, credential, installation


async def _app_http(context, method, path, body=None):
    env, _, credential, installation = context
    raw = canonical_json_bytes(body) if body is not None else b""
    headers = app_request_credential(signing_key=env.app_signing_key, aud=env.app.state.public_origin,
        method=method, path=path, team_id=credential.team_id, app_id=credential.app_id, kid=credential.kid,
        installation_id=installation["installation_id"], installation_generation=installation["generation"],
        body=raw, timestamp=datetime.now(timezone.utc).isoformat())
    headers["Content-Type"] = "application/json"
    return await env.client.request(method, path, content=raw, headers=headers)


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
    prepared = await prepare_app_task(request, body=body)
    async with env.db.transaction() as tx:
        return await create_app_task_on(tx, credential=credential, installation=installation, prepared=prepared)


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
    with pytest.raises(HTTPException) as caught:
        await _create(app_request_context, _sign(env, body))
    assert caught.value.status_code == 403 and caught.value.detail == "target_mismatch"
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
    stolen = await _v2_request(env, "carol", "PATCH", f'/v1/tasks/{receipt["task_ref"]}', {"status": "in_progress"})
    assert stolen.status_code == 403, stolen.text
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


@pytest.mark.parametrize("body", [b'{"key":1,"key":2}', b'{"n":1.0}', b'{"n":NaN}',
    b'{"n":Infinity}', b'{"n":9007199254740992}', b'{"s":"\\ud800"}'])
def test_c2_json_rejects_ambiguous_and_noncanonical_values(body):
    with pytest.raises(ValidationError, match="schema_invalid"):
        strict_json_bytes(body)


@pytest.mark.parametrize("control", ["\n", "\u061c", "\u200e", "\u200f", "\u202e", "\u2066"])
def test_app_task_titles_refuse_control_and_bidi_control_characters(control):
    task = dict(title="Review" + control, description=None, assignee_did="did:key:example",
                app_request=dict(external_request_id="a", resource_ref="r", action_ref="a",
                                 proposal_rev=None, proposal_sha256=None, choices=None))
    with pytest.raises(ValidationError, match="schema_invalid"):
        validate_app_task(task)


@pytest.mark.asyncio
@pytest.mark.parametrize("expired", [False, True])
async def test_revoked_originator_cannot_create_or_read_by_replay(app_request_context, expired):
    env, *_ = app_request_context
    body = _body(env)
    await _create(app_request_context, body)
    await env.app.state.awid_registry_client.revoke_team_certificate(
        "example.test", TEAM.split(":", 1)[0], team_controller_signing_key=env.team_sk,
        certificate_id="privacy-alice")
    with pytest.raises(HTTPException) as caught:
        await _create(app_request_context, _body(env, expired=expired))
    assert caught.value.status_code == 401 and caught.value.detail == "certificate_revoked"


@pytest.mark.asyncio
async def test_naapp_raises_decision_member_answers_and_app_reads_receipt(app_request_context):
    from urllib.parse import quote

    env, _, credential, installation = app_request_context
    body = _body(env)
    created = await _app_http(app_request_context, "POST", "/v1/tasks/app-requests", body)
    assert created.status_code == 201, created.text
    receipt = created.json()
    retry = await _app_http(app_request_context, "POST", "/v1/tasks/app-requests", body)
    assert retry.status_code == 200 and retry.json() == receipt, retry.text
    text = "D'acord — approve the proposal."
    answer = dict(expected_task_rev=1, answer_key="real-app-answer", body_md=text,
                  answer_sha256=hashlib.sha256(text.encode()).hexdigest(), choice="approve",
                  proposal_rev=2, proposal_sha256="sha256:"+"d"*64)
    path = f'/v1/tasks/{receipt["task_ref"]}/answer'
    refused = await _app_http(app_request_context, "POST", path, answer)
    assert refused.status_code == 401, refused.text
    accepted = await _v2_request(env, "bob", "POST", path, answer)
    assert accepted.status_code == 201, accepted.text
    read = await _app_http(app_request_context, "GET", "/v1/tasks/answers/" + accepted.json()["task_answer_ref"])
    assert read.status_code == 200 and read.json() == accepted.json(), read.text
    reconcile_path = "/v1/tasks/app-requests/action-1?originator=" + quote(env.actors["alice"].did, safe="")
    reconciled = await _app_http(app_request_context, "GET", reconcile_path)
    assert reconciled.status_code == 200, reconciled.text
    assert reconciled.json()["receipt"] == receipt
    assert reconciled.json()["task"]["answer"] == accepted.json()
    assert text not in reconciled.text and text not in json.dumps(env.dispatched)
    assert "certificate" not in (await _v2_request(env, "alice", "GET", f'/v1/tasks/{receipt["task_ref"]}')).json()


@pytest.mark.asyncio
async def test_retirement_atomically_cancels_an_open_request(app_request_context):
    env, *_ = app_request_context
    made = await _app_http(app_request_context, "POST", "/v1/tasks/app-requests", _body(env))
    assert made.status_code == 201, made.text
    task_id = UUID(made.json()["task_id"])
    claimed = await _v2_request(env, "bob", "PATCH", f'/v1/tasks/{made.json()["task_ref"]}', {"status": "in_progress"})
    assert claimed.status_code == 200, claimed.text
    assert await env.db.fetch_value("SELECT count(*) FROM {{tables.task_claims}} WHERE task_ref=$1", made.json()["task_ref"]) == 1
    async with env.db.transaction() as tx:
        installation = await get_installation_on(tx, team_id=TEAM, app_id="fixture", for_update=True)
        assert await cancel_installation_requests_on(tx, team_id=TEAM, app_id="fixture", installation_id=installation["installation_id"]) == 1
        await tx.execute("UPDATE {{tables.team_app_installs}} SET state='uninstalled' WHERE team_id=$1 AND app_id='fixture'", TEAM)
        # A separate connection sees neither side of the unfinished retire.
        assert await env.db.fetch_value("SELECT status FROM {{tables.tasks}} WHERE task_id=$1", task_id) == "in_progress"
        assert (await get_installation_on(env.db, team_id=TEAM, app_id="fixture"))["state"] == "active"
    row = await env.db.fetch_one("SELECT status,cancellation FROM {{tables.tasks}} WHERE task_id=$1", task_id)
    assert row["status"] == "closed"
    assert await env.db.fetch_value("SELECT count(*) FROM {{tables.task_claims}} WHERE task_ref=$1", made.json()["task_ref"]) == 0
    cancellation = json.loads(row["cancellation"]) if isinstance(row["cancellation"], str) else row["cancellation"]
    assert cancellation["reason"] == "installation_retired"
    refused = await _app_http(app_request_context, "POST", "/v1/tasks/app-requests", _body(env, request_id="after-retire"))
    assert refused.status_code == 403 and refused.json()["detail"] == "scope_denied", refused.text


@pytest.mark.asyncio
async def test_create_waits_for_retirement_lock_and_cannot_commit_after_it(app_request_context):
    env, *_ = app_request_context
    async with env.db.transaction() as tx:
        await get_installation_on(tx, team_id=TEAM, app_id="fixture", for_update=True)
        creating = asyncio.create_task(_app_http(app_request_context, "POST", "/v1/tasks/app-requests", _body(env)))
        try:
            await asyncio.sleep(0.05)
            assert not creating.done()
            assert await cancel_installation_requests_on(tx, team_id=TEAM, app_id="fixture", installation_id="install-fixture") == 0
            await tx.execute("UPDATE {{tables.team_app_installs}} SET state='uninstalled' WHERE team_id=$1 AND app_id='fixture'", TEAM)
        except BaseException:
            creating.cancel()
            await asyncio.gather(creating, return_exceptions=True)
            raise
    response = await asyncio.wait_for(creating, 5)
    assert response.status_code == 403, response.text
    assert await env.db.fetch_value("SELECT count(*) FROM {{tables.task_app_requests}}") == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("registry_suffix", ["", "/revocations", "/certificates"])
async def test_stalled_awid_does_not_block_installation_retirement(app_request_context, monkeypatch, registry_suffix):
    env, *_ = app_request_context
    made = await _app_http(app_request_context, "POST", "/v1/tasks/app-requests", _body(env))
    assert made.status_code == 201, made.text
    entered, resume = asyncio.Event(), asyncio.Event()
    registry_path = f'/v1/namespaces/example.test/teams/{TEAM.split(":", 1)[0]}' + registry_suffix

    async def stalled_registry(scope, receive, send):
        # Delay only the external HTTP boundary; all registry handlers and
        # cryptographic checks still execute against the real registry.
        if scope["type"] == "http" and scope["path"] == registry_path:
            entered.set()
            await resume.wait()
        await env.registry_app(scope, receive, send)

    transport = env.app.state.awid_registry_client.transport
    monkeypatch.setattr(transport, "app", stalled_registry)
    creating = asyncio.create_task(_app_http(app_request_context, "POST", "/v1/tasks/app-requests",
                                            _body(env, request_id="during-awid-stall")))
    try:
        await asyncio.wait_for(entered.wait(), 2)
        # Retirement must finish while AWID is still paused. A statement timeout
        # turns a held installation lock into a deterministic test failure.
        async with env.db.transaction() as tx:
            await tx.execute("SET LOCAL statement_timeout = '750ms'")
            installation = await get_installation_on(tx, team_id=TEAM, app_id="fixture", for_update=True)
            assert await cancel_installation_requests_on(tx, team_id=TEAM, app_id="fixture",
                installation_id=installation["installation_id"]) == 1
            await tx.execute("UPDATE {{tables.team_app_installs}} SET state='uninstalled' WHERE team_id=$1 AND app_id='fixture'", TEAM)
        assert not creating.done()
        assert (await get_installation_on(env.db, team_id=TEAM, app_id="fixture"))["state"] == "uninstalled"
        assert await env.db.fetch_value("SELECT status FROM {{tables.tasks}} WHERE task_id=$1", UUID(made.json()["task_id"])) == "closed"
    finally:
        resume.set()
        response = await asyncio.wait_for(creating, 5)
    assert response.status_code == 403 and response.json()["detail"] == "scope_denied", response.text
    assert await env.db.fetch_value("SELECT count(*) FROM {{tables.task_app_requests}}") == 1


@pytest_asyncio.fixture
async def cached_app_request_context(app_request_context, monkeypatch):
    env, *_ = app_request_context
    uncached = env.app.state.awid_registry_client
    clock = [1_000_000]
    unavailable = [None]
    monkeypatch.setattr(registry_module, "_cache_now", lambda: clock[0])

    async def registry_boundary(scope, receive, send):
        if scope["type"] == "http" and scope["path"] == unavailable[0]:
            raise httpx.ConnectError("disposable registry outage")
        await env.registry_app(scope, receive, send)

    cached = CachedRegistryClient(
        registry_url=f"http://c2-cache-{uuid4().hex}.test", redis_client=env.redis,
        transport=httpx.ASGITransport(app=registry_boundary), service_token=uncached.service_token,
    )
    monkeypatch.setattr(env.app.state, "awid_registry_client", cached)
    team_name = TEAM.split(":", 1)[0]
    try:
        # Prime the same public cached API production uses, against real AWID
        # and Redis. Revoke through another client so the old cache survives.
        assert await cached.get_team_public_key("example.test", team_name) == env.team_did
        assert await cached.get_team_revocations("example.test", team_name) == set()
        assert len(await cached.list_team_certificates("example.test", team_name)) == 3
        yield app_request_context, uncached, clock, unavailable
    finally:
        await asyncio.gather(*list(cached._refresh_tasks.values()), return_exceptions=True)
        await cached.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("registry_suffix", ["", "/revocations", "/certificates"])
@pytest.mark.parametrize("expired_replay", [False, True])
async def test_c2_cached_authority_outage_fails_closed(cached_app_request_context, registry_suffix, expired_replay):
    context, uncached, clock, unavailable = cached_app_request_context
    env, *_ = context
    made = await _app_http(context, "POST", "/v1/tasks/app-requests", _body(env))
    assert made.status_code == 201, made.text
    team_name = TEAM.split(":", 1)[0]
    # Keep the certificate-list case's actor current so the preceding
    # revocation check cannot short circuit the failed list read.
    if registry_suffix != "/certificates":
        await uncached.revoke_team_certificate("example.test", team_name,
            team_controller_signing_key=env.team_sk, certificate_id="privacy-alice")
    clock[0] += 61
    unavailable[0] = f"/v1/namespaces/example.test/teams/{team_name}" + registry_suffix
    body = _body(env, expired=expired_replay, request_id="action-1" if expired_replay else "cache-new")
    response = await _app_http(context, "POST", "/v1/tasks/app-requests", body)
    assert response.status_code == 503 and response.json()["detail"] == "authority_unavailable", response.text
    assert await env.db.fetch_value("SELECT count(*) FROM {{tables.task_app_requests}}") == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("cache_age", [0, 61, 601])
@pytest.mark.parametrize("expired_replay", [False, True])
async def test_c2_cached_authority_observes_revocation(cached_app_request_context, cache_age, expired_replay):
    context, uncached, clock, _ = cached_app_request_context
    env, *_ = context
    made = await _app_http(context, "POST", "/v1/tasks/app-requests", _body(env))
    assert made.status_code == 201, made.text
    await uncached.revoke_team_certificate("example.test", TEAM.split(":", 1)[0],
        team_controller_signing_key=env.team_sk, certificate_id="privacy-alice")
    clock[0] += cache_age
    body = _body(env, expired=expired_replay, request_id="action-1" if expired_replay else "cache-new")
    response = await _app_http(context, "POST", "/v1/tasks/app-requests", body)
    assert response.status_code == 401 and response.json()["detail"] == "certificate_revoked", response.text
    assert await env.db.fetch_value("SELECT count(*) FROM {{tables.task_app_requests}}") == 1


@pytest.mark.asyncio
async def test_generation_change_renews_authority_and_reinstall_cannot_read_old_requests(app_request_context):
    from urllib.parse import quote

    env, _, credential, installation = app_request_context
    body = _body(env)
    made = await _app_http(app_request_context, "POST", "/v1/tasks/app-requests", body)
    assert made.status_code == 201, made.text
    await env.db.execute("UPDATE {{tables.team_app_installs}} SET generation=2 WHERE team_id=$1 AND app_id='fixture'", TEAM)
    stale = await _app_http(app_request_context, "POST", "/v1/tasks/app-requests", body)
    assert stale.status_code == 403 and stale.json()["detail"] == "scope_denied", stale.text
    installation["generation"] = 2
    stale_member = await _app_http(app_request_context, "POST", "/v1/tasks/app-requests", body)
    assert stale_member.status_code == 403 and stale_member.json()["detail"] == "target_mismatch", stale_member.text
    body["task_authorization"]["payload"]["installation_generation"] = 2
    replay = await _app_http(app_request_context, "POST", "/v1/tasks/app-requests", _sign(env, body))
    assert replay.status_code == 200 and replay.json() == made.json(), replay.text
    await env.db.execute("UPDATE {{tables.team_app_installs}} SET installation_id='new-installation',generation=1 WHERE team_id=$1 AND app_id='fixture'", TEAM)
    installation.update(installation_id="new-installation", generation=1)
    read = await _app_http(app_request_context, "GET", "/v1/tasks/app-requests/action-1?originator=" + quote(env.actors["alice"].did, safe=""))
    assert read.status_code == 404 and read.json()["detail"] == "resource_not_found", read.text


@pytest.mark.asyncio
async def test_read_only_scope_cannot_create_or_cancel(app_request_context):
    env, *_ = app_request_context
    body = _body(env)
    made = await _app_http(app_request_context, "POST", "/v1/tasks/app-requests", body)
    assert made.status_code == 201, made.text
    await env.db.execute("UPDATE {{tables.team_app_installs}} SET granted_scopes=ARRAY['requests.read'] WHERE team_id=$1 AND app_id='fixture'", TEAM)
    replay = await _app_http(app_request_context, "POST", "/v1/tasks/app-requests", body)
    assert replay.status_code == 200, replay.text
    absent = await _app_http(app_request_context, "POST", "/v1/tasks/app-requests", _body(env, request_id="absent"))
    assert absent.status_code == 403 and absent.json()["detail"] == "scope_denied", absent.text
    cancel = await _app_http(app_request_context, "POST", "/v1/tasks/app-requests/action-1/cancel?originator=ignored")
    assert cancel.status_code == 403, cancel.text

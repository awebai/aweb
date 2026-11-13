"""Keep native certificate evidence alive through auth and locked grant effects."""

import asyncio
import json
from contextlib import asynccontextmanager
from types import SimpleNamespace
from uuid import uuid4

import httpx
import pytest
from fastapi import Depends, FastAPI, Request
from nacl.signing import SigningKey

import aweb.team_auth_deps as auth
import awid.protected_membership as membership
from aweb.api import RequestBodyCacheMiddleware
from aweb.routes.identity_grants import router as grants_router
from aweb_naapp_testing import did_key
from tests.test_protected_membership_retained import ORIGIN, TEAM, membership_env  # noqa: F401


class DelayedDB:
    """Advance only the original observation clock after a real SQL await."""

    def __init__(self, db, ticks, phase):
        self.db, self.ticks, self.phase = db, ticks, phase

    def __getattr__(self, name):
        return getattr(self.db, name)

    async def fetch_one(self, query, *args):
        row = await self.db.fetch_one(query, *args)
        if self.phase == "lookup" and "SELECT agent_id, certificate_id" in query:
            self.ticks[0] = 61.0
        return row

    async def execute(self, query, *args):
        result = await self.db.execute(query, *args)
        if self.phase == "projection" and "SET certificate_id" in query:
            self.ticks[0] = 61.0
        return result

    @asynccontextmanager
    async def transaction(self):
        async with self.db.transaction() as tx:
            yield DelayedDB(tx, self.ticks, self.phase)


async def native_app(env, ticks, monkeypatch, phase="none"):
    await env.stack.awid_db.execute(
        "INSERT INTO {{tables.team_protection}} "
        "(domain,name,service_id,service_did_key,generation) "
        "VALUES ('beta.example','backend','test-signer',$1,1)",
        did_key(SigningKey.generate()),
    )
    agent_id = uuid4()
    await env.stack.aweb_db.execute(
        "INSERT INTO {{tables.agents}} "
        "(agent_id,team_id,alias,did_key,certificate_id,identity_scope,status) "
        "VALUES ($1,$2,$3,$4,'previous-certificate','local','active')",
        agent_id, TEAM, env.member.alias, env.member.did_key,
    )
    monkeypatch.setattr(membership, "monotonic", lambda: ticks[0])
    app = FastAPI()
    app.add_middleware(RequestBodyCacheMiddleware)
    db = DelayedDB(env.stack.aweb_db, ticks, phase)
    app.state.db = SimpleNamespace(get_manager=lambda name="aweb": db)
    app.state.awid_registry_client = env.registry
    app.state.public_origin = ORIGIN
    app.include_router(grants_router)
    observed = []
    observe = membership.observe_team_protection

    async def capture(*args, **kwargs):
        observation = await observe(*args, **kwargs)
        observed.append(observation)
        return observation

    monkeypatch.setattr(membership, "observe_team_protection", capture)

    @app.get("/verify")
    async def verify(identity=Depends(auth.get_team_identity)):
        assert identity.protection_observation is observed[0]
        return {"deadline": identity.protection_observation.deadline}

    @app.get("/certificate")
    async def certificate(request: Request):
        info = await auth.verify_request_certificate(request, app.state.db)
        assert info["protection_observation"] is observed[0]
        return {"deadline": observed[0].deadline}

    return app, agent_id, observed


@pytest.mark.asyncio
@pytest.mark.parametrize("delayed", [False, True])
async def test_final_id_chain_await_keeps_original_deadline(membership_env, monkeypatch, delayed):
    env, ticks = membership_env, [0.0]
    app, _, _ = await native_app(env, ticks, monkeypatch)
    authenticate = auth.authenticate_id_chain

    async def chain(*args, **kwargs):
        result = await authenticate(*args, **kwargs)
        if delayed:
            ticks[0] = 61.0
        return result

    monkeypatch.setattr(auth, "authenticate_id_chain", chain)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url=ORIGIN) as client:
        response = await client.get("/certificate", headers=env.member.headers(aud=ORIGIN, method="GET", path="/certificate"))
    assert response.status_code == (503 if delayed else 200), response.text
    assert response.json() == ({"detail": {"code": "protected_state_unavailable"}} if delayed else {"deadline": 60.0})


@pytest.mark.asyncio
@pytest.mark.parametrize("phase", ["none", "lookup", "projection", "resolution-return"])
async def test_resolution_preserves_original_evidence_and_rolls_back_expired_projection(membership_env, monkeypatch, phase):
    env, ticks = membership_env, [0.0]
    app, agent_id, _ = await native_app(env, ticks, monkeypatch, phase)
    if phase == "resolution-return":
        resolve = auth.resolve_team_identity

        async def delayed(*args, **kwargs):
            result = await resolve(*args, **kwargs)
            ticks[0] = 61.0
            return result

        monkeypatch.setattr(auth, "resolve_team_identity", delayed)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url=ORIGIN) as client:
        response = await client.get("/verify", headers=env.member.headers(aud=ORIGIN, method="GET", path="/verify"))
    assert response.status_code == (200 if phase == "none" else 503), response.text
    recorded = await env.stack.aweb_db.fetch_value("SELECT certificate_id FROM {{tables.agents}} WHERE agent_id=$1", agent_id)
    # A completed fresh resolution may precede a later caller-side delay.
    expected = env.member.certificate_id if phase in {"none", "resolution-return"} else "previous-certificate"
    assert recorded == expected


@pytest.mark.asyncio
@pytest.mark.parametrize("expired", [False, True])
async def test_locked_grant_mint_fences_original_observation_without_partial_writes(membership_env, monkeypatch, expired):
    env, ticks = membership_env, [0.0]
    app, _, observed = await native_app(env, ticks, monkeypatch)
    key = did_key(SigningKey.generate())
    body = json.dumps({"grant_did_key": key, "scopes": ["mail.read"], "ttl_seconds": 60}).encode()
    headers = env.member.headers(aud=ORIGIN, method="POST", path="/v1/identity-grants", body=body)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url=ORIGIN) as client:
        async with env.stack.aweb_db.transaction() as blocker:
            await blocker.fetch_value("SELECT pg_advisory_xact_lock(hashtextextended($1,0))", f"identity-grant:{key}")
            pending = asyncio.create_task(client.post("/v1/identity-grants", content=body, headers=headers))
            try:
                async with asyncio.timeout(10):
                    while not await blocker.fetch_value("SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND NOT granted)"):
                        assert not pending.done(), pending.result().text if pending.done() else None
                        await asyncio.sleep(0.01)
                assert len(observed) == 1 and observed[0].deadline == 60.0
                if expired:
                    ticks[0] = 61.0
            except BaseException:
                pending.cancel()
                await asyncio.gather(pending, return_exceptions=True)
                raise
        response = await pending
    assert response.status_code == (503 if expired else 200), response.text
    if expired:
        assert response.json() == {"detail": {"code": "protected_state_unavailable"}}
    assert await env.stack.aweb_db.fetch_value("SELECT count(*) FROM {{tables.identity_session_grants}}") == (0 if expired else 1)
    assert len(observed) == 1 and observed[0].deadline == 60.0

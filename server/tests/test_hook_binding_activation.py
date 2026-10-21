"""Owner activation and revocation of hook bindings (audit-substrate.md §A3).

Real PostgreSQL, a real in-process AWID registry holding the team's controller
key, and real ``aweb.owner-act/1`` acts signed with that key and verified by the
hooks kit's verifier. Nothing in between is mocked.
"""

from __future__ import annotations

import base64
import hashlib
import os
import secrets
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import httpx
import pytest
import pytest_asyncio
from nacl.signing import SigningKey
from redis.asyncio import Redis

from aweb.app_registry import install_app
from aweb.hook_bindings import (
    PRODUCTION,
    REGISTRATION,
    HookBindingDeclaration,
    activate_binding,
    core_owner_act_verifier,
    list_app_bindings,
    revoke_binding,
    write_pending_bindings,
)
from aweb.service_errors import ConflictError, ForbiddenError, NotFoundError
from aweb_naapp.hooks.owner_act import PREFIX
from aweb_naapp.hooks.strictjson import canonical
from awid.did import did_from_public_key
from awid.ratelimit import MemoryFixedWindowRateLimiter
from awid.registry import RegistryClient
from awid_service.db import AwidDatabaseInfra
from awid_service.main import create_app as create_registry_app
from tests.test_app_events_http import _seed_team_and_agent

TEAM = "backend:acme.com"
OTHER_TEAM = "frontend:acme.com"
ORIGIN = "https://logs.example"
AUDIENCE = "https://coord.example"
INSTALLATION = "1b4e28ba-2fa1-4d3b-a3f5-ef19b5a7633b"
DIGEST = "sha256:" + hashlib.sha256(b"logs v1").hexdigest()

RECORD = HookBindingDeclaration(
    kind=REGISTRATION, catalog_id="aweb.hooks", catalog_version=1, hook="post-secret-use-hook",
    tool="ingest", method="POST", path="/hooks/ingest", scopes=("logs:write", "logs:append"),
)
EMIT = HookBindingDeclaration(
    kind=PRODUCTION, catalog_id="aweb.hooks", catalog_version=1, hook="post-governance-hook",
    reads=("search",),
)


def _did(key: SigningKey) -> str:
    return did_from_public_key(bytes(key.verify_key))


class Owner:
    """Signs owner acts with a key; the registry decides whether it is the team's."""

    def __init__(self, key: SigningKey, team_id: str = TEAM) -> None:
        self.key = key
        self.team_id = team_id

    def sign(self, act: str, binding, *, audience: str = AUDIENCE, **overrides) -> tuple[bytes, str]:
        subject = {
            "binding_id": str(binding.binding_id),
            "installation_id": binding.installation_id,
            "generation": binding.generation,
            "app_id": binding.app_id,
            "origin": binding.origin,
            "digest": binding.digest,
            "kind": binding.kind,
            "catalog_id": binding.catalog_id,
            "catalog_version": binding.catalog_version,
            "hook": binding.hook,
        }
        if binding.kind == REGISTRATION:
            subject.update(tool=binding.tool, method=binding.method, path=binding.path, scopes=list(binding.scopes))
        else:
            subject["reads"] = list(binding.reads)
        subject.update(overrides)
        issued = datetime.now(UTC).replace(microsecond=0)
        fields = {
            "v": 1,
            "type": "aweb.owner-act",
            "act": act,
            "team_id": self.team_id,
            "aud": audience,
            "team_key_did": _did(self.key),
            "subject": subject,
            "issued_at": issued.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "expires_at": (issued + timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "nonce": secrets.token_hex(16),
        }
        signing = PREFIX + canonical(fields)
        return signing, base64.b64encode(self.key.sign(signing).signature).decode().rstrip("=")


@pytest_asyncio.fixture
async def env(aweb_cloud_db, shared_test_pool, monkeypatch):
    # The registry runs on the shared test pool; its settings still require a URL.
    monkeypatch.setenv("AWID_DATABASE_URL", "postgresql://unused/test")
    # The server reads private teams with the trusted service token, as in production.
    service_token = f"hook-bindings-service-token-{uuid4().hex}"
    monkeypatch.setenv("AWID_SERVICE_TOKEN", service_token)
    db = aweb_cloud_db.aweb_db
    await _seed_team_and_agent(db, team_id=TEAM)
    await _seed_team_and_agent(db, team_id=OTHER_TEAM)
    registry_db = AwidDatabaseInfra(schema=f"hooks_registry_{uuid4().hex[:8]}")
    await registry_db.initialize(shared_pool=shared_test_pool)
    team_key = SigningKey.generate()
    for name in ("backend", "frontend"):
        await registry_db.get_manager().execute(
            "INSERT INTO {{tables.teams}} (domain, name, team_did_key, visibility) VALUES ('acme.com', $1, $2, 'private')",
            name, _did(team_key),
        )
    async with Redis.from_url(os.environ.get("REDIS_URL", "redis://localhost:6379/0"), decode_responses=True) as redis:
        registry_app = create_registry_app(
            db_infra=registry_db, redis=redis, rate_limiter=MemoryFixedWindowRateLimiter(),
        )
        async with registry_app.router.lifespan_context(registry_app):
            registry = RegistryClient(
                registry_url="http://registry.test", transport=httpx.ASGITransport(app=registry_app),
                service_token=service_token,
            )
            try:
                yield type("Env", (), {
                    "db": db,
                    "registry_db": registry_db.get_manager(),
                    "registry": registry,
                    "owner": Owner(team_key),
                    "verifier": core_owner_act_verifier(audience=AUDIENCE, registry_client=registry),
                })
            finally:
                await registry.aclose()


async def _install(db, *, team_id=TEAM, digest=DIGEST, from_bytes=True):
    await install_app(
        db, team_id=team_id, app_id="logs", origin=ORIGIN, app_version="1.0.0",
        manifest_version=1, digest=digest, granted_scopes=[],
    )
    if from_bytes:
        await db.execute(
            "UPDATE {{tables.team_app_installs}} SET registered_from_manifest_bytes = TRUE"
            " WHERE team_id = $1 AND app_id = 'logs'",
            team_id,
        )


async def _bindings(env, *, team_id=TEAM, installation_id=INSTALLATION, generation=1, digest=DIGEST):
    async with env.db.transaction() as tx:
        return await write_pending_bindings(
            tx, team_id=team_id, app_id="logs", origin=ORIGIN, digest=digest,
            installation_id=installation_id, generation=generation, declarations=[RECORD, EMIT],
        )


async def _hook_keys(db, *, purposes=("hook-event", "hook-delivery"), team_id=TEAM, digest=DIGEST):
    await db.execute(
        "INSERT INTO {{tables.team_app_keys}} (team_id, app_id, origin, digest, key_id, did_key, purposes)"
        " VALUES ($1, 'logs', $2, $3, $4, $5, $6::TEXT[])",
        team_id, ORIGIN, digest, f"logs:{uuid4().hex[:8]}", _did(SigningKey.generate()), list(purposes),
    )


async def _activate(env, binding, *, owner=None, team_id=TEAM, act="hook-binding.activate", **overrides):
    signing, signature = (owner or env.owner).sign(act, binding, **overrides)
    return await activate_binding(
        env.db, env.verifier, team_id=team_id, binding_id=binding.binding_id, signing=signing, signature=signature,
    )


async def _revoke(env, binding, *, owner=None, team_id=TEAM, act="hook-binding.revoke"):
    signing, signature = (owner or env.owner).sign(act, binding)
    return await revoke_binding(
        env.db, env.verifier, team_id=team_id, binding_id=binding.binding_id, signing=signing, signature=signature,
    )


@pytest.mark.asyncio
async def test_the_owner_activates_a_registration_from_the_next_minute(env):
    await _install(env.db)
    registration, _ = await _bindings(env)
    signing, signature = env.owner.sign("hook-binding.activate", registration)

    active = await activate_binding(
        env.db, env.verifier, team_id=TEAM, binding_id=registration.binding_id, signing=signing, signature=signature,
    )

    assert active.state == "active"
    assert active.activated_at.microsecond % 1000 == 0
    assert active.active_from - active.activated_at == timedelta(seconds=60)
    stored = await env.db.fetch_value(
        "SELECT activation_act_sha256 FROM {{tables.app_hook_bindings}} WHERE binding_id = $1", registration.binding_id,
    )
    assert stored == hashlib.sha256(signing).hexdigest()


@pytest.mark.asyncio
async def test_a_production_activates_once_its_hook_keys_come_from_the_pinned_bytes(env):
    await _install(env.db)
    _, production = await _bindings(env)
    with pytest.raises(ConflictError, match="hook keys"):
        await _activate(env, production)
    await _hook_keys(env.db, purposes=("app-event",))
    with pytest.raises(ConflictError, match="hook keys"):
        await _activate(env, production)

    await _hook_keys(env.db)
    assert (await _activate(env, production)).state == "active"


@pytest.mark.asyncio
async def test_a_production_of_an_install_registered_without_its_bytes_is_refused(env):
    await _install(env.db, from_bytes=False)
    _, production = await _bindings(env)
    await _hook_keys(env.db)

    with pytest.raises(ConflictError, match="pinned manifest bytes"):
        await _activate(env, production)


@pytest.mark.asyncio
async def test_a_key_other_than_the_teams_current_one_is_refused(env):
    await _install(env.db)
    registration, _ = await _bindings(env)

    with pytest.raises(ForbiddenError, match="owner_required"):
        await _activate(env, registration, owner=Owner(SigningKey.generate()))

    assert (await list_app_bindings(env.db, team_id=TEAM, app_id="logs"))[0].state == "pending"


@pytest.mark.asyncio
async def test_a_rotated_out_team_key_stops_activating_at_once(env):
    await _install(env.db)
    registration, _ = await _bindings(env)
    rotated = SigningKey.generate()
    await env.registry_db.execute(
        "UPDATE {{tables.teams}} SET team_did_key = $1 WHERE domain = 'acme.com' AND name = 'backend'", _did(rotated),
    )

    with pytest.raises(ForbiddenError, match="owner_required"):
        await _activate(env, registration)
    assert (await _activate(env, registration, owner=Owner(rotated))).state == "active"


@pytest.mark.asyncio
async def test_a_subject_that_is_not_the_stored_binding_is_refused(env):
    await _install(env.db)
    registration, _ = await _bindings(env)

    with pytest.raises(ConflictError, match="subject_mismatch"):
        await _activate(env, registration, path="/hooks/other")
    with pytest.raises(ConflictError, match="subject_mismatch"):
        await _activate(env, registration, generation=2)


@pytest.mark.asyncio
async def test_an_act_naming_a_superseded_generation_is_refused(env):
    await _install(env.db)
    old, _ = await _bindings(env)
    newer = "sha256:" + hashlib.sha256(b"logs v2").hexdigest()
    await _install(env.db, digest=newer)
    await _bindings(env, generation=2, digest=newer)

    with pytest.raises(ConflictError, match="superseded"):
        await _activate(env, old)


@pytest.mark.asyncio
async def test_a_replayed_act_is_refused(env):
    await _install(env.db)
    registration, _ = await _bindings(env)
    signing, signature = env.owner.sign("hook-binding.revoke", registration)
    await revoke_binding(
        env.db, env.verifier, team_id=TEAM, binding_id=registration.binding_id, signing=signing, signature=signature,
    )
    second, _ = await _bindings(env, generation=2)

    with pytest.raises(ConflictError):
        await revoke_binding(
            env.db, env.verifier, team_id=TEAM, binding_id=registration.binding_id,
            signing=signing, signature=signature,
        )
    assert second.state == "pending"


@pytest.mark.asyncio
async def test_a_replayed_activation_nonce_is_refused(env):
    await _install(env.db)
    registration, _ = await _bindings(env)
    signing, signature = env.owner.sign("hook-binding.activate", registration)
    await activate_binding(
        env.db, env.verifier, team_id=TEAM, binding_id=registration.binding_id, signing=signing, signature=signature,
    )
    await env.db.execute(
        "UPDATE {{tables.app_hook_bindings}} SET state = 'pending', activated_at = NULL, active_from = NULL,"
        " activation_act_sha256 = NULL WHERE binding_id = $1",
        registration.binding_id,
    )

    with pytest.raises(ConflictError, match="nonce_reused"):
        await activate_binding(
            env.db, env.verifier, team_id=TEAM, binding_id=registration.binding_id,
            signing=signing, signature=signature,
        )


@pytest.mark.asyncio
async def test_a_revoke_act_cannot_activate_and_an_activate_act_cannot_revoke(env):
    await _install(env.db)
    registration, _ = await _bindings(env)

    with pytest.raises(ForbiddenError, match="hook-binding.activate"):
        await _activate(env, registration, act="hook-binding.revoke")
    await _activate(env, registration)
    with pytest.raises(ForbiddenError, match="hook-binding.revoke"):
        await _revoke(env, registration, act="hook-binding.activate")


@pytest.mark.asyncio
async def test_bindings_without_installation_identity_cannot_activate(env):
    await _install(env.db)
    registration, _ = await _bindings(env, installation_id=None, generation=None)

    with pytest.raises(ConflictError, match="installation identity"):
        await activate_binding(
            env.db, env.verifier, team_id=TEAM, binding_id=registration.binding_id,
            signing=b"", signature="",
        )


@pytest.mark.asyncio
async def test_another_teams_binding_is_not_found(env):
    await _install(env.db)
    registration, _ = await _bindings(env)

    with pytest.raises(NotFoundError):
        await _activate(env, registration, owner=Owner(env.owner.key, team_id=OTHER_TEAM), team_id=OTHER_TEAM)


@pytest.mark.asyncio
async def test_activation_needs_a_pending_binding(env):
    await _install(env.db)
    registration, _ = await _bindings(env)
    await _activate(env, registration)

    with pytest.raises(ConflictError, match="not pending"):
        await _activate(env, registration)


@pytest.mark.asyncio
async def test_the_owner_revokes_an_active_or_pending_binding_and_records_the_act(env):
    await _install(env.db)
    await _hook_keys(env.db)
    registration, production = await _bindings(env)
    await _activate(env, registration)

    for binding in (registration, production):
        signing, signature = env.owner.sign("hook-binding.revoke", binding)
        revoked = await revoke_binding(
            env.db, env.verifier, team_id=TEAM, binding_id=binding.binding_id, signing=signing, signature=signature,
        )
        assert (revoked.state, revoked.ended_by) == ("revoked", "owner_act")
        assert revoked.revoked_at.microsecond % 1000 == 0
        assert await env.db.fetch_value(
            "SELECT revocation_act_sha256 FROM {{tables.app_hook_bindings}} WHERE binding_id = $1", binding.binding_id,
        ) == hashlib.sha256(signing).hexdigest()

    with pytest.raises(ConflictError, match="already ended"):
        await _revoke(env, registration)


@pytest.mark.asyncio
async def test_work_in_the_activating_transaction_commits_or_rolls_back_with_it(env):
    await _install(env.db)
    registration, _ = await _bindings(env)
    signing, signature = env.owner.sign("hook-binding.activate", registration)

    async def fails(tx):
        raise RuntimeError("the hook event could not be enqueued")

    with pytest.raises(RuntimeError):
        await activate_binding(
            env.db, env.verifier, team_id=TEAM, binding_id=registration.binding_id,
            signing=signing, signature=signature, in_transaction=fails,
        )
    assert (await list_app_bindings(env.db, team_id=TEAM, app_id="logs"))[0].state == "pending"

    seen = []

    async def records(tx):
        seen.append(await tx.fetch_value(
            "SELECT state FROM {{tables.app_hook_bindings}} WHERE binding_id = $1", registration.binding_id,
        ))

    active = await activate_binding(
        env.db, env.verifier, team_id=TEAM, binding_id=registration.binding_id,
        signing=signing, signature=signature, in_transaction=records,
    )
    assert active.state == "active" and seen == ["active"]

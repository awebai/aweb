"""An app producer's registration view (K3b) against this server's real
resolution routes, reached through real discovery.

Bindings are written by the install path's own writer and made active through
the row values a real owner activation must satisfy (owner activation is not
built yet). The producer's audit-critical gate reads the view; so does the
drain's resolver.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest
import pytest_asyncio
from nacl.signing import SigningKey

from awid.did import did_from_public_key
from aweb.app_credentials import HOOK_RESOLVE
from aweb.app_registry import install_app
from aweb.hook_bindings import PRODUCTION, REGISTRATION, HookBindingDeclaration, write_pending_bindings
from aweb_naapp.hooks.producer import (
    HOOKS_CHANNEL,
    HookProducer,
    ServerProducer,
    hook_targets,
)
from aweb_naapp.hooks.resolver import TeamServerRegistrations
from aweb_naapp.hooks.strictjson import Refused
from aweb_naapp.outbox import StoredEvent, apply_outbox_migrations
from aweb_naapp.runtime.app_credentials import AppCredentialSigner
from aweb_naapp.runtime.app_keys import AppKey
from aweb_naapp.runtime.hook_resolver import HookResolver

TEAM = "backend:producer.example"
HOOK = "post-secret-use-hook"
LOGS = {"app_id": "logs", "origin": "https://logs.example", "digest": "sha256:" + "1" * 64}
SECRETS = {"app_id": "secrets", "origin": "https://secrets.example", "digest": "sha256:" + "2" * 64}
INGEST = HookBindingDeclaration(
    kind=REGISTRATION, catalog_id="aweb.hooks", catalog_version=1, hook=HOOK,
    tool="ingest", method="POST", path="/hooks/ingest", scopes=("logs:ingest",),
)
SECRET_USE = HookBindingDeclaration(kind=PRODUCTION, catalog_id="aweb.hooks", catalog_version=1, hook=HOOK)
SECRET_USE_PAYLOAD = {
    "action": "refused",
    "op_kind": "broker",
    "refusal_code": "grant_missing",
    "target_method": "POST",
    "target_host": "api.example.com",
    "target_port": 443,
    "target_path_template": "/v1/charges",
    "request_sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
}
SYSTEM = {"authority_mode": "system", "attestations": []}


class Clock:
    """Monotonic time for the resolver's cache and wall time for its data, moved together."""

    def __init__(self) -> None:
        self.now = 1000.0
        self.wall = datetime.now(UTC).replace(microsecond=0)

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds
        self.wall += timedelta(seconds=seconds)


async def _install(db, app: dict, installation_id: str, declarations) -> dict:
    await install_app(
        db, team_id=TEAM, app_id=app["app_id"], origin=app["origin"], app_version="1.0.0",
        manifest_version=2, digest=app["digest"], granted_scopes=[],
    )
    async with db.transaction() as tx:
        written = await write_pending_bindings(
            tx, team_id=TEAM, app_id=app["app_id"], origin=app["origin"], digest=app["digest"],
            installation_id=installation_id, generation=1, declarations=list(declarations),
        )
    return {binding.kind: binding for binding in written}


async def _activate(db, binding_id: UUID, *, active_from: datetime) -> None:
    await db.execute(
        """
        UPDATE {{tables.app_hook_bindings}}
        SET state = 'active', activated_at = $2, active_from = $3, activation_act_sha256 = $4
        WHERE binding_id = $1
        """,
        binding_id, active_from - timedelta(seconds=60), active_from, "ab" * 32,
    )


async def _revoke(db, binding_id: UUID, *, at: datetime) -> None:
    await db.execute(
        """
        UPDATE {{tables.app_hook_bindings}}
        SET state = 'revoked', revoked_at = $2, ended_by = 'owner_act', revocation_act_sha256 = $3
        WHERE binding_id = $1
        """,
        binding_id, at, "cd" * 32,
    )


@pytest_asyncio.fixture
async def team(real_stack):
    team_key = await real_stack.add_team(TEAM)
    await real_stack.publish_server(TEAM, team_key)
    db = real_stack.aweb_db
    clock = Clock()
    logs = await _install(db, LOGS, "inst-logs", [INGEST])
    secrets = await _install(db, SECRETS, "inst-secrets", [SECRET_USE])
    await _activate(db, logs[REGISTRATION].binding_id, active_from=clock.wall - timedelta(minutes=5))
    await _activate(db, secrets[PRODUCTION].binding_id, active_from=clock.wall - timedelta(minutes=5))
    signing_key = SigningKey.generate()
    did_key = did_from_public_key(bytes(signing_key.verify_key))
    await db.execute(
        """
        INSERT INTO {{tables.team_app_keys}} (team_id, app_id, origin, digest, key_id, did_key, purposes)
        VALUES ($1, $2, $3, $4, $5, $6, $7::TEXT[])
        """,
        TEAM, "secrets", SECRETS["origin"], SECRETS["digest"], "resolve-secrets", did_key, [HOOK_RESOLVE],
    )
    resolver = HookResolver(
        directory=real_stack.directory(clock=clock),
        signer=AppCredentialSigner(
            app_id="secrets",
            key=AppKey(kid="resolve-secrets", did_key=did_key, signing_key=signing_key),
            purpose=HOOK_RESOLVE,
        ),
        app_origin=SECRETS["origin"],
        transport=real_stack.aweb,
        monotonic=clock,
        clock=lambda: clock.wall,
    )
    return {
        "stack": real_stack,
        "db": db,
        "clock": clock,
        "registrations": TeamServerRegistrations(resolver),
        "registration": logs[REGISTRATION],
    }


@pytest_asyncio.fixture
async def outbox_db(test_db_factory):
    database = await test_db_factory.create_db(suffix="producer_outbox")
    await apply_outbox_migrations(database)
    yield database


def _producer(clock: Clock) -> HookProducer:
    return HookProducer(
        ServerProducer.app(
            origin=SECRETS["origin"],
            app_id="secrets",
            installation_id="1b4e28ba-2fa1-4d3b-a3f5-ef19b5a7633b",
            generation=1,
            kid="hook-2026-10",
            seed=bytes(range(32)),
        ),
        clock=lambda: clock.wall,
    )


async def _enqueue(outbox_db, team) -> UUID:
    clock = team["clock"]
    view = await team["registrations"].view(TEAM, HOOK)
    async with outbox_db.transaction() as tx:
        return await _producer(clock).enqueue(
            tx,
            hook=HOOK,
            team_id=TEAM,
            payload=SECRET_USE_PAYLOAD,
            actor=SYSTEM,
            occurred_at=clock.wall,
            result_status="denied",
            view=view,
        )


def _stored(occurred_at: datetime) -> StoredEvent:
    return StoredEvent(
        event_id=UUID(int=1), team_id=TEAM, kind=HOOK, occurred_at=occurred_at, payload=b"",
        signature="", critical=True, producer={}, channel=HOOKS_CHANNEL,
    )


@pytest.mark.asyncio
async def test_the_view_lists_the_activated_registration_with_its_endpoint(team):
    view = await team["registrations"].view(TEAM, HOOK)
    assert view is not None
    assert (view.team_id, view.hook) == (TEAM, HOOK)
    assert view.as_of == team["clock"].wall
    assert view.max_age == timedelta(seconds=60)
    [registration] = view.registrations
    assert registration.binding_id == str(team["registration"].binding_id)
    assert (registration.origin, registration.method, registration.path) == (
        LOGS["origin"], "POST", "/hooks/ingest",
    )


@pytest.mark.asyncio
async def test_a_fresh_view_lets_an_audit_critical_effect_through(team, outbox_db):
    await _enqueue(outbox_db, team)
    assert await outbox_db.fetch_value("SELECT count(*) FROM {{tables.outbox_events}}") == 1


@pytest.mark.asyncio
async def test_an_expired_view_refuses_the_effect_when_the_server_cannot_refresh_it(team, outbox_db):
    await team["registrations"].view(TEAM, HOOK)
    team["clock"].advance(61)
    team["stack"].aweb.down = True
    assert await team["registrations"].view(TEAM, HOOK) is None
    with pytest.raises(Refused) as refused:
        await _enqueue(outbox_db, team)
    assert refused.value.code == "audit_target_unavailable"
    assert await outbox_db.fetch_value("SELECT count(*) FROM {{tables.outbox_events}}") == 0


@pytest.mark.asyncio
async def test_a_view_held_past_its_window_no_longer_counts(team, outbox_db):
    view = await team["registrations"].view(TEAM, HOOK)
    team["clock"].advance(61)
    clock = team["clock"]
    with pytest.raises(Refused) as refused:
        async with outbox_db.transaction() as tx:
            await _producer(clock).enqueue(
                tx, hook=HOOK, team_id=TEAM, payload=SECRET_USE_PAYLOAD, actor=SYSTEM,
                occurred_at=clock.wall, result_status="denied", view=view,
            )
    assert refused.value.code == "audit_target_unavailable"


@pytest.mark.asyncio
async def test_a_revoked_binding_drops_out_within_the_bound(team):
    resolve = hook_targets(team["registrations"], clock=lambda: team["clock"].wall)
    before = await resolve(_stored(team["clock"].wall))
    assert [target.id for target in before or []] == [str(team["registration"].binding_id)]
    await _revoke(team["db"], team["registration"].binding_id, at=team["clock"].wall)
    team["clock"].advance(61)
    after = await resolve(_stored(team["clock"].wall))
    assert after == []
    view = await team["registrations"].view(TEAM, HOOK)
    assert view is not None and view.registrations == ()


@pytest.mark.asyncio
async def test_a_producer_without_its_production_binding_has_no_view(team):
    await _revoke(team["db"], (await _production_id(team)), at=team["clock"].wall)
    assert await team["registrations"].view(TEAM, HOOK) is None


async def _production_id(team) -> UUID:
    return await team["db"].fetch_value(
        "SELECT binding_id FROM {{tables.app_hook_bindings}} WHERE app_id = 'secrets'"
    )

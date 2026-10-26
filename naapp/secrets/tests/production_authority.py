"""Real aweb app-authority routes and writers for production-root tests.

Only the external installation/activated hook bindings are fixture state.
Secrets starts with no F6 or owner rows. Installation fetch/owner activation
journeys are separate acceptance; this fixture does not claim to exercise them.
"""

import hashlib
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta

import httpx
from aweb.app_manifests import FetchedManifest
from aweb.db import DatabaseInfra
from aweb.installations import install_verified_manifest_on
from aweb.routes.app_hooks import router as hooks_router
from aweb.routes.apps import router as apps_router
from aweb_naapp.manifest import canonical_bytes, load_manifest
from awid.db_config import build_database_config
from awid.signing import sign_message
from awid.team_server_record import record_signing_bytes
from awid_service.testing import REGISTRY_URL, ServiceTransport
from fastapi import FastAPI
from pgdbm import AsyncDatabaseManager

SERVER = "https://aweb.example"


async def no_dns_override(domain):
    # A controlled external DNS answer; signed discovery still uses real AWID.
    return None


@asynccontextmanager
async def authority(test_db_factory, registry, member):
    database = await test_db_factory.create_db(suffix="root_external_aweb")
    pool = await AsyncDatabaseManager.create_shared_pool(
        build_database_config(
            connection_string=database.config.get_dsn(), min_connections=2, max_connections=5
        )
    )
    infra = DatabaseInfra()
    try:
        await infra.initialize(shared_pool=pool)
        db = infra.get_manager()
        assert await db.fetch_value("SELECT current_database()") == await database.fetch_value(
            "SELECT current_database()"
        )
        name, domain = member.team_id.split(":", 1)
        await registry.add_team(member.team_id, member.team_did_key)
        await registry.add_certificate(member.certificate())
        await db.execute(
            "INSERT INTO {{tables.teams}} (team_id,namespace,team_name,team_did_key) VALUES ($1,$2,$3,$4)",
            member.team_id,
            domain,
            name,
            member.team_did_key,
        )
        record = {
            "v": 1,
            "type": "aweb.team-server",
            "team_id": member.team_id,
            "team_did_key": member.team_did_key,
            "server_url": SERVER,
            "issued_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        async with httpx.AsyncClient(transport=registry.transport) as client:
            published = await client.put(
                f"{REGISTRY_URL}/v1/namespaces/{domain}/teams/{name}/server",
                json={
                    "record": record,
                    "signature": sign_message(bytes(member.team_key), record_signing_bytes(record)),
                },
            )
        assert published.status_code == 200
        app = FastAPI()
        app.state.db, app.state.public_origin = infra, SERVER
        app.include_router(apps_router)
        app.include_router(hooks_router)

        @app.middleware("http")
        async def cache_body(request, call_next):
            body = await request.body()
            request.state.cached_body = body
            request.state.body_sha256 = hashlib.sha256(body).hexdigest()
            return await call_next(request)

        yield db, ServiceTransport(app)
    finally:
        await infra.close()
        await pool.close()


async def install(db, member, data, scopes):
    manifest = load_manifest(data)
    origin = manifest.document["app"]["origin"]
    fetched = FetchedManifest(
        origin=origin,
        url=origin + "/manifests/v2.json",
        digest="sha256:" + hashlib.sha256(data).hexdigest(),
        data=data,
        manifest=manifest,
    )
    async with db.transaction() as tx:
        row = await install_verified_manifest_on(
            tx,
            team_id=member.team_id,
            fetched=fetched,
            granted_scopes=scopes,
        )
    return row


async def install_audit_receiver(db, member):
    hooks = ("post-governance-hook", "post-secret-use-hook")
    data = canonical_bytes(
        {
            "manifest_version": 2,
            "app": {"id": "logs", "origin": "https://logs.example", "version": "0.1.0"},
            "app_keys": [],
            "tools": [
                {
                    "name": "ingest",
                    "invocation_contexts": ["hook"],
                    "method": "POST",
                    "path": "/hooks/ingest",
                    "scopes": ["logs:ingest"],
                    "description": "Record signed events",
                }
            ],
            "hooks": {
                "registration_version": 1,
                "registrations": [
                    {
                        "catalog": {"id": "aweb.hooks", "version": 1},
                        "hook": hook,
                        "tool": "ingest",
                        "scopes": ["logs:ingest"],
                    }
                    for hook in hooks
                ],
            },
        }
    )
    await install(db, member, data, [])
    # External activation precondition, exactly the persisted eligibility read
    # by the real hook resolver. The activation ceremony is not under test here.
    active = datetime.now(UTC) - timedelta(minutes=1)
    await db.execute(
        "UPDATE {{tables.app_hook_bindings}} SET state='active',activated_at=$2::timestamptz - INTERVAL '60 seconds',active_from=$2,activation_act_sha256=$3 WHERE team_id=$1",
        member.team_id,
        active,
        "ab" * 32,
    )

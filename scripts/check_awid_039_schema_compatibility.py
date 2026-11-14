"""Real published 0.5.39 CLI on a current migrated, isolated registry DB."""
import asyncio
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from uuid import uuid4

import asyncpg
import httpx
from redis.asyncio import Redis
from awid.did import generate_keypair, did_from_public_key
from awid.signing import canonical_json_bytes, sign_message
from awid_service.db import AwidDatabaseInfra
from awid_service.main import create_app
from awid_service.protected_teams import provision_team_protection


def keypair():
    seed, public = generate_keypair()
    return seed, did_from_public_key(public)


def signed(identity, claims):
    stamp = datetime.now(timezone.utc).isoformat()
    return {"Authorization": f"DIDKey {identity[1]} {sign_message(identity[0], canonical_json_bytes({**claims, 'timestamp': stamp}))}",
            "X-AWEB-Timestamp": stamp}


async def main():
    base = os.environ["AWID_COMPAT_POSTGRES_URL"]
    maintenance = await asyncpg.connect(base)
    database = "awid_compat_" + uuid4().hex
    await maintenance.execute(f'CREATE DATABASE "{database}"')
    dsn = base.rsplit("/", 1)[0] + "/" + database
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    origin = f"http://127.0.0.1:{port}"
    os.environ.update(AWID_DATABASE_URL=dsn, AWID_DB_SCHEMA="awid", AWID_PUBLIC_ORIGINS=origin)
    infra, process = AwidDatabaseInfra(), None
    redis = Redis.from_url(os.environ["AWID_REDIS_URL"], decode_responses=True)
    log = tempfile.NamedTemporaryFile(mode="w", prefix="awid-039-", suffix=".log", delete=False)
    succeeded = False
    result = {}
    try:
        await infra.initialize()
        db = infra.get_manager()
        assert await db.fetch_value("SELECT count(*) FROM {{schema}}.schema_migrations") == 15
        result["new_schema_migrations"] = 15
        app = create_app(db_infra=infra, redis=redis)
        owner, team = keypair(), keypair()
        async with app.router.lifespan_context(app):
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url=origin) as current:
                response = await current.post("/v1/namespaces", json={"domain": "local"},
                    headers=signed(owner, {"domain": "local", "operation": "register"}))
                assert response.status_code == 200, response.text
                path = "/v1/namespaces/local/teams/base"
                response = await current.post("/v1/namespaces/local/teams", json={"name": "base", "team_did_key": team[1], "visibility": "public"},
                    headers=signed(owner, {"domain": "local", "operation": "create_team", "name": "base"}))
                assert response.status_code == 200, response.text
                child_env = {**os.environ, "AWID_HOST": "127.0.0.1", "AWID_PORT": str(port), "PYTHONPATH": "", "AWID_LOG_JSON": "false"}
                child_env.pop("UV_FROZEN", None)
                process = subprocess.Popen([shutil.which("uv"), "run", "--isolated", "--no-project", "--with", "awid-service==0.5.39", "awid", "--host", "127.0.0.1", "--port", str(port)],
                    cwd="/tmp", env=child_env, stdout=log, stderr=subprocess.STDOUT)
                async with httpx.AsyncClient(base_url=origin, timeout=2) as old:
                    async with asyncio.timeout(45):
                        while True:
                            assert process.poll() is None, f"old CLI exited; inspect {log.name}"
                            try:
                                health = await old.get("/health")
                                if health.status_code == 200:
                                    break
                            except httpx.TransportError:
                                pass
                            await asyncio.sleep(.05)
                    result["old_health"] = health.status_code
                    info = await old.get("/")
                    result["old_root"] = info.json()
                    assert "0.5.39" in json.dumps(info.json()), info.text
                    response = await old.get(path)
                    assert response.status_code == 200 and "protection" not in response.json(), response.text
                    result["legacy_team_read"] = response.status_code
                    claims = {"domain": "local", "operation": "set_team_visibility", "team_name": "base", "visibility": "public"}
                    response = await old.post(path + "/visibility", json={"visibility": "public"}, headers=signed(team, claims))
                    assert response.status_code == 200, response.text
                    result["legacy_old_mutation"] = response.status_code
                    service = keypair()
                    async with db.transaction() as tx:
                        await provision_team_protection(tx, domain="local", name="base", service_id="matrix-service", service_did_key=service[1], expected_generation=0, approval_ref="native-rollback-matrix")
                    claims["visibility"] = "private"
                    response = await current.post(path + "/visibility", json={"visibility": "private"}, headers=signed(team, claims))
                    assert response.status_code == 403 and response.json()["detail"]["code"] == "protected_controller_required", response.text
                    result["current_protected_key_only_mutation"] = response.status_code
                    response = await old.post(path + "/visibility", json={"visibility": "private"}, headers=signed(team, claims))
                    assert response.status_code == 200, response.text
                    result["old_protected_key_only_mutation"] = response.status_code
                    assert await db.fetch_value("SELECT mode FROM {{tables.team_protection}}") == "protected"
                    async with db.transaction() as tx:
                        await provision_team_protection(tx, domain="local", name="base", service_id="matrix-service", service_did_key=service[1], expected_generation=1, mode="legacy", approval_ref="native-forward-deprotection")
                    before = await db.fetch_value("SELECT generation FROM {{tables.team_protection}}")
                    rotated = keypair()
                    response = await old.post(path + "/rotate", json={"new_team_did_key": rotated[1]}, headers=signed(owner, {"domain": "local", "operation": "rotate_team_key", "name": "base", "new_team_did_key": rotated[1]}))
                    assert response.status_code == 200, response.text
                    after = await db.fetch_value("SELECT generation FROM {{tables.team_protection}}")
                    assert before == after == 2
                    result.update(old_rotation_after_forward_deprotection=response.status_code, generation_before_old_rotation=before, generation_after_old_rotation=after)
                    assert await db.fetch_value("SELECT count(*) FROM {{schema}}.schema_migrations") == 15
        print(json.dumps(result, indent=2))
        succeeded = True
    finally:
        if process is not None:
            process.terminate()
            try:
                await asyncio.to_thread(process.wait, 10)
            except subprocess.TimeoutExpired:
                process.kill()
                await asyncio.to_thread(process.wait)
        log.close()
        if succeeded:
            Path(log.name).unlink()
        else:
            print(f"Legacy registry process log retained at {log.name}", file=sys.stderr)
        await infra.close()
        await redis.aclose()
        await maintenance.execute(f'DROP DATABASE "{database}" WITH (FORCE)')
        await maintenance.close()


asyncio.run(main())

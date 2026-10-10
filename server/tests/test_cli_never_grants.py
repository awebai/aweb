"""Never grants against real HTTP aweb/AWID, PostgreSQL, Redis, CLI and custody.

Reuse the existing disposable resource fixture; replace its in-process registry
transport with a real loopback listener. No authentication, signing, registry,
grant status, stream, or clock behavior is mocked. SQL only provisions fixtures
and injects the subject-inactive / past-storage-horizon conditions.
"""
from __future__ import annotations

import asyncio
import base64
from contextlib import AsyncExitStack, asynccontextmanager
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import socket
import time
from urllib.parse import urlencode

import pytest
import uvicorn
from nacl.signing import SigningKey

from awid.did import did_from_public_key
from awid.registry import RegistryClient
from awid.signing import canonical_json_bytes, sign_message
from test_cli_human_reply import _pem
from test_dashboard_privacy import TEAM, _request, privacy_app  # noqa: F401
from test_messages_http import _make_certificate, _make_keypair


@asynccontextmanager
async def registry_listener(env):
    existing = env.app.state.awid_registry_client
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    server = uvicorn.Server(uvicorn.Config(existing.transport.app, lifespan="off", log_level="error"))
    serving = asyncio.create_task(server.serve(sockets=[sock]))
    client = None
    try:
        for _ in range(100):
            if server.started:
                break
            await asyncio.sleep(.02)
        assert server.started
        origin = f"http://127.0.0.1:{sock.getsockname()[1]}"
        client = RegistryClient(origin, service_token=existing.service_token)
        env.app.state.awid_registry_client = client
        yield client, origin
    finally:
        env.app.state.awid_registry_client = existing
        if client:
            await client.aclose()
        server.should_exit = True
        await asyncio.wait_for(serving, 5)
        sock.close()


def grant_headers(grant_home, grant_id, origin, path, method="GET"):
    pem = (grant_home / "grant-signing.key").read_text().splitlines()
    seed = base64.b64decode("".join(pem[1:-1]))
    did = did_from_public_key(bytes(SigningKey(seed).verify_key))
    timestamp = datetime.now(timezone.utc).isoformat()
    payload = canonical_json_bytes(dict(
        v=1, auth="identity-grant", method=method, path=path,
        grant_id=grant_id, body_sha256=hashlib.sha256(b"").hexdigest(),
        timestamp=timestamp, aud=origin,
    ))
    return {
        "Authorization": f"AWEB-Grant DIDKey {did} {sign_message(seed, payload)}",
        "X-AWEB-Grant-ID": grant_id, "X-AWEB-Timestamp": timestamp,
        "X-AWEB-Signed-Payload": base64.urlsafe_b64encode(payload).decode().rstrip("="),
    }


@pytest.mark.asyncio
async def test_cli_never_grants_real_stack(privacy_app, tmp_path):
    env = privacy_app
    root = Path(__file__).resolve().parents[2]
    binary = tmp_path / "aw"
    build = await asyncio.create_subprocess_exec(
        "go", "build", "-o", str(binary), "./cmd/aw", cwd=root / "cli/go",
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
    )
    output, _ = await build.communicate()
    assert build.returncode == 0, output.decode()
    actor = env.actors["bob"]
    team_sk, _, team_did = _make_keypair()
    await env.db.execute("UPDATE {{tables.teams}} SET team_did_key=$1 WHERE team_id=$2", team_did, TEAM)
    await env.registry_db.execute("UPDATE {{tables.teams}} SET team_did_key=$1 WHERE name=$2", team_did, TEAM.split(":", 1)[0])
    cert = _make_certificate(team_sk, team_did, actor.did, team_id=TEAM, alias="bob", identity_scope="local")
    for field in ("signature", "member_did_aw", "member_address"):
        cert.pop(field)
    cert["signature"] = sign_message(team_sk, canonical_json_bytes(cert))
    home = tmp_path / "resident" / ".aw"
    home.mkdir(parents=True, mode=0o700)
    _pem(home / "signing.key", "ED25519 PRIVATE KEY", actor.sk)
    (home / "identity.yaml").write_text(json.dumps(dict(did=actor.did, custody="self", identity_scope="local")))
    (home / "certificate.json").write_text(json.dumps(cert))
    membership = dict(team_id=TEAM, alias="bob", cert_path="certificate.json")
    (home / "teams.yaml").write_text(json.dumps(dict(active_team=TEAM, memberships=[membership])))
    (home / "workspace.yaml").write_text(json.dumps(dict(
        aweb_url=str(env.client.base_url), memberships=[dict(membership, workspace_id=str(actor.workspace))],
    )))
    origin = str(env.client.base_url).rstrip("/")
    env.app.state.public_origin = origin
    child_env = {k: v for k, v in os.environ.items() if not k.startswith(("AW_", "AWEB_", "AWID_", "OATS_"))}
    child_env.update(HOME=str(tmp_path), XDG_CONFIG_HOME=str(tmp_path / "config"), AW_NO_UPDATE_CHECK="1")

    async def run(selected, *args, success=True):
        process = await asyncio.create_subprocess_exec(
            str(binary), "--identity-home", str(selected), *args,
            cwd=tmp_path, env=child_env, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
        )
        data, _ = await asyncio.wait_for(process.communicate(), 30)
        assert (process.returncode == 0) == success, data.decode()
        return data.decode()

    async with registry_listener(env) as (registry, registry_origin):
        child_env["AWID_REGISTRY_URL"] = registry_origin
        await registry.register_team_certificate(
            "example.test", TEAM.split(":", 1)[0], team_controller_signing_key=team_sk,
            certificate_id=cert["certificate_id"], member_did_key=actor.did,
            member_did_aw=None, member_address=None, alias="bob", identity_scope="local",
            certificate=base64.b64encode(json.dumps(cert).encode()).decode(),
        )
        custody_log = (tmp_path / "custody.log").open("wb")
        custody = await asyncio.create_subprocess_exec(
            str(binary), "--identity-home", str(home), "custody", "serve",
            cwd=tmp_path, env=child_env, stdout=custody_log, stderr=asyncio.subprocess.STDOUT,
        )
        try:
            for _ in range(100):
                if custody.returncode is not None:
                    pytest.fail("custody exited during startup")
                status = json.loads(await run(home, "custody", "status", "--json"))
                if status["status"] == "running":
                    break
                await asyncio.sleep(.05)
            assert "grant_never_ttl.v1" in status["ops"]
            finite = json.loads(await run(home, "id", "grant", "mint", "--scope", "mail.read", "--ttl", "60s", "--out", str(tmp_path / "finite"), "--json"))
            assert finite["expires_at"] != "never"
            finite_row = await env.db.fetch_one("SELECT issued_at, expires_at FROM {{tables.identity_session_grants}} WHERE grant_id=$1::uuid", finite["grant_id"])
            assert finite_row["expires_at"] - finite_row["issued_at"] == timedelta(seconds=60)

            for cause, terminal in (("owner", "grant_revoked"), ("subject", "grant_subject_inactive"), ("issuer", "grant_issuer_revoked")):
                grant_home = tmp_path / cause
                args = ["id", "grant", "mint", "--bundle", "normal-agent", "--custody-socket", "auto", "--out", str(grant_home), "--json"]
                if cause == "owner":
                    args += ["--ttl", "never"]
                minted = json.loads(await run(home, *args))
                grant_id = minted["grant_id"]
                assert minted["expires_at"] == "never"
                shown = json.loads(await run(home, "id", "grant", "show", grant_id, "--json"))
                assert shown["expires_at"] == "never"
                if cause == "owner":
                    # Cross the storage horizon without mocking a clock or auth.
                    await env.db.execute("UPDATE {{tables.identity_session_grants}} SET issued_at='1900-01-01T00:00:00Z', expires_at='2000-01-01T00:00:00Z' WHERE grant_id=$1::uuid", grant_id)
                inbox = json.loads(await run(grant_home, "mail", "inbox", "--json"))
                assert isinstance(inbox["messages"], list)
                heartbeat = await env.client.post("/v1/agents/heartbeat", headers=grant_headers(grant_home, grant_id, origin, "/v1/agents/heartbeat", "POST"))
                assert heartbeat.status_code == 200, heartbeat.text
                presence = await env.db.fetch_one("SELECT last_seen_at, expires_at FROM {{tables.identity_grant_liveness}} WHERE grant_id=$1::uuid", grant_id)
                assert presence["expires_at"] > presence["last_seen_at"]
                chat = await _request(env, "alice", "POST", "/v1/chat/sessions", {"to_dids": [actor.did], "message": "stream revocation control"})
                assert chat.status_code == 200, chat.text
                session_id = chat.json()["session_id"]
                query = urlencode({"deadline": (datetime.now(timezone.utc) + timedelta(seconds=50)).isoformat()})
                paths = [f"/v1/events/stream?{query}", f"/v1/status/stream?workspace_id={actor.workspace}&{query}", f"/v1/chat/sessions/{session_id}/stream?{query}"]
                async with AsyncExitStack() as stack:
                    streams = []
                    for path in paths:
                        response = await stack.enter_async_context(env.client.stream("GET", path, headers=grant_headers(grant_home, grant_id, origin, path), timeout=40))
                        assert response.status_code == 200, await response.aread()
                        streams.append(response)
                    start = time.monotonic()
                    if cause == "owner":
                        await run(home, "id", "grant", "revoke", grant_id, "--json")
                    elif cause == "subject":
                        await env.db.execute("UPDATE {{tables.agents}} SET status='retired' WHERE agent_id=$1", actor.id)
                    else:
                        await registry.revoke_team_certificate("example.test", TEAM.split(":", 1)[0], team_controller_signing_key=team_sk, certificate_id=cert["certificate_id"])
                    denied = await env.client.get("/v1/messages/inbox", headers=grant_headers(grant_home, grant_id, origin, "/v1/messages/inbox"))
                    assert denied.status_code == 403, denied.text

                    async def terminal_event(response):
                        async for line in response.aiter_lines():
                            if terminal in line:
                                return
                        raise AssertionError(f"stream closed without {terminal}")

                    await asyncio.wait_for(asyncio.gather(*(terminal_event(r) for r in streams)), 35)
                    assert time.monotonic() - start <= 35
                if cause == "subject":
                    await env.db.execute("UPDATE {{tables.agents}} SET status='active' WHERE agent_id=$1", actor.id)
        finally:
            custody.terminate()
            await asyncio.wait_for(custody.wait(), 10)
            custody_log.close()

"""The real CLI carries discovery into a real AWID enrollment read.

Only the public-default proxy is a refusal fixture. The discovered service,
registry, signature admission, certificate registration and connect are real.
"""
import asyncio
import base64
from contextlib import asynccontextmanager
import json
import os
from pathlib import Path

import pytest

from identity_binding_support import register_global_identity
from test_cli_human_reply import _pem
from test_cli_never_grants import registry_listener
from test_dashboard_privacy import TEAM, TEAM_NAME, privacy_app  # noqa: F401
from test_identity_binding_http import certificate, request


@asynccontextmanager
async def public_default_probe():
    requests = []

    async def refuse(reader, writer):
        try:
            headers = await reader.readuntil(b"\r\n\r\n")
            requests.append(headers.split(b"\r\n", 1)[0].decode())
            writer.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    server = await asyncio.start_server(refuse, "127.0.0.1", 0)
    try:
        yield f"http://127.0.0.1:{server.sockets[0].getsockname()[1]}", requests
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_global_inviter_without_registry_pins_uses_real_discovery(
    privacy_app, source_cli_binary, tmp_path, monkeypatch,
):
    env = privacy_app
    actor = env.actors["bob"]
    calls = []
    original_registry = env.app.state.awid_registry_client.transport.app

    async def observe_registry(scope, receive, send):
        if scope["type"] == "http":
            calls.append((scope["method"], scope["path"]))
        await original_registry(scope, receive, send)

    monkeypatch.setattr(env.app.state.awid_registry_client.transport, "app", observe_registry)
    async with registry_listener(env) as (registry, registry_origin):
        stable = await register_global_identity(env, actor, "example.test/bob")
        actor.certificate = certificate(env, actor, stable, "example.test/bob")
        admitted = await request(env, actor, "POST", "/v1/connect", {})
        assert admitted.status_code == 200, admitted.text
        service_origin = str(env.client.base_url).rstrip("/")
        env.app.state.public_origin = service_origin
        monkeypatch.setenv("AWEB_DATABASE_URL", env.db.config.get_dsn())
        monkeypatch.setenv("AWEB_DISCOVERY_ORIGIN", service_origin)
        monkeypatch.setenv("AWID_PUBLIC_REGISTRY_URL", registry_origin)
        discovery_calls = []
        discovery_body = bytearray()
        route = next(route for route in env.app.routes if getattr(route, "path", "") == "/api/v1/discovery")
        original_discovery = route.app

        async def observe_discovery(scope, receive, send):
            discovery_calls.append(scope["path"])
            async def observe_response(message):
                if message["type"] == "http.response.body":
                    discovery_body.extend(message.get("body", b""))
                await send(message)
            await original_discovery(scope, receive, observe_response)

        monkeypatch.setattr(route, "app", observe_discovery)
        repo = tmp_path / "repo"
        repo.mkdir()
        for args in (("init",), ("config", "user.name", "Fixture"),
                     ("config", "user.email", "fixture@example.test"), ("commit", "--allow-empty", "-m", "fixture")):
            process = await asyncio.create_subprocess_exec("git", *args, cwd=repo,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            stdout, stderr = await process.communicate()
            assert process.returncode == 0, stderr.decode()
        home = repo / ".aw"
        (home / "team-certs").mkdir(parents=True)
        _pem(home / "signing.key", "ED25519 PRIVATE KEY", actor.sk)
        identity = dict(did=actor.did, stable_id=stable, address="example.test/bob",
                        custody="self", identity_scope="global")
        (home / "identity.yaml").write_text(json.dumps(identity))
        cert_path = "team-certs/" + TEAM.replace("__", "____").replace(":", "__") + ".pem"
        (home / cert_path).write_bytes(base64.b64decode(actor.certificate))
        membership = dict(team_id=TEAM, alias="bob", cert_path=cert_path,
                          workspace_id=str(actor.workspace))
        (home / "teams.yaml").write_text(json.dumps(dict(active_team=TEAM, memberships=[membership])))
        (home / "workspace.yaml").write_text(json.dumps(dict(aweb_url=service_origin, memberships=[membership])))
        team_keys = tmp_path / ".awid" / "team-keys" / "example.test"
        team_keys.mkdir(parents=True)
        _pem(team_keys / f"{TEAM_NAME}.key", "ED25519 PRIVATE KEY", env.team_sk)
        child_env = {k: v for k, v in os.environ.items() if not k.startswith(("AW", "XDG_"))}
        child_env.update(HOME=str(tmp_path), AW_NO_UPDATE_CHECK="1")
        calls.clear()
        async with public_default_probe() as (proxy, default_calls):
            child_env.update(HTTPS_PROXY=proxy, HTTP_PROXY=proxy, NO_PROXY="127.0.0.1,localhost")
            process = await asyncio.create_subprocess_exec(str(source_cli_binary), "workspace", "add-worktree",
                "developer", "--name", "discovery-child", "--json", cwd=repo, env=child_env,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            stdout, stderr = await asyncio.wait_for(process.communicate(), 45)
            assert discovery_calls == ["/api/v1/discovery"]
            assert json.loads(discovery_body)["registry_url"] == registry_origin
            assert process.returncode == 0, f"{stderr.decode()} public default attempts={default_calls}"
            assert default_calls == []
        assert ("GET", f"/v1/did/{stable}/key") in calls
        assert ("POST", f"/v1/namespaces/example.test/teams/{TEAM_NAME}/certificates") in calls
        result = json.loads(stdout)
        assert result["alias"] == "discovery-child"
        child_home = Path(result["worktree_path"]) / ".aw"
        assert not (child_home / "identity.yaml").exists()
        assert json.loads((home / "identity.yaml").read_text()) == identity
        row = await env.db.fetch_one("SELECT identity_scope FROM {{tables.agents}} WHERE team_id=$1 AND alias='discovery-child'", TEAM)
        assert row is not None and row["identity_scope"] == "local"
        certs = await registry.list_team_certificates("example.test", TEAM_NAME, active_only=True)
        assert any(cert.alias == "discovery-child" for cert in certs)

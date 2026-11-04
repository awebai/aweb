"""Mixed-version journeys against an unmodified published server package.

Install aweb==1.27.15 into an isolated target directory, then set
AW_TEST_PRE_MEMBERSHIP_SERVER_ROOT and AW_TEST_RELEASED_CLI_BINARY. The older
app reads the actual upgraded database; no response projection is stripped.
"""
import asyncio
from contextlib import asynccontextmanager
import json
import os
from pathlib import Path
import sys
from urllib.parse import quote

import httpx
import pytest

from test_actf_return_route import route_pair, _cli, _effects, _reader_home, _send, _socket, _origin  # noqa: F401
from test_messages_http import _signed_identity_headers


@asynccontextmanager
async def _older_server(node, tmp_path):
    package = os.environ.get("AW_TEST_PRE_MEMBERSHIP_SERVER_ROOT")
    if not package:
        pytest.skip("set AW_TEST_PRE_MEMBERSHIP_SERVER_ROOT to published aweb1.27.15")
    package = str(Path(package).resolve())
    assert (Path(package) / "aweb-1.27.15.dist-info").is_dir()
    database = await node.db.fetch_value("SELECT current_database()")
    env = dict(os.environ)
    env.update(PYTHONPATH=package, AWEB_DATABASE_URL=(
        f"postgresql://{quote(env.get('TEST_DB_USER','postgres'))}:{quote(env.get('TEST_DB_PASSWORD','postgres'))}"
        f"@{env.get('TEST_DB_HOST','127.0.0.1')}:{env.get('TEST_DB_PORT','5432')}/{database}"),
        AWID_REGISTRY_URL=node.registry_client.registry_url, AWEB_LOG_LEVEL="error")
    sock = _socket()
    origin, port = _origin(sock), sock.getsockname()[1]
    sock.close()
    env["AWEB_PUBLIC_ORIGIN"] = origin
    code = '''import asyncio, os
import importlib.metadata
from pathlib import Path
import aweb.api
assert importlib.metadata.version("aweb") == "1.27.15"
assert Path(aweb.api.__file__).resolve().is_relative_to(Path(os.environ["PYTHONPATH"]).resolve())
from aweb.api import create_app
from aweb.db import DatabaseInfra
from redis.asyncio import Redis
import uvicorn
async def main():
    db = DatabaseInfra()
    await db.initialize(run_migrations=False)
    redis = Redis.from_url(os.environ["REDIS_URL"], decode_responses=True)
    try:
        app = create_app(db_infra=db, redis=redis)
        await uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=PORT, log_level="error", ws="none")).serve()
    finally:
        await redis.aclose()
        await db.close()
asyncio.run(main())
'''.replace("PORT", str(port))
    with (tmp_path / "older-server.log").open("wb") as log:
        process = await asyncio.create_subprocess_exec(sys.executable, "-c", code, env=env,
            cwd=tmp_path, stdout=log, stderr=log)
        try:
            async with httpx.AsyncClient(base_url=origin) as client:
                for _ in range(200):
                    if process.returncode is not None:
                        pytest.fail((tmp_path / "older-server.log").read_text())
                    try:
                        response = await client.get("/health")
                        if response.status_code == 200:
                            break
                    except httpx.RequestError:
                        pass
                    await asyncio.sleep(.05)
                else:
                    pytest.fail("published older server did not become healthy: " + (tmp_path / "older-server.log").read_text())
                yield origin, client
        finally:
            if process.returncode is None:
                process.terminate()
                try:
                    await asyncio.wait_for(process.wait(), 5)
                except TimeoutError:
                    process.kill()
            await process.wait()


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
@pytest.mark.parametrize("encrypted", [False, True], ids=["plaintext", "v2"])
async def test_released_cli_without_server_membership_is_stale(route_pair, tmp_path, kind, encrypted):
    binary = os.environ.get("AW_TEST_RELEASED_CLI_BINARY")
    if not binary:
        pytest.skip("set AW_TEST_RELEASED_CLI_BINARY")
    source, target = route_pair.source, route_pair.target
    response, first = await _send(source.local, target.global_actor, kind, encrypted=encrypted)
    assert response.status_code == 200, response.text
    async with _older_server(target, tmp_path) as (origin, client):
        path = "/v1/messages/inbox" if kind == "mail" else f"/v1/chat/sessions/{first.cid}/messages"
        recipient = target.global_actor
        read = await client.get(path, headers=_signed_identity_headers(recipient.sk, recipient.did, recipient.stable))
        assert read.status_code == 200, read.text
        message = next(row for row in read.json()["messages"] if row["message_id"] == str(first.mid))
        assert "sender_membership" not in message
        home, env = _reader_home(recipient, tmp_path / "reader")
        config = json.loads((home / "workspace.yaml").read_text())
        config["aweb_url"] = origin
        (home / "workspace.yaml").write_text(json.dumps(config))
        args = ["mail", "inbox"] if kind == "mail" else ["chat", "history", "--session-id", str(first.cid)]
        result = await _cli(binary, home, env, *args, "--json")
        message = next(row for row in result["messages"] if row["message_id"] == str(first.mid))
        # Athena's matrix-11 ruling: the old chat projection substitutes an
        # alias for the signed label. The released reader rejects that before
        # membership fallback; none of these old-server reads may be trusted.
        expected = "failed" if kind == "chat" and not encrypted else "verification_stale"
        assert message["verification_status"] == expected, message
        assert message["verification_status"] != "verified"
        assert message["body"] == first.fields["body"]


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
@pytest.mark.parametrize("encrypted", [False, True], ids=["plaintext", "v2"])
async def test_real_cli_explains_older_receiver_refusal(route_pair, source_cli_binary, tmp_path, kind, encrypted):
    source, target = route_pair.source, route_pair.target
    async with _older_server(target, tmp_path) as (origin, _):
        await target.registry.db.execute("UPDATE {{tables.dns_namespaces}} SET default_delivery_origin=$1 WHERE domain=$2", origin, target.domain)
        home, env = _reader_home(source.local, tmp_path / "sender")
        env["AWID_REGISTRY_URL"] = target.registry_client.registry_url
        body = tmp_path / "body.txt"
        body.write_text("Mixed-version first contact")
        args = (["mail", "send", "--to-address", target.global_actor.address, "--subject", "Mixed versions"]
                if kind == "mail" else ["chat", "send-and-leave", target.global_actor.address])
        if not encrypted:
            args.append("--plaintext")
        before = await _effects(source), await _effects(target)
        process = await asyncio.create_subprocess_exec(str(source_cli_binary), "--identity-home", str(home),
            *args, "--body-file", str(body), "--json", cwd=home.parent, env=env,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        out, err = await asyncio.wait_for(process.communicate(), 30)
        assert process.returncode != 0
        error = json.loads(out)["error"]
        assert error.get("reason") in {"local_sender_route_mismatch", "federation_envelope_invalid"}, error
        assert "recipient's server may not yet accept first messages from team-only agents" in err.decode(), err.decode()
        assert (await _effects(source), await _effects(target)) == before

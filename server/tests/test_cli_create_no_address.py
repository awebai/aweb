"""Ordinary no-address creation through the built aw and real AWID/PostgreSQL."""

import asyncio
import json
import os
import socket
from contextlib import asynccontextmanager

import httpx
import pytest
import uvicorn
from awid_service.testing import running_registry


def _listener():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    return sock, f"http://127.0.0.1:{sock.getsockname()[1]}"


@asynccontextmanager
async def _serving(app, sock):
    server = uvicorn.Server(
        uvicorn.Config(app, lifespan="off", log_level="error", ws="none")
    )
    serving = asyncio.create_task(server.serve(sockets=[sock]))
    try:
        for _ in range(250):
            if server.started:
                break
            await asyncio.sleep(0.02)
        assert server.started
        yield
    finally:
        server.should_exit = True
        await asyncio.wait_for(serving, 5)
        sock.close()


@asynccontextmanager
async def _running(home, *args, grace=5.0):
    """The aw process for args, which never outlives its caller: on every
    exit, a timeout, cancellation or failed assertion included, it is asked to
    terminate, killed if it has not after grace seconds, and waited for."""
    root, env = home
    proc = await asyncio.create_subprocess_exec(
        os.environ["AW_TEST_CLI_BINARY"],
        "--json",
        *args,
        cwd=root,
        env=env,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        yield proc
    finally:
        if proc.returncode is None:
            proc.terminate()
            try:
                await asyncio.wait_for(proc.wait(), grace)
            except TimeoutError:
                proc.kill()
                await proc.wait()


async def _aw(home, *args, timeout=120, grace=5.0):
    """aw's exit status, its --json answer and its progress lines."""
    async with _running(home, *args, grace=grace) as proc:
        out, err = await asyncio.wait_for(proc.communicate(), timeout)
    return proc.returncode, json.loads(out or b"{}"), err.decode()


@pytest.mark.usefixtures("source_cli_binary")
@pytest.mark.asyncio
async def test_a_root_is_created_with_no_address_at_the_real_registry_and_only_once(
    test_db_factory, tmp_path
):
    registry_sock, registry_origin = _listener()
    db = await test_db_factory.create_db(suffix="cli_create", schema="app")
    async with running_registry(db.config.get_dsn()) as registry:
        # Served at registry_origin, which covering controller signatures name.
        registry.app.state.awid_public_origins = (
            *registry.app.state.awid_public_origins,
            registry_origin,
        )
        async with _serving(registry.app, registry_sock):
            root = (tmp_path / "new-root").resolve()
            no_opener = tmp_path / "no-browser-opener"
            no_opener.mkdir()
            env = {
                k: v for k, v in os.environ.items() if not k.startswith(("AW", "XDG_"))
            }
            env.update(
                HOME=str(tmp_path),
                XDG_CONFIG_HOME=str(tmp_path / ".config"),
                XDG_STATE_HOME=str(tmp_path / ".state"),
                AW_NO_UPDATE_CHECK="1",
                PATH=str(no_opener),
            )
            create = (
                "--identity-home",
                str(root),
                "id",
                "create",
                "--no-address",
                "--registry",
                registry_origin,
            )
            status, created, progress = await _aw((tmp_path, env), *create)
            assert status == 0, progress
            assert (
                created["status"] == "created"
                and created["registry_url"] == registry_origin
            )
            # The registry itself maps the new did:aw to the key aw holds.
            async with httpx.AsyncClient(base_url=registry_origin) as client:
                key = (await client.get(f"/v1/did/{created['did_aw']}/key")).json()
            assert key["current_did_key"] == created["did_key"]
            assert (root / "signing.key").stat().st_mode & 0o777 == 0o600
            assert "address" not in (root / "identity.yaml").read_text()
            # A rerun on the complete identity creates nothing.
            status, refused, progress = await _aw((tmp_path, env), *create)
            assert status != 0 and refused["error"]["code"] == "identity_exists", (
                progress
            )

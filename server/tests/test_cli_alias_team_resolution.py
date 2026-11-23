"""Real CLI/AWID/aweb: an unavailable selected-team roster cannot select a peer.

Both teams and their members are registered and admitted by the production
services, which also handle roster reads, sends, revocations and inbox reads. The
fault is a genuinely unreachable client-only registry origin, a conflicting
registry pin, or a dropped agent-list TCP connection; no decision is replaced.
"""

from __future__ import annotations

import asyncio
import json
import os
import socket
from contextlib import asynccontextmanager
from pathlib import Path
from uuid import UUID, uuid4

import pytest
import pytest_asyncio
import uvicorn
from aweb_naapp_testing.network import make_certificates
import yaml
from awid.identity_observation import IdentityKind
from awid.team_certificate import decode_team_certificate, issue_team_certificate

from messaging_actor_support import admit_messaging_actor, privacy_actor, register_messaging_team
from tests.test_addressless_sender_cli import _registry_http
from tests.test_dashboard_privacy import TEAM, privacy_stack
from tests.test_messages_http import _make_keypair, _signed_identity_headers


@pytest_asyncio.fixture
async def alias_world(shared_test_pool, monkeypatch):
    async with privacy_stack(shared_test_pool, monkeypatch, aliases=()) as env:
        yield env


@asynccontextmanager
async def unavailable_origin():
    # Hold the port without listening: real TCP connect refuses it, and no
    # unrelated process can acquire it during the CLI invocation.
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    try:
        yield f"http://127.0.0.1:{sock.getsockname()[1]}"
    finally:
        sock.close()


@asynccontextmanager
async def registry_origin(env, tmp_path, monkeypatch, secured):
    if not secured:
        async with _registry_http(env.registry_app) as (origin, _):
            yield origin
        return
    certificates = make_certificates(tmp_path, ["localhost"], ["127.0.0.1"])
    monkeypatch.setenv("SSL_CERT_FILE", str(certificates.ca_file))
    monkeypatch.setenv("GODEBUG", ",".join(filter(None, [os.environ.get("GODEBUG"), "x509sslcertoverrideplatform=1"])))
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    origin = f"https://127.0.0.1:{sock.getsockname()[1]}"
    server = uvicorn.Server(uvicorn.Config(
        env.registry_app, lifespan="off", log_level="error", ws="none",
        ssl_certfile=str(certificates.cert_file), ssl_keyfile=str(certificates.key_file),
    ))
    serving = asyncio.create_task(server.serve(sockets=[sock]))
    try:
        for _ in range(100):
            if server.started:
                break
            await asyncio.sleep(.02)
        assert server.started
        yield origin
    finally:
        server.should_exit = True
        await asyncio.wait_for(serving, 5)
        sock.close()


@asynccontextmanager
async def agent_list_connection_failure(origin):
    """A TCP fault at the client edge, with all other requests forwarded.

    Drop only the agent-list request, without inventing a roster, identity,
    auth result or send response. Closing each forwarded connection lets us
    inspect the next request even when the CLI normally reuses connections.
    """
    from types import SimpleNamespace
    from urllib.parse import urlsplit

    upstream = urlsplit(origin)
    fault = SimpleNamespace(enabled=False, requests=[])

    async def forward(reader, writer):
        upstream_writer = None
        try:
            headers = await reader.readuntil(b"\r\n\r\n")
            method, target, _ = headers.split(b"\r\n", 1)[0].decode().split()
            fault.requests.append((method, target))
            if fault.enabled and method == "GET" and target.split("?", 1)[0] == "/v1/agents":
                return
            upstream_reader, upstream_writer = await asyncio.open_connection(upstream.hostname, upstream.port)
            lines = [line for line in headers.split(b"\r\n")[:-2] if not line.lower().startswith(b"connection:")]
            upstream_writer.write(b"\r\n".join([*lines, b"Connection: close", b"", b""]))
            await upstream_writer.drain()

            async def body():
                while chunk := await reader.read(65536):
                    upstream_writer.write(chunk)
                    await upstream_writer.drain()

            sending = asyncio.create_task(body())
            try:
                while chunk := await upstream_reader.read(65536):
                    writer.write(chunk)
                    await writer.drain()
            finally:
                sending.cancel()
                await asyncio.gather(sending, return_exceptions=True)
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            if upstream_writer:
                upstream_writer.close()
                await upstream_writer.wait_closed()
            writer.close()
            await writer.wait_closed()

    server = await asyncio.start_server(forward, "127.0.0.1", 0)
    try:
        yield f"http://127.0.0.1:{server.sockets[0].getsockname()[1]}", fault
    finally:
        server.close()
        await server.wait_closed()


async def run_aw(binary, cwd, env, *args):
    process = await asyncio.create_subprocess_exec(
        str(binary), "--json", *args, cwd=cwd, env=env,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    try:
        out, err = await asyncio.wait_for(process.communicate(), 45)
    finally:
        if process.returncode is None:
            process.kill()
            await process.wait()
    return process.returncode, json.loads(out or b"{}"), err.decode()


async def register_sender(env, team, controller, did):
    name, domain = team.split(":", 1)
    certificate, wire = issue_team_certificate(
        team_id=team, team_signing_key=controller, member_did_key=did,
        alias="sender", identity_scope="local",
    )
    await env.app.state.awid_registry_client.register_team_certificate(
        domain, name, team_controller_signing_key=controller,
        certificate_id=certificate["certificate_id"], member_did_key=did,
        member_did_aw=None, member_address=None, alias="sender", identity_scope="local",
        certificate=wire,
    )
    return certificate


async def memberships(env, tmp_path, registry_url, *, missing):
    from types import SimpleNamespace

    beta = f"alias-{uuid4().hex[:12]}:example.test"
    beta_key, _, beta_did = _make_keypair()
    beta_world = SimpleNamespace(
        app=env.app, client=env.client, registry=env.registry,
        team_sk=beta_key, team_did=beta_did,
    )
    await register_messaging_team(beta_world, team_id=beta)
    alpha_alias = "someone-else" if missing else "reviewer"
    alice = privacy_actor(await admit_messaging_actor(
        env, alias=alpha_alias, team_id=TEAM, kind=IdentityKind.HUMAN,
    ))
    bob = privacy_actor(await admit_messaging_actor(env, alias="bob", team_id=TEAM, local=True))
    carol = privacy_actor(await admit_messaging_actor(
        beta_world, alias="reviewer", team_id=beta, local=True,
    ))
    env.actors.update(alice=alice, bob=bob, carol=carol)
    projection = await env.db.fetch_one(
        """SELECT did_aw, did_aw_verified_key, human_verified_key
           FROM {{tables.agents}} WHERE agent_id=$1""",
        alice.id,
    )
    assert projection is not None
    assert (projection["did_aw"] or "").startswith("did:aw:")
    assert projection["did_aw"] == alice.stable_id
    assert projection["did_aw_verified_key"] == alice.did
    assert projection["human_verified_key"] == alice.did
    home = tmp_path / "sender-home"
    home.mkdir(mode=0o700)
    child_env = {k: v for k, v in os.environ.items() if not k.startswith(("AW", "XDG_"))}
    child_env.update(AWEB_IDENTITY_HOME=str(home), AWEB_URL=str(env.client.base_url), AWID_REGISTRY_URL=registry_url,
        AW_NO_UPDATE_CHECK="1", HOME=str(tmp_path), XDG_CONFIG_HOME=str(tmp_path / "config"))
    binary = Path(os.environ["AW_TEST_CLI_BINARY"])
    code, identity, stderr = await run_aw(binary, tmp_path, child_env,
        "--identity-home", str(home), "id", "create", "--local")
    assert code == 0, (identity, stderr)
    sender_did = identity["did_key"]
    # Let the real CLI write every identity, certificate, membership and
    # workspace file. Registry pins belong to teams.yaml, never workspace.yaml.
    for team, key in ((TEAM, env.team_sk), (beta, beta_key)):
        cert = await register_sender(env, team, key, sender_did)
        code, fetched, stderr = await run_aw(binary, tmp_path, child_env,
            "id", "team", "fetch-cert", "--team", team.split(":", 1)[0],
            "--namespace", "example.test", "--cert-id", cert["certificate_id"], "--registry", registry_url)
        assert code == 0, (fetched, stderr)
        code, connected, stderr = await run_aw(binary, tmp_path, child_env,
            "workspace", "connect", "--team", team, "--service", str(env.client.base_url))
        assert code == 0, (connected, stderr)
        assert connected["team_id"] == team
    code, switched, stderr = await run_aw(binary, tmp_path, child_env, "id", "team", "switch", TEAM)
    assert code == 0, (switched, stderr)
    code, status, stderr = await run_aw(binary, tmp_path, child_env, "workspace", "status")
    assert code == 0, (status, stderr)
    assert status["selected_team"] == TEAM
    alpha_sender = await env.db.fetch_value("SELECT agent_id FROM {{tables.agents}} WHERE team_id=$1 AND did_key=$2", TEAM, sender_did)
    beta_sender = await env.db.fetch_value("SELECT agent_id FROM {{tables.agents}} WHERE team_id=$1 AND did_key=$2", beta, sender_did)
    assert alpha_sender is not None and beta_sender is not None
    return SimpleNamespace(beta=beta, alpha_sender=alpha_sender, beta_sender=beta_sender,
        human=decode_team_certificate(alice.certificate),
        env=child_env, home=home)


async def inbox(env, actor):
    response = await env.client.get("/v1/messages/inbox", headers=_signed_identity_headers(actor.sk, actor.did, actor.stable_id, b""))
    assert response.status_code == 200, response.text
    return response.json()["messages"]


@pytest.mark.usefixtures("source_cli_binary")
@pytest.mark.asyncio
@pytest.mark.parametrize("condition,kind", [
    ("available", "mail"), ("https", "mail"), ("unreachable", "mail"), ("pin_refused", "mail"),
    ("revoked_unreachable", "mail"), ("not_found", "mail"),
    ("unreachable_not_found", "mail"), ("agent_list_unavailable", "mail"),
    ("listed_agent", "mail"), ("unknown", "mail"),
    ("available", "chat"), ("unreachable", "chat"),
    ("agent_list_unavailable", "chat"), ("listed_agent", "chat"), ("unknown", "chat"),
    ("agent_list_unavailable", "chat_wait"), ("unreachable", "chat_wait"),
])
async def test_bare_alias_never_changes_team_on_unknown_roster(alias_world, tmp_path, monkeypatch, condition, kind):
    tmp_path = tmp_path.resolve()
    env = alias_world
    async with (
        registry_origin(env, tmp_path, monkeypatch, condition == "https") as registry_url,
        unavailable_origin() as down,
        agent_list_connection_failure(str(env.client.base_url)) as (front, fault),
    ):
        env.client.base_url = front
        env.app.state.public_origin = front
        world = await memberships(env, tmp_path, registry_url, missing=condition in ("not_found", "unreachable_not_found"))
        if condition == "revoked_unreachable":
            await env.app.state.awid_registry_client.revoke_team_certificate(
                "example.test", TEAM.split(":", 1)[0], team_controller_signing_key=env.team_sk,
                certificate_id=world.human["certificate_id"],
            )
        if condition in ("unreachable", "revoked_unreachable", "unreachable_not_found"):
            world.env["AWID_REGISTRY_URL"] = down
        if condition in ("unreachable", "pin_refused", "revoked_unreachable", "unreachable_not_found"):
            # Change only the selected membership's stored pin to introduce
            # the declared fault after successful real CLI setup/routing.
            state = yaml.safe_load((world.home / "teams.yaml").read_text())
            next(entry for entry in state["memberships"] if entry["team_id"] == TEAM)["registry_url"] = down
            (world.home / "teams.yaml").write_text(yaml.safe_dump(state))
        # Faults need not spend the default API timeout retrying a closed
        # endpoint; this is the real CLI's supported request deadline.
        if condition not in ("available", "https", "listed_agent", "unknown", "not_found"):
            world.env["AWEB_HTTP_TIMEOUT"] = "2s"
        fault.enabled = condition == "agent_list_unavailable"
        fault.requests.clear()
        recipient = "bob" if condition == "listed_agent" else "absent-everywhere" if condition == "unknown" else "reviewer"
        body = tmp_path / "body.txt"
        body.write_text("The selected team's reviewer is the intended recipient.")
        binary = Path(os.environ["AW_TEST_CLI_BINARY"])
        command = (["mail", "send", "--to", recipient, "--subject", "alias isolation"] if kind == "mail"
            else ["chat", "send-and-wait" if kind == "chat_wait" else "send-and-leave", recipient, "--start-conversation"])
        if condition not in ("available", "https", "listed_agent", "unknown", "not_found"):
            # Exercise the send's own lookup branch, without spending its
            # request deadline first searching other local memberships.
            command = ["--team", TEAM, *command]
        # Independently confirm the real fault once; each send also observes
        # its own lookup error and must never issue a delivery request.
        if condition == "unreachable" and kind == "mail":
            roster_code, roster, roster_error = await run_aw(
                binary, tmp_path, world.env, "id", "team", "members", "--team-id", TEAM,
            )
            assert roster_code != 0, (roster, roster_error)
        code, result, stderr = await run_aw(binary, tmp_path, world.env, *command, "--plaintext", "--body-file", str(body))
        rows = await env.db.fetch_all("SELECT * FROM {{tables.messages}} ORDER BY created_at")
        alpha_inbox, beta_inbox = await inbox(env, env.actors["alice"]), await inbox(env, env.actors["carol"])
        lookup_failed = condition in ("unreachable", "pin_refused", "revoked_unreachable", "unreachable_not_found", "agent_list_unavailable")
        if lookup_failed or condition == "unknown" or (kind.startswith("chat") and condition != "listed_agent"):
            assert code != 0, (result, stderr)
            assert not rows and not alpha_inbox and not beta_inbox, (rows, alpha_inbox, beta_inbox)
            assert await env.db.fetch_value("SELECT count(*) FROM {{tables.chat_messages}}") == 0
            assert await env.db.fetch_value("SELECT count(*) FROM {{tables.chat_sessions}}") == 0
            if lookup_failed:
                message = result["error"]["message"]
                assert "lookup failed" in message and "retry" in message, (result, stderr)
                assert "full address" in message and "DID" in message, (result, stderr)
                assert "agent list" in message if condition == "agent_list_unavailable" else "roster" in message
                assert not any(method == "POST" and path in ("/v1/messages", "/v1/chat/sessions") for method, path in fault.requests)
            elif condition == "unknown":
                assert result["error"]["http_status"] == 404, (result, stderr)
                assert any(method == "POST" for method, _ in fault.requests)
            else:
                assert result["error"]["reason"] == "recipient_human_mail_only", (result, stderr)
            return
        if kind == "chat":
            assert code == 0, (result, stderr)
            assert not rows and not alpha_inbox and not beta_inbox
            assert await env.db.fetch_value("SELECT count(*) FROM {{tables.chat_messages}}") == 1
            assert await env.db.fetch_value("SELECT count(*) FROM {{tables.chat_sessions}}") == 1
            return
        assert code == 0, (result, stderr)
        assert len(rows) == 1, rows
        [stored] = rows
        selected_beta = condition == "not_found"
        expected = env.actors["carol"] if selected_beta else env.actors["bob"] if condition == "listed_agent" else env.actors["alice"]
        assert stored["message_id"] == UUID(result["message_id"])
        assert stored["team_id"] == (world.beta if selected_beta else TEAM), dict(stored)
        assert stored["from_agent_id"] == (world.beta_sender if selected_beta else world.alpha_sender), dict(stored)
        if condition in ("available", "https"):
            # Direct roster sends store the global participant's stable ID
            # (docs/identity-messaging-contract.md:126–131).
            assert stored["to_did"] == expected.stable_id, dict(stored)
            assert stored["to_agent_id"] is None, dict(stored)
        else:
            assert stored["to_did"] == expected.did, dict(stored)
            assert stored["to_agent_id"] == expected.id, dict(stored)
        selected_inbox = await inbox(env, env.actors["bob"]) if condition == "listed_agent" else beta_inbox if selected_beta else alpha_inbox
        assert [str(row["message_id"]) for row in selected_inbox] == [result["message_id"]]
        assert not (alpha_inbox if selected_beta else beta_inbox)
        if selected_beta:
            assert world.beta in stderr, (result, stderr)
        assert yaml.safe_load((world.home / "teams.yaml").read_text())["active_team"] == TEAM

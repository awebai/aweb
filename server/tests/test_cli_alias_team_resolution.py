"""Real CLI/AWID/aweb: an unavailable selected-team roster cannot select a peer.

Disposable SQL provisions two teams. All certificate registrations/revocations,
roster reads, mail/chat sends and inbox reads use real production services. The
fault is an unavailable client-only registry transport (or a conflicting
registry pin), never a substituted response or product test hook.
"""

from __future__ import annotations

import asyncio
import json
import os
from contextlib import asynccontextmanager
from pathlib import Path
from uuid import UUID, uuid4

import pytest
import yaml
from awid.signing import canonical_json_bytes, load_signing_key_pem, sign_message

from tests.test_addressless_sender_cli import _registry_http
from tests.test_dashboard_privacy import TEAM, privacy_app as privacy_app  # noqa: F401
from tests.test_messages_http import _encode_certificate, _make_certificate, _make_keypair, _signed_identity_headers


@asynccontextmanager
async def unavailable_origin():
    # Keep the port owned and fail with a real TCP close, without serving HTTP.
    # A bound but non-listening socket silently times out on some platforms.
    async def close_connection(_reader, writer):
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(close_connection, "127.0.0.1", 0)
    try:
        yield f"http://127.0.0.1:{server.sockets[0].getsockname()[1]}"
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


async def register(env, team, controller, actor, alias):
    domain, name = team.split(":", 1)[1], team.split(":", 1)[0]
    certificate = _make_certificate(controller, "", actor.did, team_id=team, alias=alias,
        identity_scope="local", certificate_id=str(uuid4()))
    # Local membership has no invented global identity/address.
    for field in ("member_did_aw", "member_address", "signature"):
        certificate.pop(field)
    from awid.did import did_from_public_key
    from nacl.signing import SigningKey

    certificate["team_did_key"] = did_from_public_key(bytes(SigningKey(controller).verify_key))
    certificate["signature"] = sign_message(controller, canonical_json_bytes(certificate))
    await env.app.state.awid_registry_client.register_team_certificate(
        domain, name, team_controller_signing_key=controller,
        certificate_id=certificate["certificate_id"], member_did_key=actor.did,
        member_did_aw=None, member_address=None, alias=alias, identity_scope="local",
        certificate=_encode_certificate(certificate),
    )
    return certificate


async def memberships(env, tmp_path, registry_url, *, missing):
    from types import SimpleNamespace

    beta = f"alias-{uuid4().hex[:12]}:example.test"
    beta_key, _, beta_did = _make_keypair()
    await env.db.execute(
        "INSERT INTO {{tables.teams}} (team_id,namespace,team_name,team_did_key) VALUES($1,'example.test',$2,$3)",
        beta, beta.split(":", 1)[0], beta_did,
    )
    await env.registry_db.execute(
        "INSERT INTO {{tables.teams}} (domain,name,team_did_key,visibility) VALUES('example.test',$1,$2,'public')",
        beta.split(":", 1)[0], beta_did,
    )
    alice, carol = (env.actors[name] for name in ("alice", "carol"))
    alpha_alias = "someone-else" if missing else "reviewer"
    await env.db.execute(
        "UPDATE {{tables.agents}} SET alias=$1,agent_type='human',human_verified_key=did_key WHERE agent_id=$2",
        alpha_alias, alice.id,
    )
    await env.db.execute("UPDATE {{tables.workspaces}} SET alias=$1 WHERE workspace_id=$2", alpha_alias, alice.workspace)
    await env.db.execute("UPDATE {{tables.agents}} SET team_id=$1,alias='reviewer' WHERE agent_id=$2", beta, carol.id)
    await env.db.execute("UPDATE {{tables.workspaces}} SET team_id=$1,alias='reviewer' WHERE workspace_id=$2", beta, carol.workspace)
    human_certificate = await register(env, TEAM, env.team_sk, alice, alpha_alias)
    peer_certificate = await register(env, beta, beta_key, carol, "reviewer")
    for actor, cert in ((alice, human_certificate), (carol, peer_certificate)):
        await env.db.execute("UPDATE {{tables.agents}} SET certificate_id=$1 WHERE agent_id=$2", cert["certificate_id"], actor.id)
    home = tmp_path / "sender-home"
    home.mkdir(mode=0o700)
    child_env = {k: v for k, v in os.environ.items() if not k.startswith(("AW", "XDG_"))}
    child_env.update(AWEB_IDENTITY_HOME=str(home), AWEB_URL=str(env.client.base_url), AWID_REGISTRY_URL=registry_url,
        AW_NO_UPDATE_CHECK="1", HOME=str(tmp_path), XDG_CONFIG_HOME=str(tmp_path / "config"))
    binary = Path(os.environ["AW_TEST_CLI_BINARY"])
    code, identity, stderr = await run_aw(binary, tmp_path, child_env,
        "--identity-home", str(home), "id", "create", "--local")
    assert code == 0, (identity, stderr)
    sender = SimpleNamespace(did=identity["did_key"], sk=load_signing_key_pem((home / "signing.key").read_bytes()))
    # Let the real CLI write every identity, certificate, membership and
    # workspace file. Registry pins belong to teams.yaml, never workspace.yaml.
    for team, key in ((TEAM, env.team_sk), (beta, beta_key)):
        cert = await register(env, team, key, sender, "sender")
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
    alpha_sender = await env.db.fetch_value("SELECT agent_id FROM {{tables.agents}} WHERE team_id=$1 AND did_key=$2", TEAM, sender.did)
    beta_sender = await env.db.fetch_value("SELECT agent_id FROM {{tables.agents}} WHERE team_id=$1 AND did_key=$2", beta, sender.did)
    assert alpha_sender is not None and beta_sender is not None
    return SimpleNamespace(beta=beta, alpha_sender=alpha_sender, beta_sender=beta_sender, human=human_certificate,
        env=child_env, home=home)


async def inbox(env, actor):
    response = await env.client.get("/v1/messages/inbox", headers=_signed_identity_headers(actor.sk, actor.did, "", b""))
    assert response.status_code == 200, response.text
    return response.json()["messages"]


@pytest.mark.usefixtures("source_cli_binary")
@pytest.mark.asyncio
@pytest.mark.parametrize("condition,kind", [
    ("available", "mail"), ("unreachable", "mail"), ("pin_refused", "mail"),
    ("revoked_unreachable", "mail"), ("not_found", "mail"),
    ("unreachable_not_found", "mail"),
    ("available", "chat"), ("unreachable", "chat"),
])
async def test_bare_alias_never_changes_team_on_unknown_roster(privacy_app, tmp_path, condition, kind):
    tmp_path = tmp_path.resolve()
    env = privacy_app
    async with _registry_http(env.registry_app) as (registry_url, _), unavailable_origin() as down:
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
        body = tmp_path / "body.txt"
        body.write_text("The selected team's reviewer is the intended recipient.")
        binary = Path(os.environ["AW_TEST_CLI_BINARY"])
        command = (["mail", "send", "--to", "reviewer", "--subject", "alias isolation"] if kind == "mail"
            else ["chat", "send-and-leave", "reviewer", "--start-conversation"])
        # Observe the actual CLI registry-read failure independently of the
        # messaging selector, without substituting registry responses.
        if condition in ("unreachable", "pin_refused", "revoked_unreachable", "unreachable_not_found"):
            roster_code, roster, roster_error = await run_aw(
                binary, tmp_path, world.env, "id", "team", "members", "--team-id", TEAM,
            )
            assert roster_code != 0, (roster, roster_error)
        code, result, stderr = await run_aw(binary, tmp_path, world.env, *command, "--plaintext", "--body-file", str(body))
        rows = await env.db.fetch_all("SELECT * FROM {{tables.messages}} ORDER BY created_at")
        alpha_inbox, beta_inbox = await inbox(env, env.actors["alice"]), await inbox(env, env.actors["carol"])
        if kind == "chat" or condition in ("revoked_unreachable", "unreachable_not_found"):
            assert code != 0, (result, stderr)
            assert not rows and not alpha_inbox and not beta_inbox, (rows, alpha_inbox, beta_inbox)
            assert await env.db.fetch_value("SELECT count(*) FROM {{tables.chat_messages}}") == 0
            if kind == "chat":
                assert result["error"]["reason"] == "recipient_human_mail_only", (result, stderr)
            if condition == "unreachable_not_found":
                # A real HTTP not-found answer establishes that the send
                # reached the selected service, rather than refusing locally
                # because its separate client-side AWID read was unavailable.
                assert result["error"]["http_status"] == 404, (result, stderr)
                assert "Recipient agent not found" in result["error"]["message"], (result, stderr)
            return
        assert code == 0, (result, stderr)
        assert len(rows) == 1, rows
        [stored] = rows
        selected_beta = condition == "not_found"
        expected = env.actors["carol"] if selected_beta else env.actors["alice"]
        assert stored["message_id"] == UUID(result["message_id"])
        assert stored["team_id"] == (world.beta if selected_beta else TEAM), dict(stored)
        assert stored["from_agent_id"] == (world.beta_sender if selected_beta else world.alpha_sender), dict(stored)
        assert stored["to_did"] == expected.did, dict(stored)
        if condition == "available":
            # The live human lookup becomes a direct-DID send: participants
            # are literal identities, not actor pointers (canonical contract:
            # docs/identity-messaging-contract.md:77-82,113-120).
            assert stored["to_agent_id"] is None, dict(stored)
        else:
            assert stored["to_agent_id"] == expected.id, dict(stored)
        assert [str(row["message_id"]) for row in (beta_inbox if selected_beta else alpha_inbox)] == [result["message_id"]]
        assert not (alpha_inbox if selected_beta else beta_inbox)
        if selected_beta:
            assert world.beta in stderr, (result, stderr)
        assert yaml.safe_load((world.home / "teams.yaml").read_text())["active_team"] == TEAM

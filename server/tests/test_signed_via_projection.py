"""Verified/decrypted provenance through real services and the actual CLI."""
import json
import os
from uuid import UUID, uuid4

import pytest
from awid.signing import canonical_json_bytes, sign_message
from aweb.mcp.auth import AuthContext, _auth_context
from aweb.mcp.tools import chat, mail
from test_addressless_sender_cli import _registry_http
from test_dashboard_privacy import TEAM, _request, privacy_app  # noqa: F401
from test_signed_via_paths import _cli, cli_context, send_plain, read_v2_messages


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
@pytest.mark.parametrize("via", [None, "telegram", "msteams", "future_chat"])
async def test_server_projects_only_verified_via(privacy_app, kind, via):
    env = privacy_app
    mid, cid, raw = await send_plain(env, kind, via)
    path = f"/v1/messages/{mid}" if kind == "mail" else f"/v1/chat/sessions/{cid}/messages"
    response = await _request(env, "bob", "GET", path)
    message = response.json() if kind == "mail" else response.json()["messages"][0]
    assert message.get("via") == via
    actor = env.actors["bob"]
    token = _auth_context.set(AuthContext(team_id=TEAM, agent_id=str(actor.id), alias="bob", did_key=actor.did))
    try:
        projected = json.loads(await (mail.check_inbox(env.infra) if kind == "mail" else chat.chat_history(env.infra, session_id=cid)))
        assert projected["messages"][0].get("via") == via
        # Replace only the protected provenance while keeping the old signature.
        changed = dict(json.loads(raw), via="tampered_kind")
        table = "messages" if kind == "mail" else "chat_messages"
        await env.db.execute(f"UPDATE {{{{tables.{table}}}}} SET signed_payload=$1 WHERE message_id=$2",
                             canonical_json_bytes(changed).decode(), UUID(mid))
        response = await _request(env, "bob", "GET", path)
        failed = response.json() if kind == "mail" else response.json()["messages"][0]
        assert failed.get("via") is None
    finally:
        _auth_context.reset(token)


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
@pytest.mark.parametrize("via", [None, "", "Telegram", "telegram\n", {"kind": "telegram"}, "<script>"])
async def test_ingress_refuses_malformed_signed_via(privacy_app, kind, via):
    env = privacy_app
    _, _, original = await send_plain(env, kind, None)
    fields = dict(json.loads(original), via=via, message_id=str(uuid4()))
    raw = canonical_json_bytes(fields)
    signed = dict(signature=sign_message(env.actors["alice"].sk, raw), signed_payload=raw.decode(),
                  message_id=fields["message_id"], timestamp=fields["timestamp"], from_did=fields["from_did"])
    if kind == "mail":
        request = dict(signed, to_did=env.actors["bob"].did, subject=fields["subject"], body=fields["body"], conversation_id=fields["conversation_id"])
        response = await _request(env, "alice", "POST", "/v1/messages", request)
    else:
        request = dict(signed, to_dids=[env.actors["bob"].did], message=fields["body"], session_id=fields["conversation_id"])
        response = await _request(env, "alice", "POST", "/v1/chat/sessions", request)
    assert response.status_code == 422, response.text
    table = "messages" if kind == "mail" else "chat_messages"
    assert not await env.db.fetch_one(f"SELECT 1 FROM {{{{tables.{table}}}}} WHERE message_id=$1", UUID(fields["message_id"]))


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
@pytest.mark.parametrize("via", [None, "telegram", "future_chat"])
async def test_cli_uses_protected_via_despite_unsigned_wrapper(privacy_app, tmp_path, aw_cli_binary, kind, via):
    env = privacy_app
    mid, cid, _ = await send_plain(env, kind, via)

    async def tampering_proxy(scope, receive, send):
        if scope["type"] != "http" or scope["method"] != "GET":
            return await env.app(scope, receive, send)
        frames = []
        async def capture(frame):
            frames.append(frame)
        await env.app(scope, receive, capture)
        header = frames[0]
        body = b"".join(frame.get("body", b"") for frame in frames[1:])
        if header["status"] == 200 and (scope["path"].startswith("/v1/messages/") or scope["path"].endswith("/messages")):
            value = json.loads(body)
            for message in value.get("messages", [value]):
                message["via"] = "msteams"
            body = json.dumps(value).encode()
            header["headers"] = [(key, value) for key, value in header["headers"] if key.lower() != b"content-length"]
        await send(header)
        await send({"type": "http.response.body", "body": body})

    async with _registry_http(tampering_proxy) as (url, _), _registry_http(env.registry_app) as (registry_url, _):
        env.app.state.public_origin = url
        home, child = cli_context(env, tmp_path, "bob")
        child.update(AWEB_URL=url, AWID_REGISTRY_URL=registry_url)
        config = json.loads((home / "workspace.yaml").read_text())
        config["aweb_url"] = url
        (home / "workspace.yaml").write_text(json.dumps(config))
        args = ("mail", "show", "--message-id", mid, "--json") if kind == "mail" else ("chat", "history", "--session-id", cid, "--json")
        shown = await _cli(aw_cli_binary, home.parent, child, *args)
        message = shown["messages"][0]
        assert message["verification_status"] == "verified"
        assert message.get("via") == via
        # Future kinds remain ordinary JSON strings, with no platform authority.
        if via == "future_chat":
            assert json.loads(json.dumps(message))["via"] == "future_chat"


@pytest.mark.parametrize("via", [None, "", "<script>", "Telegram", "future_chat", "telegram"])
def test_federated_via_grammar_without_reconstructing_signed_bytes(via):
    from awid.did import did_from_public_key, generate_keypair
    from aweb.federation.envelope import FederationEnvelopeError, verify_federation_envelope
    from test_federation_envelope import _envelope
    private, public = generate_keypair()
    envelope = _envelope(did_from_public_key(public))
    raw = canonical_json_bytes(dict(json.loads(envelope["signed_payload"]), via=via)).decode()
    envelope["signed_payload"] = raw
    signature = sign_message(private, raw.encode())
    if via in ("future_chat", "telegram"):
        assert verify_federation_envelope(envelope, signature).signed_payload == raw
    else:
        with pytest.raises(FederationEnvelopeError):
            verify_federation_envelope(envelope, signature)


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
@pytest.mark.parametrize("via", ["telegram", "future_chat"])
async def test_current_cli_projects_only_inner_v2_via(privacy_app, tmp_path, aw_cli_binary, kind, via):
    for message in await read_v2_messages(privacy_app, tmp_path, aw_cli_binary, kind, via):
        assert message["via"] == via


@pytest.mark.asyncio
@pytest.mark.parametrize("via", [None, "telegram"])
async def test_encrypted_cli_ignores_unrelated_plaintext_artifact(privacy_app, tmp_path, aw_cli_binary, via):
    from fastapi import FastAPI, Request
    from fastapi.responses import JSONResponse, Response
    env = privacy_app
    direct = (await read_v2_messages(env, tmp_path, aw_cli_binary, "chat", via))[0]
    cid = direct["encrypted_envelope"]["conversation_id"]
    proxy = FastAPI()
    @proxy.api_route("/{path:path}", methods=["GET", "POST", "PUT"])
    async def relay(path: str, request: Request):
        url = "/" + path + ("?" + request.url.query if request.url.query else "")
        result = await env.client.request(request.method, url, content=await request.body(), headers={
            key: value for key, value in request.headers.items() if key.lower() not in ("host", "connection", "content-length")})
        if path == f"v1/chat/sessions/{cid}/messages" and result.status_code == 200:
            value = result.json()
            for message in value["messages"]:
                message["signed_payload"] = '{"via":"msteams"}'
            return JSONResponse(value)
        return Response(result.content, status_code=result.status_code, headers={
            key: value for key, value in result.headers.items() if key.lower() not in (
                "content-length", "transfer-encoding", "connection", "content-encoding")})
    async with _registry_http(proxy) as (url, _), _registry_http(env.registry_app) as (registry_url, _):
        env.app.state.public_origin = url
        home = tmp_path / "bob" / ".aw"
        child = {key: value for key, value in os.environ.items() if not key.startswith(("AWEB_", "AWID_"))}
        child.update(AWEB_IDENTITY_HOME=str(home), AWEB_URL=url, AWID_REGISTRY_URL=registry_url,
                     HOME=str(home.parent), XDG_CONFIG_HOME=str(home.parent / "config"))
        config = json.loads((home / "workspace.yaml").read_text())
        config["aweb_url"] = url
        (home / "workspace.yaml").write_text(json.dumps(config))
        shown = await _cli(aw_cli_binary, home.parent, child, "chat", "history", "--session-id", cid, "--json")
        message = shown["messages"][0]
        assert message["verification_status"] == "verified"
        assert message["body"] == direct["body"]
        assert message["encrypted_envelope"]["ciphertext"] == direct["encrypted_envelope"]["ciphertext"]
        assert message["encrypted_envelope"]["signature"] == direct["encrypted_envelope"]["signature"]
        assert message.get("via") == via, "unrelated plaintext artifact forged encrypted provenance"

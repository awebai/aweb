"""Row-owned ingress through actual participant HTTP, MCP and event builders."""
import asyncio
from datetime import datetime, timedelta, timezone
import json
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest
import pytest_asyncio

from aweb.human_channels.native import NativeMessagingService
from aweb.identity_auth_deps import MessagingAuth
from aweb.mcp.auth import AuthContext, _auth_context, get_auth
from aweb.mcp.tools import chat, contacts, mail
from aweb.mutation_hooks import _translate
from aweb.messaging.verification import message_verification_status
from awid.signing import canonical_json_bytes, sign_message
from test_channel_ingress_acceptance import CONTEXT, _bind, _channel_service, _prepare
from test_dashboard_privacy import TEAM, _request, privacy_app  # noqa: F401
from test_human_channels_native_send import HostAuthority, complete, dto
from test_messages_http import _signed_team_headers


@pytest_asyncio.fixture
async def ingress_app(privacy_app):
    env = privacy_app
    await env.db.execute("""CREATE TABLE public.host_authority (
        actor_id uuid PRIMARY KEY,principal text,signing_key text,custody text,active bool,
        revision int,encryption_assertion jsonb)""")
    for alias in ("alice", "bob"):
        actor = env.actors[alias]
        await env.db.execute("INSERT INTO public.host_authority VALUES ($1,$2,$2,$3,true,1,NULL)",
                             actor.id, actor.did, "bridge_custodial" if alias == "alice" else "self_custodial")
    await env.db.execute("CREATE TABLE public.host_ingress (ingress_key text PRIMARY KEY,result jsonb)")
    alice = env.actors["alice"]
    binding = dto("ServiceBinding", dict(service=alice.did, signing_key_id=alice.did,
                                         audience=str(env.client.base_url).rstrip("/")))
    authority = HostAuthority(env.db, binding)
    service = NativeMessagingService(env.infra, authority=authority, service=binding)
    native = dict(db=env.db, service=service, provider=authority,
                  auth=MessagingAuth(did_key=alice.did, did_aw=None, address=None, team_id=TEAM, alias="alice", agent_id=str(alice.id)),
                  a=str(alice.id), b=str(env.actors["bob"].id), signing_key=alice.sk,
                  recipient_did=env.actors["bob"].did, recipient_alias="bob", recipient_stable_id=None)
    await _channel_service(native)
    async def publish(mutation_id, event_type, context):
        await env.app.state.on_mutation(event_type, context)
    native["service"].publisher = publish
    messages = {}
    for kind in ("mail", "chat"):
        key = dto("IngressKey", dict(issuer=alice.did, namespace="verified-events", key=kind,
                                    input_hash="sha256:" + "11" * 32))
        native["key"] = key
        prepared = await _prepare(native, kind)
        await _bind(native, prepared)
        await complete(native, prepared)
        messages[kind] = prepared.value
    return SimpleNamespace(env=env, native=native, messages=messages)


def assert_ingress(message):
    assert message.get("ingress") == CONTEXT, message
    if message.get("signed_payload"):
        assert "ingress" not in json.loads(message["signed_payload"])


@pytest.mark.asyncio
@pytest.mark.parametrize("view", ["inbox", "show", "conversation", "mail-self", "history", "exact", "page", "chat-self"])
async def test_channel_ingress_rest_projection(ingress_app, view):
    app = ingress_app
    message = app.messages["mail" if view in {"inbox", "show", "conversation", "mail-self"} else "chat"]
    mid, cid = message["message_id"], message["conversation_id"]
    path = {
        "inbox": "/v1/messages/inbox?unread_only=false", "show": f"/v1/messages/{mid}",
        "conversation": f"/v1/messages/conversations/{cid}", "mail-self": f"/v1/messages/{mid}",
        "history": f"/v1/chat/sessions/{cid}/messages", "exact": f"/v1/chat/sessions/{cid}/messages?message_id={mid}",
        "page": f"/v1/chat/sessions/{cid}/messages?order=desc&limit=1", "chat-self": f"/v1/chat/sessions/{cid}/messages",
    }[view]
    actor = "alice" if view.endswith("self") else "bob"
    response = await _request(app.env, actor, "GET", path)
    assert response.status_code == 200, response.text
    data = response.json()
    item = data if view in {"show", "mail-self"} else next(row for row in data["messages"] if row["message_id"] == mid)
    assert_ingress(item)
    denied = await _request(app.env, "carol", "GET", path.replace("/inbox?unread_only=false", "/" + mid))
    assert denied.status_code == 404, denied.text


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
async def test_channel_ingress_and_author_chain_round_trip(ingress_app, kind):
    from dataclasses import replace
    from test_id_chain_message_metadata import _bundle

    app, env = ingress_app, ingress_app.env
    native = app.native
    chain = _bundle(env.actors["alice"].did)
    native["auth"] = replace(native["auth"], id_chain=chain)
    native["key"] = dto("IngressKey", dict(
        issuer=native["auth"].did_key, namespace="verified-events", key=str(uuid4()),
        input_hash="sha256:" + "11" * 32))
    prepared = await _prepare(native, kind, via="telegram")
    await _bind(native, prepared)
    await complete(native, prepared)

    mid, cid = prepared.value["message_id"], prepared.value["conversation_id"]
    path = (f"/v1/messages/{mid}" if kind == "mail" else
            f"/v1/chat/sessions/{cid}/messages?order=desc&limit=1")
    response = await _request(env, "bob", "GET", path)
    assert response.status_code == 200, response.text
    item = response.json() if kind == "mail" else response.json()["messages"][0]
    assert_ingress(item)
    assert item["id_chain"] == chain
    assert item["via"] == "telegram"
    signed = json.loads(item["signed_payload"])
    assert "id_chain" not in signed
    assert "ingress" not in signed


@pytest.mark.asyncio
@pytest.mark.parametrize("view", ["inbox", "mail-contact", "history", "wait", "chat-contact"])
async def test_channel_ingress_mcp_projection(ingress_app, view):
    app, env = ingress_app, ingress_app.env
    bob = env.actors["bob"]
    token = _auth_context.set(AuthContext(team_id=TEAM, agent_id=str(bob.id), alias="bob", did_key=bob.did))
    try:
        target = dict(did_key=env.actors["alice"].did, alias="alice")
        if view == "inbox":
            rows = json.loads(await mail.check_inbox(env.infra, unread_only=False))["messages"]
        elif view == "mail-contact":
            rows = await contacts._read_mail_messages_from_target(env.infra, target=target, limit=10)
        elif view == "history":
            rows = json.loads(await chat.chat_history(env.infra, session_id=app.messages["chat"]["conversation_id"]))["messages"]
        elif view == "chat-contact":
            rows = await contacts._read_chat_messages_from_target(env.infra, target=target, limit=10)
        else:
            rows, timed_out = await chat._wait_for_replies(env.db, env.redis,
                session_id=UUID(app.messages["chat"]["conversation_id"]), participant_did=bob.did,
                after=datetime.now(timezone.utc) - timedelta(minutes=1), wait_seconds=1,
                auth=get_auth(), hosted_decryptor=None)
            assert not timed_out
        assert_ingress(rows[0])
    finally:
        _auth_context.reset(token)


@pytest.mark.asyncio
async def test_channel_ingress_actionable_mail_and_chat_discovery(ingress_app):
    app, env = ingress_app, ingress_app.env
    bob = env.actors["bob"]
    response = await env.client.get("/v1/events/stream", params={
        "deadline": (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()},
        headers=_signed_team_headers(bob.sk, bob.did, TEAM, bob.certificate))
    assert response.status_code == 200, response.text
    events = [json.loads(line[6:]) for line in response.text.splitlines() if line.startswith("data: ")]
    mail_event = next(row for row in events if row.get("message_id") == app.messages["mail"]["message_id"])
    assert_ingress(mail_event)
    discovery = next(row for row in events if row.get("session_id") == app.messages["chat"]["conversation_id"])
    assert "ingress" not in discovery


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
async def test_channel_ingress_durable_event_translation(ingress_app, kind):
    env = ingress_app.env
    row = await env.db.fetch_one("SELECT event_type,context FROM {{tables.human_channel_mutations}} WHERE message_id=$1",
                                UUID(ingress_app.messages[kind]["message_id"]))
    event = _translate(row["event_type"], json.loads(row["context"]))
    assert_ingress(event.to_dict())


@pytest.mark.asyncio
async def test_channel_ingress_http_inputs_refuse_and_same_signer_ordinary_is_absent(ingress_app):
    app, env = ingress_app, ingress_app.env
    cases = [("/v1/messages", dict(to_did=env.actors["bob"].did, subject="ordinary", body="ordinary")),
             ("/v1/chat/sessions", dict(session_id=str(uuid4()), to_dids=[env.actors["bob"].did], message="ordinary")),
             (f'/v1/chat/sessions/{app.messages["chat"]["conversation_id"]}/messages', dict(body="ordinary"))]
    for path, body in cases:
        response = await _request(env, "alice", "POST", path, dict(body, ingress=CONTEXT))
        assert response.status_code == 422, response.text
    for path, body in (cases[0], cases[2]):
        response = await _request(env, "alice", "POST", path, body)
        assert response.status_code == 200, response.text
        sent = response.json()
        resource = (f'/v1/messages/{sent["message_id"]}' if path == "/v1/messages" else
                    f'/v1/chat/sessions/{app.messages["chat"]["conversation_id"]}/messages?message_id={sent["message_id"]}')
        shown = await _request(env, "bob", "GET", resource)
        assert shown.status_code == 200, shown.text
        rows = [shown.json()] if path == "/v1/messages" else shown.json()["messages"]
        assert all("ingress" not in row for row in rows)


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["replay", "live"])
async def test_channel_ingress_chat_sse(ingress_app, mode):
    from aweb.messaging.waiting import get_waiting_agents
    app, env = ingress_app, ingress_app.env
    cid = app.messages["chat"]["conversation_id"]
    params = dict(deadline=(datetime.now(timezone.utc) + timedelta(seconds=2)).isoformat())
    if mode == "replay":
        params["after"] = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
    bob = env.actors["bob"]
    listening = asyncio.create_task(env.client.get(f"/v1/chat/sessions/{cid}/stream", params=params,
        headers=_signed_team_headers(bob.sk, bob.did, TEAM, bob.certificate)))
    try:
        mid = app.messages["chat"]["message_id"]
        if mode == "live":
            async with asyncio.timeout(5):
                while not await get_waiting_agents(env.redis, cid, [bob.did]):
                    await asyncio.sleep(0.02)
            native = app.native
            native["key"] = dto("IngressKey", dict(issuer=native["auth"].did_key,
                namespace="verified-events", key="chat-live", input_hash="sha256:" + "22" * 32))
            prepared = await _prepare(native, "chat", conversation_id=cid)
            await _bind(native, prepared)
            await complete(native, prepared)
            mid = prepared.value["message_id"]
        response = await listening
        assert response.status_code == 200, response.text
        events = [json.loads(line[6:]) for line in response.text.splitlines() if line.startswith("data: ")]
        assert_ingress(next(event for event in events if event.get("message_id") == mid))
    finally:
        if not listening.done():
            await listening


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
async def test_channel_ingress_survives_failed_signature_verification(ingress_app, kind):
    app, env = ingress_app, ingress_app.env
    message = app.messages[kind]
    table = "messages" if kind == "mail" else "chat_messages"
    await env.db.execute("UPDATE {{tables." + table + "}} SET signature='invalid' WHERE message_id=$1",
                         UUID(message["message_id"]))
    path = (f'/v1/messages/{message["message_id"]}' if kind == "mail" else
            f'/v1/chat/sessions/{message["conversation_id"]}/messages')
    response = await _request(env, "bob", "GET", path)
    assert response.status_code == 200, response.text
    value = response.json() if kind == "mail" else response.json()["messages"][0]
    assert message_verification_status(value) != "verified"
    assert_ingress(value)


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
async def test_author_signed_ingress_remains_author_content(ingress_app, kind):
    app, env = ingress_app, ingress_app.env
    alice, bob = env.actors["alice"], env.actors["bob"]
    mid = str(uuid4())
    cid = app.messages[kind]["conversation_id"]
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    payload = dict(type=kind, from_did=alice.did, to_did=bob.did,
        subject="author field" if kind == "mail" else "", body="author content",
        timestamp=stamp, message_id=mid, conversation_id=cid,
        ingress=dict(CONTEXT, confidentiality="end_to_end"), **{"from": "alice", "to": "bob"})
    raw = canonical_json_bytes(payload).decode()
    signed = dict(from_did=alice.did, message_id=mid, timestamp=stamp,
                  signature=sign_message(alice.sk, raw.encode()), signed_payload=raw)
    if kind == "mail":
        path = "/v1/messages"
        body = dict(signed, to_did=bob.did, subject="author field", body="author content", conversation_id=cid)
        read = f"/v1/messages/{mid}"
    else:
        path = f"/v1/chat/sessions/{cid}/messages"
        body = dict(signed, body="author content")
        read = path + f"?message_id={mid}"
    response = await _request(env, "alice", "POST", path, body)
    assert response.status_code == 200, response.text
    shown = await _request(env, "bob", "GET", read)
    assert shown.status_code == 200, shown.text
    value = shown.json() if kind == "mail" else shown.json()["messages"][0]
    assert message_verification_status(value) == "verified"
    assert value["signed_payload"] == raw
    assert "ingress" not in value


@pytest.mark.asyncio
async def test_channel_ingress_released_aw_readers(ingress_app, tmp_path, aw_cli_binary):
    from test_signed_via_paths import _cli, cli_context
    from test_addressless_sender_cli import _registry_http
    app, env = ingress_app, ingress_app.env
    home, child = cli_context(env, tmp_path, "bob")
    async with _registry_http(env.registry_app) as (registry_url, _):
        child["AWID_REGISTRY_URL"] = registry_url
        for kind in ("mail", "chat"):
            expected = app.messages[kind]
            args = ("mail", "show", "--message-id", expected["message_id"], "--json") if kind == "mail" else (
                "chat", "history", "--session-id", expected["conversation_id"], "--json")
            shown = await _cli(aw_cli_binary, home.parent, child, *args)
            message = next(row for row in shown["messages"] if row["message_id"] == expected["message_id"])
            assert message["verification_status"] == "verified", message
            assert message["body"] == "channel input"
            table = "messages" if kind == "mail" else "chat_messages"
            original = await env.db.fetch_one("SELECT signed_payload FROM {{tables." + table + "}} WHERE message_id=$1",
                                              UUID(expected["message_id"]))
            # Released chat Event JSON omits signed_payload after verification.
            if kind == "mail":
                assert message["signed_payload"] == original["signed_payload"]


@pytest.mark.asyncio
async def test_channel_ingress_released_plugin_reader(ingress_app, tmp_path):
    import hashlib
    import os
    from pathlib import Path
    artifact = os.environ.get("AW_TEST_CHANNEL_BUNDLE")
    if not artifact:
        pytest.skip("set AW_TEST_CHANNEL_BUNDLE to the published channel1.8.0 dist/index.js")
    original = Path(artifact).read_bytes()
    assert hashlib.sha256(original).hexdigest() == "bf9c42ccc91c82eb172a9304bdc493288097c794efa6da56d7afc4d765dd4c96"
    module = tmp_path / "released-ingress.mjs"
    module.write_bytes(original + b"\nexport {APIClient,fetchInbox,fetchHistory,verifyInboxMessage,verifyChatMessage,parseSSEResponse};\n")
    app, env = ingress_app, ingress_app.env
    bob = env.actors["bob"]
    raw = {}
    for kind in ("mail", "chat"):
        table = "messages" if kind == "mail" else "chat_messages"
        row = await env.db.fetch_one("SELECT signed_payload FROM {{tables." + table + "}} WHERE message_id=$1",
                                     UUID(app.messages[kind]["message_id"]))
        raw[kind] = row["signed_payload"]
    arguments = dict(url=str(env.client.base_url), messages=app.messages, raw=raw, ingress=CONTEXT,
        auth=dict(did=bob.did, stableID="", teamID=TEAM, teamCertificateHeader=bob.certificate, signingKey=bob.sk.hex()))
    process = await asyncio.create_subprocess_exec("node", str(Path(__file__).with_name("released_channel_ingress_probe.mjs")),
        str(module), stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    stdout, stderr = await asyncio.wait_for(process.communicate(json.dumps(arguments).encode()), 30)
    assert process.returncode == 0, stderr.decode()
    assert json.loads(stdout)["verified"] == ["mail", "chat"]


async def _encrypted_channel_messages(app, tmp_path, *, inner_ingress=False):
    from test_signed_via_paths import cli_context
    from aweb.e2ee_messages import encrypt_e2ee_message
    identities, contexts = {}, {}
    env, native = app.env, app.native
    for alias in ("alice", "bob"):
        home, child = cli_context(env, tmp_path, alias)
        contexts[alias] = home, child
        actor = env.actors[alias]
        assertion = json.loads((home / "assertion.json").read_text())
        identities[alias] = dict(did=actor.did, team_id=TEAM, signing_key=actor.sk, encryption_key=assertion)
        await env.db.execute("UPDATE public.host_authority SET encryption_assertion=$1::jsonb WHERE actor_id=$2",
                             json.dumps(assertion), actor.id)
    for kind in ("mail", "chat"):
        mid, cid = str(uuid4()), app.messages[kind]["conversation_id"]
        envelope = encrypt_e2ee_message(kind=kind, sender=identities["alice"], recipients=[identities["bob"]],
            message_id=mid, conversation_id=cid, created_at=datetime.now(timezone.utc),
            subject="protected channel subject", body="protected channel input", via="telegram")
        if inner_ingress:
            import base64
            from aweb import e2ee_messages as crypto
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            bob = dict(identities["bob"], private_key=base64.b64decode("".join(
                (contexts["bob"][0] / "encryption.key").read_text().splitlines()[1:-1])))
            inner = crypto.decrypt_e2ee_message(envelope, bob)
            inner["ingress"] = dict(CONTEXT, confidentiality="end_to_end")
            cek = crypto._open_key_wrap(wrap=crypto._select_key_wrap(envelope, bob), envelope=envelope, identity=bob)
            content = canonical_json_bytes(inner)
            envelope["crypto"]["ciphertext_size"] = len(content) + 16
            nonce = crypto._b64_raw_decode(envelope["crypto"]["content_nonce"], field="content_nonce")
            ciphertext = AESGCM(cek).encrypt(nonce, content, crypto._content_aad(envelope))
            envelope["ciphertext"] = crypto._b64_raw_encode(ciphertext)
            envelope["crypto"]["ciphertext_hash"] = crypto._hash_bytes(ciphertext)
            envelope["signature"] = sign_message(identities["alice"]["signing_key"], canonical_json_bytes(
                crypto._envelope_map(envelope, include_signature=False, include_ciphertext=True, include_ciphertext_hash=True)))
            assert crypto.decrypt_e2ee_message(envelope, bob)["ingress"]["confidentiality"] == "end_to_end"
        target = await native["service"].resolve(native["auth"], dto("ResolveRequest", dict(
            version="aweb-human-resolve-v1", team_id=TEAM, selector="bob")))
        prepared = await native["service"].prepare(native["auth"], dto("PrepareRequest", dict(
            version="aweb-human-prepare-v1", kind=kind, message_id=mid, conversation_id=cid,
            author=dict(kind="native", did=native["auth"].did_key), format="native_encrypted_v2",
            envelope=canonical_json_bytes(envelope).decode(), target=target.value)))
        native["key"] = dto("IngressKey", dict(issuer=native["auth"].did_key, namespace="verified-events",
            key=kind+"-encrypted", input_hash="sha256:" + "33" * 32))
        await _bind(native, prepared)
        await complete(native, prepared)
        app.messages[kind] = prepared.value
    return contexts["bob"]


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["plaintext", "omitted", "forged", "failure", "inner", "unknown", "failed_trust"])
async def test_channel_ingress_current_channel_runtime(ingress_app, tmp_path, aw_cli_binary, mode):
    import os
    from pathlib import Path
    from test_signed_via_paths import cli_context
    from test_addressless_sender_cli import _registry_http
    module = os.environ.get("AW_TEST_CHANNEL_CORE")
    if not module:
        pytest.skip("set AW_TEST_CHANNEL_CORE to the built current channel-core dist/index.js")
    app, env = ingress_app, ingress_app.env
    expected_ingress = CONTEXT
    if mode == "unknown":
        expected_ingress = dict(CONTEXT, platform="future_platform")
        for kind in ("mail", "chat"):
            native = app.native
            prepared = await _prepare(native, kind, conversation_id=app.messages[kind]["conversation_id"])
            native["key"] = dto("IngressKey", dict(issuer=native["auth"].did_key, namespace="verified-events",
                key=kind+"-unknown", input_hash="sha256:" + "44" * 32))
            await _bind(native, prepared, context=expected_ingress)
            await complete(native, prepared)
            app.messages[kind] = prepared.value
    home, child = (cli_context(env, tmp_path, "bob") if mode in {"plaintext", "unknown", "failed_trust"} else
                   await _encrypted_channel_messages(app, tmp_path, inner_ingress=mode == "inner"))
    if mode == "failed_trust":
        for kind in ("mail", "chat"):
            table = "messages" if kind == "mail" else "chat_messages"
            await env.db.execute("UPDATE {{tables." + table + "}} SET signature='invalid' WHERE message_id=$1",
                                 UUID(app.messages[kind]["message_id"]))
    bob = env.actors["bob"]
    arguments = dict(url=str(env.client.base_url), messages=app.messages, ingress=expected_ingress,
        mode="plaintext" if mode in {"unknown", "failed_trust"} else mode, failed_trust=mode == "failed_trust",
        workdir=str(home.parent), identityHome=str(home), aw=str(aw_cli_binary),
        auth=dict(did=bob.did, stableID="", teamID=TEAM, teamCertificateHeader=bob.certificate, signingKey=bob.sk.hex()))
    async with _registry_http(env.registry_app) as (registry_url, _):
        child["AWID_REGISTRY_URL"] = registry_url
        process = await asyncio.create_subprocess_exec("node", str(Path(__file__).with_name("current_channel_ingress_probe.mjs")),
            module, env=child, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        stdout, stderr = await asyncio.wait_for(process.communicate(json.dumps(arguments).encode()), 30)
    assert process.returncode == 0, stderr.decode()
    assert len(json.loads(stdout)) == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("location", ["wrapper", "envelope"])
async def test_federation_cannot_supply_local_channel_ingress(ingress_app, location):
    from aweb.federation.envelope import FederatedDeliveryRequest, verify_federation_envelope
    from test_federation_envelope import _envelope, _sign
    env = ingress_app.env
    alice = env.actors["alice"]
    envelope = _envelope(alice.did)
    original = dict(envelope=envelope, signature=_sign(envelope, alice.sk))
    # The same signed artifact and closed transport grammar accept the neighbour.
    checked = FederatedDeliveryRequest.model_validate(original)
    verify_federation_envelope(checked.envelope, checked.signature)
    payload = dict(original)
    if location == "wrapper":
        payload["ingress"] = CONTEXT
    else:
        payload["envelope"] = dict(envelope, ingress=CONTEXT)
    response = await env.client.post("/v1/federation/messages", json=payload)
    assert response.status_code == 422, response.text
    assert response.json()["reason"] == "federation_envelope_invalid"
    from pydantic import ValidationError
    with pytest.raises(ValidationError) as refused:
        FederatedDeliveryRequest.model_validate(payload)
    assert any(error["loc"][-1] == "ingress" for error in refused.value.errors())
    assert await env.db.fetch_one("SELECT message_id FROM {{tables.messages}} WHERE message_id=$1", UUID(envelope["message_id"])) is None


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
async def test_native_prepare_client_context_is_refused(ingress_app, kind):
    app, env = ingress_app, ingress_app.env
    env.app.state.human_channels_service = app.native["service"]
    prepared = await _prepare(app.native, kind, conversation_id=app.messages[kind]["conversation_id"])
    retained = app.native["service"]._preparations[prepared.value["prepared_id"]]
    request = json.loads(retained.request_bytes)
    response = await _request(env, "alice", "POST", "/v1/messaging/prepare", dict(request, ingress=CONTEXT))
    assert response.status_code == 422, response.text
    assert response.json()["detail"]["effects"] == "none"
    table = "messages" if kind == "mail" else "chat_messages"
    assert await env.db.fetch_one("SELECT message_id FROM {{tables." + table + "}} WHERE message_id=$1", UUID(prepared.value["message_id"])) is None


@pytest.mark.asyncio
async def test_channel_ingress_current_aw_carrier(ingress_app, tmp_path, aw_cli_binary):
    import os
    from test_signed_via_paths import _cli, cli_context
    from test_addressless_sender_cli import _registry_http
    if os.environ.get("AW_TEST_CLI_BINARY"):
        pytest.skip("current Go carrier requires the default source-built CLI fixture")
    app, env = ingress_app, ingress_app.env
    home, child = cli_context(env, tmp_path, "bob")
    async with _registry_http(env.registry_app) as (registry_url, _):
        child["AWID_REGISTRY_URL"] = registry_url
        for kind in ("mail", "chat"):
            expected = app.messages[kind]
            args = ("mail", "show", "--message-id", expected["message_id"], "--json") if kind == "mail" else (
                "chat", "history", "--session-id", expected["conversation_id"], "--json")
            shown = await _cli(aw_cli_binary, home.parent, child, *args)
            message = next(row for row in shown["messages"] if row["message_id"] == expected["message_id"])
            assert_ingress(message)
            assert message["verification_status"] == "verified"

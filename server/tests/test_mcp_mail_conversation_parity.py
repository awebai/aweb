"""Mail threading parity through the real MCP/HTTP apps and PostgreSQL."""

import json
from types import SimpleNamespace
from uuid import UUID, uuid4

import httpx
import pytest
import pytest_asyncio

from awid.signing import sign_message
from aweb.internal_auth import build_internal_auth_header_value
from aweb.mcp.server import create_mcp_app
from aweb.mcp.signing import HostedMessageSigningResult, canonical_signed_payload
from test_messages_http import (
    _build_test_app,
    _encrypted_mail_envelope,
    _insert_agent,
    _insert_team,
    _make_keypair,
    _signed_identity_headers,
)


@pytest_asyncio.fixture
async def mail_server(aweb_cloud_db, monkeypatch):
    db = aweb_cloud_db.aweb_db
    team = "ops:acme.com"
    await _insert_team(db, team)
    pilot_key, _, pilot_did = _make_keypair()
    human_key, _, human_did = _make_keypair()
    pilot = await _insert_agent(db, team_id=team, alias="pilot", did_key=pilot_did,
                                did_aw="did:aw:pilot", address="acme.com/pilot")
    human = await _insert_agent(db, team_id=team, alias="human", did_key=human_did,
                                did_aw="did:aw:human", address=None)
    await db.execute("UPDATE {{tables.agents}} SET agent_type='human' WHERE agent_id=$1", UUID(human))
    await db.execute(
        """INSERT INTO {{tables.workspaces}}
           (workspace_id, team_id, agent_id, alias, workspace_type)
           VALUES ($1, $2, $3, 'pilot', 'hosted_mcp')""",
        uuid4(), team, UUID(pilot),
    )
    monkeypatch.setenv("AWEB_TRUST_PROXY_HEADERS", "1")
    monkeypatch.setenv("AWEB_INTERNAL_AUTH_SECRET", "mail-parity-test-secret")
    custody = SimpleNamespace(payloads=[], wrong_conversation=False)

    async def signer(**kwargs):
        payload = dict(kwargs["payload"])
        custody.payloads.append(payload)
        if custody.wrong_conversation:
            payload["conversation_id"] = str(uuid4())
        signed = canonical_signed_payload(payload)
        return HostedMessageSigningResult(
            from_did=pilot_did, signing_key_id=pilot_did, signed_payload=signed,
            signature=sign_message(pilot_key, signed.encode()),
        )

    async def encryptor(**kwargs):
        payload, recipient = kwargs["payload"], kwargs["recipient"]
        custody.payloads.append(dict(payload))
        # The server routes opaque ciphertext. This fixture supplies a genuinely
        # signed v2 envelope; hosted acceptance owns content encryption/decryption.
        envelope = _encrypted_mail_envelope(
            sender_sk=pilot_key, sender_did=pilot_did, sender_stable_id="did:aw:pilot",
            recipient_did=recipient["did_key"], recipient_stable_id=recipient["did_aw"],
            sender_address=payload["from"], recipient_address=recipient.get("address") or "",
            message_id=payload["message_id"], conversation_id=payload["conversation_id"],
        )
        return {"content_mode": "encrypted_v2", "message_version": 2, "encrypted_envelope": envelope}

    app = _build_test_app(db, None)
    mcp = create_mcp_app(db_infra=app.state.db, hosted_signer=signer, hosted_encryptor=encryptor)
    app.mount("/mcp", mcp)
    await mcp.startup()
    try:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            async def human_mail(body="hello", **target):
                data = json.dumps({"body": body, **(target or {"to_alias": "pilot"})}).encode()
                response = await client.post(
                    "/v1/messages", content=data,
                    headers={"Content-Type": "application/json", **_signed_identity_headers(human_key, human_did, "", data)},
                )
                assert response.status_code == 200, response.text
                return response.json()

            async def mcp_mail(**arguments):
                principal = str(uuid4())
                headers = {
                    "Accept": "application/json, text/event-stream", "X-Team-ID": team,
                    "X-User-ID": principal, "X-AWEB-Actor-ID": pilot,
                    "X-AWEB-Auth": build_internal_auth_header_value(
                        secret="mail-parity-test-secret", team_id=team,
                        principal_type="u", principal_id=principal, actor_id=pilot,
                    ),
                }
                response = await client.post("/mcp/", headers=headers, json={
                    "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                    "params": {"name": "send_mail", "arguments": {"body": "unprompted update", **arguments}},
                })
                assert response.status_code == 200, response.text
                result = response.json()
                assert "error" not in result, result
                return json.loads(result["result"]["content"][0]["text"])

            yield SimpleNamespace(db=db, human_mail=human_mail, mcp_mail=mcp_mail,
                                  custody=custody, human=human, human_did=human_did, pilot=pilot)
    finally:
        await mcp.shutdown()


@pytest.mark.asyncio
@pytest.mark.parametrize("target", ["alias", "stable_did", "current_did", "address"])
@pytest.mark.parametrize("plaintext", [True, False])
async def test_mcp_recipient_send_continues_http_conversation(mail_server, target, plaintext):
    server = mail_server
    if target == "alias":
        # Bare aliases are an agent-only selector in both public surfaces;
        # the addressless human uses a DID in the customer flow.
        await server.db.execute("UPDATE {{tables.agents}} SET agent_type='agent' WHERE agent_id=$1", UUID(server.human))
    original = await server.human_mail()
    # The HTTP route already reuses this conversation without its ID.
    ordinary = await server.human_mail("another human message")
    assert ordinary["conversation_id"] == original["conversation_id"]
    recipient = {"alias": "human", "stable_did": "did:aw:human",
                 "current_did": server.human_did, "address": "acme.com/human"}[target]
    sent = await server.mcp_mail(to=recipient, plaintext=plaintext)
    assert "error" not in sent, sent
    assert sent["conversation_id"] == original["conversation_id"]
    assert server.custody.payloads[-1]["conversation_id"] == original["conversation_id"]
    row = await server.db.fetch_one("SELECT * FROM {{tables.messages}} WHERE message_id=$1", UUID(sent["message_id"]))
    assert str(row["conversation_id"]) == original["conversation_id"]
    assert row["to_did"] == "did:aw:human"
    if plaintext:
        assert json.loads(row["signed_payload"])["conversation_id"] == original["conversation_id"]
    else:
        assert row["content_mode"] == "encrypted_v2"
        envelope = json.loads(row["encrypted_envelope"])
        assert envelope["conversation_id"] == original["conversation_id"]
    assert (await server.db.fetch_one("SELECT count(*) AS n FROM {{tables.conversations}}"))["n"] == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("old_status", [None, "closed", "expired"])
async def test_mcp_recipient_send_creates_when_no_active_conversation(mail_server, old_status):
    server = mail_server
    old = None
    if old_status:
        old = (await server.human_mail())["conversation_id"]
        await server.db.execute("UPDATE {{tables.conversations}} SET status=$2 WHERE conversation_id=$1", UUID(old), old_status)
    sent = await server.mcp_mail(to="did:aw:human", plaintext=True)
    assert "error" not in sent, sent
    assert sent["conversation_id"] != old
    assert server.custody.payloads[-1]["conversation_id"] == sent["conversation_id"]


@pytest.mark.asyncio
async def test_mcp_reused_conversation_does_not_bypass_recipient_policy(mail_server):
    server = mail_server
    old = (await server.human_mail())["conversation_id"]
    await _insert_team(server.db, "ops:otherco.com")
    await server.db.execute(
        "UPDATE {{tables.agents}} SET team_id='ops:otherco.com', inbound_mode='team_and_contacts' WHERE agent_id=$1", UUID(server.human),
    )
    result = await server.mcp_mail(to="did:aw:human", plaintext=True)
    assert "error" in result, result
    assert (await server.db.fetch_one("SELECT count(*) AS n FROM {{tables.messages}}"))["n"] == 1
    assert (await server.db.fetch_one("SELECT count(*) AS n FROM {{tables.conversations}}"))["n"] == 1
    assert server.custody.payloads[-1]["conversation_id"] == old


@pytest.mark.asyncio
async def test_mcp_custody_cannot_sign_a_different_conversation(mail_server):
    server = mail_server
    await server.human_mail()
    server.custody.wrong_conversation = True
    result = await server.mcp_mail(to="did:aw:human", plaintext=True)
    assert "error" in result, result
    assert (await server.db.fetch_one("SELECT count(*) AS n FROM {{tables.messages}}"))["n"] == 1
    assert (await server.db.fetch_one("SELECT count(*) AS n FROM {{tables.conversations}}"))["n"] == 1


@pytest.mark.asyncio
async def test_mcp_lookup_does_not_reuse_another_senders_conversation(mail_server):
    server = mail_server
    _, _, other_did = _make_keypair()
    await _insert_agent(server.db, team_id="ops:acme.com", alias="other",
                        did_key=other_did, did_aw="did:aw:other", address="acme.com/other")
    old = (await server.human_mail(to_alias="other"))["conversation_id"]
    sent = await server.mcp_mail(to="did:aw:human", plaintext=True)
    assert "error" not in sent, sent
    assert sent["conversation_id"] != old
    assert (await server.db.fetch_one("SELECT count(*) AS n FROM {{tables.conversations}}"))["n"] == 2

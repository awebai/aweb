"""Mail threading parity through the real MCP/HTTP apps and PostgreSQL."""

from identity_binding_support import seed_verified_bindings

import json
from datetime import datetime, timezone
from types import SimpleNamespace
from uuid import UUID, uuid4

import asyncpg
import httpx
import pytest
import pytest_asyncio
from pgdbm.errors import QueryError

from awid.e2ee_keys import build_encryption_key_assertion
from awid.registry import Address, Namespace
from awid.signing import sign_message
from aweb.internal_auth import build_internal_auth_header_value
from aweb.messaging.address_auth import unreachable_address_refusal
from aweb.messaging.mail_send import _validate_signed_mail_payload
from aweb.mcp.server import create_mcp_app
from aweb.mcp.signing import HostedMessageSigningResult, canonical_signed_payload
from test_messages_http import (
    _build_test_app,
    _encrypted_mail_envelope,
    _insert_agent,
    _insert_agent_encryption_assertion,
    _insert_team,
    _make_keypair,
    _signed_identity_headers,
)

REGISTRY_ORIGIN = "https://registry.test"


class _AddressRegistry:
    """The AWID registry at its boundary: the home registry of every namespace, holding the bound addresses."""

    registry_url = REGISTRY_ORIGIN

    def __init__(self):
        self.addresses = {}
        self.controller_did = _make_keypair()[2]

    def bind(self, address, did_aw, did_key):
        domain, name = address.split("/", 1)
        self.addresses[address] = Address(
            address_id=f"addr-{name}", domain=domain, name=name, did_aw=did_aw,
            current_did_key=did_key, created_at=datetime.now(timezone.utc).isoformat(),
        )

    async def registry_audience(self, domain):
        return REGISTRY_ORIGIN

    async def get_namespace_fresh(self, domain):
        return Namespace(
            namespace_id=f"namespace-{domain}", domain=domain, controller_did=self.controller_did,
            verification_status="verified", last_verified_at=None,
            created_at=datetime.now(timezone.utc).isoformat(),
        )

    async def resolve_address(self, domain, name, *, did_key=None):
        return self.addresses.get(f"{domain}/{name}")

    async def resolve_address_fresh(self, domain, name):
        return self.addresses.get(f"{domain}/{name}")


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
    await db.execute("UPDATE {{tables.agents}} SET agent_type='human', human_verified_key=did_key WHERE agent_id=$1", UUID(human))
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

    registry = _AddressRegistry()
    app = _build_test_app(db, registry)
    seed_verified_bindings(app, ("did:aw:pilot", pilot_did, "acme.com/pilot"),
                           ("did:aw:human", human_did, ""))
    from aweb.routes.messaging import router as messaging_router
    app.include_router(messaging_router)
    from aweb.routes.conversations import router as conversations_router
    app.include_router(conversations_router)
    mcp = create_mcp_app(
        db_infra=app.state.db, registry_client=registry, hosted_signer=signer, hosted_encryptor=encryptor,
    )
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

            async def mcp_call(tool, **arguments):
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
                    "params": {"name": tool, "arguments": arguments},
                })
                assert response.status_code == 200, response.text
                result = response.json()
                assert "error" not in result, result
                return json.loads(result["result"]["content"][0]["text"])

            async def mcp_mail(**arguments):
                return await mcp_call("send_mail", body="unprompted update", **arguments)

            yield SimpleNamespace(db=db, human_mail=human_mail, mcp_mail=mcp_mail, mcp_call=mcp_call,
                                  custody=custody, human=human, human_did=human_did, pilot=pilot,
                                  client=client, pilot_key=pilot_key, pilot_did=pilot_did,
                                  human_key=human_key, registry=registry)
    finally:
        await mcp.shutdown()


@pytest.mark.asyncio
@pytest.mark.parametrize("target", ["alias", "stable_did", "current_did", "address"])
@pytest.mark.parametrize("plaintext", [True, False])
async def test_mcp_recipient_send_starts_new_conversation(mail_server, target, plaintext):
    server = mail_server
    original = await server.human_mail()
    # Neither HTTP nor MCP adopts a pair without an explicit conversation ID.
    ordinary = await server.human_mail("another human message")
    assert ordinary["conversation_id"] != original["conversation_id"]
    recipient = {"alias": "human", "stable_did": "did:aw:human",
                 "current_did": server.human_did, "address": "acme.com/human"}[target]
    sent = await server.mcp_mail(to=recipient, plaintext=plaintext)
    assert "error" not in sent, sent
    assert sent["conversation_id"] not in {original["conversation_id"], ordinary["conversation_id"]}
    assert server.custody.payloads[-1]["conversation_id"] == sent["conversation_id"]
    row = await server.db.fetch_one("SELECT * FROM {{tables.messages}} WHERE message_id=$1", UUID(sent["message_id"]))
    assert str(row["conversation_id"]) == sent["conversation_id"]
    assert row["to_did"] == "did:aw:human"
    if plaintext:
        assert json.loads(row["signed_payload"])["conversation_id"] == sent["conversation_id"]
    else:
        assert row["content_mode"] == "encrypted_v2"
        envelope = json.loads(row["encrypted_envelope"])
        assert envelope["conversation_id"] == sent["conversation_id"]
    assert (await server.db.fetch_one("SELECT count(*) AS n FROM {{tables.conversations}}"))["n"] == 3


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
async def test_mcp_new_conversation_does_not_bypass_recipient_policy(mail_server):
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
    assert server.custody.payloads[-1]["conversation_id"] != old


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


@pytest.mark.asyncio
async def test_mcp_lookup_preserves_its_existing_selector_validation(mail_server):
    server = mail_server
    # MCP's published `to` is an unconstrained string, unlike the HTTP model's
    # 64-character alias validator. Sharing its lookup must not narrow MCP.
    alias = "a" * 65
    await server.db.execute(
        "UPDATE {{tables.agents}} SET alias=$2, agent_type='agent' WHERE agent_id=$1", UUID(server.human), alias,
    )
    sent = await server.mcp_mail(to=alias, plaintext=True)
    assert "error" not in sent, sent
    assert (await server.db.fetch_one("SELECT count(*) AS n FROM {{tables.messages}}"))["n"] == 1


@pytest.mark.asyncio
async def test_http_selected_team_human_alias_and_discovery(mail_server):
    server = mail_server
    raw = json.dumps({"to_alias":"human", "body":"first contact"}).encode()
    headers = {"Content-Type":"application/json", **_signed_identity_headers(server.pilot_key, server.pilot_did, "", raw)}
    sent = await server.client.post("/v1/messages", content=raw, headers=headers)
    assert sent.status_code == 200, sent.text
    found = await server.client.get("/v1/messaging/participants/human", headers=_signed_identity_headers(server.pilot_key, server.pilot_did, "", b""))
    assert found.status_code == 200, found.text
    assert found.json()["did_aw"] == "did:aw:human"
    assert found.json()["team_id"] == "ops:acme.com"
    assert found.json()["encryption_key"] is None  # Plaintext required no assertion.
    stored = await server.db.fetch_one("SELECT to_did FROM {{tables.messages}} WHERE message_id=$1", UUID(sent.json()["message_id"]))
    assert stored["to_did"] == "did:aw:human"


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["inactive", "wrong_team", "unknown_bare_did"])
async def test_human_alias_refusal_has_no_message_or_mutation(mail_server, failure):
    server = mail_server
    target = {"to_alias":"human"}
    if failure == "inactive":
        await server.db.execute("UPDATE {{tables.agents}} SET status='retired' WHERE agent_id=$1", UUID(server.human))
    elif failure == "wrong_team":
        await _insert_team(server.db, "other:acme.com")
        target = {"to_alias":"other~human"}
    else:
        target = {"to_did":"did:aw:unknown-external"}
    raw = json.dumps({**target,"body":"must refuse"}).encode()
    response = await server.client.post("/v1/messages", content=raw, headers={"Content-Type":"application/json", **_signed_identity_headers(server.pilot_key, server.pilot_did, "", raw)})
    assert response.status_code in (404,422), response.text
    assert (await server.db.fetch_one("SELECT count(*) AS n FROM {{tables.messages}}"))["n"] == 0
    assert (await server.db.fetch_one("SELECT count(*) AS n FROM {{tables.conversations}}"))["n"] == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("plaintext", [True, False])
async def test_mcp_lists_threads_from_the_participant_http_index_without_ack(mail_server, plaintext):
    server = mail_server
    first = await server.mcp_mail(to="human", subject="First title", plaintext=plaintext)
    reply = await server.mcp_mail(conversation_id=first["conversation_id"], subject="New subject", plaintext=True)
    assert reply["conversation_id"] == first["conversation_id"]
    # Another pair's mail stays outside this actor's index.
    _, _, other = _make_keypair()
    await _insert_agent(server.db, team_id="ops:acme.com", alias="other", did_key=other, did_aw=None, address=None)
    await server.human_mail(to_alias="other", subject="Private other pair")
    before = await server.db.fetch_all("SELECT message_id,read_at FROM {{tables.messages}} ORDER BY message_id")
    listed = await server.mcp_call("list_threads", participant_did="did:aw:human")
    assert len(listed["conversations"]) == 1, listed
    item = listed["conversations"][0]
    assert item["conversation_id"] == first["conversation_id"]
    assert item["first_message_id"] == first["message_id"]
    assert item["title"] == ("First title" if plaintext else "")
    assert item["subject"] == "New subject"
    assert set(item["participant_dids"]) == {"did:aw:pilot", "did:aw:human"}
    response = await server.client.get(
        "/v1/conversations?conversation_type=mail&participant_did=did:aw:human",
        headers=_signed_identity_headers(server.pilot_key, server.pilot_did, "", b""),
    )
    assert response.status_code == 200, response.text
    assert listed == response.json()
    assert before == await server.db.fetch_all("SELECT message_id,read_at FROM {{tables.messages}} ORDER BY message_id")
    # A filter does not grant access to another pair, nor acknowledge its mail.
    assert (await server.mcp_call("list_threads", participant_did=other))["conversations"] == []
    invalid = await server.mcp_call("list_threads", limit=101)
    assert "error" in invalid, invalid


@pytest.mark.asyncio
async def test_mcp_address_mail_keeps_the_selected_membership(mail_server):
    server = mail_server
    await _insert_team(server.db, "partner:partner.test")
    other = await _insert_agent(server.db, team_id="partner:partner.test", alias="human", did_key=server.human_did,
        did_aw="did:aw:human", address="partner.test/human")
    await server.db.execute("UPDATE {{tables.agents}} SET created_at=NOW()+INTERVAL '1 second' WHERE agent_id=$1", UUID(other))
    sent = await server.mcp_mail(to="acme.com/human", plaintext=True)
    assert "error" not in sent, sent
    continued = await server.mcp_mail(conversation_id=sent['conversation_id'], plaintext=True)
    assert "error" not in continued, continued
    participant = await server.db.fetch_one("SELECT agent_id,address FROM {{tables.conversation_participants}} WHERE conversation_id=$1 AND did='did:aw:human'", UUID(sent['conversation_id']))
    assert participant['agent_id'] is None
    assert participant['address'] == 'acme.com/human'


async def _mail_state(server):
    """Every stored conversation and message."""
    return (
        (await server.db.fetch_one("SELECT count(*) AS n FROM {{tables.conversations}}"))["n"],
        (await server.db.fetch_one("SELECT count(*) AS n FROM {{tables.messages}}"))["n"],
    )


async def _participants(server, conversation_id):
    rows = await server.db.fetch_all(
        """SELECT role, transport_hint, current_did_key FROM {{tables.conversation_participants}}
           WHERE conversation_id=$1""",
        UUID(conversation_id),
    )
    return {row["role"]: (row["transport_hint"], row["current_did_key"]) for row in rows}


@pytest.mark.asyncio
async def test_first_mail_records_the_same_participants_through_both_adapters(mail_server):
    server = mail_server
    from_mcp = await server.mcp_mail(to="human", plaintext=True)
    assert "error" not in from_mcp, from_mcp
    from_rest = await server.human_mail(to_alias="pilot")

    assert await _participants(server, from_mcp["conversation_id"]) == {
        "initiator": ("local", server.pilot_did), "participant": ("local", server.human_did),
    }
    assert await _participants(server, from_rest["conversation_id"]) == {
        "initiator": ("local", server.human_did), "participant": ("local", server.pilot_did),
    }


@pytest.mark.asyncio
async def test_a_failed_message_insert_leaves_no_conversation_through_either_adapter(mail_server):
    server = mail_server
    # Every message insert is refused by the database, after the send was admitted.
    await server.db.execute(
        "ALTER TABLE {{tables.messages}} ADD CONSTRAINT refuse_every_insert CHECK (false) NOT VALID"
    )
    try:
        from_mcp = await server.mcp_mail(to="human", plaintext=True)
        assert "error" in from_mcp, from_mcp
        assert await _mail_state(server) == (0, 0)

        raw = json.dumps({"to_alias": "pilot", "body": "hello"}).encode()
        # The route does not handle a database refusal: the application
        # answers 500, or the test transport raises the refusal itself.
        try:
            response = await server.client.post("/v1/messages", content=raw, headers={
                "Content-Type": "application/json",
                **_signed_identity_headers(server.human_key, server.human_did, "", raw),
            })
        except (QueryError, asyncpg.PostgresError):
            response = None
        assert response is None or response.status_code == 500, response.text
        assert await _mail_state(server) == (0, 0)
    finally:
        await server.db.execute("ALTER TABLE {{tables.messages}} DROP CONSTRAINT refuse_every_insert")


@pytest.mark.asyncio
async def test_an_address_send_records_the_senders_contact_through_both_adapters(mail_server):
    server = mail_server
    _, _, bob_did = _make_keypair()
    await _insert_agent(server.db, team_id="ops:acme.com", alias="bob", did_key=bob_did,
                        did_aw="did:aw:bob", address="acme.com/bob")
    server.registry.bind("acme.com/bob", "did:aw:bob", bob_did)

    from_mcp = await server.mcp_mail(to="acme.com/bob", plaintext=True)
    assert "error" not in from_mcp, from_mcp
    await server.human_mail(to_address="acme.com/bob")

    contacts = await server.db.fetch_all(
        """SELECT owner_did, contact_address, contact_did_aw, binding_controller_did, status
           FROM {{tables.contacts}} ORDER BY owner_did"""
    )
    assert [dict(row) for row in contacts] == [
        {"owner_did": owner, "contact_address": "acme.com/bob", "contact_did_aw": "did:aw:bob",
         "binding_controller_did": server.registry.controller_did, "status": "active"}
        for owner in ("did:aw:human", "did:aw:pilot")
    ]


async def _publish_hosted_key(server, *, agent_id, signing_key, did_key, did_aw, public_key):
    await _insert_agent_encryption_assertion(
        server.db, agent_id=UUID(agent_id), team_id="ops:acme.com",
        assertion=build_encryption_key_assertion(
            signing_key=signing_key, identity_did=did_key, identity_stable_id=did_aw,
            encryption_public_key=public_key, custody="hosted_custodial",
        ),
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("sender_key_published", [True, False])
async def test_mcp_encrypted_mail_to_a_hosted_recipient_needs_the_senders_hosted_key(
    mail_server, sender_key_published,
):
    server = mail_server
    # The fixture's envelopes wrap to these two keys.
    await _publish_hosted_key(server, agent_id=server.human, signing_key=server.human_key,
                              did_key=server.human_did, did_aw="did:aw:human", public_key=b"r" * 32)
    if sender_key_published:
        await _publish_hosted_key(server, agent_id=server.pilot, signing_key=server.pilot_key,
                                  did_key=server.pilot_did, did_aw="did:aw:pilot", public_key=b"s" * 32)

    sent = await server.mcp_mail(to="human")

    if sender_key_published:
        assert "error" not in sent, sent
        row = await server.db.fetch_one(
            "SELECT content_mode FROM {{tables.messages}} WHERE message_id=$1", UUID(sent["message_id"]),
        )
        assert row["content_mode"] == "encrypted_v2"
    else:
        assert sent == {
            "error": "your encryption key isn't published yet; try again shortly, "
                     "and if it persists contact support",
            "reason": "recipient_custodial_no_e2ee",
        }
        assert await _mail_state(server) == (0, 0)


@pytest.mark.asyncio
async def test_mcp_handle_address_outside_the_senders_team_needs_its_registry_binding(mail_server):
    server = mail_server
    _, _, c3po_did = _make_keypair()
    await _insert_team(server.db, "home:jane.aweb.ai")
    await _insert_agent(server.db, team_id="home:jane.aweb.ai", alias="c3po", did_key=c3po_did,
                        did_aw="did:aw:c3po", address="jane.aweb.ai/c3po")

    refused = await server.mcp_mail(to="@jane/c3po", plaintext=True)
    assert refused == {"error": unreachable_address_refusal("jane.aweb.ai/c3po")}
    assert await _mail_state(server) == (0, 0)

    server.registry.bind("jane.aweb.ai/c3po", "did:aw:c3po", c3po_did)
    sent = await server.mcp_mail(to="@jane/c3po", plaintext=True)
    assert "error" not in sent, sent
    row = await server.db.fetch_one(
        "SELECT to_did, to_alias, to_agent_id FROM {{tables.messages}} WHERE message_id=$1",
        UUID(sent["message_id"]),
    )
    assert dict(row) == {"to_did": "did:aw:c3po", "to_alias": "c3po", "to_agent_id": None}
    assert server.custody.payloads[-1]["to"] == "jane.aweb.ai/c3po"


@pytest.mark.asyncio
async def test_mcp_mail_reaches_another_team_of_the_senders_organization_by_alias(mail_server):
    server = mail_server
    _, _, zed_did = _make_keypair()
    await _insert_team(server.db, "eng:acme.com")
    zed = await _insert_agent(server.db, team_id="eng:acme.com", alias="zed", did_key=zed_did,
                              did_aw="did:aw:zed", address="acme.com/zed")

    sent = await server.mcp_mail(to="eng~zed", plaintext=True)

    assert "error" not in sent, sent
    assert sent["to"] == "zed"
    row = await server.db.fetch_one(
        "SELECT to_did, to_agent_id FROM {{tables.messages}} WHERE message_id=$1", UUID(sent["message_id"]),
    )
    assert (row["to_did"], str(row["to_agent_id"])) == ("did:aw:zed", zed)
    # The signed recipient is the selector the sender named.
    assert server.custody.payloads[-1]["to"] == "eng~zed"
    assert (await server.mcp_mail(to="nowhere~zed", plaintext=True)) == {"error": "Unknown team: nowhere:acme.com"}


@pytest.mark.asyncio
async def test_mcp_refusals_of_an_unknown_recipient_read_as_the_routes_do(mail_server):
    server = mail_server
    assert await server.mcp_mail(to="nobody", plaintext=True) == {"error": "Recipient agent not found"}
    assert await server.mcp_mail(to="did:aw:nobody", plaintext=True) == {
        "error": "Bare did:aw first-contact is unsupported; use to_address=domain/name "
                 "or continue an existing conversation",
    }
    assert await _mail_state(server) == (0, 0)


SIGNED_SELECTORS = [
    # (what the caller names, the selector field it becomes, the recipient the service resolves)
    ("bob", "to_alias", {"alias": "bob", "did_key": "did:key:zBob", "did_aw": "did:aw:bob",
                         "address": "acme.com/bob"}),
    ("eng~bob", "to_alias", {"alias": "bob", "did_key": "did:key:zBob", "did_aw": "did:aw:bob",
                             "address": "acme.com/bob"}),
    ("acme.com/bob", "to_address", {"alias": "bob", "did_key": "did:key:zBob", "did_aw": "did:aw:bob",
                                    "address": "acme.com/bob"}),
    ("did:aw:bob", "to_did", {"alias": "bob", "did_key": "did:key:zBob", "did_aw": "did:aw:bob",
                              "address": "acme.com/bob"}),
    ("did:key:zBob", "to_did", {"alias": "bob", "did_key": "did:key:zBob", "did_aw": None, "address": None}),
]


@pytest.mark.parametrize("named,field,recipient", SIGNED_SELECTORS)
@pytest.mark.parametrize("priority", ["normal", "urgent"])
def test_the_fields_mcp_signs_for_a_first_mail_satisfy_the_send_validation(named, field, recipient, priority):
    from aweb.mcp.auth import AuthContext
    from aweb.mcp.tools.mail import _signed_mail_fields, _signed_recipient

    auth = AuthContext(team_id="ops:acme.com", agent_id=str(uuid4()), alias="pilot",
                       did_key="did:key:zPilot", did_aw="did:aw:pilot", address="acme.com/pilot")
    message_id, conversation_id = str(uuid4()), str(uuid4())
    fields = _signed_mail_fields(
        auth, signed_from="pilot", to=_signed_recipient(named, recipient["alias"]),
        to_did=recipient["did_key"], to_stable_id=recipient["did_aw"] or "",
        subject="status", body="hello", priority=priority, message_id=message_id,
        conversation_id=conversation_id, timestamp="2026-11-10T12:00:00Z",
    )

    _validate_signed_mail_payload(
        signature=sign_message(_make_keypair()[0], b"shape only"),
        signed_payload=canonical_signed_payload(fields), recipient=recipient,
        to_agent_id=None, to_alias=recipient["alias"],
        requested_to_alias=named if field == "to_alias" else None,
        from_alias="pilot", from_address="acme.com/pilot", from_stable_id="did:aw:pilot",
        priority=priority, subject="status", body="hello", from_did="did:key:zPilot",
        message_id=message_id, timestamp="2026-11-10T12:00:00Z", conversation_id=conversation_id,
    )


def test_the_fields_mcp_signs_for_a_reply_satisfy_the_send_validation():
    from aweb.mcp.auth import AuthContext
    from aweb.mcp.tools.mail import _signed_mail_fields

    auth = AuthContext(team_id="ops:acme.com", agent_id=str(uuid4()), alias="pilot",
                       did_key="did:key:zPilot", did_aw="did:aw:pilot", address="acme.com/pilot")
    message_id, conversation_id = str(uuid4()), str(uuid4())
    # A reply to a local participant names its stable identity and no current key.
    fields = _signed_mail_fields(
        auth, signed_from="pilot", to="", to_did="", to_stable_id="did:aw:bob",
        subject="re", body="hello", priority="normal", message_id=message_id,
        conversation_id=conversation_id, timestamp="2026-11-10T12:00:00Z",
    )
    assert (fields["to"], fields["to_did"], fields["to_stable_id"]) == ("", "", "did:aw:bob")

    _validate_signed_mail_payload(
        signature=sign_message(_make_keypair()[0], b"shape only"),
        signed_payload=canonical_signed_payload(fields),
        recipient={"alias": "bob", "did_key": "did:key:zBob", "did_aw": "did:aw:bob", "address": "acme.com/bob"},
        to_agent_id=None, to_alias="bob", requested_to_alias=None,
        from_alias="pilot", from_address="acme.com/pilot", from_stable_id="did:aw:pilot",
        priority="normal", subject="re", body="hello", from_did="did:key:zPilot",
        message_id=message_id, timestamp="2026-11-10T12:00:00Z", conversation_id=conversation_id,
    )


def _authority_refusal(reason):
    from awid.federation_errors import FederationAuthorityError

    return FederationAuthorityError(reason)


def _binding_refusal(status, code):
    from fastapi import HTTPException

    return HTTPException(status_code=status, detail=code)


# (the refusal the send raises, what the tool knows about the send, what the tool answers)
NEXT_ACTIONS = [
    (lambda: _authority_refusal("sender_registry_unavailable"), {"address": "jane.aweb.ai/c3po"}, {
        "error": "the registry can't confirm jane.aweb.ai/c3po right now; try again, or check the address",
        "reason": "sender_registry_unavailable",
    }),
    (lambda: _authority_refusal("recipient_custodial_no_e2ee"), {"hosted_envelope": True}, {
        "error": "your encryption key isn't published yet; try again shortly, and if it persists contact support",
        "reason": "recipient_custodial_no_e2ee",
    }),
    (lambda: _authority_refusal("federation_envelope_invalid"), {"hosted_envelope": True}, {
        "error": "your published encryption key can't be verified right now; try again shortly, "
                 "and if it persists contact support",
        "reason": "federation_envelope_invalid",
    }),
    (lambda: _authority_refusal("recipient_encryption_assertion_invalid_or_stale"), {"hosted_envelope": True}, {
        "error": "this recipient's published encryption key can't be verified right now; try again later, "
                 "and if it persists contact support",
        "reason": "recipient_encryption_assertion_invalid_or_stale",
    }),
    (lambda: _binding_refusal(403, "identity_binding_mismatch"), {}, {
        "error": "this recipient's identity or key no longer matches the registry; check the address and resend",
        "reason": "identity_binding_mismatch",
    }),
    (lambda: _binding_refusal(503, "identity_binding_unavailable"), {}, {
        "error": "the registry can't confirm this recipient's key right now; try again shortly",
        "reason": "identity_binding_unavailable",
    }),
]


@pytest.mark.parametrize("refusal,known,answer", NEXT_ACTIONS)
def test_mcp_mail_refusals_name_the_next_action_and_keep_their_code(refusal, known, answer):
    from aweb.mcp.tools.mail import _send_refusal

    assert json.loads(_send_refusal(refusal(), **known)) == answer


@pytest.mark.parametrize("reason", [
    "sender_registry_unavailable", "recipient_custodial_no_e2ee", "federation_envelope_invalid",
    "recipient_encryption_assertion_invalid_or_stale",
])
def test_the_route_answers_a_federation_refusal_with_its_code_alone(reason):
    from aweb.federation.errors import authority_error_body

    body = authority_error_body(_authority_refusal(reason), correlation_id="c")
    assert (body["detail"], body["reason"]) == (reason, reason)
    assert set(body) == {"detail", "reason", "retryable", "correlation_id"}


def test_mcp_mail_codes_without_a_next_action_are_answered_as_the_code():
    from aweb.mcp.tools.mail import _send_refusal

    # Outside a hosted envelope the custody refusal says nothing about the sender's key.
    assert json.loads(_send_refusal(_authority_refusal("recipient_custodial_no_e2ee"))) == {
        "error": "recipient_custodial_no_e2ee",
    }
    assert json.loads(_send_refusal(_authority_refusal("federation_rate_limited"), address="a.test/b")) == {
        "error": "federation_rate_limited",
    }
    # An address the registry does not bind is refused in the words for a name nobody holds.
    for refusal in (_authority_refusal("recipient_identity_not_found"),
                    _authority_refusal("local_recipient_route_missing"),
                    _binding_refusal(404, "Recipient address not found")):
        assert json.loads(_send_refusal(refusal, address="a.test/b")) == {
            "error": unreachable_address_refusal("a.test/b"),
        }


def test_an_envelope_for_a_key_this_server_does_not_record_is_refused_as_a_changed_key():
    from fastapi import HTTPException

    from aweb.identity_auth_deps import MessagingAuth
    from aweb.mcp.tools.mail import _send_refusal
    from aweb.messaging.mail_send import _validate_encrypted_payload
    from aweb.routes.messages import SendMessageRequest

    pilot_key, _, pilot_did = _make_keypair()
    recorded_did, registry_did = _make_keypair()[2], _make_keypair()[2]
    message_id, conversation_id = str(uuid4()), str(uuid4())
    envelope = _encrypted_mail_envelope(
        sender_sk=pilot_key, sender_did=pilot_did, sender_stable_id="did:aw:pilot",
        recipient_did=registry_did, recipient_stable_id="did:aw:bob",
        message_id=message_id, conversation_id=conversation_id,
    )
    payload = SendMessageRequest(
        to_alias="bob", message_id=message_id, conversation_id=conversation_id,
        content_mode="encrypted_v2", message_version=2, encrypted_envelope=envelope,
    )

    with pytest.raises(HTTPException) as refused:
        _validate_encrypted_payload(
            payload, auth=MessagingAuth(did_key=pilot_did, did_aw="did:aw:pilot", address="acme.com/pilot"),
            sender_did="did:aw:pilot",
            recipient={"did_key": recorded_did, "did_aw": "did:aw:bob", "address": "acme.com/bob"},
            recipient_did="did:aw:bob",
        )

    # The route's answer is unchanged.
    assert (refused.value.status_code, refused.value.detail) == (422, "encrypted envelope recipient did mismatch")
    assert json.loads(_send_refusal(refused.value, hosted_envelope=True)) == {
        "error": "this recipient's key changed; resend the message",
    }


def test_a_refusal_whose_detail_is_an_object_is_answered_with_that_object():
    from aweb.mcp.tools.mail import _send_refusal

    # A retired participant is refused with a code and a message, as one object.
    retired = {"code": "participant_retired", "message": "human has moved; start a new mail to human in ops:acme.com"}
    assert json.loads(_send_refusal(_binding_refusal(410, retired))) == {"error": retired}
    assert json.loads(_send_refusal(_binding_refusal(410, retired), address="a.test/b", hosted_envelope=True)) == {
        "error": retired,
    }

"""A chat send behaves the same through the MCP tool and the routes.

The database cases run through the real mounted MCP app and the REST app over
ASGI, with real PostgreSQL. The cases without a fixture read no database.
"""

from identity_binding_support import seed_verified_bindings

import asyncio
import json
from datetime import datetime, timezone
from types import SimpleNamespace
from uuid import UUID, uuid4

import httpx
import pytest
import pytest_asyncio
from fastapi import HTTPException

from awid.e2ee_keys import build_encryption_key_assertion
from awid.federation_errors import FederationAuthorityError
from awid.signing import sign_message
from aweb.e2ee_messages import encrypt_e2ee_chat, generate_x25519_keypair
from aweb.internal_auth import build_internal_auth_header_value
from aweb.mcp.server import create_mcp_app
from aweb.mcp.signing import HostedMessageSigningResult, canonical_signed_payload
from aweb.messaging.address_auth import unreachable_address_refusal
from aweb.messaging.chat_policy import HumanChatRefused
from aweb.messaging.runtime import messaging_runtime
from aweb.routes.chat import router as chat_router
from test_mcp_mail_conversation_parity import _AddressRegistry
from test_messages_http import (
    _build_test_app,
    _insert_agent,
    _insert_agent_encryption_assertion,
    _insert_team,
    _make_keypair,
    _signed_identity_headers,
)

TEAM = "ops:acme.com"
INTERNAL_SECRET = "chat-parity-test-secret"


@pytest_asyncio.fixture
async def chat_server(aweb_cloud_db, monkeypatch):
    db = aweb_cloud_db.aweb_db
    await _insert_team(db, TEAM)
    registry = _AddressRegistry()
    keys, agents, custody = {}, {}, {}
    for alias in ("pilot", "bob"):
        sk, _, did_key = _make_keypair()
        keys[alias] = (sk, did_key)
        agents[alias] = await _insert_agent(
            db, team_id=TEAM, alias=alias, did_key=did_key,
            did_aw=f"did:aw:{alias}", address=f"acme.com/{alias}",
        )
        await db.execute(
            """INSERT INTO {{tables.workspaces}}
               (workspace_id, team_id, agent_id, alias, workspace_type)
               VALUES ($1, $2, $3, $4, 'hosted_mcp')""",
            uuid4(), TEAM, UUID(agents[alias]), alias,
        )
        registry.bind(f"acme.com/{alias}", f"did:aw:{alias}", did_key)
        # The identity hosted custody encrypts as and to: its signing key and
        # an encryption key it asserts as held in hosted custody.
        _, encryption_public_key = generate_x25519_keypair()
        custody[alias] = {
            "signing_key": sk, "did": did_key, "stable_id": f"did:aw:{alias}",
            "address": f"acme.com/{alias}",
            "encryption_key": build_encryption_key_assertion(
                signing_key=sk, identity_did=did_key, identity_stable_id=f"did:aw:{alias}",
                encryption_public_key=encryption_public_key, custody="hosted_custodial",
            ),
        }
    monkeypatch.setenv("AWEB_TRUST_PROXY_HEADERS", "1")
    monkeypatch.setenv("AWEB_INTERNAL_AUTH_SECRET", INTERNAL_SECRET)
    signed_payloads = []
    alias_of = {agent_id: alias for alias, agent_id in agents.items()}
    # When set, custody holds each signature until two sends are waiting for
    # one, so both resolved their recipient before either stores anything.
    together = SimpleNamespace(waiting=0, released=None)

    async def signer(**kwargs):
        sk, did_key = keys[alias_of[kwargs["agent_id"]]]
        if together.released is not None:
            together.waiting += 1
            if together.waiting >= 2:
                together.released.set()
            await together.released.wait()
        signed_payloads.append(dict(kwargs["payload"]))
        signed = canonical_signed_payload(dict(kwargs["payload"]))
        return HostedMessageSigningResult(
            from_did=did_key, signing_key_id=did_key, signed_payload=signed,
            signature=sign_message(sk, signed.encode()),
        )

    async def encryptor(**kwargs):
        payload = kwargs["payload"]
        by_did = {identity["did"]: identity for identity in custody.values()}
        envelope = encrypt_e2ee_chat(
            sender=custody[alias_of[kwargs["agent_id"]]],
            recipients=[by_did[recipient["did_key"]] for recipient in kwargs["recipients"]],
            body=payload["body"], message_id=payload["message_id"],
            conversation_id=payload["conversation_id"],
            created_at=datetime.fromisoformat(payload["timestamp"].replace("Z", "+00:00")),
        )
        return {"content_mode": "encrypted_v2", "message_version": 2, "encrypted_envelope": envelope}

    mutations = []

    async def record_mutation(event_type, context):
        mutations.append((event_type, dict(context)))

    app = _build_test_app(db, registry)
    app.include_router(chat_router)
    seed_verified_bindings(app, *((f"did:aw:{alias}", did, f"acme.com/{alias}")
                                  for alias, (_, did) in keys.items()))
    app.state.on_mutation = record_mutation
    mcp = create_mcp_app(
        db_infra=app.state.db, registry_client=registry, hosted_signer=signer, hosted_encryptor=encryptor,
    )
    app.mount("/mcp", mcp)
    await mcp.startup()
    try:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:

            async def mcp_chat(alias, **arguments):
                principal = str(uuid4())
                headers = {
                    "Accept": "application/json, text/event-stream", "X-Team-ID": TEAM,
                    "X-User-ID": principal, "X-AWEB-Actor-ID": agents[alias],
                    "X-AWEB-Auth": build_internal_auth_header_value(
                        secret=INTERNAL_SECRET, team_id=TEAM,
                        principal_type="u", principal_id=principal, actor_id=agents[alias],
                    ),
                }
                response = await client.post("/mcp/", headers=headers, json={
                    "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                    "params": {"name": "send_chat", "arguments": arguments},
                })
                assert response.status_code == 200, response.text
                result = response.json()
                assert "error" not in result, result
                return json.loads(result["result"]["content"][0]["text"])

            async def rest_chat(alias, body, *, session_id=None):
                sk, did_key = keys[alias]
                path = "/v1/chat/sessions" if session_id is None else f"/v1/chat/sessions/{session_id}/messages"
                data = json.dumps(body).encode()
                response = await client.post(path, content=data, headers={
                    "Content-Type": "application/json", **_signed_identity_headers(sk, did_key, "", data),
                })
                assert response.status_code == 200, response.text
                return response.json()

            async def first_chat(via, alias, message, *, to_alias=None, to_address=None, wait_seconds=None):
                """A send naming its recipient, through one adapter; the session and message ids."""
                if via == "mcp":
                    arguments = {"to": to_alias or to_address, "message": message, "plaintext": True}
                    if wait_seconds is not None:
                        arguments.update(wait=True, wait_seconds=wait_seconds)
                    sent = await mcp_chat(alias, **arguments)
                    assert "error" not in sent, sent
                else:
                    body = {"message": message}
                    body.update({"to_aliases": [to_alias]} if to_alias else {"to_addresses": [to_address]})
                    if wait_seconds is not None:
                        body["wait_seconds"] = wait_seconds
                    sent = await rest_chat(alias, body)
                return sent["session_id"], sent["message_id"]

            async def continued_chat(via, alias, session_id, message, *, wait_seconds=None):
                if via == "mcp":
                    arguments = {"conversation_id": session_id, "message": message, "plaintext": True}
                    if wait_seconds is not None:
                        arguments.update(wait=True, wait_seconds=wait_seconds)
                    sent = await mcp_chat(alias, **arguments)
                    assert "error" not in sent, sent
                else:
                    body = {"body": message}
                    if wait_seconds is not None:
                        body["wait_seconds"] = wait_seconds
                    sent = await rest_chat(alias, body, session_id=session_id)
                return sent["message_id"]

            yield SimpleNamespace(
                db=db, agents=agents, keys=keys, custody=custody, registry=registry, mutations=mutations,
                signed_payloads=signed_payloads, mcp_chat=mcp_chat, rest_chat=rest_chat,
                first_chat=first_chat, continued_chat=continued_chat, together=together,
                infra=app.state.db, runtime=messaging_runtime(app.state),
            )
    finally:
        await mcp.shutdown()


@pytest.mark.asyncio
@pytest.mark.parametrize("via", ["mcp", "rest"])
async def test_a_first_chat_to_an_address_records_the_senders_contact(chat_server, via):
    server = chat_server

    await server.first_chat(via, "pilot", "hello bob", to_address="acme.com/bob")

    contacts = await server.db.fetch_all(
        """SELECT owner_did, contact_address, contact_did_aw, binding_controller_did, status
           FROM {{tables.contacts}}"""
    )
    assert [dict(row) for row in contacts] == [{
        "owner_did": "did:aw:pilot", "contact_address": "acme.com/bob", "contact_did_aw": "did:aw:bob",
        "binding_controller_did": server.registry.controller_did, "status": "active",
    }]


@pytest.mark.asyncio
@pytest.mark.parametrize("via", ["mcp", "rest"])
async def test_a_send_that_waits_records_the_wait_on_the_session(chat_server, via):
    server = chat_server

    session_id, message_id = await server.first_chat(via, "pilot", "are you there?", to_alias="bob", wait_seconds=1)

    session = await server.db.fetch_one(
        "SELECT wait_seconds, wait_started_at, wait_started_by FROM {{tables.chat_sessions}} WHERE session_id=$1",
        UUID(session_id),
    )
    message = await server.db.fetch_one(
        "SELECT created_at FROM {{tables.chat_messages}} WHERE message_id=$1", UUID(message_id),
    )
    assert dict(session) == {
        "wait_seconds": 1, "wait_started_at": message["created_at"],
        "wait_started_by": UUID(server.agents["pilot"]),
    }


async def _pending_for_bob_while_pilot_waits(server, sending, *, earlier_message_ids=()):
    """Bob reads everything pilot sent while ``sending``, a send that waits 60 seconds, is in flight.

    Returns the session, the waiting message and bob's pending conversations;
    bob then answers, which ends the wait. The MCP tool answers when the wait
    ends; the route answers at once.
    """
    from aweb.messaging.chat import get_pending_conversations, mark_messages_read

    try:
        waited = None
        for _ in range(100):
            waited = await server.db.fetch_one(
                """SELECT s.session_id, s.wait_started_at, m.message_id
                   FROM {{tables.chat_sessions}} s
                   JOIN {{tables.chat_messages}} m ON m.session_id = s.session_id AND m.created_at = s.wait_started_at
                   WHERE s.wait_seconds IS NOT NULL"""
            )
            if waited is not None or sending.done():
                break
            await asyncio.sleep(0.05)
        assert waited is not None
        session_id, message_id = str(waited["session_id"]), str(waited["message_id"])
        await mark_messages_read(
            server.infra, session_id=UUID(session_id), participant_did="did:aw:bob",
            participant_agent_id=server.agents["bob"], message_ids=[*earlier_message_ids, message_id],
        )
        pending = await get_pending_conversations(
            server.infra, participant_did="did:aw:bob", participant_agent_id=server.agents["bob"],
        )
        await server.rest_chat("bob", {"body": "here"}, session_id=session_id)
        await asyncio.wait_for(sending, timeout=10)
        return session_id, message_id, pending
    finally:
        sending.cancel()


def _seconds_left(item):
    return item["wait_seconds"] - (datetime.now(timezone.utc) - item["wait_started_at"]).total_seconds()


@pytest.mark.asyncio
@pytest.mark.parametrize("via", ["mcp", "rest"])
async def test_a_recorded_wait_keeps_the_chat_pending_for_the_other_party_after_they_read_it(chat_server, via):
    server = chat_server
    sending = asyncio.create_task(
        server.first_chat(via, "pilot", "are you there?", to_alias="bob", wait_seconds=60)
    )

    session_id, _, pending = await _pending_for_bob_while_pilot_waits(server, sending)

    assert [(item["session_id"], item["unread_count"], item["wait_seconds"]) for item in pending] == [
        (session_id, 0, 60),
    ]
    assert _seconds_left(pending[0]) > 0


@pytest.mark.asyncio
@pytest.mark.parametrize("via", ["mcp", "rest"])
async def test_a_waiting_message_in_a_session_records_the_wait_and_keeps_the_chat_pending(chat_server, via):
    server = chat_server
    session_id, opened = await server.first_chat(via, "pilot", "hello bob", to_alias="bob")
    sending = asyncio.create_task(
        server.continued_chat(via, "pilot", session_id, "are you there?", wait_seconds=60)
    )

    waited_session, waiting_message, pending = await _pending_for_bob_while_pilot_waits(
        server, sending, earlier_message_ids=[opened],
    )

    assert waited_session == session_id
    assert [(item["session_id"], item["unread_count"], item["wait_seconds"]) for item in pending] == [
        (session_id, 0, 60),
    ]
    assert _seconds_left(pending[0]) > 0
    session = await server.db.fetch_one(
        "SELECT wait_started_by FROM {{tables.chat_sessions}} WHERE session_id=$1", UUID(session_id),
    )
    assert session["wait_started_by"] == UUID(server.agents["pilot"])
    assert waiting_message != opened


@pytest.mark.asyncio
@pytest.mark.parametrize("via", ["mcp", "rest"])
async def test_a_message_that_does_not_wait_leaves_the_recorded_wait_as_it_is(chat_server, via):
    server = chat_server

    async def recorded_wait(session_id):
        return dict(await server.db.fetch_one(
            """SELECT wait_seconds, wait_started_at, wait_started_by
               FROM {{tables.chat_sessions}} WHERE session_id=$1""",
            UUID(session_id),
        ))

    session_id, _ = await server.first_chat(via, "pilot", "are you there?", to_alias="bob", wait_seconds=0)
    before = await recorded_wait(session_id)
    assert before["wait_seconds"] == 0

    await server.continued_chat(via, "pilot", session_id, "one more thing")
    assert await recorded_wait(session_id) == before
    # The other party's message starts no wait of its own and leaves pilot's recorded.
    await server.continued_chat(via, "bob", session_id, "here")
    assert await recorded_wait(session_id) == before


async def _chat_sessions(server):
    """Every chat conversation with its status, and the bodies stored in each."""
    conversations = await server.db.fetch_all(
        """SELECT conversation_id, status FROM {{tables.conversations}}
           WHERE conversation_type='chat' ORDER BY created_at"""
    )
    messages = await server.db.fetch_all(
        "SELECT session_id, body FROM {{tables.chat_messages}} ORDER BY body"
    )
    return (
        [(str(row["conversation_id"]), row["status"]) for row in conversations],
        [(str(row["session_id"]), row["body"]) for row in messages],
    )


@pytest.mark.asyncio
async def test_two_interleaved_sends_that_reuse_or_create_share_one_session_and_close_none(chat_server):
    from aweb.identity_auth_deps import MessagingAuth
    from aweb.messaging.chat_send import ChatSessionChanged, resolve_chat_targets, send_chat
    from aweb.routes.chat import CreateSessionRequest

    server = chat_server
    pilot = MessagingAuth(
        did_key=server.keys["pilot"][1], did_aw="did:aw:pilot", address="acme.com/pilot",
        team_id=TEAM, alias="pilot", agent_id=server.agents["pilot"], identity_scope="global",
    )

    async def resolve():
        return await resolve_chat_targets(
            server.infra, pilot, CreateSessionRequest(to_aliases=["bob"], message=""), server.runtime, "test",
            reuse_or_create=True,
        )

    async def send(target, session_id, message):
        return await send_chat(
            server.infra, pilot, target,
            CreateSessionRequest(to_aliases=["bob"], session_id=str(session_id), message=message),
            server.runtime,
        )

    # Both sends resolve before either stores anything: neither finds a session.
    target_a, target_b = await resolve(), await resolve()
    assert (target_a.shared_session_id, target_b.shared_session_id) == (None, None)
    proposed_a, proposed_b = uuid4(), uuid4()

    sent_b = await send(target_b, proposed_b, "from b")
    assert sent_b.session_id == proposed_b
    # A's target was resolved when the pair shared no session: nothing is stored or closed.
    with pytest.raises(ChatSessionChanged):
        await send(target_a, proposed_a, "from a")
    assert await _chat_sessions(server) == ([(str(proposed_b), "active")], [(str(proposed_b), "from b")])

    # A resolves again, finds B's session and sends into it.
    target_a = await resolve()
    assert target_a.shared_session_id == proposed_b
    sent_a = await send(target_a, proposed_b, "from a")

    assert sent_a.session_id == proposed_b
    assert await _chat_sessions(server) == (
        [(str(proposed_b), "active")],
        [(str(proposed_b), "from a"), (str(proposed_b), "from b")],
    )


@pytest.mark.asyncio
async def test_two_concurrent_mcp_sends_for_one_pair_end_with_one_live_session(chat_server):
    server = chat_server
    # Custody releases the two signatures together, after both sends resolved.
    server.together.released = asyncio.Event()

    from_pilot, from_bob = await asyncio.wait_for(asyncio.gather(
        server.mcp_chat("pilot", to="bob", message="from pilot", plaintext=True),
        server.mcp_chat("bob", to="pilot", message="from bob", plaintext=True),
    ), timeout=30)

    assert "error" not in from_pilot, from_pilot
    assert "error" not in from_bob, from_bob
    assert from_pilot["session_id"] == from_bob["session_id"]
    session_id = from_pilot["session_id"]
    assert await _chat_sessions(server) == (
        [(session_id, "active")],
        [(session_id, "from bob"), (session_id, "from pilot")],
    )
    # Each message is signed for the session it is stored in.
    stored = await server.db.fetch_all("SELECT signed_payload FROM {{tables.chat_messages}}")
    assert {json.loads(row["signed_payload"])["conversation_id"] for row in stored} == {session_id}


@pytest.mark.asyncio
@pytest.mark.parametrize("via", ["mcp", "rest"])
async def test_chat_message_sent_has_one_context(chat_server, via):
    server = chat_server

    session_id, first = await server.first_chat(via, "pilot", "hello bob", to_alias="bob")
    second = await server.continued_chat(via, "pilot", session_id, "still there?")

    sent = [context for kind, context in server.mutations if kind == "chat.message_sent"]
    assert sent == [
        {
            "team_id": TEAM, "session_id": session_id, "conversation_id": session_id,
            "message_id": message_id, "from_agent_id": server.agents["pilot"], "from_alias": "pilot",
            "from_did": "did:aw:pilot", "from_did_aw": "did:aw:pilot", "to_aliases": ["bob"],
            "preview": preview, "content_mode": "legacy_plaintext_v1",
        }
        for message_id, preview in ((first, "hello bob"), (second, "still there?"))
    ]


@pytest.mark.asyncio
async def test_mcp_signed_chat_payloads_are_stored_as_signed_for_each_way_of_naming_the_recipient(chat_server):
    server = chat_server
    bob_did = server.keys["bob"][1]

    by_alias = await server.mcp_chat("pilot", to="bob", message="by alias", plaintext=True, wait=True, wait_seconds=0)
    assert "error" not in by_alias, by_alias
    session_id = by_alias["session_id"]
    later = [
        await server.mcp_chat("pilot", to="did:aw:bob", message="by did", plaintext=True),
        await server.mcp_chat("pilot", to="acme.com/bob", message="by address", plaintext=True),
        await server.mcp_chat(
            "pilot", conversation_id=session_id, message="in session", plaintext=True, wait=True, wait_seconds=0,
        ),
        await server.mcp_chat("pilot", to="bob", message="hang on", plaintext=True, hang_on=True),
        await server.mcp_chat("pilot", conversation_id=session_id, message="leaving", plaintext=True, leaving=True),
    ]
    for sent in later:
        assert "error" not in sent, sent
        # One pair, one session: every send reuses the session the pair shares.
        assert sent["session_id"] == session_id

    rows = await server.db.fetch_all(
        """SELECT body, signed_payload, hang_on, sender_leaving FROM {{tables.chat_messages}}
           WHERE session_id=$1 ORDER BY seq""",
        UUID(session_id),
    )
    signed = [json.loads(row["signed_payload"]) for row in rows]
    assert [row["body"] for row in rows] == ["by alias", "by did", "by address", "in session", "hang on", "leaving"]
    assert [(row["hang_on"], row["sender_leaving"]) for row in rows] == [
        (False, False), (False, False), (False, False), (False, False), (True, False), (False, True),
    ]
    for payload in signed:
        assert payload["conversation_id"] == session_id
        assert (payload["to"], payload["to_did"], payload["to_stable_id"]) == ("bob", bob_did, "did:aw:bob")
        assert (payload["from"], payload["from_stable_id"]) == ("pilot", "did:aw:pilot")
    assert [payload.get("wait_seconds") for payload in signed] == [0, None, None, 0, None, None]
    assert [payload.get("hang_on") for payload in signed] == [None, None, None, None, True, None]
    assert [payload.get("sender_leaving") for payload in signed] == [None, None, None, None, None, True]


@pytest.mark.asyncio
@pytest.mark.parametrize("sender_key_published", [True, False])
async def test_mcp_encrypted_chat_to_a_hosted_recipient_needs_the_senders_hosted_key(
    chat_server, sender_key_published,
):
    server = chat_server
    published = ["bob", "pilot"] if sender_key_published else ["bob"]
    for alias in published:
        await _insert_agent_encryption_assertion(
            server.db, agent_id=UUID(server.agents[alias]), team_id=TEAM,
            assertion=server.custody[alias]["encryption_key"],
        )

    sent = await server.mcp_chat("pilot", to="bob", message="for bob only")

    stored = await server.db.fetch_all("SELECT content_mode, body FROM {{tables.chat_messages}}")
    if sender_key_published:
        assert "error" not in sent, sent
        assert [dict(row) for row in stored] == [{"content_mode": "encrypted_v2", "body": ""}]
    else:
        assert sent == {
            "error": "your encryption key isn't published yet; try again shortly, "
                     "and if it persists contact support",
            "reason": "recipient_custodial_no_e2ee",
        }
        assert stored == []


@pytest.mark.asyncio
async def test_mcp_refusals_of_an_unknown_chat_recipient_read_as_the_routes_do(chat_server):
    server = chat_server

    assert await server.mcp_chat("pilot", to="nobody", message="hello", plaintext=True) == {
        "error": "Unknown aliases: nobody",
    }
    assert await server.mcp_chat("pilot", to="did:aw:nobody", message="hello", plaintext=True) == {
        "error": "Bare did:aw first-contact is unsupported; use to_addresses=domain/name "
                 "or continue an existing session",
    }
    assert await server.mcp_chat("pilot", to="pilot", message="hello", plaintext=True) == {
        "error": "Self-chat is not supported",
    }
    assert await server.mcp_chat("pilot", to="acme.com/nobody", message="hello", plaintext=True) == {
        "error": unreachable_address_refusal("acme.com/nobody"),
    }
    assert await server.mcp_chat("pilot", conversation_id=str(uuid4()), message="hello", plaintext=True) == {
        "error": "Session not found",
    }
    assert await server.db.fetch_all("SELECT message_id FROM {{tables.chat_messages}}") == []


def _sender():
    from aweb.identity_auth_deps import MessagingAuth

    return MessagingAuth(
        did_key="did:key:z6MkPilot", did_aw="did:aw:pilot", address="acme.com/pilot",
        team_id=TEAM, alias="pilot", agent_id=str(uuid4()),
    )


def _row(alias, **fields):
    """A resolved recipient, as chat resolution returns one."""
    return {"alias": alias, "did_key": f"did:key:z6Mk{alias}", "did_aw": f"did:aw:{alias}",
            "address": f"acme.com/{alias}", **fields}


def _signed(sender, rows, **fields):
    from aweb.mcp.tools.chat import _signed_chat_fields

    known = dict(
        signed_from="pilot", recipient_rows=rows, named_alias="", message="hello",
        message_id=str(uuid4()), conversation_id=str(uuid4()),
        timestamp=datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        wait_seconds=None, hang_on=False, leaving=False,
    )
    known.update(fields)
    return _signed_chat_fields(sender, **known)


# (how the caller named the recipient, the alias it named, the resolved recipient, the signed sender)
FIRST_CHAT_RECIPIENTS = [
    ("alias", "bob", _row("bob"), "pilot"),
    ("alias of another team", "support~bob", _row("bob"), "pilot"),
    ("did", "", _row("bob"), "pilot"),
    ("address on this server", "", _row("bob"), "pilot"),
    ("address on another server", "", _row("bob", external=True, delivery_origin="https://other.test"),
     "acme.com/pilot"),
    ("local identity without a stable id", "", {"alias": "bob", "did_key": "did:key:z6Mkbob", "did_aw": None,
                                                 "address": None}, "pilot"),
]


@pytest.mark.parametrize("named,named_alias,row,signed_from", FIRST_CHAT_RECIPIENTS)
@pytest.mark.parametrize("wait_seconds", [None, 120])
@pytest.mark.parametrize("leaving,hang_on", [(False, False), (True, False), (False, True)])
def test_the_fields_mcp_signs_for_a_first_chat_satisfy_the_send_validation(
    named, named_alias, row, signed_from, wait_seconds, leaving, hang_on,
):
    from aweb.messaging.chat_send import _validate_signed_chat_payload

    sender = _sender()
    fields = _signed(
        sender, [row], named_alias=named_alias, signed_from=signed_from,
        wait_seconds=wait_seconds, leaving=leaving, hang_on=hang_on,
    )

    # The send validates a first chat with these arguments.
    _validate_signed_chat_payload(
        signature=sign_message(_make_keypair()[0], b"shape only"),
        signed_payload=canonical_signed_payload(fields),
        recipient_rows=[row],
        requested_to_aliases=[named_alias] if named_alias else [],
        from_alias=sender.alias,
        from_address=sender.address,
        from_stable_id=sender.did_aw,
        body="hello",
        from_did=sender.did_key,
        message_id=fields["message_id"],
        timestamp=fields["timestamp"],
        wait_seconds=wait_seconds,
        reply_to=None,
        conversation_id=fields["conversation_id"],
        sender_leaving=leaving,
        hang_on=hang_on,
    )


# (who else is in the session, the signed sender, what is signed as to, to_did and to_stable_id)
SESSION_RECIPIENTS = [
    ("one member of this server", [_row("bob", did="did:aw:bob")], "pilot",
     ("bob", "did:key:z6Mkbob", "did:aw:bob")),
    ("one identity on another server",
     [_row("bob", did="did:aw:bob", delivery_origin="https://other.test")], "acme.com/pilot",
     ("acme.com/bob", "did:key:z6Mkbob", "did:aw:bob")),
    ("a local identity without a stable id",
     [{"alias": "bob", "did": "did:key:z6Mkbob", "did_key": "did:key:z6Mkbob", "did_aw": "", "address": ""}],
     "pilot", ("bob", "did:key:z6Mkbob", "")),
    ("two members", [_row("carol", did="did:aw:carol"), _row("bob", did="did:aw:bob")], "pilot",
     ("bob,carol", "", "")),
]


@pytest.mark.parametrize("others,rows,signed_from,recipient_fields", SESSION_RECIPIENTS)
@pytest.mark.parametrize("hang_on", [False, True])
@pytest.mark.parametrize("wait_seconds", [None, 120])
def test_the_fields_mcp_signs_for_a_message_in_a_session_satisfy_the_send_validation(
    others, rows, signed_from, recipient_fields, hang_on, wait_seconds,
):
    from aweb.messaging.chat_send import _validate_signed_chat_payload

    sender = _sender()
    fields = _signed(sender, rows, signed_from=signed_from, hang_on=hang_on, wait_seconds=wait_seconds)
    assert (fields["to"], fields["to_did"], fields.get("to_stable_id", "")) == recipient_fields

    # The send validates a message in a session with these arguments.
    _validate_signed_chat_payload(
        signature=sign_message(_make_keypair()[0], b"shape only"),
        signed_payload=canonical_signed_payload(fields),
        recipient_rows=rows,
        from_alias=sender.alias,
        from_address=sender.address,
        from_stable_id=sender.did_aw,
        body="hello",
        from_did=sender.did_key,
        message_id=fields["message_id"],
        timestamp=fields["timestamp"],
        wait_seconds=wait_seconds,
        reply_to=None,
        conversation_id=fields["conversation_id"],
        sender_leaving=False,
        hang_on=hang_on,
    )


def test_a_signed_wait_the_message_does_not_carry_is_refused_by_the_send_validation():
    from aweb.messaging.chat_send import _validate_signed_chat_payload

    sender = _sender()
    rows = [_row("bob", did="did:aw:bob")]
    fields = _signed(sender, rows, wait_seconds=120)

    with pytest.raises(HTTPException) as refused:
        _validate_signed_chat_payload(
            signature=sign_message(_make_keypair()[0], b"shape only"),
            signed_payload=canonical_signed_payload(fields),
            recipient_rows=rows, from_alias=sender.alias, from_address=sender.address,
            from_stable_id=sender.did_aw, body="hello", from_did=sender.did_key,
            message_id=fields["message_id"], timestamp=fields["timestamp"], wait_seconds=None, reply_to=None,
            conversation_id=fields["conversation_id"], sender_leaving=False, hang_on=False,
        )

    assert refused.value.detail == "signed_payload wait_seconds must match the chat message"


def test_the_request_that_opens_a_session_may_carry_hang_on():
    from aweb.routes.chat import CreateSessionRequest

    assert CreateSessionRequest(to_aliases=["bob"], message="hello").hang_on is False
    assert CreateSessionRequest(to_aliases=["bob"], message="hello", hang_on=True).hang_on is True


def _authority_refusal(reason):
    return FederationAuthorityError(reason)


def _refusal(status, detail):
    return HTTPException(status_code=status, detail=detail)


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
    (lambda: _refusal(403, "identity_binding_mismatch"), {}, {
        "error": "this recipient's identity or key no longer matches the registry; check the address and resend",
        "reason": "identity_binding_mismatch",
    }),
    (lambda: _refusal(503, "identity_binding_unavailable"), {}, {
        "error": "the registry can't confirm this recipient's key right now; try again shortly",
        "reason": "identity_binding_unavailable",
    }),
    (lambda: _refusal(422, "Local did:key recipient requires local resolution or learned return route"), {}, {
        "error": "this recipient can no longer be reached in this conversation; "
                 "start a new conversation with them by alias or address",
    }),
]


@pytest.mark.parametrize("refusal,known,answer", NEXT_ACTIONS)
def test_mcp_chat_refusals_name_the_next_action_and_keep_their_code(refusal, known, answer):
    from aweb.mcp.tools.chat import _send_refusal

    assert json.loads(_send_refusal(refusal(), **known)) == answer


def test_mcp_chat_codes_without_a_next_action_are_answered_as_the_code():
    from aweb.mcp.tools.chat import _send_refusal

    # Outside a hosted envelope the custody refusal says nothing about the sender's key.
    assert json.loads(_send_refusal(_authority_refusal("recipient_custodial_no_e2ee"))) == {
        "error": "recipient_custodial_no_e2ee",
    }
    assert json.loads(_send_refusal(_authority_refusal("federation_rate_limited"), address="a.test/b")) == {
        "error": "federation_rate_limited",
    }
    # An address that reaches no one is refused in the words for a name nobody holds.
    for refusal in (_authority_refusal("recipient_identity_not_found"),
                    _authority_refusal("local_recipient_route_missing"),
                    _refusal(404, "Recipient address not found: a.test/b")):
        assert json.loads(_send_refusal(refusal, address="a.test/b")) == {
            "error": unreachable_address_refusal("a.test/b"),
        }
    # A refusal with no next action keeps the route's detail.
    assert json.loads(_send_refusal(_refusal(404, "Unknown aliases: nobody"))) == {
        "error": "Unknown aliases: nobody",
    }


def test_a_person_named_as_a_chat_recipient_is_refused_with_the_mail_direction():
    from aweb.mcp.tools.chat import _send_refusal

    refused = HumanChatRefused("juan")
    answer = json.loads(_send_refusal(refused, address="acme.com/juan", hosted_envelope=True))

    assert answer["error"] == "juan is a person; aweb reaches people by mail: aw mail send --to juan"
    assert (answer["reason"], answer["retryable"], answer["recipients"]) == (
        "recipient_human_mail_only", False, ["juan"],
    )


def test_a_chat_envelope_for_a_key_this_server_does_not_record_is_refused_as_a_changed_key():
    from aweb.identity_auth_deps import MessagingAuth
    from aweb.mcp.tools.chat import _send_refusal
    from aweb.messaging.chat_send import validate_encrypted_chat_payload
    from aweb.routes.chat import SendMessageRequest

    pilot_key, _, pilot_did = _make_keypair()
    bob_key, _, registry_did = _make_keypair()
    recorded_did = _make_keypair()[2]
    message_id, session_id = str(uuid4()), str(uuid4())

    def identity(signing_key, did, stable_id, address):
        return {
            "signing_key": signing_key, "did": did, "stable_id": stable_id, "address": address,
            "encryption_key": build_encryption_key_assertion(
                signing_key=signing_key, identity_did=did, identity_stable_id=stable_id,
                encryption_public_key=generate_x25519_keypair()[1], custody="hosted_custodial",
            ),
        }

    envelope = encrypt_e2ee_chat(
        sender=identity(pilot_key, pilot_did, "did:aw:pilot", "acme.com/pilot"),
        recipients=[identity(bob_key, registry_did, "did:aw:bob", "acme.com/bob")],
        body="for bob only", message_id=message_id, conversation_id=session_id,
    )
    payload = SendMessageRequest(
        message_id=message_id, timestamp=envelope["created_at"],
        content_mode="encrypted_v2", message_version=2, encrypted_envelope=envelope,
    )

    with pytest.raises(HTTPException) as refused:
        validate_encrypted_chat_payload(
            payload, auth=MessagingAuth(did_key=pilot_did, did_aw="did:aw:pilot", address="acme.com/pilot"),
            actor_did="did:aw:pilot", session_id=session_id,
            recipient_rows=[{"did": "did:aw:bob", "did_key": recorded_did, "did_aw": "did:aw:bob",
                             "address": "acme.com/bob"}],
        )

    # The route's answer is unchanged.
    assert (refused.value.status_code, refused.value.detail) == (422, "encrypted envelope recipient did mismatch")
    assert json.loads(_send_refusal(refused.value, hosted_envelope=True)) == {
        "error": "this recipient's key changed; resend the message",
    }

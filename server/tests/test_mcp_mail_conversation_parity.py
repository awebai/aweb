"""Mail threading parity through the real MCP/HTTP apps and PostgreSQL."""

from team_facts_fixtures import LegacyTeamFacts

import json
from datetime import datetime, timezone
from types import SimpleNamespace
from uuid import UUID, uuid4

import asyncpg
import pytest

from aweb.federation.errors import LocalRecipientNotFoundError
from aweb.mcp.tools.refusals import SendRefusalMode
from aweb.service_errors import IdentityBindingCode, IdentityBindingError
from aweb.messaging.refusals import RecipientAddressNotFound
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
    _encrypted_mail_envelope,
    _insert_agent,
    _insert_team,
    _make_keypair,
    _signed_identity_headers,
    _signed_team_headers,
)

REGISTRY_ORIGIN = "https://registry.test"


class _AddressRegistry(LegacyTeamFacts):
    """The AWID registry at its boundary: the home registry of every namespace, holding the bound addresses."""

    registry_url = REGISTRY_ORIGIN

    def __init__(self):
        self.addresses = {}
        self.controller_did = _make_keypair()[2]

    def bind(self, address, did_aw, did_key):
        domain, name = address.split("/", 1)
        self.addresses[address] = Address(
            address_id=f"addr-{name}",
            domain=domain,
            name=name,
            did_aw=did_aw,
            current_did_key=did_key,
            created_at=datetime.now(timezone.utc).isoformat(),
        )

    async def registry_audience(self, domain):
        return REGISTRY_ORIGIN

    async def get_namespace_fresh(self, domain):
        return Namespace(
            namespace_id=f"namespace-{domain}",
            domain=domain,
            controller_did=self.controller_did,
            verification_status="verified",
            last_verified_at=None,
            created_at=datetime.now(timezone.utc).isoformat(),
        )

    async def resolve_address(self, domain, name, *, did_key=None):
        return self.addresses.get(f"{domain}/{name}")

    async def resolve_address_fresh(self, domain, name):
        return self.addresses.get(f"{domain}/{name}")


@pytest_asyncio.fixture
async def mail_server(shared_test_pool, monkeypatch):
    from awid.identity_observation import IdentityKind
    from aweb.application_state import application_registry_client
    from messaging_actor_support import admit_messaging_actor, register_messaging_team
    from test_dashboard_privacy import privacy_stack

    monkeypatch.setenv("AWEB_TRUST_PROXY_HEADERS", "1")
    monkeypatch.setenv("AWEB_INTERNAL_AUTH_SECRET", "mail-parity-test-secret")
    async with privacy_stack(shared_test_pool, monkeypatch) as stack:
        team = "ops:acme.com"
        await register_messaging_team(stack, team_id=team)
        pilot_actor = await admit_messaging_actor(
            stack,
            alias="pilot",
            team_id=team,
            address="acme.com/pilot",
            kind=IdentityKind.AGENT,
        )
        human_actor = await admit_messaging_actor(
            stack,
            alias="human",
            team_id=team,
            address="acme.com/human",
            kind=IdentityKind.HUMAN,
        )
        pilot_key, pilot_did, pilot = (
            pilot_actor.signing_key,
            pilot_actor.did_key,
            pilot_actor.agent_id,
        )
        human_key, human_did, human = (
            human_actor.signing_key,
            human_actor.did_key,
            human_actor.agent_id,
        )
        custody = SimpleNamespace(payloads=[], wrong_conversation=False)

        async def signer(**kwargs):
            payload = dict(kwargs["payload"])
            custody.payloads.append(payload)
            if custody.wrong_conversation:
                payload["conversation_id"] = str(uuid4())
            signed = canonical_signed_payload(payload)
            return HostedMessageSigningResult(
                from_did=pilot_did,
                signing_key_id=pilot_did,
                signed_payload=signed,
                signature=sign_message(pilot_key, signed.encode()),
            )

        async def encryptor(**kwargs):
            payload, recipient = kwargs["payload"], kwargs["recipient"]
            custody.payloads.append(dict(payload))
            envelope = _encrypted_mail_envelope(
                sender_sk=pilot_key,
                sender_did=pilot_did,
                sender_stable_id=pilot_actor.stable_id,
                recipient_did=recipient["did_key"],
                recipient_stable_id=recipient["did_aw"],
                sender_address=payload["from"],
                recipient_address=recipient.get("address") or "",
                message_id=payload["message_id"],
                conversation_id=payload["conversation_id"],
            )
            return {
                "content_mode": "encrypted_v2",
                "message_version": 2,
                "encrypted_envelope": envelope,
            }

        registry = application_registry_client(stack.app.state)
        app, client, db = stack.app, stack.client, stack.db
        mcp = create_mcp_app(
            db_infra=stack.infra,
            redis=stack.redis,
            registry_client=registry,
            hosted_signer=signer,
            hosted_encryptor=encryptor,
            public_origin=app.state.public_origin,
        )
        app.mount("/mcp", mcp)
        await mcp.startup()
        try:

            async def human_mail(body="hello", **target):
                data = json.dumps(
                    {"body": body, **(target or {"to_alias": "pilot"})}
                ).encode()
                response = await client.post(
                    "/v1/messages",
                    content=data,
                    headers={
                        "Content-Type": "application/json",
                        "X-Team-ID": team,
                        **_signed_identity_headers(
                            human_key, human_did, human_actor.stable_id, data
                        ),
                    },
                )
                assert response.status_code == 200, response.text
                return response.json()

            async def mcp_call(tool, **arguments):
                principal = str(uuid4())
                headers = {
                    "Accept": "application/json, text/event-stream",
                    "X-Team-ID": team,
                    "X-User-ID": principal,
                    "X-AWEB-Actor-ID": pilot,
                    "X-AWEB-Auth": build_internal_auth_header_value(
                        secret="mail-parity-test-secret",
                        team_id=team,
                        principal_type="u",
                        principal_id=principal,
                        actor_id=pilot,
                    ),
                }
                response = await client.post(
                    "/mcp/",
                    headers=headers,
                    json={
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "tools/call",
                        "params": {"name": tool, "arguments": arguments},
                    },
                )
                assert response.status_code == 200, response.text
                result = response.json()
                assert "error" not in result, result
                return json.loads(result["result"]["content"][0]["text"])

            async def mcp_mail(**arguments):
                return await mcp_call(
                    "send_mail", body="unprompted update", **arguments
                )

            yield SimpleNamespace(
                db=db,
                human_mail=human_mail,
                mcp_mail=mcp_mail,
                mcp_call=mcp_call,
                custody=custody,
                human=human,
                human_did=human_did,
                human_stable=human_actor.stable_id,
                pilot=pilot,
                client=client,
                pilot_key=pilot_key,
                pilot_did=pilot_did,
                pilot_stable=pilot_actor.stable_id,
                human_key=human_key,
                actors={pilot: pilot_actor, human: human_actor},
                registry=registry,
                fixture=stack,
                namespace_controller_did=(
                    await stack.registry.namespace_authority("acme.com")
                ).controller_did,
            )
        finally:
            await mcp.shutdown()


@pytest.mark.asyncio
@pytest.mark.parametrize("target", ["alias", "stable_did", "current_did", "address"])
@pytest.mark.parametrize("plaintext", [True, False])
async def test_mcp_recipient_send_starts_new_conversation(
    mail_server, target, plaintext
):
    server = mail_server
    original = await server.human_mail()
    # Neither HTTP nor MCP adopts a pair without an explicit conversation ID.
    ordinary = await server.human_mail("another human message")
    assert ordinary["conversation_id"] != original["conversation_id"]
    recipient = {
        "alias": "human",
        "stable_did": server.human_stable,
        "current_did": server.human_did,
        "address": "acme.com/human",
    }[target]
    sent = await server.mcp_mail(to=recipient, plaintext=plaintext)
    assert "error" not in sent, sent
    assert sent["conversation_id"] not in {
        original["conversation_id"],
        ordinary["conversation_id"],
    }
    assert server.custody.payloads[-1]["conversation_id"] == sent["conversation_id"]
    row = await server.db.fetch_one(
        "SELECT * FROM {{tables.messages}} WHERE message_id=$1",
        UUID(sent["message_id"]),
    )
    assert str(row["conversation_id"]) == sent["conversation_id"]
    assert row["to_did"] == server.human_stable
    if plaintext:
        assert (
            json.loads(row["signed_payload"])["conversation_id"]
            == sent["conversation_id"]
        )
    else:
        assert row["content_mode"] == "encrypted_v2"
        envelope = json.loads(row["encrypted_envelope"])
        assert envelope["conversation_id"] == sent["conversation_id"]
    assert (
        await server.db.fetch_one("SELECT count(*) AS n FROM {{tables.conversations}}")
    )["n"] == 3


@pytest.mark.asyncio
@pytest.mark.parametrize("old_status", [None, "closed", "expired"])
async def test_mcp_recipient_send_creates_when_no_active_conversation(
    mail_server, old_status
):
    server = mail_server
    old = None
    if old_status:
        old = (await server.human_mail())["conversation_id"]
        await server.db.execute(
            "UPDATE {{tables.conversations}} SET status=$2 WHERE conversation_id=$1",
            UUID(old),
            old_status,
        )
    sent = await server.mcp_mail(to=server.human_stable, plaintext=True)
    assert "error" not in sent, sent
    assert sent["conversation_id"] != old
    assert server.custody.payloads[-1]["conversation_id"] == sent["conversation_id"]


@pytest.mark.asyncio
async def test_mcp_new_conversation_does_not_bypass_recipient_policy(mail_server):
    from messaging_actor_support import admit_messaging_actor, register_messaging_team

    server = mail_server
    old = (await server.human_mail())["conversation_id"]
    await register_messaging_team(server.fixture, team_id="ops:otherco.com")
    other = await admit_messaging_actor(
        server.fixture,
        alias="human",
        team_id="ops:otherco.com",
        signing_key=server.human_key,
    )
    from aweb.member_team_key import MemberStatus

    # The former local membership is retired; the new one was actually admitted.
    await server.db.execute(
        "UPDATE {{tables.agents}} SET status=$2 WHERE agent_id=$1",
        UUID(server.human),
        MemberStatus.RETIRED.value,
    )
    raw = json.dumps({"inbound_mode": "team_and_contacts"}).encode()
    changed = await server.client.patch(
        "/v1/agents/me/inbound-mode",
        content=raw,
        headers={
            **_signed_team_headers(
                server.human_key,
                server.human_did,
                other.team_id,
                other.certificate,
                raw,
            ),
            "Content-Type": "application/json",
        },
    )
    assert changed.status_code == 200, changed.text
    result = await server.mcp_mail(to=server.human_stable, plaintext=True)
    assert result == {
        "reason": "recipient_policy_rejected",
        "error": "Recipient only accepts messages from verified team members or exact active contacts. Ask the recipient to add your exact address as a contact or check their inbound policy.",
    }
    assert (await server.db.fetch_one("SELECT count(*) AS n FROM {{tables.messages}}"))[
        "n"
    ] == 1
    assert (
        await server.db.fetch_one("SELECT count(*) AS n FROM {{tables.conversations}}")
    )["n"] == 1
    assert server.custody.payloads[-1]["conversation_id"] != old


@pytest.mark.asyncio
async def test_mcp_custody_cannot_sign_a_different_conversation(mail_server):
    server = mail_server
    await server.human_mail()
    server.custody.wrong_conversation = True
    result = await server.mcp_mail(to=server.human_stable, plaintext=True)
    assert "error" in result, result
    assert (await server.db.fetch_one("SELECT count(*) AS n FROM {{tables.messages}}"))[
        "n"
    ] == 1
    assert (
        await server.db.fetch_one("SELECT count(*) AS n FROM {{tables.conversations}}")
    )["n"] == 1


@pytest.mark.asyncio
async def test_mcp_lookup_does_not_reuse_another_senders_conversation(mail_server):
    server = mail_server
    _, _, other_did = _make_keypair()
    await _insert_agent(
        server.db,
        team_id="ops:acme.com",
        alias="other",
        did_key=other_did,
        did_aw="did:aw:other",
        address="acme.com/other",
    )
    old = (await server.human_mail(to_alias="other"))["conversation_id"]
    sent = await server.mcp_mail(to=server.human_stable, plaintext=True)
    assert "error" not in sent, sent
    assert sent["conversation_id"] != old
    assert (
        await server.db.fetch_one("SELECT count(*) AS n FROM {{tables.conversations}}")
    )["n"] == 2


@pytest.mark.asyncio
async def test_mcp_lookup_preserves_its_existing_selector_validation(mail_server):
    server = mail_server
    # MCP's published `to` is an unconstrained string, unlike the HTTP model's
    # 64-character alias validator. Sharing its lookup must not narrow MCP.
    alias = "a" * 65
    await server.db.execute(
        "UPDATE {{tables.agents}} SET alias=$2, agent_type='agent' WHERE agent_id=$1",
        UUID(server.human),
        alias,
    )
    sent = await server.mcp_mail(to=alias, plaintext=True)
    assert "error" not in sent, sent
    assert (await server.db.fetch_one("SELECT count(*) AS n FROM {{tables.messages}}"))[
        "n"
    ] == 1


@pytest.mark.asyncio
async def test_http_selected_team_human_alias_and_discovery(mail_server):
    server = mail_server
    raw = json.dumps({"to_alias": "human", "body": "first contact"}).encode()
    headers = {
        "Content-Type": "application/json",
        **_signed_identity_headers(server.pilot_key, server.pilot_did, "", raw),
    }
    sent = await server.client.post("/v1/messages", content=raw, headers=headers)
    assert sent.status_code == 200, sent.text
    found = await server.client.get(
        "/v1/messaging/participants/human",
        headers=_signed_identity_headers(server.pilot_key, server.pilot_did, "", b""),
    )
    assert found.status_code == 200, found.text
    assert found.json()["did_aw"] == server.human_stable
    assert found.json()["team_id"] == "ops:acme.com"
    assert found.json()["encryption_key"] is None  # Plaintext required no assertion.
    stored = await server.db.fetch_one(
        "SELECT to_did FROM {{tables.messages}} WHERE message_id=$1",
        UUID(sent.json()["message_id"]),
    )
    assert stored["to_did"] == server.human_stable


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["inactive", "wrong_team", "unknown_bare_did"])
async def test_human_alias_refusal_has_no_message_or_mutation(mail_server, failure):
    server = mail_server
    target = {"to_alias": "human"}
    if failure == "inactive":
        await server.db.execute(
            "UPDATE {{tables.agents}} SET status='retired' WHERE agent_id=$1",
            UUID(server.human),
        )
    elif failure == "wrong_team":
        await _insert_team(server.db, "other:acme.com")
        target = {"to_alias": "other~human"}
    else:
        target = {"to_did": "did:aw:unknown-external"}
    raw = json.dumps({**target, "body": "must refuse"}).encode()
    response = await server.client.post(
        "/v1/messages",
        content=raw,
        headers={
            "Content-Type": "application/json",
            **_signed_identity_headers(server.pilot_key, server.pilot_did, "", raw),
        },
    )
    assert response.status_code in (404, 422), response.text
    assert (await server.db.fetch_one("SELECT count(*) AS n FROM {{tables.messages}}"))[
        "n"
    ] == 0
    assert (
        await server.db.fetch_one("SELECT count(*) AS n FROM {{tables.conversations}}")
    )["n"] == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("plaintext", [True, False])
async def test_mcp_lists_threads_from_the_participant_http_index_without_ack(
    mail_server, plaintext
):
    server = mail_server
    first = await server.mcp_mail(
        to="human", subject="First title", plaintext=plaintext
    )
    reply = await server.mcp_mail(
        conversation_id=first["conversation_id"], subject="New subject", plaintext=True
    )
    assert reply["conversation_id"] == first["conversation_id"]
    # Another pair's mail stays outside this actor's index.
    _, _, other = _make_keypair()
    await _insert_agent(
        server.db,
        team_id="ops:acme.com",
        alias="other",
        did_key=other,
        did_aw=None,
        address=None,
    )
    await server.human_mail(to_alias="other", subject="Private other pair")
    before = await server.db.fetch_all(
        "SELECT message_id,read_at FROM {{tables.messages}} ORDER BY message_id"
    )
    listed = await server.mcp_call("list_threads", participant_did=server.human_stable)
    assert len(listed["conversations"]) == 1, listed
    item = listed["conversations"][0]
    assert item["conversation_id"] == first["conversation_id"]
    assert item["first_message_id"] == first["message_id"]
    assert item["title"] == ("First title" if plaintext else "")
    assert item["subject"] == "New subject"
    assert set(item["participant_dids"]) == {server.pilot_stable, server.human_stable}
    response = await server.client.get(
        "/v1/conversations",
        params={"conversation_type": "mail", "participant_did": server.human_stable},
        headers=_signed_identity_headers(server.pilot_key, server.pilot_did, "", b""),
    )
    assert response.status_code == 200, response.text
    assert listed == response.json()
    assert before == await server.db.fetch_all(
        "SELECT message_id,read_at FROM {{tables.messages}} ORDER BY message_id"
    )
    # A filter does not grant access to another pair, nor acknowledge its mail.
    assert (await server.mcp_call("list_threads", participant_did=other))[
        "conversations"
    ] == []
    invalid = await server.mcp_call("list_threads", limit=101)
    assert "error" in invalid, invalid


@pytest.mark.asyncio
async def test_mcp_address_mail_keeps_the_selected_membership(mail_server):
    from messaging_actor_support import admit_messaging_actor, register_messaging_team

    server = mail_server
    await register_messaging_team(server.fixture, team_id="partner:partner.test")
    other = await admit_messaging_actor(
        server.fixture,
        alias="human",
        team_id="partner:partner.test",
        address="partner.test/human",
        signing_key=server.human_key,
    )
    await server.db.execute(
        "UPDATE {{tables.agents}} SET created_at=NOW()+INTERVAL '1 second' WHERE agent_id=$1",
        UUID(other.agent_id),
    )
    sent = await server.mcp_mail(to="acme.com/human", plaintext=True)
    assert "error" not in sent, sent
    continued = await server.mcp_mail(
        conversation_id=sent["conversation_id"], plaintext=True
    )
    assert "error" not in continued, continued
    participant = await server.db.fetch_one(
        "SELECT agent_id,address FROM {{tables.conversation_participants}} WHERE conversation_id=$1 AND did=$2",
        UUID(sent["conversation_id"]),
        server.human_stable,
    )
    assert participant["agent_id"] is None
    assert participant["address"] == "acme.com/human"


async def _mail_state(server):
    """Every stored conversation and message."""
    return (
        (
            await server.db.fetch_one(
                "SELECT count(*) AS n FROM {{tables.conversations}}"
            )
        )["n"],
        (await server.db.fetch_one("SELECT count(*) AS n FROM {{tables.messages}}"))[
            "n"
        ],
    )


async def _participants(server, conversation_id):
    rows = await server.db.fetch_all(
        """SELECT role, transport_hint, current_did_key FROM {{tables.conversation_participants}}
           WHERE conversation_id=$1""",
        UUID(conversation_id),
    )
    return {
        row["role"]: (row["transport_hint"], row["current_did_key"]) for row in rows
    }


@pytest.mark.asyncio
async def test_first_mail_records_the_same_participants_through_both_adapters(
    mail_server,
):
    server = mail_server
    from_mcp = await server.mcp_mail(to="human", plaintext=True)
    assert "error" not in from_mcp, from_mcp
    from_rest = await server.human_mail(to_alias="pilot")

    assert await _participants(server, from_mcp["conversation_id"]) == {
        "initiator": ("local", server.pilot_did),
        "participant": ("local", server.human_did),
    }
    assert await _participants(server, from_rest["conversation_id"]) == {
        "initiator": ("local", server.human_did),
        "participant": ("local", server.pilot_did),
    }


@pytest.mark.asyncio
async def test_a_failed_message_insert_leaves_no_conversation_through_either_adapter(
    mail_server,
):
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
            response = await server.client.post(
                "/v1/messages",
                content=raw,
                headers={
                    "Content-Type": "application/json",
                    **_signed_identity_headers(
                        server.human_key, server.human_did, "", raw
                    ),
                },
            )
        except (QueryError, asyncpg.PostgresError):
            response = None
        assert response is None or response.status_code == 500, response.text
        assert await _mail_state(server) == (0, 0)
    finally:
        await server.db.execute(
            "ALTER TABLE {{tables.messages}} DROP CONSTRAINT refuse_every_insert"
        )


@pytest.mark.asyncio
async def test_an_address_send_records_the_senders_contact_through_both_adapters(
    mail_server,
):
    from messaging_actor_support import admit_messaging_actor

    server = mail_server
    bob = await admit_messaging_actor(
        server.fixture,
        alias="bob",
        team_id="ops:acme.com",
        address="acme.com/bob",
    )
    from_mcp = await server.mcp_mail(to="acme.com/bob", plaintext=True)
    assert "error" not in from_mcp, from_mcp
    await server.human_mail(to_address="acme.com/bob")
    contacts = await server.db.fetch_all(
        """SELECT owner_did, contact_address, contact_did_aw, binding_controller_did, status
           FROM {{tables.contacts}} ORDER BY owner_did"""
    )
    assert sorted(
        (dict(row) for row in contacts), key=lambda row: row["owner_did"]
    ) == [
        {
            "owner_did": owner,
            "contact_address": "acme.com/bob",
            "contact_did_aw": bob.stable_id,
            "binding_controller_did": server.namespace_controller_did,
            "status": "active",
        }
        for owner in sorted((server.human_stable, server.pilot_stable))
    ]


async def _publish_hosted_key(
    server, *, agent_id, signing_key, did_key, did_aw, public_key
):
    actor = server.actors[agent_id]
    assertion = build_encryption_key_assertion(
        signing_key=signing_key,
        identity_did=did_key,
        identity_stable_id=did_aw,
        encryption_public_key=public_key,
        custody="hosted_custodial",
    )
    raw = json.dumps(assertion).encode()
    response = await server.client.put(
        "/v1/agents/me/encryption-key",
        content=raw,
        headers={
            **_signed_team_headers(
                signing_key, did_key, actor.team_id, actor.certificate, raw
            ),
            "Content-Type": "application/json",
        },
    )
    assert response.status_code == 200, response.text


@pytest.mark.asyncio
@pytest.mark.parametrize("sender_key_published", [True, False])
async def test_mcp_encrypted_mail_to_a_hosted_recipient_needs_the_senders_hosted_key(
    mail_server,
    sender_key_published,
):
    server = mail_server
    # The fixture's envelopes wrap to these two keys.
    await _publish_hosted_key(
        server,
        agent_id=server.human,
        signing_key=server.human_key,
        did_key=server.human_did,
        did_aw=server.human_stable,
        public_key=b"r" * 32,
    )
    if sender_key_published:
        await _publish_hosted_key(
            server,
            agent_id=server.pilot,
            signing_key=server.pilot_key,
            did_key=server.pilot_did,
            did_aw=server.pilot_stable,
            public_key=b"s" * 32,
        )

    sent = await server.mcp_mail(to="human")

    if sender_key_published:
        assert "error" not in sent, sent
        row = await server.db.fetch_one(
            "SELECT content_mode FROM {{tables.messages}} WHERE message_id=$1",
            UUID(sent["message_id"]),
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
async def test_mcp_handle_address_outside_the_senders_team_needs_its_registry_binding(
    mail_server,
):
    from messaging_actor_support import admit_messaging_actor, register_messaging_team

    server = mail_server
    await register_messaging_team(server.fixture, team_id="home:jane.aweb.ai")
    c3po = await admit_messaging_actor(
        server.fixture, alias="c3po", team_id="home:jane.aweb.ai"
    )
    # An admitted member's unbound stored address claim supplies no registry authority.
    await server.db.execute(
        "UPDATE {{tables.agents}} SET address='jane.aweb.ai/c3po' WHERE agent_id=$1",
        UUID(c3po.agent_id),
    )
    refused = await server.mcp_mail(to="@jane/c3po", plaintext=True)
    assert refused == {
        "error": unreachable_address_refusal("jane.aweb.ai/c3po"),
        "reason": "recipient_identity_not_found",
    }
    assert await _mail_state(server) == (0, 0)
    controller = await server.fixture.registry.ensure_namespace(domain="jane.aweb.ai")
    await server.registry.register_address(
        "jane.aweb.ai",
        "c3po",
        c3po.stable_id,
        controller,
        current_did_key=c3po.did_key,
    )
    sent = await server.mcp_mail(to="@jane/c3po", plaintext=True)
    assert "error" not in sent, sent
    row = await server.db.fetch_one(
        "SELECT to_did, to_alias, to_agent_id FROM {{tables.messages}} WHERE message_id=$1",
        UUID(sent["message_id"]),
    )
    assert dict(row) == {
        "to_did": c3po.stable_id,
        "to_alias": "c3po",
        "to_agent_id": None,
    }
    assert server.custody.payloads[-1]["to"] == "jane.aweb.ai/c3po"


@pytest.mark.asyncio
async def test_mcp_mail_reaches_another_team_of_the_senders_organization_by_alias(
    mail_server,
):
    from messaging_actor_support import admit_messaging_actor, register_messaging_team

    server = mail_server
    await register_messaging_team(server.fixture, team_id="eng:acme.com")
    zed = await admit_messaging_actor(
        server.fixture,
        alias="zed",
        team_id="eng:acme.com",
        address="acme.com/zed",
    )
    sent = await server.mcp_mail(to="eng~zed", plaintext=True)
    assert "error" not in sent, sent
    assert sent["to"] == "zed"
    row = await server.db.fetch_one(
        "SELECT to_did, to_agent_id FROM {{tables.messages}} WHERE message_id=$1",
        UUID(sent["message_id"]),
    )
    assert (row["to_did"], str(row["to_agent_id"])) == (zed.stable_id, zed.agent_id)
    assert server.custody.payloads[-1]["to"] == "eng~zed"
    assert (await server.mcp_mail(to="nowhere~zed", plaintext=True)) == {
        "error": "Unknown team: nowhere:acme.com"
    }


@pytest.mark.asyncio
async def test_mcp_refusals_of_an_unknown_recipient_read_as_the_routes_do(mail_server):
    server = mail_server
    assert await server.mcp_mail(to="nobody", plaintext=True) == {
        "error": "Recipient name does not identify a current member of the team. Check the name; if the agent exists, ask it to reconnect with a current team certificate."
    }
    assert await server.mcp_mail(to="did:aw:nobody", plaintext=True) == {
        "error": "Bare did:aw first-contact is unsupported; use to_address=domain/name "
        "or continue an existing conversation",
    }
    assert await _mail_state(server) == (0, 0)


SIGNED_SELECTORS = [
    # (what the caller names, the selector field it becomes, the recipient the service resolves)
    (
        "bob",
        "to_alias",
        {
            "alias": "bob",
            "did_key": "did:key:zBob",
            "did_aw": "did:aw:bob",
            "address": "acme.com/bob",
        },
    ),
    (
        "eng~bob",
        "to_alias",
        {
            "alias": "bob",
            "did_key": "did:key:zBob",
            "did_aw": "did:aw:bob",
            "address": "acme.com/bob",
        },
    ),
    (
        "acme.com/bob",
        "to_address",
        {
            "alias": "bob",
            "did_key": "did:key:zBob",
            "did_aw": "did:aw:bob",
            "address": "acme.com/bob",
        },
    ),
    (
        "did:aw:bob",
        "to_did",
        {
            "alias": "bob",
            "did_key": "did:key:zBob",
            "did_aw": "did:aw:bob",
            "address": "acme.com/bob",
        },
    ),
    (
        "did:key:zBob",
        "to_did",
        {"alias": "bob", "did_key": "did:key:zBob", "did_aw": None, "address": None},
    ),
]


@pytest.mark.parametrize("named,field,recipient", SIGNED_SELECTORS)
@pytest.mark.parametrize("priority", ["normal", "urgent"])
def test_the_fields_mcp_signs_for_a_first_mail_satisfy_the_send_validation(
    named, field, recipient, priority
):
    from aweb.mcp.auth import AuthContext
    from aweb.mcp.tools.mail import _signed_mail_fields, _signed_recipient

    sender_key, _, sender_did = _make_keypair()
    auth = AuthContext(
        team_id="ops:acme.com",
        agent_id=str(uuid4()),
        alias="pilot",
        did_key=sender_did,
        did_aw="did:aw:pilot",
        address="acme.com/pilot",
    )
    message_id, conversation_id = str(uuid4()), str(uuid4())
    fields = _signed_mail_fields(
        auth,
        signed_from="pilot",
        to=_signed_recipient(named, recipient["alias"]),
        to_did=recipient["did_key"],
        to_stable_id=recipient["did_aw"] or "",
        subject="status",
        body="hello",
        priority=priority,
        message_id=message_id,
        conversation_id=conversation_id,
        timestamp="2026-11-10T12:00:00Z",
    )

    _validate_signed_mail_payload(
        signature=sign_message(sender_key, canonical_signed_payload(fields).encode()),
        signed_payload=canonical_signed_payload(fields),
        recipient=recipient,
        to_agent_id=None,
        to_alias=recipient["alias"],
        requested_to_alias=named if field == "to_alias" else None,
        from_alias="pilot",
        from_address="acme.com/pilot",
        from_stable_id="did:aw:pilot",
        priority=priority,
        subject="status",
        body="hello",
        from_did=sender_did,
        message_id=message_id,
        timestamp="2026-11-10T12:00:00Z",
        conversation_id=conversation_id,
    )


def test_the_fields_mcp_signs_for_a_reply_satisfy_the_send_validation():
    from aweb.mcp.auth import AuthContext
    from aweb.mcp.tools.mail import _signed_mail_fields

    sender_key, _, sender_did = _make_keypair()
    auth = AuthContext(
        team_id="ops:acme.com",
        agent_id=str(uuid4()),
        alias="pilot",
        did_key=sender_did,
        did_aw="did:aw:pilot",
        address="acme.com/pilot",
    )
    message_id, conversation_id = str(uuid4()), str(uuid4())
    # A reply to a local participant names its stable identity and no current key.
    fields = _signed_mail_fields(
        auth,
        signed_from="pilot",
        to="",
        to_did="",
        to_stable_id="did:aw:bob",
        subject="re",
        body="hello",
        priority="normal",
        message_id=message_id,
        conversation_id=conversation_id,
        timestamp="2026-11-10T12:00:00Z",
    )
    assert (fields["to"], fields["to_did"], fields["to_stable_id"]) == (
        "",
        "",
        "did:aw:bob",
    )

    _validate_signed_mail_payload(
        signature=sign_message(sender_key, canonical_signed_payload(fields).encode()),
        signed_payload=canonical_signed_payload(fields),
        recipient={
            "alias": "bob",
            "did_key": "did:key:zBob",
            "did_aw": "did:aw:bob",
            "address": "acme.com/bob",
        },
        to_agent_id=None,
        to_alias="bob",
        requested_to_alias=None,
        from_alias="pilot",
        from_address="acme.com/pilot",
        from_stable_id="did:aw:pilot",
        priority="normal",
        subject="re",
        body="hello",
        from_did=sender_did,
        message_id=message_id,
        timestamp="2026-11-10T12:00:00Z",
        conversation_id=conversation_id,
    )


def _authority_refusal(reason):
    from awid.federation_errors import FederationAuthorityError

    return FederationAuthorityError(reason)


def _binding_refusal(status, code):
    from fastapi import HTTPException

    return HTTPException(status_code=status, detail=code)


# (the refusal the send raises, what the tool knows about the send, what the tool answers)
NEXT_ACTIONS = [
    (
        LocalRecipientNotFoundError,
        {"address": "example.test/member"},
        {
            "error": unreachable_address_refusal("example.test/member"),
            "reason": "recipient_identity_not_found",
        },
    ),
    (
        lambda: _authority_refusal("sender_registry_unavailable"),
        {"address": "jane.aweb.ai/c3po"},
        {
            "error": "the registry can't confirm jane.aweb.ai/c3po right now; try again, or check the address",
            "reason": "sender_registry_unavailable",
        },
    ),
    (
        lambda: _authority_refusal("recipient_custodial_no_e2ee"),
        {"mode": SendRefusalMode.HOSTED_ENVELOPE},
        {
            "error": "your encryption key isn't published yet; try again shortly, and if it persists contact support",
            "reason": "recipient_custodial_no_e2ee",
        },
    ),
    (
        lambda: _authority_refusal("federation_envelope_invalid"),
        {"mode": SendRefusalMode.HOSTED_ENVELOPE},
        {
            "error": "your published encryption key can't be verified right now; try again shortly, "
            "and if it persists contact support",
            "reason": "federation_envelope_invalid",
        },
    ),
    (
        lambda: _authority_refusal("recipient_encryption_assertion_invalid_or_stale"),
        {"mode": SendRefusalMode.HOSTED_ENVELOPE},
        {
            "error": "this recipient's published encryption key can't be verified right now; try again later, "
            "and if it persists contact support",
            "reason": "recipient_encryption_assertion_invalid_or_stale",
        },
    ),
    (
        lambda: IdentityBindingError(IdentityBindingCode.MISMATCH),
        {},
        {
            "error": "The claimed identity and signing key do not match. "
            "Check the identity and its current public-key binding, "
            "then correct the request and retry.",
            "reason": "identity_binding_mismatch",
        },
    ),
    (
        lambda: IdentityBindingError(IdentityBindingCode.UNAVAILABLE),
        {},
        {
            "error": "Identity verification is unavailable. Retry when the identity registry is available.",
            "reason": "identity_binding_unavailable",
        },
    ),
]


@pytest.mark.parametrize("refusal,known,answer", NEXT_ACTIONS)
def test_mcp_mail_refusals_name_the_next_action_and_keep_their_code(
    refusal, known, answer
):
    from aweb.mcp.tools.refusals import send_refusal

    assert json.loads(send_refusal(refusal(), **known)) == answer


@pytest.mark.parametrize(
    "reason",
    [
        "sender_registry_unavailable",
        "recipient_custodial_no_e2ee",
        "federation_envelope_invalid",
        "recipient_encryption_assertion_invalid_or_stale",
    ],
)
def test_the_route_answers_a_federation_refusal_with_its_code_alone(reason):
    from aweb.federation.errors import authority_error_body

    body = authority_error_body(_authority_refusal(reason), correlation_id="c")
    assert (body["detail"], body["reason"]) == (reason, reason)
    assert set(body) == {"detail", "reason", "retryable", "correlation_id"}


def test_mcp_mail_codes_keep_their_code_and_add_a_recovery_action():
    from aweb.mcp.tools.refusals import send_refusal

    # Without custody context, keep the code and give a general recovery action.
    assert json.loads(
        send_refusal(_authority_refusal("recipient_custodial_no_e2ee"))
    ) == {
        "error": "recipient_custodial_no_e2ee",
        "message": "The federation service refused this send. Check the recipient and signed message with the server operator, then retry.",
    }
    assert json.loads(
        send_refusal(_authority_refusal("federation_rate_limited"), address="a.test/b")
    ) == {
        "error": "federation_rate_limited",
        "message": "The federation service cannot complete this send now. Wait briefly and retry.",
    }
    # An address the registry does not bind is refused in the words for a name nobody holds.
    for refusal, reason in (
        (
            _authority_refusal("recipient_identity_not_found"),
            "recipient_identity_not_found",
        ),
        (
            _authority_refusal("local_recipient_route_missing"),
            "recipient_identity_not_found",
        ),
        (RecipientAddressNotFound(address="a.test/b"), "recipient_identity_not_found"),
    ):
        assert json.loads(send_refusal(refusal, address="a.test/b")) == {
            "error": unreachable_address_refusal("a.test/b"),
            "reason": reason,
        }


def test_an_envelope_for_a_key_this_server_does_not_record_is_refused_as_a_changed_key():
    from aweb.identity_auth_deps import MessagingAuth
    from aweb.mcp.tools.refusals import send_refusal
    from aweb.messaging.mail_send import _validate_encrypted_payload
    from aweb.messaging.refusals import DeliveryRefusal
    from aweb.routes.messages import SendMessageRequest

    pilot_key, _, pilot_did = _make_keypair()
    recorded_did, registry_did = _make_keypair()[2], _make_keypair()[2]
    message_id, conversation_id = str(uuid4()), str(uuid4())
    envelope = _encrypted_mail_envelope(
        sender_sk=pilot_key,
        sender_did=pilot_did,
        sender_stable_id="did:aw:pilot",
        recipient_did=registry_did,
        recipient_stable_id="did:aw:bob",
        message_id=message_id,
        conversation_id=conversation_id,
    )
    payload = SendMessageRequest(
        to_alias="bob",
        message_id=message_id,
        conversation_id=conversation_id,
        content_mode="encrypted_v2",
        message_version=2,
        encrypted_envelope=envelope,
    )

    with pytest.raises(DeliveryRefusal) as refused:
        _validate_encrypted_payload(
            payload,
            auth=MessagingAuth(
                did_key=pilot_did, did_aw="did:aw:pilot", address="acme.com/pilot"
            ),
            sender_did="did:aw:pilot",
            recipient={
                "did_key": recorded_did,
                "did_aw": "did:aw:bob",
                "address": "acme.com/bob",
            },
            recipient_did="did:aw:bob",
        )

    # The same key mismatch retains 422 and the encrypted retry recovery action.
    assert (refused.value.status_code, refused.value.detail) == (
        422,
        (
            "encrypted envelope recipient did mismatch. "
            "Check whether the original message was delivered before preparing a new encrypted message."
        ),
    )
    assert json.loads(
        send_refusal(refused.value, mode=SendRefusalMode.HOSTED_ENVELOPE)
    ) == {
        "error": "this recipient's key changed; resend the message",
    }


def test_a_refusal_whose_detail_is_an_object_is_answered_with_that_object():
    from aweb.mcp.tools.refusals import send_refusal

    # A retired participant is refused with a code and a message, as one object.
    retired = {
        "code": "participant_retired",
        "message": "human has moved; start a new mail to human in ops:acme.com",
    }
    assert json.loads(send_refusal(_binding_refusal(410, retired))) == {
        "error": retired
    }
    assert json.loads(
        send_refusal(
            _binding_refusal(410, retired),
            address="a.test/b",
            mode=SendRefusalMode.HOSTED_ENVELOPE,
        )
    ) == {
        "error": retired,
    }

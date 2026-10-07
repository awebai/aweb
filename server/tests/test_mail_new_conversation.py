"""Fresh mail is additive; a reused ID must not become a continuation."""
import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock
from uuid import UUID, uuid4

import pytest
from httpx import ASGITransport, AsyncClient

from awid.signing import canonical_json_bytes, sign_message
import aweb.routes.messages as message_routes
from aweb.identity_auth_deps import MessagingAuth, get_messaging_auth
from test_messages_http import _build_test_app, _insert_agent, _insert_team, _make_keypair


@pytest.mark.asyncio
@pytest.mark.parametrize("target", ["alias", "did", "stable_id", "address"])
async def test_new_mail_conversation(aweb_cloud_db, target, monkeypatch):
    db = aweb_cloud_db.aweb_db
    alice_sk, _, alice_key = _make_keypair()
    _, _, bob_key = _make_keypair()
    await _insert_team(db, "backend:acme.com")
    alice = await _insert_agent(db, team_id="backend:acme.com", alias="alice",
                               did_key=alice_key, did_aw="did:aw:alice", address="acme.com/alice")
    await _insert_agent(db, team_id="backend:acme.com", alias="bob",
                        did_key=bob_key, did_aw="did:aw:bob", address="acme.com/bob")
    app = _build_test_app(db, AsyncMock())
    app.state.awid_registry_client.resolve_address = AsyncMock(return_value=None)

    async def auth():
        return MessagingAuth(did_key=alice_key, did_aw="did:aw:alice", address="acme.com/alice",
                             team_id="backend:acme.com", alias="alice", agent_id=alice)
    app.dependency_overrides[get_messaging_auth] = auth
    recipient = {"alias": {"to_alias": "bob"}, "did": {"to_did": bob_key},
                 "stable_id": {"to_stable_id": "did:aw:bob"},
                 "address": {"to_address": "acme.com/bob"}}[target]
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        original = await client.post("/v1/messages", json={**recipient, "body": "original"})
        assert original.status_code == 200, original.text
        old = original.json()["conversation_id"]
        ordinary = await client.post("/v1/messages", json={**recipient, "body": "ordinary"})
        assert ordinary.status_code == 200, ordinary.text
        assert ordinary.json()["conversation_id"] == old
        fresh, message = str(uuid4()), str(uuid4())
        timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        signed = canonical_json_bytes({
            "type": "mail", "from": "acme.com/alice", "from_did": alice_key,
            "from_stable_id": "did:aw:alice", "to": next(iter(recipient.values())),
            "to_did": bob_key, "to_stable_id": "did:aw:bob", "subject": "fresh",
            "body": "nonce", "priority": "normal", "conversation_id": fresh,
            "message_id": message, "timestamp": timestamp,
        })
        request = {**recipient, "new_conversation": True, "conversation_id": fresh,
                   "message_id": message, "from_did": alice_key, "timestamp": timestamp,
                   "subject": "fresh", "body": "nonce", "signature": sign_message(alice_sk, signed),
                   "signed_payload": signed.decode()}
        response = await client.post("/v1/messages", json=request)
        assert response.status_code == 200, response.text
        assert response.json()["conversation_id"] == fresh != old
        assert response.json()["message_id"] == message
        rows = await db.fetch_all("SELECT message_id FROM {{tables.messages}} WHERE conversation_id=$1", UUID(fresh))
        assert [str(row["message_id"]) for row in rows] == [message]
        before = await db.fetch_all("SELECT * FROM {{tables.conversations}} ORDER BY conversation_id")
        for identifier in [fresh, old]:
            duplicate = await client.post("/v1/messages", json={**recipient, "new_conversation": True,
                                          "conversation_id": identifier, "body": "must not send"})
            assert duplicate.status_code == 409, duplicate.text
            assert duplicate.json()["detail"] == "conversation_exists"
        missing = await client.post("/v1/messages", json={**recipient, "new_conversation": True, "body": "must not send"})
        assert missing.status_code == 422, missing.text
        continuation = await client.post("/v1/messages", json={"new_conversation": True, "conversation_id": old, "body": "must not send"})
        assert continuation.status_code == 422, continuation.text
        assert before == await db.fetch_all("SELECT * FROM {{tables.conversations}} ORDER BY conversation_id")
        count = await db.fetch_one("SELECT count(*) AS n FROM {{tables.messages}}")
        assert count["n"] == 3

        # The fresh flag does not make a changed signed conversation ID valid.
        tampered = await client.post("/v1/messages", json={**request, "conversation_id": str(uuid4())})
        assert tampered.status_code == 422, tampered.text
        assert (await db.fetch_one("SELECT count(*) AS n FROM {{tables.messages}}"))["n"] == 3

        await _insert_team(db, "ops:otherco.com")
        _, _, blocked_key = _make_keypair()
        await _insert_agent(db, team_id="ops:otherco.com", alias="blocked",
                            did_key=blocked_key, did_aw="did:aw:blocked", address="otherco.com/blocked",
                            inbound_mode="team_and_contacts")
        denied_id = str(uuid4())
        denied = await client.post("/v1/messages", json={"to_did": blocked_key, "new_conversation": True,
                                   "conversation_id": denied_id, "body": "must not send"})
        assert denied.status_code == 403, denied.text
        assert await db.fetch_one("SELECT conversation_id FROM {{tables.conversations}} WHERE conversation_id=$1", UUID(denied_id)) is None
        assert (await db.fetch_one("SELECT count(*) AS n FROM {{tables.messages}}"))["n"] == 3

        if target == "alias":
            # Force both requests past the absence precheck before either INSERT.
            original_create = message_routes.create_conversation
            ready = asyncio.Event()
            arrivals = 0

            async def concurrent_create(*args, **kwargs):
                nonlocal arrivals
                arrivals += 1
                if arrivals == 2:
                    ready.set()
                await asyncio.wait_for(ready.wait(), timeout=5)
                return await original_create(*args, **kwargs)

            monkeypatch.setattr(message_routes, "create_conversation", concurrent_create)
            racing_id = str(uuid4())
            responses = await asyncio.gather(*[
                client.post("/v1/messages", json={**recipient, "new_conversation": True,
                            "conversation_id": racing_id, "body": "race"})
                for _ in range(2)
            ])
            assert sorted(response.status_code for response in responses) == [200, 409]
            loser = next(response for response in responses if response.status_code == 409)
            assert loser.json()["detail"] == "conversation_exists"
            assert (await db.fetch_one("SELECT count(*) AS n FROM {{tables.messages}} WHERE conversation_id=$1", UUID(racing_id)))["n"] == 1

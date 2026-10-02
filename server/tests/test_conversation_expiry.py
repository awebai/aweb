"""Real database + HTTP regression coverage for lazy mail expiry (abnj)."""
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock
from uuid import UUID, uuid4

import pytest
from httpx import ASGITransport, AsyncClient

from aweb.identity_auth_deps import MessagingAuth, get_messaging_auth
from aweb.messaging import conversations
from aweb.routes.conversations import router as conversations_router
from test_conversations_service import _DbShim, _create_two_party_conversation
from test_messages_http import _build_test_app


async def _fixture(aweb_cloud_db, *, expires_at, status="active"):
    conv = await _create_two_party_conversation(aweb_cloud_db)
    await aweb_cloud_db.aweb_db.execute(
        "UPDATE {{tables.conversations}} SET expires_at=$2, status=$3 WHERE conversation_id=$1",
        UUID(conv["conversation_id"]), expires_at, status,
    )
    await aweb_cloud_db.aweb_db.execute(
        """INSERT INTO {{tables.messages}}
        (message_id, conversation_id, from_did, to_did, from_alias, to_alias, body)
        VALUES ($1, $2, 'did:aw:alice', 'did:aw:bob', 'alice', 'bob', 'original')""",
        uuid4(), UUID(conv["conversation_id"]),
    )
    app = _build_test_app(aweb_cloud_db.aweb_db, AsyncMock())
    app.include_router(conversations_router)

    async def auth():
        return MessagingAuth(did_key="did:key:z6Mkalice", did_aw="did:aw:alice",
                             team_id="backend:acme.com", alias="alice", address="acme.com/alice")

    app.dependency_overrides[get_messaging_auth] = auth
    return conv["conversation_id"], app


@pytest.mark.asyncio
@pytest.mark.parametrize("offset,status,expected", [(-1,"active","expired"),(0,"active","expired"),(3600,"active","active"),(None,"active","active"),(-1,"closed","closed")])
async def test_lookup_classifies_and_persists_expiry(aweb_cloud_db, monkeypatch, offset, status, expected):
    now = datetime.now(timezone.utc)
    monkeypatch.setattr(conversations, "_now_utc", lambda: now)
    expires = None if offset is None else now + timedelta(seconds=offset)
    cid, _ = await _fixture(aweb_cloud_db, expires_at=expires, status=status)
    found = await conversations.get_conversation(_DbShim(aweb_cloud_db.aweb_db), conversation_id=cid)
    assert found["status"] == expected
    # Read raw storage, not another getter which could hide a rolled-back write.
    stored = await aweb_cloud_db.aweb_db.fetch_one(
        "SELECT status, updated_at FROM {{tables.conversations}} WHERE conversation_id=$1", UUID(cid)
    )
    assert stored["status"] == expected
    await conversations.get_conversation(_DbShim(aweb_cloud_db.aweb_db), conversation_id=cid)
    again = await aweb_cloud_db.aweb_db.fetch_one(
        "SELECT status, updated_at FROM {{tables.conversations}} WHERE conversation_id=$1", UUID(cid)
    )
    assert again == stored


@pytest.mark.asyncio
@pytest.mark.parametrize("offset,status,expected", [(-1,"active","expired"),(0,"active","expired"),(3600,"active","active"),(None,"active","active"),(-1,"closed","closed")])
async def test_mail_listing_reports_effective_expiry(aweb_cloud_db, offset, status, expected):
    expires = None if offset is None else datetime.now(timezone.utc) + timedelta(seconds=offset)
    cid, app = await _fixture(aweb_cloud_db, expires_at=expires, status=status)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/v1/conversations?conversation_type=mail&participant_did=did:aw:bob")
    assert response.status_code == 200, response.text
    assert [(c["conversation_id"], c["status"]) for c in response.json()["conversations"]] == [(cid, expected)]


@pytest.mark.asyncio
@pytest.mark.parametrize("offset", [-1, 0, 3600, None])
async def test_pair_lookup_never_selects_elapsed_conversation(aweb_cloud_db, monkeypatch, offset):
    now = datetime.now(timezone.utc)
    monkeypatch.setattr(conversations, "_now_utc", lambda: now)
    cid, _ = await _fixture(aweb_cloud_db, expires_at=None if offset is None else now + timedelta(seconds=offset))
    found = await conversations.find_active_one_to_one_conversation_between(
        _DbShim(aweb_cloud_db.aweb_db), conversation_type="mail", did_a="did:aw:alice", did_b="did:aw:bob",
    )
    if offset is not None and offset <= 0:
        assert found is None
    else:
        assert found["conversation_id"] == cid


@pytest.mark.asyncio
@pytest.mark.parametrize("explicit_recipient", [False, True])
async def test_http_expired_send_persists_expiry_despite_403(aweb_cloud_db, explicit_recipient):
    cid, app = await _fixture(aweb_cloud_db, expires_at=datetime.now(timezone.utc) - timedelta(seconds=1))
    payload = {"conversation_id":cid,"body":"must not be delivered"}
    if explicit_recipient:
        payload["to_did"] = "did:aw:bob"
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        for _ in range(2):
            response = await client.post("/v1/messages",json=payload)
            assert response.status_code == 403, response.text
            assert response.json()["detail"] == "Conversation is expired"
            stored = await aweb_cloud_db.aweb_db.fetch_one(
                "SELECT status FROM {{tables.conversations}} WHERE conversation_id=$1", UUID(cid)
            )
            assert stored["status"] == "expired"
        response = await client.get("/v1/conversations?conversation_type=mail")
        assert response.json()["conversations"][0]["status"] == "expired"
    count = await aweb_cloud_db.aweb_db.fetch_value(
        "SELECT COUNT(*) FROM {{tables.messages}} WHERE conversation_id=$1", UUID(cid)
    )
    assert count == 1

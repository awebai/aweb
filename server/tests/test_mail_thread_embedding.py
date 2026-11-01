"""Public participant checks against real stored conversations, without HTTP."""
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import get_type_hints
from uuid import UUID, uuid4

import pytest
from fastapi import HTTPException, Request

from aweb.auth_context import GrantContext
from aweb.identity_auth_deps import MessagingAuth
from aweb.messaging.conversations import create_conversation
from aweb.routes import conversations
from aweb.routes.messages import get_inbox
from did_key_fixtures import named_did_key


HUMAN = "did:aw:human"
PEER = "did:aw:peer"
OTHER = "did:aw:other"
HUMAN_KEY = named_did_key("thread-owner")
PEER_KEY = named_did_key("thread-peer")
AUTH = MessagingAuth(did_key=HUMAN_KEY, did_aw=HUMAN, address=None)


def _infra(db):
    return SimpleNamespace(get_manager=lambda _: db)


async def _thread(db, *, kind="mail", owner=HUMAN, peer=PEER):
    result = await create_conversation(
        _infra(db), conversation_type=kind, created_by_did=owner, ttl=None,
        initiator={"did": owner, "alias": "human", "current_did_key": HUMAN_KEY, "transport_hint": "local"},
        recipients=[{"did": peer, "alias": "peer", "current_did_key": PEER_KEY, "transport_hint": "local"}],
    )
    return UUID(result["conversation_id"])


@pytest.mark.asyncio
@pytest.mark.parametrize("state", ["empty", "closed", "past_expiry"])
async def test_exact_peer_check_is_read_only_for_empty_and_historical_mail(aweb_cloud_db, state):
    db = aweb_cloud_db.aweb_db
    cid = await _thread(db)
    if state == "closed":
        await db.execute("UPDATE {{tables.conversations}} SET status='closed', closed_at=NOW() WHERE conversation_id=$1", cid)
    elif state == "past_expiry":
        # The check must not perform get_conversation's lazy expiry write.
        await db.execute("UPDATE {{tables.conversations}} SET expires_at=NOW()-INTERVAL '1 day' WHERE conversation_id=$1", cid)
    snapshots = [
        dict(await db.fetch_one("SELECT * FROM {{tables.conversations}} WHERE conversation_id=$1", cid)),
        [dict(row) for row in await db.fetch_all("SELECT * FROM {{tables.conversation_participants}} WHERE conversation_id=$1 ORDER BY did", cid)],
    ]
    assert await conversations.require_mail_thread_peer_for_auth(
        _infra(db), AUTH, conversation_id=str(cid), peer_did=PEER,
    ) is None
    assert dict(await db.fetch_one("SELECT * FROM {{tables.conversations}} WHERE conversation_id=$1", cid)) == snapshots[0]
    assert [dict(row) for row in await db.fetch_all("SELECT * FROM {{tables.conversation_participants}} WHERE conversation_id=$1 ORDER BY did", cid)] == snapshots[1]
    assert await db.fetch_val("SELECT COUNT(*) FROM {{tables.messages}}") == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("miss", ["thread", "caller", "peer", "other_thread", "chat", "caller_key", "peer_key"])
async def test_exact_peer_check_hides_every_missing_binding(aweb_cloud_db, miss):
    db = aweb_cloud_db.aweb_db
    cid = await _thread(db, kind="chat" if miss == "chat" else "mail")
    auth, peer = AUTH, PEER
    if miss == "thread":
        cid = uuid4()
    elif miss == "caller":
        auth = replace(AUTH, did_aw=OTHER)
    elif miss in {"peer", "other_thread"}:
        peer = OTHER
        if miss == "other_thread":
            await _thread(db, peer=OTHER)
    elif miss == "caller_key":
        auth = replace(AUTH, did_aw=None)
    elif miss == "peer_key":
        peer = PEER_KEY
    with pytest.raises(HTTPException) as error:
        await conversations.require_mail_thread_peer_for_auth(
            _infra(db), auth, conversation_id=cid, peer_did=peer,
        )
    assert (error.value.status_code, error.value.detail) == (404, "Mail thread not found")


@pytest.mark.asyncio
async def test_exact_peer_check_keeps_a_local_peer_literal(aweb_cloud_db):
    db = aweb_cloud_db.aweb_db
    cid = await _thread(db, peer=PEER_KEY)
    assert await conversations.require_mail_thread_peer_for_auth(
        _infra(db), AUTH, conversation_id=cid, peer_did=PEER_KEY,
    ) is None
    with pytest.raises(HTTPException) as error:
        await conversations.require_mail_thread_peer_for_auth(_infra(db), AUTH, conversation_id=cid, peer_did=PEER)
    assert error.value.status_code == 404


@pytest.mark.asyncio
@pytest.mark.parametrize("conversation_id,peer", [("not-a-uuid", PEER), (str(uuid4()), "peer"), (str(uuid4()), "did:web:example.test")])
async def test_exact_peer_check_validates_native_locators(aweb_cloud_db, conversation_id, peer):
    with pytest.raises(HTTPException) as error:
        await conversations.require_mail_thread_peer_for_auth(
            _infra(aweb_cloud_db.aweb_db), AUTH, conversation_id=conversation_id, peer_did=peer,
        )
    assert error.value.status_code == 422


@pytest.mark.asyncio
async def test_exact_peer_check_requires_identity_and_mail_read_scope(aweb_cloud_db):
    db = aweb_cloud_db.aweb_db
    cid = await _thread(db)
    with pytest.raises(HTTPException) as error:
        await conversations.require_mail_thread_peer_for_auth(
            _infra(db), MessagingAuth(did_key="", did_aw=None, address=None), conversation_id=cid, peer_did=PEER,
        )
    assert error.value.status_code == 401
    grant = GrantContext(
        grant_id=str(uuid4()), session_did_key=named_did_key("read-session"),
        issuing_certificate_id=None, scopes=("chat.read",),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    with pytest.raises(HTTPException) as error:
        await conversations.require_mail_thread_peer_for_auth(
            _infra(db), replace(AUTH, grant=grant), conversation_id=cid, peer_did=PEER,
        )
    assert error.value.status_code == 403
    assert await conversations.require_mail_thread_peer_for_auth(
        _infra(db), replace(AUTH, grant=replace(grant, scopes=("mail.read",))), conversation_id=cid, peer_did=PEER,
    ) is None


@pytest.mark.asyncio
async def test_direct_inbox_without_request_returns_canonical_incoming_mail(aweb_cloud_db):
    assert get_type_hints(get_inbox)["request"] == Request | None
    db = aweb_cloud_db.aweb_db
    cid = await _thread(db)
    foreign = await _thread(db, owner=OTHER)
    incoming, outgoing, hidden = uuid4(), uuid4(), uuid4()
    for mid, thread, sender, recipient in (
        (incoming, cid, PEER, HUMAN_KEY),
        (outgoing, cid, HUMAN_KEY, PEER),
        (hidden, foreign, PEER, HUMAN_KEY),
    ):
        await db.execute("""INSERT INTO {{tables.messages}}
            (message_id,conversation_id,from_did,to_did,from_alias,to_alias,subject,body)
            VALUES ($1,$2,$3,$4,'sender','human','subject','body')""", mid, thread, sender, recipient)
    page = await get_inbox(request=None, db=_infra(db), auth=AUTH,
        limit=10, cursor=None, unread_only=False, message_id=None)
    assert [message.message_id for message in page.messages] == [str(incoming)]
    assert page.messages[0].sender_membership.state == "unknown"
    assert page.messages[0].read_at is None
    assert await db.fetch_val("SELECT COUNT(*) FROM {{tables.messages}} WHERE read_at IS NOT NULL") == 0

"""Fresh chat replacement is sender-authorized and independent of wire format.

Real HTTP, signatures, AWID, PG and (for the foreign cases) federation/DNS.
"""
import json
from copy import deepcopy
from uuid import uuid4

import pytest

from chat_pair_support import (  # noqa: F401
    route_pair, _submission, _send, _stored, _effects, _signed_team_headers,
)


async def _post(sender, submission):
    path, payload, _ = submission
    raw = json.dumps(payload).encode()
    return await sender.node.client.post(path, content=raw, headers={
        **_signed_team_headers(sender.sk, sender.did, sender.node.team_id,
                               sender.encoded_certificate, raw),
        "Content-Type": "application/json",
    })


async def _snapshot(pair):
    result = []
    for node in (pair.source, pair.target):
        result.append((await _effects(node), await node.db.fetch_all(
            "SELECT conversation_id, status, updated_at, closed_at FROM {{tables.conversations}} "
            "ORDER BY conversation_id"), await node.db.fetch_all(
            "SELECT * FROM {{tables.conversation_participants}} ORDER BY conversation_id,did"),
            await node.db.fetch_all(
                "SELECT * FROM {{tables.chat_sessions}} ORDER BY session_id")))
    return result


async def _status(node, cid):
    return await node.db.fetch_value(
        "SELECT status FROM {{tables.conversations}} WHERE conversation_id=$1", cid)


@pytest.mark.asyncio
@pytest.mark.parametrize("foreign", [False, True], ids=["local", "federated"])
@pytest.mark.parametrize("encrypted", [False, True], ids=["v2-then-plaintext", "plaintext-then-v2"])
async def test_signed_fresh_chat_replaces_in_both_orders(route_pair, foreign, encrypted):
    pair = route_pair
    sender = pair.source.global_actor if foreign else pair.source.local
    target = (pair.target if foreign else pair.source).global_actor
    first, old = await _send(sender, target, "chat", encrypted=not encrypted)
    assert first.status_code == 200, first.text
    fresh = _submission(sender, target, "chat", encrypted=encrypted)
    response = await _post(sender, fresh)
    assert response.status_code == 200, response.text
    assert response.json()["session_id"] == str(fresh[2].cid)
    assert await _status(pair.source, old.cid) == "closed"
    assert await _status(pair.source, fresh[2].cid) == "active"
    await _stored(target, "chat", fresh[2])
    assert ("POST", "/v1/federation/messages") not in pair.source.calls
    if foreign:
        assert pair.target.calls.count(("POST", "/v1/federation/messages")) == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("foreign", [False, True], ids=["local", "federated"])
@pytest.mark.parametrize("encrypted,fault", [(e, f) for e in (False, True)
    for f in ("mismatched-id", "unsigned", "tampered", "foreign-signer")
    if e or f in ("mismatched-id", "unsigned", "foreign-signer")])
async def test_unbound_fresh_chat_does_not_close_or_deliver(route_pair, foreign, encrypted, fault):
    pair = route_pair
    sender = pair.source.global_actor if foreign else pair.source.local
    target = (pair.target if foreign else pair.source).global_actor
    first, old = await _send(sender, target, "chat")
    assert first.status_code == 200, first.text
    other = pair.source.local if foreign else pair.source.global_actor
    signer = other if fault == "foreign-signer" else sender
    fresh = _submission(signer, target, "chat", encrypted=encrypted)
    payload = fresh[1]
    if fault == "mismatched-id":
        payload["session_id"] = str(uuid4())
    elif fault == "unsigned":
        if encrypted:
            payload["encrypted_envelope"]["signature"] = ""
        else:
            payload.pop("signature")
            payload.pop("signed_payload")
    elif fault == "tampered":
        if encrypted:
            payload["encrypted_envelope"]["ciphertext"] += "A"
        else:
            payload["signature"] = "invalid"
    before = await _snapshot(pair)
    posts = len(pair.target.calls)
    response = await _post(sender, fresh)
    assert response.status_code in ({409, 422} if fault == "foreign-signer" else {409}), response.text
    assert await _snapshot(pair) == before
    assert await _status(pair.source, old.cid) == "active"
    assert len(pair.target.calls) == posts


@pytest.mark.asyncio
@pytest.mark.parametrize("foreign", [False, True], ids=["local", "federated"])
async def test_exact_encrypted_waiting_create_retry_preserves_wait_state(route_pair, foreign):
    pair = route_pair
    sender = pair.source.global_actor if foreign else pair.source.local
    target = (pair.target if foreign else pair.source).global_actor
    fresh = _submission(sender, target, "chat", encrypted=True)
    # Released prepareE2EEChatCreate retains these outer send-and-wait fields.
    fresh[1].update(leaving=False, wait_seconds=300)
    accepted = await _post(sender, fresh)
    assert accepted.status_code == 200, accepted.text
    await _stored(target, "chat", fresh[2])
    if not foreign:
        waiting = await pair.source.db.fetch_one(
            "SELECT wait_seconds, wait_started_at, wait_started_by "
            "FROM {{tables.chat_sessions}} WHERE session_id=$1", fresh[2].cid)
        assert waiting["wait_seconds"] == 300
        assert waiting["wait_started_at"] is not None
        assert waiting["wait_started_by"] == sender.id
    newer = _submission(sender, target, "chat", encrypted=True)
    newer[1].update(leaving=False, wait_seconds=120)
    response = await _post(sender, newer)
    assert response.status_code == 200, response.text
    before = await _snapshot(pair)
    federation = ("POST", "/v1/federation/messages")
    calls = (pair.source.calls.count(federation), pair.target.calls.count(federation))
    changed = deepcopy(fresh)
    changed[1]["encrypted_envelope"]["ciphertext"] += "A"
    conflict = await _post(sender, changed)
    assert conflict.status_code == 409, conflict.text
    assert await _snapshot(pair) == before
    retry = await _post(sender, fresh)
    assert retry.status_code == 200, retry.text
    assert retry.json()["message_id"] == str(fresh[2].mid)
    assert retry.json()["session_id"] == str(fresh[2].cid)
    assert await _status(pair.source, newer[2].cid) == "active"
    assert await _snapshot(pair) == before
    assert (pair.source.calls.count(federation), pair.target.calls.count(federation)) == calls


@pytest.mark.asyncio
@pytest.mark.parametrize("foreign", [False, True], ids=["local", "federated"])
@pytest.mark.parametrize("encrypted", [False, True], ids=["plaintext", "v2"])
async def test_exact_fresh_chat_retry_does_not_close_newer_session(route_pair, foreign, encrypted):
    pair = route_pair
    sender = pair.source.global_actor if foreign else pair.source.local
    target = (pair.target if foreign else pair.source).global_actor
    first, _ = await _send(sender, target, "chat", encrypted=not encrypted)
    assert first.status_code == 200, first.text
    fresh = _submission(sender, target, "chat", encrypted=encrypted)
    if encrypted:
        # The protected sender is authoritative; released clients may omit
        # the redundant legacy from_did field on encrypted requests.
        fresh[1].pop("from_did")
    accepted = await _post(sender, fresh)
    assert accepted.status_code == 200, accepted.text
    newer, newest = await _send(sender, target, "chat")
    assert newer.status_code == 200, newer.text
    before = await _snapshot(pair)
    posts = len(pair.target.calls)
    changed = deepcopy(fresh)
    if encrypted:
        changed[1]["encrypted_envelope"]["ciphertext"] += "A"
    else:
        changed[1]["message"] += " changed"
    conflict = await _post(sender, changed)
    assert conflict.status_code == 409, conflict.text
    assert conflict.json()["detail"] == (
        "This message ID has already been used for a different chat request. "
        "Retry the original request unchanged. Use a new message ID only if you intend to send a new message."
    )
    assert await _snapshot(pair) == before
    retry = await _post(sender, fresh)
    assert retry.status_code == 200, retry.text
    assert retry.json()["message_id"] == str(fresh[2].mid)
    assert retry.json()["session_id"] == str(fresh[2].cid)
    assert await _snapshot(pair) == before
    assert await _status(pair.source, newest.cid) == "active"
    assert len(pair.target.calls) == posts


@pytest.mark.asyncio
@pytest.mark.parametrize("foreign", [False, True], ids=["local", "federated"])
@pytest.mark.parametrize("encrypted", [False, True], ids=["plaintext", "v2"])
async def test_exact_create_retry_without_outer_session_id(route_pair, foreign, encrypted):
    pair = route_pair
    sender = pair.source.global_actor if foreign else pair.source.local
    target = (pair.target if foreign else pair.source).global_actor
    first, old = await _send(sender, target, "chat")
    assert first.status_code == 200, first.text
    _, payload, submitted = _submission(sender, target, "chat", encrypted=encrypted,
                                         continuation=str(old.cid))
    payload["message"] = payload.pop("body")
    payload["to_addresses"] = [target.address]
    request = ("/v1/chat/sessions", payload, submitted)
    assert "session_id" not in payload
    accepted = await _post(sender, request)
    assert accepted.status_code == 200, accepted.text
    assert accepted.json()["session_id"] == str(old.cid)
    await _stored(target, "chat", submitted)
    newer, newest = await _send(sender, target, "chat")
    assert newer.status_code == 200, newer.text
    before = await _snapshot(pair)
    posts = len(pair.target.calls)
    retry = await _post(sender, request)
    assert retry.status_code == 200, retry.text
    assert retry.json()["message_id"] == str(submitted.mid)
    assert retry.json()["session_id"] == str(old.cid)
    assert await _status(pair.source, newest.cid) == "active"
    assert await _snapshot(pair) == before
    assert len(pair.target.calls) == posts

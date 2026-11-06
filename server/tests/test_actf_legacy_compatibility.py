"""Established routes remain usable by released and team-label senders."""
import pytest

from test_actf_return_route import (  # noqa: F401
    route_pair, _effects, _expire_team_evidence, _federation_packet,
    _publish_server, _route_rows, _send, _stored,
)


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
@pytest.mark.parametrize("encrypted", [False, True], ids=["plaintext", "v2"])
@pytest.mark.parametrize("record", ["missing", "other-server"])
async def test_legacy_continuation_with_new_label_does_not_require_team_server(
    route_pair, kind, encrypted, record,
):
    source, target = route_pair.source, route_pair.target
    response, first = await _send(source.local, target.global_actor, kind, encrypted=encrypted)
    assert response.status_code == 200, response.text
    # Provision the pre-actf learned participant shape; no new legacy admission.
    for table, key in (("conversation_participants", "conversation_id"), ("chat_participants", "session_id")):
        await target.db.execute(
            "UPDATE {{tables." + table + "}} SET route_team_id=NULL,route_certificate_id=NULL,route_certificate=NULL "
            "WHERE " + key + "=$1 AND did=$2", first.cid, source.local.did,
        )
    routes = await _route_rows(target, first.cid, source.local.did)
    if record == "missing":
        await source.registry.db.execute("DELETE FROM {{tables.team_server_records}}")
    else:
        await _publish_server(source, target.origin)
    await _expire_team_evidence(source)
    await _expire_team_evidence(target)
    # New software presents its real certificate/full signed team label. Both
    # sender and receiver must retain the established route without upgrading it.
    response, sent = await _send(source.local, target.global_actor, kind,
                                encrypted=encrypted, continuation=str(first.cid))
    assert response.status_code == 200, response.text
    await _stored(target.global_actor, kind, sent)
    assert await _route_rows(target, first.cid, source.local.did) == routes
    # The receiver still refuses an altered learned origin even with that proof.
    packet, _ = _federation_packet(source.local, target.global_actor, kind,
                                 encrypted=encrypted, continuation=str(first.cid))
    packet["envelope"]["sender_delivery_origin"] = target.origin
    before = await _effects(target)
    refused = await target.client.post("/v1/federation/messages", json=packet)
    assert refused.status_code == 422, refused.text
    assert refused.json()["reason"] == "local_sender_route_mismatch"
    assert await _effects(target) == before
    assert await _route_rows(target, first.cid, source.local.did) == routes


@pytest.mark.asyncio
async def test_team_local_history_does_not_promote_unverified_global_projection(route_pair):
    from test_messages_http import _signed_team_headers

    source, target = route_pair.source, route_pair.target
    response, sent = await _send(source.local, target.global_actor, "chat")
    assert response.status_code == 200, response.text
    await target.db.execute(
        "INSERT INTO {{tables.agents}} (team_id,alias,did_key,did_aw,address,identity_scope) "
        "VALUES ($1,'unverified-projection',$2,'did:aw:unverified','unverified.test/local','global')",
        target.team_id, source.local.did,
    )
    recipient = target.global_actor
    response = await target.client.get(
        f"/v1/chat/sessions/{sent.cid}/messages",
        headers=_signed_team_headers(recipient.sk, recipient.did, target.team_id,
                                     recipient.encoded_certificate, b""),
    )
    assert response.status_code == 200, response.text
    message = next(row for row in response.json()["messages"] if row["message_id"] == str(sent.mid))
    assert not message.get("from_address")
    assert not message.get("from_stable_id")
    assert message["sender_membership"]["team_id"] == source.team_id

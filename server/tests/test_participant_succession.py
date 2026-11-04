"""Same-server human mail succession; historical signed bytes are immutable."""

# Pytest discovers the imported fixture by name.
# ruff: noqa: F811
import base64
import json
from datetime import datetime, timezone
from uuid import uuid4

import pytest
from aweb.mcp.server import create_mcp_app
from aweb.messaging.participant_succession import succeed_local_human_participant_on
from aweb.routes.events import _current_actionable_mail
from aweb.service_errors import ConflictError, ValidationError
from chat_pair_support import (
    _actor,
    _effects,
    _encode_certificate,
    _signed_team_headers,
    _submission,
    route_pair,  # noqa: F401
)  # noqa: F401
from test_actl_fresh_chat import _post

from awid.e2ee_keys import build_encryption_key_assertion
from awid.signing import canonical_json_bytes, sign_message


async def _send(sender, target, kind, *, encrypted=False, continuation=None):
    request = _submission(
        sender, target, kind, encrypted=encrypted, continuation=continuation
    )
    if kind == "mail" and target.stable and not target.address:
        request[1]["to_stable_id"] = target.stable
    return await _post(sender, request), request[2]


async def _human(actor):
    await actor.node.db.execute(
        "UPDATE {{tables.agents}} SET agent_type='human' WHERE agent_id=$1", actor.id
    )


async def _retire(actor):
    await actor.node.db.execute(
        "UPDATE {{tables.agents}} SET deleted_at=NOW(),status='deleted' WHERE agent_id=$1",
        actor.id,
    )


async def _messages(node, cid):
    return await node.db.fetch_all(
        "SELECT * FROM {{tables.messages}} WHERE conversation_id=$1 ORDER BY message_id",
        cid,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "human_first", [False, True], ids=["agent-first", "human-first"]
)
@pytest.mark.parametrize(
    "stable_predecessor", [False, True], ids=["key-predecessor", "stable-predecessor"]
)
async def test_plaintext_mail_continues_after_human_succession(
    route_pair, human_first, stable_predecessor
):
    node = route_pair.source
    old, agent = node.local, node.global_actor
    if stable_predecessor:
        old = await _actor(node, "old-human", global_identity=True)
        # A stable identity need not own an address. The cutover cohort has none.
        await node.db.execute(
            "UPDATE {{tables.agents}} SET address=NULL WHERE agent_id=$1", old.id
        )
        await node.registry.db.execute(
            "DELETE FROM {{tables.public_addresses}} WHERE did_aw=$1", old.stable
        )
        old.address = ""
        await node.registry_client.revoke_team_certificate(
            node.domain,
            "members",
            team_controller_signing_key=node.team_sk,
            certificate_id=old.certificate["certificate_id"],
        )
        certificate = dict(old.certificate)
        certificate.pop("signature")
        certificate.pop("member_address", None)
        certificate["certificate_id"] = str(uuid4())
        certificate["signature"] = sign_message(
            node.team_sk, canonical_json_bytes(certificate)
        )
        old.certificate = certificate
        old.encoded_certificate = _encode_certificate(certificate)
        await node.registry_client.register_team_certificate(
            node.domain,
            "members",
            team_controller_signing_key=node.team_sk,
            certificate_id=certificate["certificate_id"],
            member_did_key=old.did,
            member_did_aw=old.stable,
            member_address=None,
            alias=old.alias,
            identity_scope="global",
            certificate=old.encoded_certificate,
        )
    successor = await _actor(node, "account-human", global_identity=True)
    await _human(old)
    await _human(successor)
    response, first = await _send(agent, old, "mail")
    assert response.status_code == 200, response.text
    encrypted, old_encrypted = await _send(
        agent, old, "mail", encrypted=True, continuation=str(first.cid)
    )
    assert encrypted.status_code == 200, encrypted.text
    old_outgoing, old_sent = await _send(
        old, agent, "mail", continuation=str(first.cid)
    )
    assert old_outgoing.status_code == 200, old_outgoing.text
    historical = await _messages(node, first.cid)
    queued = _submission(agent, old, "mail", continuation=str(first.cid))
    await _retire(old)
    async with node.db.transaction() as tx:
        result = await succeed_local_human_participant_on(
            tx, predecessor_did=old.stable or old.did, successor_did=successor.stable
        )
    assert result.mapping_created and result.conversations_updated == 1
    assert result.chat_sessions_updated == 0
    before_replay = await _state(node)
    async with node.db.transaction() as tx:
        replay = await succeed_local_human_participant_on(
            tx, predecessor_did=old.stable or old.did, successor_did=successor.stable
        )
    assert not replay.mapping_created and replay.conversations_updated == 0
    assert await _state(node) == before_replay
    if human_first:
        response, submitted = await _send(
            successor, agent, "mail", continuation=str(first.cid)
        )
    else:
        response = await _post(agent, queued)
        submitted = queued[2]
    assert response.status_code == 200, response.text
    assert response.json()["conversation_id"] == str(first.cid)
    row = await node.db.fetch_one(
        "SELECT * FROM {{tables.messages}} WHERE message_id=$1", submitted.mid
    )
    assert row["conversation_id"] == first.cid
    assert row["from_did"] == (successor.stable if human_first else agent.stable)
    assert row["to_did"] == (agent.stable if human_first else (old.stable or old.did))
    stored = await _messages(node, first.cid)
    assert all(row in stored for row in historical)
    history = await _get(successor, f"/v1/messages/conversations/{first.cid}")
    assert history.status_code == 200, history.text
    history_rows = {r["message_id"]: r for r in history.json()["messages"]}
    assert set(history_rows) == {str(r["message_id"]) for r in stored}
    assert (
        history_rows[str(old_encrypted.mid)]["encrypted_envelope"]
        == old_encrypted.envelope
    )
    # Released readers compare the response target against the signed target.
    if not human_first:
        assert history_rows[str(submitted.mid)]["to_did"] in {
            submitted.fields["to_did"],
            old.stable,
        }
        assert history_rows[str(submitted.mid)]["to_stable_id"] == (old.stable or None)
    assert (
        history_rows[str(first.mid)]["signed_payload"]
        == historical[[r["message_id"] for r in historical].index(first.mid)][
            "signed_payload"
        ]
    )
    inbox = await _get(successor, "/v1/messages/inbox")
    assert inbox.status_code == 200, inbox.text
    incoming = {r["message_id"] for r in inbox.json()["messages"]}
    assert str(first.mid) in incoming and str(old_encrypted.mid) in incoming
    assert str(old_sent.mid) not in incoming  # historical outgoing is still ours
    actionable = await _current_actionable_mail(
        node.db, inbox_dids=[successor.stable, successor.did]
    )
    assert {r["message_id"] for r in actionable} == incoming
    roster = await _get(agent, f"/v1/messaging/participants/{successor.alias}")
    assert roster.status_code == 200, roster.text
    assert roster.json()["did_aw"] == successor.stable
    assert roster.json()["did_key"] == successor.did
    # Subsequent ordinary current-H targets work in the same thread, too.
    current, _ = await _send(agent, successor, "mail", continuation=str(first.cid))
    assert current.status_code == 200, current.text
    assert current.json()["conversation_id"] == str(first.cid)
    assert ("POST", "/v1/federation/messages") not in node.calls


@pytest.mark.asyncio
async def test_retired_human_chat_continuation_has_mail_refusal(route_pair):
    node = route_pair.source
    old, agent = node.local, node.global_actor
    # Historical chat was created before authoritative human kind became known.
    opening = _submission(agent, old, "chat")
    opening[1]["to_dids"] = opening[1].pop("to_addresses")
    response = await _post(agent, opening)
    first = opening[2]
    assert response.status_code == 200, response.text
    await _human(old)
    await _retire(old)
    before = await _effects(node)
    response, _ = await _send(agent, old, "chat", continuation=str(first.cid))
    assert response.status_code == 410, response.text
    assert response.json()["detail"]["code"] == "participant_retired"
    assert "mail" in response.json()["detail"]["message"]
    assert await _effects(node) == before
    # A recorded mail succession must leave these old chat rows untouched.
    successor = await _actor(node, "account-human", global_identity=True)
    chat_before = await _state(node)
    await _move(node, old, successor)
    chat_after = await _state(node)
    for table in ("chat_participants", "chat_read_receipts", "chat_message_reads"):
        assert chat_after[table] == chat_before[table]
    before = await _state(node)
    mcp = create_mcp_app(
        db_infra=node.server.db,
        redis=node.server.app.state.redis,
        registry_client=node.server.app.state.awid_registry_client,
        federation_authority=node.server.app.state.federation_authority,
        public_origin=node.origin,
    )
    node.server.app.mount("/succession-mcp", mcp)
    await mcp.startup()
    try:
        raw = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "chat_send",
                    "arguments": {
                        "session_id": str(first.cid),
                        "message": "retired continuation",
                        "plaintext": True,
                    },
                },
            }
        ).encode()
        response = await node.client.post(
            "/succession-mcp/",
            content=raw,
            headers={
                **_signed_team_headers(
                    agent.sk, agent.did, node.team_id, agent.encoded_certificate, raw
                ),
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
            },
        )
        assert response.status_code == 200, response.text
        result = response.json()["result"]
        assert not result.get("isError"), result
        refusal = json.loads(result["content"][0]["text"])
        assert refusal["error"]["code"] == "participant_retired"
        assert "mail" in refusal["error"]["message"]
        assert await _state(node) == before
    finally:
        await mcp.shutdown()


async def _get(actor, path):
    return await actor.node.client.get(
        path,
        headers=_signed_team_headers(
            actor.sk, actor.did, actor.node.team_id, actor.encoded_certificate
        ),
    )


async def _state(node):
    tables = (
        "conversation_participants",
        "chat_participants",
        "chat_messages",
        "chat_read_receipts",
        "chat_message_reads",
        "messages",
        "local_human_successions",
        "conversation_participant_successions",
    )
    return {
        table: await node.db.fetch_all(
            "SELECT * FROM {{tables." + table + "}} ORDER BY 1,2"
        )
        for table in tables
    }


async def _move(node, old, successor):
    await _human(old)
    await _human(successor)
    await _retire(old)
    async with node.db.transaction() as tx:
        return await succeed_local_human_participant_on(
            tx, predecessor_did=old.stable or old.did, successor_did=successor.stable
        )


@pytest.mark.asyncio
async def test_succession_does_not_grant_other_threads_old_signers_or_encrypted_targets(
    route_pair,
):
    node = route_pair.source
    old, agent = node.local, node.global_actor
    successor = await _actor(node, "account-human", global_identity=True)
    response, first = await _send(agent, old, "mail")
    assert response.status_code == 200, response.text
    queued_encrypted = _submission(
        agent, old, "mail", encrypted=True, continuation=str(first.cid)
    )
    await _move(node, old, successor)
    before = await _state(node)
    response = await _post(agent, queued_encrypted)
    assert response.status_code in (409, 422), response.text
    response, _ = await _send(old, agent, "mail", continuation=str(first.cid))
    assert response.status_code in (401, 403, 404), response.text
    assert await _state(node) == before
    fresh_old, _ = await _send(agent, old, "mail")
    assert fresh_old.status_code in (404, 422), fresh_old.text
    assert await _state(node) == before
    # An unrelated new H thread does not inherit predecessor target authority.
    response, other = await _send(agent, successor, "mail")
    assert response.status_code == 200, response.text
    before = await _state(node)
    stale = _submission(agent, old, "mail", continuation=str(other.cid))
    response = await _post(agent, stale)
    assert response.status_code == 409, response.text
    assert await _state(node) == before
    response, _ = await _send(agent, successor, "chat")
    assert response.status_code == 422, response.text
    assert response.json()["reason"] == "recipient_human_mail_only"
    assert await _state(node) == before

    # Current H custody keeps the ordinary explicit-encryption refusal.
    assertion = build_encryption_key_assertion(
        signing_key=successor.sk,
        identity_did=successor.did,
        identity_stable_id=successor.stable,
        encryption_public_key=base64.b64decode(
            successor.encryption_key["encryption_public_key"] + "=="
        ),
        custody="hosted_custodial",
        now=datetime.now(timezone.utc),
    )
    successor.encryption_key = assertion
    signature = assertion["signature"]
    canonical = canonical_json_bytes(
        {k: v for k, v in assertion.items() if k != "signature"}
    ).decode()
    await node.db.execute(
        "UPDATE {{tables.agent_encryption_keys}} SET assertion_canonical=$2,assertion_signature=$3 WHERE agent_id=$1",
        successor.id,
        canonical,
        signature,
    )
    response, _ = await _send(
        agent, successor, "mail", encrypted=True, continuation=str(first.cid)
    )
    assert response.status_code == 422, response.text
    assert response.json()["reason"] == "recipient_custodial_no_e2ee"
    assert await _state(node) == before


@pytest.mark.asyncio
async def test_retired_mail_without_succession_still_refuses(route_pair):
    node = route_pair.source
    old, agent = node.local, node.global_actor
    await _human(old)
    response, first = await _send(agent, old, "mail")
    assert response.status_code == 200
    await _retire(old)
    before = await _state(node)
    response, _ = await _send(agent, old, "mail", continuation=str(first.cid))
    assert response.status_code == 410
    assert response.json()["detail"]["code"] == "participant_retired"
    assert await _state(node) == before


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "fault", ["agent", "live", "address", "foreign", "conflict", "same-key", "rollback"]
)
async def test_succession_rejects_unsupported_shapes_and_uses_callers_transaction(
    route_pair, fault
):
    node = route_pair.source
    old, agent = node.local, node.global_actor
    successor = await _actor(node, "account-human", global_identity=True)
    response, first = await _send(agent, old, "mail")
    assert response.status_code == 200
    await _human(old)
    await _human(successor)
    await _retire(old)
    if fault == "agent":
        await node.db.execute(
            "UPDATE {{tables.agents}} SET agent_type='agent' WHERE agent_id=$1", old.id
        )
    elif fault == "live":
        await node.db.execute(
            "UPDATE {{tables.agents}} SET deleted_at=NULL WHERE agent_id=$1", old.id
        )
    elif fault == "address":
        await node.db.execute(
            "UPDATE {{tables.agents}} SET address='old.example/human' WHERE agent_id=$1",
            old.id,
        )
    elif fault == "foreign":
        await node.db.execute(
            "UPDATE {{tables.conversation_participants}} SET delivery_origin=$2 WHERE conversation_id=$1 AND did=$3",
            first.cid,
            route_pair.target.origin,
            agent.stable,
        )
    elif fault == "same-key":
        await node.db.execute(
            "UPDATE {{tables.agents}} SET did_key=$2,did_aw_verified_key=$2 WHERE agent_id=$1",
            successor.id,
            old.did,
        )
    elif fault == "conflict":
        await _move(node, old, successor)
        successor = await _actor(node, "different-human", global_identity=True)
        await _human(successor)
    before = await _state(node)
    expected = (
        RuntimeError
        if fault == "rollback"
        else ConflictError
        if fault == "conflict"
        else ValidationError
    )
    with pytest.raises(expected):
        async with node.db.transaction() as tx:
            await succeed_local_human_participant_on(
                tx, predecessor_did=old.did, successor_did=successor.stable
            )
            if fault == "rollback":
                raise RuntimeError("caller rolls back its entire cutover")
    assert await _state(node) == before


@pytest.mark.asyncio
async def test_succession_alias_reuse_resolves_current_h_without_alias_forwarding(
    route_pair,
):
    node = route_pair.source
    old, agent = node.local, node.global_actor
    response, first = await _send(agent, old, "mail")
    assert response.status_code == 200
    await _human(old)
    await _retire(old)
    # Reuse the selected-team name exactly, as a release projection does.
    await node.db.execute(
        "UPDATE {{tables.workspaces}} SET deleted_at=NOW() WHERE agent_id=$1", old.id
    )
    await node.registry_client.revoke_team_certificate(
        node.domain,
        "members",
        team_controller_signing_key=node.team_sk,
        certificate_id=old.certificate["certificate_id"],
    )
    successor = await _actor(node, old.alias, global_identity=True)
    await _human(successor)
    async with node.db.transaction() as tx:
        await succeed_local_human_participant_on(
            tx, predecessor_did=old.did, successor_did=successor.stable
        )
    roster = await _get(agent, f"/v1/messaging/participants/{old.alias}")
    assert roster.status_code == 200, roster.text
    assert roster.json()["did_aw"] == successor.stable
    assert roster.json()["did_key"] == successor.did
    response, _ = await _send(agent, successor, "mail", continuation=str(first.cid))
    assert response.status_code == 200, response.text
    # Key and stable selectors replay one mapping, not two succession claims.
    async with node.db.transaction() as tx:
        result = await succeed_local_human_participant_on(
            tx, predecessor_did=old.did, successor_did=successor.stable
        )
    assert result.conversations_updated == 0 and not result.mapping_created

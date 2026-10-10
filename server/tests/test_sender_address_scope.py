"""Sender address policy with real OSS/AWID/DB/Redis and authenticated HTTP."""
from uuid import UUID

import pytest
from awid.did import stable_id_from_did_key
from aweb.messaging.alias_targets import derive_team_address
from test_dashboard_privacy import TEAM, _request, privacy_app  # noqa: F401


@pytest.mark.asyncio
@pytest.mark.parametrize("scope,address", [("global", ""), ("local", ""), ("global", "example.test/alice")])
async def test_sender_address_preserves_team_context(privacy_app, scope, address):
    env = privacy_app
    actor = env.actors["alice"]
    stable = stable_id_from_did_key(actor.did) if scope == "global" else None
    await env.db.execute(
        "UPDATE {{tables.agents}} SET identity_scope=$1, did_aw=$2, address=$3, "
        "certificate_id='privacy-alice' WHERE agent_id=$4", scope, stable, address, actor.id,
    )
    expected = address or (derive_team_address(TEAM, "alice") if scope == "local" else None)
    mail = await _request(env, "alice", "POST", "/v1/messages", {
        "to_alias": "bob", "subject": "scope", "body": "mail control",
    })
    assert mail.status_code == 200, mail.text
    chat = await _request(env, "alice", "POST", "/v1/chat/sessions", {
        "to_aliases": ["bob"], "message": "chat control",
    })
    assert chat.status_code == 200, chat.text
    for table, message_id in [("messages", mail.json()["message_id"]), ("chat_messages", chat.json()["message_id"])]:
        row = await env.db.fetch_one(
            "SELECT from_address, from_alias, from_did FROM {{tables." + table + "}} WHERE message_id=$1", UUID(message_id),
        )
        assert row["from_address"] == expected
        assert row["from_alias"] == "alice"
        assert row["from_did"] == (stable if table == "chat_messages" and stable else actor.did)
    for path in [f"/v1/messages/{mail.json()['message_id']}", f"/v1/chat/sessions/{chat.json()['session_id']}/messages"]:
        response = await _request(env, "bob", "GET", path)
        assert response.status_code == 200, response.text
        data = response.json()
        item = data["messages"][0] if "messages" in data else data
        assert (item.get("from_address") or None) == expected
        assert item.get("from_alias", item.get("from_agent")) == "alice"
        assert item["sender_membership"]["team_id"] == TEAM
        assert item["sender_membership"]["state"] == "active"
        assert item["sender_membership"]["member_did_aw"] == stable

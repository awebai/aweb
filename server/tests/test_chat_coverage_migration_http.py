# ruff: noqa: F811 -- pytest imports the real shared fixture by name.
"""Historical chat rows migrate without changing participant read authority."""

from datetime import datetime, timezone
from uuid import uuid4

import pytest

from chat_coverage_support import migrate_chat_conversation_coverage
from test_dashboard_privacy import TEAM, _request, privacy_app  # noqa: F401


@pytest.mark.asyncio
async def test_migrated_pair_group_and_single_keep_exact_history_and_empty_stays_private(
    privacy_app,
):
    env = privacy_app
    historical_time = datetime(2026, 5, 1, tzinfo=timezone.utc)
    cases = {}
    for count in range(4):
        session_id, message_id = uuid4(), uuid4()
        names = ["alice", "bob", "carol"][:count]
        await env.db.execute(
            """INSERT INTO {{tables.chat_sessions}} (session_id,team_id,created_by,created_at)
               VALUES ($1,$2,'alice',$3)""",
            session_id,
            TEAM,
            historical_time,
        )
        for name in names:
            actor = env.actors[name]
            await env.db.execute(
                """INSERT INTO {{tables.chat_participants}}
                   (session_id,did,agent_id,alias,address,current_did_key,joined_at,delivery_origin,left_at)
                   VALUES ($1,$2,$3,$4,$5,$2,$6,$7,$8)""",
                session_id,
                actor.did,
                actor.id,
                name,
                f"example.test/{name}",
                historical_time,
                "https://old-route.example.test" if name == "carol" else None,
                historical_time if name == "carol" else None,
            )
        await env.db.execute(
            """INSERT INTO {{tables.chat_messages}}
               (message_id,session_id,from_agent_id,from_did,from_alias,body,created_at)
               VALUES ($1,$2,$3,$4,'alice',$5,$6)""",
            message_id,
            session_id,
            env.actors["alice"].id,
            env.actors["alice"].did,
            f"historical {count}",
            historical_time,
        )
        cases[count] = (session_id, message_id, names)

    before = [
        dict(row)
        for row in await env.db.fetch_all(
            "SELECT * FROM {{tables.chat_participants}} ORDER BY session_id,did"
        )
    ]
    for count, (session_id, message_id, _) in cases.items():
        response = await _request(
            env, "alice", "GET", f"/v1/chat/sessions/{session_id}/messages"
        )
        assert response.status_code == (200 if count else 404), response.text
        if count:
            assert [
                (row["message_id"], row["body"]) for row in response.json()["messages"]
            ] == [(str(message_id), f"historical {count}")]

    await migrate_chat_conversation_coverage(env.db)
    await migrate_chat_conversation_coverage(env.db)
    assert [
        dict(row)
        for row in await env.db.fetch_all(
            "SELECT * FROM {{tables.chat_participants}} ORDER BY session_id,did"
        )
    ] == before
    for count, (session_id, message_id, names) in cases.items():
        conversation = await env.db.fetch_one(
            "SELECT * FROM {{tables.conversations}} WHERE conversation_id=$1",
            session_id,
        )
        if count:
            assert conversation["created_at"] == historical_time
            assert conversation["created_by_did"] == env.actors["alice"].did
            assert (
                conversation["conversation_type"] == "chat"
                and conversation["status"] == "active"
            )
            migrated = [
                dict(row)
                for row in await env.db.fetch_all(
                    """SELECT participant_id,participant_kind,did,agent_id,alias,address,current_did_key,delivery_origin,joined_at
                   FROM {{tables.conversation_participants}} WHERE conversation_id=$1 ORDER BY did""",
                    session_id,
                )
            ]
            expected = [
                {
                    key: row[key]
                    for key in (
                        "participant_id",
                        "participant_kind",
                        "did",
                        "agent_id",
                        "alias",
                        "address",
                        "current_did_key",
                        "delivery_origin",
                        "joined_at",
                    )
                }
                for row in before
                if row["session_id"] == session_id
            ]
            assert migrated == expected
        else:
            assert conversation is None
        assert (
            await env.db.fetch_value(
                "SELECT count(*) FROM {{tables.chat_messages}} WHERE session_id=$1",
                session_id,
            )
            == 1
        )
        for viewer in ("alice", "bob", "carol"):
            response = await _request(
                env, viewer, "GET", f"/v1/chat/sessions/{session_id}/messages"
            )
            assert response.status_code == (200 if viewer in names else 404), (
                response.text
            )
            if viewer in names:
                assert [
                    (row["message_id"], row["body"])
                    for row in response.json()["messages"]
                ] == [(str(message_id), f"historical {count}")]

# ruff: noqa: F811 -- pytest imports the real shared fixture by name.
"""Historical chat rows migrate without changing participant read authority."""

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from tests.chat_coverage_support import COVERAGE_MIGRATION
from test_dashboard_privacy import (
    TEAM,
    _request,
    pre_chat_coverage_privacy_app as pre_chat_coverage_privacy_app,
)

__all__ = ["pre_chat_coverage_privacy_app"]


@pytest.mark.asyncio
async def test_migrated_pair_group_and_single_keep_exact_history_and_empty_stays_private(
    pre_chat_coverage_privacy_app,
    chat_coverage_upgrade,
):
    env = pre_chat_coverage_privacy_app
    historical_time = datetime(2026, 5, 1, tzinfo=timezone.utc)
    cases = {}
    for count in range(4):
        session_id, message_id = uuid4(), uuid4()
        names = ["alice", "bob", "carol"][:count]
        # unreachable-state: pre-055 session without conversation coverage (migration 055)
        await env.db.execute(
            """INSERT INTO {{tables.chat_sessions}} (session_id,team_id,created_by,created_at)
               VALUES ($1,$2,'alice',$3)""",
            session_id,
            TEAM,
            historical_time,
        )
        for name in names:
            actor = env.actors[name]
            # unreachable-state: pre-055 session party without a canonical conversation participant (migration 055)
            await env.db.execute(
                """INSERT INTO {{tables.chat_participants}}
                   (session_id,did,agent_id,alias,address,current_did_key,joined_at,delivery_origin)
                   VALUES ($1,$2,$3,$4,$5,$2,$6,$7)""",
                session_id,
                actor.did,
                actor.id,
                name,
                f"example.test/{name}",
                historical_time,
                "https://old-route.example.test" if name == "carol" else None,
            )
        # unreachable-state: pre-055 message attached to an uncovered session (migration 055)
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

    assert await chat_coverage_upgrade.apply() == [COVERAGE_MIGRATION]
    assert await chat_coverage_upgrade.apply() == []
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


async def _legacy_pair(env, *, created_at, party_override=None):
    session_id, message_id = uuid4(), uuid4()
    # unreachable-state: pre-055 session without conversation coverage (migration 055)
    await env.db.execute(
        "INSERT INTO {{tables.chat_sessions}} (session_id,team_id,created_by,created_at) VALUES ($1,$2,'alice',$3)",
        session_id,
        TEAM,
        created_at,
    )
    for name in ("alice", "bob"):
        actor = env.actors[name]
        party = dict(did=actor.did, alias=name)
        if name == "bob":
            party.update(party_override or {})
        # unreachable-state: pre-055 blank or uncovered session party without a canonical conversation participant (migration 055)
        await env.db.execute(
            """INSERT INTO {{tables.chat_participants}}
               (session_id,did,agent_id,alias,current_did_key,joined_at)
               VALUES ($1,$2,$3,$4,$5,$6)""",
            session_id,
            party["did"],
            actor.id,
            party["alias"],
            actor.did,
            created_at,
        )
    # unreachable-state: pre-055 message attached to an uncovered session (migration 055)
    await env.db.execute(
        """INSERT INTO {{tables.chat_messages}}
           (message_id,session_id,from_agent_id,from_did,from_alias,body,created_at)
           VALUES ($1,$2,$3,$4,'alice','retained legacy history',$5)""",
        message_id,
        session_id,
        env.actors["alice"].id,
        env.actors["alice"].did,
        created_at,
    )
    return session_id, message_id


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "party_override,bob_status",
    [
        ({"alias": ""}, 200),
        ({"alias": "  "}, 200),
        ({"did": ""}, 404),
        ({"did": "  "}, 404),
    ],
)
async def test_blank_legacy_party_retains_history_without_aborting_valid_coverage(
    pre_chat_coverage_privacy_app, chat_coverage_upgrade, party_override, bob_status
):
    env = pre_chat_coverage_privacy_app
    at = datetime(2026, 5, 1, tzinfo=timezone.utc)
    malformed, message_id = await _legacy_pair(
        env, created_at=at, party_override=party_override
    )
    valid, _ = await _legacy_pair(env, created_at=at + timedelta(days=1))
    before = await env.db.fetch_all(
        "SELECT * FROM {{tables.chat_participants}} WHERE session_id=$1 ORDER BY participant_id",
        malformed,
    )
    for viewer, expected_status in (("alice", 200), ("bob", bob_status)):
        old = await _request(
            env, viewer, "GET", f"/v1/chat/sessions/{malformed}/messages"
        )
        assert old.status_code == expected_status, old.text
    assert await chat_coverage_upgrade.apply() == [COVERAGE_MIGRATION]
    assert await chat_coverage_upgrade.apply() == []
    assert (
        await env.db.fetch_all(
            "SELECT * FROM {{tables.chat_participants}} WHERE session_id=$1 ORDER BY participant_id",
            malformed,
        )
        == before
    )
    assert (
        await env.db.fetch_value(
            "SELECT count(*) FROM {{tables.conversations}} WHERE conversation_id=$1",
            malformed,
        )
        == 0
    )
    assert (
        await env.db.fetch_value(
            "SELECT count(*) FROM {{tables.conversations}} WHERE conversation_id=$1",
            valid,
        )
        == 1
    )
    for viewer, expected_status in (("alice", 200), ("bob", bob_status)):
        history = await _request(
            env, viewer, "GET", f"/v1/chat/sessions/{malformed}/messages"
        )
        assert history.status_code == expected_status, history.text
        if expected_status == 200:
            assert [
                (m["message_id"], m["body"]) for m in history.json()["messages"]
            ] == [(str(message_id), "retained legacy history")]


@pytest.mark.asyncio
async def test_only_newest_uncovered_pair_is_active_and_older_history_remains_readable(
    pre_chat_coverage_privacy_app,
    chat_coverage_upgrade,
):
    from aweb.messaging.chat import find_session_between

    env = pre_chat_coverage_privacy_app
    at = datetime(2026, 5, 1, tzinfo=timezone.utc)
    older, old_message = await _legacy_pair(env, created_at=at)
    newer, _ = await _legacy_pair(env, created_at=at + timedelta(days=1))
    assert await chat_coverage_upgrade.apply() == [COVERAGE_MIGRATION]
    rows = await env.db.fetch_all(
        "SELECT conversation_id,status FROM {{tables.conversations}} WHERE conversation_id=ANY($1::uuid[])",
        [older, newer],
    )
    assert {row["conversation_id"]: row["status"] for row in rows} == {
        older: "closed",
        newer: "active",
    }
    assert (
        await find_session_between(
            env.infra,
            did_a=env.actors["alice"].did,
            did_b=env.actors["bob"].did,
        )
        == newer
    )
    history = await _request(env, "alice", "GET", f"/v1/chat/sessions/{older}/messages")
    assert history.status_code == 200, history.text
    assert [m["message_id"] for m in history.json()["messages"]] == [str(old_message)]


@pytest.mark.asyncio
async def test_active_canonical_pair_wins_over_newer_uncovered_pair(
    pre_chat_coverage_privacy_app,
    chat_coverage_upgrade,
):
    from aweb.messaging.chat import find_session_between

    env = pre_chat_coverage_privacy_app
    current = await _request(
        env,
        "alice",
        "POST",
        "/v1/chat/sessions",
        {
            "to_dids": [env.actors["bob"].did],
            "message": "current canonical conversation",
        },
    )
    assert current.status_code == 200, current.text
    canonical_id = current.json()["session_id"]
    uncovered, old_message = await _legacy_pair(
        env,
        created_at=datetime.now(timezone.utc) + timedelta(days=1),
    )
    assert await chat_coverage_upgrade.apply() == [COVERAGE_MIGRATION]
    assert (
        await env.db.fetch_value(
            "SELECT status FROM {{tables.conversations}} WHERE conversation_id=$1",
            uncovered,
        )
        == "closed"
    )
    assert (
        str(
            await find_session_between(
                env.infra,
                did_a=env.actors["alice"].did,
                did_b=env.actors["bob"].did,
            )
        )
        == canonical_id
    )
    history = await _request(
        env, "bob", "GET", f"/v1/chat/sessions/{uncovered}/messages"
    )
    assert history.status_code == 200, history.text
    assert [m["message_id"] for m in history.json()["messages"]] == [str(old_message)]

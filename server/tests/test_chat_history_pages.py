"""Public chat pages through real HTTP auth, PostgreSQL, Redis and AWID."""
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from pgdbm.migrations import AsyncMigrationManager

from awid.pagination import decode_cursor, encode_cursor
from awid.e2ee_keys import build_encryption_key_assertion
from awid.signing import canonical_json_bytes, sign_message, verify_signature, VerifyResult
from aweb.e2ee_messages import encrypt_e2ee_chat, generate_x25519_keypair
from test_dashboard_privacy import TEAM, _request, privacy_app  # noqa: F401


async def _session(env):
    session = uuid4()
    await env.db.execute(
        "INSERT INTO {{tables.chat_sessions}} (session_id,team_id,created_by) VALUES ($1,$2,'alice')",
        session, TEAM,
    )
    for alias in ("alice", "bob"):
        actor = env.actors[alias]
        await env.db.execute(
            "INSERT INTO {{tables.chat_participants}} (session_id,did,alias,agent_id) VALUES ($1,$2,$3,$4)",
            session, actor.did, alias, actor.id,
        )
    return session


async def _message(env, session, stamp=None, *, db=None, alias="alice"):
    db = db or env.db
    sender = env.actors[alias]
    recipient = env.actors["bob" if alias == "alice" else "alice"]
    mid = uuid4()
    payload = dict(type="chat", message_id=str(mid), conversation_id=str(session),
                   from_did=sender.did, to_did=recipient.did, to_stable_id="did:aw:display-only",
                   timestamp=datetime.now(timezone.utc).isoformat(), body=f"body {mid}",
                   **{"from": alias, "to": "bob" if alias == "alice" else "alice"})
    raw = canonical_json_bytes(payload).decode()
    signature = sign_message(sender.sk, raw.encode())
    row = await db.fetch_one(
        """INSERT INTO {{tables.chat_messages}}
        (message_id,session_id,from_agent_id,from_did,from_alias,body,created_at,signature,signed_payload)
        VALUES ($1,$2,$3,$4,$5,$6,COALESCE($7::timestamptz,NOW()),$8,$9) RETURNING created_at""",
        mid, session, sender.id, sender.did, alias, payload["body"], stamp, signature, raw,
    )
    return dict(message_id=str(mid), created_at=row["created_at"], signed_payload=raw, signature=signature)


async def _get(env, session, query="", actor="bob"):
    return await _request(env, actor, "GET", f"/v1/chat/sessions/{session}/messages{query}")


async def _page(env, session, *, cursor=None, limit=2):
    query = f"?order=desc&limit={limit}"
    if cursor is not None:
        query += "&cursor=" + cursor
    response = await _get(env, session, query)
    assert response.status_code == 200, response.text
    return response.json()


async def _cycle(env, session, limit=2):
    messages, cursor = [], None
    for _ in range(30):
        page = await _page(env, session, cursor=cursor, limit=limit)
        messages.extend(page["messages"])
        if not page["has_more"]:
            assert page["next_cursor"] is None
            return messages
        assert page["messages"] and page["next_cursor"] != cursor
        cursor = page["next_cursor"]
    pytest.fail("page traversal did not terminate")


@pytest.mark.asyncio
async def test_chat_pages_total_order_and_original_projection(privacy_app):
    env = privacy_app
    session = await _session(env)
    base = datetime.now(timezone.utc) - timedelta(hours=1)
    originals = [await _message(env, session, base + timedelta(microseconds=offset))
                 for offset in (0, 1, 1, 2, 2, 2, 3)]
    expected = sorted(originals, key=lambda m: (m["created_at"], UUID(m["message_id"])), reverse=True)
    first = await _page(env, session)
    assert datetime.fromisoformat(decode_cursor(first["next_cursor"])["created_at"]) == expected[1]["created_at"]
    read = await _cycle(env, session)
    assert [m["message_id"] for m in read] == [m["message_id"] for m in expected]
    for message, original in zip(read, expected):
        assert message["signed_payload"] == original["signed_payload"]
        assert message["signature"] == original["signature"]
        assert message["conversation_id"] == str(session)
        assert message["to_did"] == env.actors["bob"].did
        assert message["to_stable_id"] == "did:aw:display-only"
        # Preserve the established seconds-precision display timestamp; cursor
        # positions above retain full database precision independently.
        assert datetime.fromisoformat(message["timestamp"]) == original["created_at"].replace(microsecond=0)
        assert verify_signature(env.actors["alice"].did, original["signed_payload"].encode(),
                                original["signature"]) == VerifyResult.VERIFIED
    assert await env.db.fetch_value("SELECT count(*) FROM {{tables.chat_message_reads}}") == 0


@pytest.mark.asyncio
async def test_chat_pages_authorize_each_page_and_validate_scope(privacy_app):
    env = privacy_app
    session = await _session(env)
    for _ in range(3):
        await _message(env, session)
    page = await _page(env, session)
    cursor = page["next_cursor"]
    for query in ("?order=desc", "?order=desc&cursor=" + cursor, "?order=desc&cursor=malformed"):
        denied = await _get(env, session, query, actor="carol")
        assert denied.status_code == 404, denied.text
    other = await _session(env)
    denied = await _get(env, other, "?order=desc&cursor=" + cursor)
    assert denied.status_code == 422, denied.text
    data = decode_cursor(cursor)
    mutations = [dict(created_at="2026-10-27T00:00:00"), dict(message_id="not-a-uuid"),
                 dict(created_at="0001-01-01T00:00:00+23:59"), dict(created_at="invalid"),
                 dict(kind="mail_conversation"), dict(order="asc"), dict(unread_only=True),
                 dict(unread_only=0), dict(unread_only=None), dict(unread_only="false")]
    bad_cursors = ["", "malformed", "x" * 8193, encode_cursor({}),
                   "W10", "_w", encode_cursor({**data, "created_at": None})]
    bad_cursors += [encode_cursor({**data, **change}) for change in mutations]
    for bad in bad_cursors:
        response = await _get(env, session, "?order=desc&cursor=" + bad)
        assert response.status_code == 422, (bad, response.text)
    # Equivalent aware offsets preserve the same microsecond-precise boundary.
    offset_cursor = encode_cursor({**data, "created_at": datetime.fromisoformat(data["created_at"]).astimezone(
        timezone(timedelta(hours=1))).isoformat()})
    original = await _page(env, session, cursor=cursor)
    normalized = await _page(env, session, cursor=offset_cursor)
    assert normalized == original


@pytest.mark.asyncio
async def test_chat_pages_legacy_tail_exact_id_and_query_neighbors(privacy_app):
    env = privacy_app
    session = await _session(env)
    base = datetime.now(timezone.utc) - timedelta(minutes=1)
    originals = [await _message(env, session, base + timedelta(seconds=i)) for i in range(3)]
    legacy = await _get(env, session, "?limit=2")
    assert legacy.status_code == 200, legacy.text
    assert set(legacy.json()) == {"messages"}
    assert [m["message_id"] for m in legacy.json()["messages"]] == [m["message_id"] for m in originals[-2:]]
    large_legacy = await _get(env, session, "?limit=2000")
    assert large_legacy.status_code == 200
    exact = await _get(env, session, "?unread_only=true&message_id=" + originals[0]["message_id"])
    assert exact.status_code == 200, exact.text
    assert [m["message_id"] for m in exact.json()["messages"]] == [originals[0]["message_id"]]
    for query in ("?order=desc&limit=201", "?order=desc&limit=0", "?cursor=malformed",
                  "?order=desc&message_id=" + originals[0]["message_id"],
                  "?order=asc", "?order=desc&cursor=malformed&message_id=" + originals[0]["message_id"]):
        response = await _get(env, session, query)
        assert response.status_code == 422, (query, response.text)
    empty = await _session(env)
    assert await _page(env, empty) == dict(messages=[], has_more=False, next_cursor=None)
    full = await _page(env, session, limit=3)
    assert len(full["messages"]) == 3 and not full["has_more"] and full["next_cursor"] is None


@pytest.mark.asyncio
async def test_chat_pages_filter_unread_before_limit(privacy_app):
    env = privacy_app
    session = await _session(env)
    base = datetime.now(timezone.utc) - timedelta(minutes=1)
    incoming = [await _message(env, session, base + timedelta(seconds=i)) for i in range(3)]
    await _message(env, session, base + timedelta(seconds=5), alias="bob")
    await env.db.execute(
        "INSERT INTO {{tables.chat_message_reads}} (session_id,did,message_id) VALUES ($1,$2,$3)",
        session, env.actors["bob"].did, UUID(incoming[-1]["message_id"]),
    )
    response = await _get(env, session, "?order=desc&unread_only=true&limit=1")
    assert response.status_code == 200, response.text
    first = response.json()
    assert first["messages"][0]["message_id"] == incoming[1]["message_id"]
    assert first["has_more"]
    response = await _get(env, session, "?order=desc&unread_only=true&limit=1&cursor=" + first["next_cursor"])
    assert response.status_code == 200, response.text
    last = response.json()
    assert [m["message_id"] for m in last["messages"]] == [incoming[0]["message_id"]]
    assert not last["has_more"] and last["next_cursor"] is None


@pytest.mark.asyncio
async def test_chat_pages_preserve_encrypted_history_projection(privacy_app):
    env = privacy_app
    refs = {}
    for alias in ("alice", "bob"):
        actor = env.actors[alias]
        _, public = generate_x25519_keypair()
        refs[alias] = dict(did=actor.did, team_id=TEAM, encryption_key=build_encryption_key_assertion(
            signing_key=actor.sk, identity_did=actor.did, identity_stable_id="",
            encryption_public_key=public, custody="self", now=datetime.now(timezone.utc)))
    sender = dict(refs["alice"], signing_key=env.actors["alice"].sk)
    session, originals = uuid4(), {}
    for i in range(2):
        mid = str(uuid4())
        envelope = encrypt_e2ee_chat(sender=sender, recipients=[refs["bob"]], body="private page body",
                                     message_id=mid, conversation_id=str(session))
        wire = dict(content_mode="encrypted_v2", message_version=2, encrypted_envelope=envelope,
                    message_id=mid, timestamp=envelope["created_at"], from_did=sender["did"])
        if i == 0:
            path = "/v1/chat/sessions"
            wire.update(session_id=str(session), to_dids=[refs["bob"]["did"]], message="")
        else:
            path = f"/v1/chat/sessions/{session}/messages"
            wire["body"] = ""
        response = await _request(env, "alice", "POST", path, wire)
        assert response.status_code == 200, response.text
        originals[mid] = envelope
    legacy = await _get(env, session)
    assert legacy.status_code == 200, legacy.text
    descending = await _cycle(env, session, limit=1)
    assert descending == list(reversed(legacy.json()["messages"]))
    for message in descending:
        assert message["body"] == ""
        assert message["content_mode"] == "encrypted_v2" and message["message_version"] == 2
        assert message["encrypted_envelope"] == originals[message["message_id"]]


@pytest.mark.asyncio
async def test_chat_pages_stable_when_messages_insert_across_boundary(privacy_app):
    env = privacy_app
    session = await _session(env)
    base = datetime.now(timezone.utc) - timedelta(minutes=1)
    initial = [await _message(env, session, base + timedelta(seconds=i)) for i in (10, 20, 30)]
    first = await _page(env, session)
    assert [m["message_id"] for m in first["messages"]] == [m["message_id"] for m in initial[:0:-1]]
    above = await _message(env, session, base + timedelta(seconds=40))
    below = await _message(env, session, base + timedelta(seconds=15))
    second = await _page(env, session, cursor=first["next_cursor"])
    assert [m["message_id"] for m in second["messages"]] == [below["message_id"], initial[0]["message_id"]]
    assert not second["has_more"]
    repeated = await _cycle(env, session)
    assert [m["message_id"] for m in repeated] == [above["message_id"], initial[2]["message_id"],
                                                  initial[1]["message_id"], below["message_id"], initial[0]["message_id"]]


@pytest.mark.asyncio
async def test_chat_pages_late_commit_is_found_on_next_cycle(privacy_app):
    env = privacy_app
    session = await _session(env)
    old = await _message(env, session, datetime.now(timezone.utc) - timedelta(minutes=1))
    # Hold a genuine transaction open; NOW() is its PostgreSQL start time.
    async with env.db.transaction() as transaction:
        late = await _message(env, session, db=transaction)
        newer = [await _message(env, session) for _ in range(2)]
        assert all(row["created_at"] > late["created_at"] for row in newer)
        before_commit = await _cycle(env, session, limit=1)
        assert late["message_id"] not in {m["message_id"] for m in before_commit}
        assert before_commit[-1]["message_id"] == old["message_id"]
    # The old traversal is exhausted. Resetting from newest recovers this row.
    repeated = await _cycle(env, session, limit=1)
    assert [m["message_id"] for m in repeated] == [newer[1]["message_id"], newer[0]["message_id"],
                                                  late["message_id"], old["message_id"]]


@pytest.mark.asyncio
async def test_chat_page_index_populated_apply_reapply_and_invalid_recovery(privacy_app):
    env = privacy_app
    session = await _session(env)
    for _ in range(4):
        await _message(env, session)
    migrations = AsyncMigrationManager(env.db, module_name="aweb-aweb", migrations_path=str(
        Path(__file__).parents[1] / "src/aweb/migrations/aweb"))
    filename = "042_chat_history_page_index.sql"
    index = "aweb.idx_chat_messages_history_page"
    await env.db.execute("DROP INDEX IF EXISTS " + index)
    for state in ("absent", "existing-valid", "existing-invalid"):
        if state == "existing-invalid":
            # This is our isolated test database, never a deployed catalog.
            await env.db.execute("UPDATE pg_index SET indisvalid=false WHERE indexrelid=$1::regclass", index)
            assert not await env.db.fetch_value("SELECT indisvalid FROM pg_index WHERE indexrelid=$1::regclass", index)
        await env.db.execute(
            f"DELETE FROM aweb.{migrations.migrations_table} WHERE filename=$1 AND module_name='aweb-aweb'", filename)
        result = await migrations.apply_pending_migrations()
        assert filename in [item["filename"] for item in result["applied"]], result
        info = await env.db.fetch_one(
            "SELECT indisvalid,pg_get_indexdef(indexrelid) AS definition FROM pg_index WHERE indexrelid=to_regclass($1)", index)
        assert info and info["indisvalid"], (state, info)
        assert "(session_id, created_at, message_id)" in info["definition"]
        assert await env.db.fetch_value("SELECT count(*) FROM {{tables.chat_messages}} WHERE session_id=$1", session) == 4
    assert (await migrations.apply_pending_migrations())["status"] == "up_to_date"

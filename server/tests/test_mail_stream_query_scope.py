"""Real PostgreSQL plan regression for the per-second mail snapshot."""

import json
import os
from pathlib import Path
from uuid import uuid4

import pytest

from aweb.routes.events import _current_actionable_mail
from aweb.messaging.participant_succession import load_mail_succession_scope


class RecordingDatabase:
    """Observe SQL without replacing database execution or its result."""

    def __init__(self, db):
        self.db = db
        self.calls = []
        self.row_counts = []

    async def fetch_all(self, query, *args):
        self.calls.append((query, args))
        rows = await self.db.fetch_all(query, *args)
        self.row_counts.append(len(rows))
        return rows

    def __getattr__(self, name):
        return getattr(self.db, name)


def _nodes(plan):
    yield plan
    for child in plan.get("Plans", []):
        yield from _nodes(child)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "has_succession", [False, True], ids=["ordinary", "succession"]
)
async def test_mail_tick_uses_recipient_index_on_large_unread_history(
    aweb_cloud_db, has_succession
):
    db = aweb_cloud_db.aweb_db
    await db.execute("""
        INSERT INTO {{tables.messages}} (from_did, to_did, body, read_at)
        SELECT 'did:aw:peer', 'did:aw:other-' || n,
               'historical mail', CASE WHEN n % 10 = 0 THEN NULL ELSE NOW() END
        FROM generate_series(1, 100000) n
    """)
    expected = set()
    if has_succession:
        c1, c2 = uuid4(), uuid4()
        for cid, predecessor in ((c1, "did:key:old-one"), (c2, "did:key:old-two")):
            await db.execute(
                """INSERT INTO {{tables.conversations}}
                   (conversation_id, conversation_type, created_by_did)
                   VALUES ($1, 'mail', 'did:aw:peer')""",
                cid,
            )
            await db.execute(
                """INSERT INTO {{tables.conversation_participants}}
                   (conversation_id, did, alias, transport_hint, current_did_key)
                   VALUES ($1, 'did:aw:viewer', 'viewer', 'local', 'did:key:thread-key')""",
                cid,
            )
            await db.execute(
                """INSERT INTO {{tables.local_human_successions}}
                   (predecessor_did, predecessor_did_key, successor_did)
                   VALUES ($1, $1, 'did:aw:viewer')""",
                predecessor,
            )
            await db.execute(
                """INSERT INTO {{tables.conversation_participant_successions}}
                   (conversation_id, predecessor_did, predecessor_alias)
                   VALUES ($1, $2, 'old')""",
                cid,
                predecessor,
            )
        cases = [
            (c1, "did:aw:peer", "did:key:old-one", True),
            (c2, "did:aw:peer", "did:key:old-two", True),
            (c1, "did:aw:peer", "did:key:thread-key", True),
            (c1, "did:aw:peer", "did:aw:viewer", True),
            (None, "did:aw:peer", "did:aw:viewer", True),
            (c1, "did:key:old-one", "did:aw:viewer", False),
            (c1, "did:key:thread-key", "did:aw:viewer", False),
            (c2, "did:aw:peer", "did:key:old-one", False),
            (c1, "did:aw:peer", "did:key:old-two", False),
            (None, "did:aw:peer", "did:key:old-one", False),
            # The old-one evidence does not classify a sender in old-two's thread.
            (c2, "did:key:old-one", "did:aw:viewer", True),
            (None, "did:key:old-one", "did:aw:viewer", True),
        ]
        for cid, sender, target, incoming in cases:
            mid = uuid4()
            await db.execute(
                """INSERT INTO {{tables.messages}}
                   (message_id, conversation_id, from_did, to_did, body)
                   VALUES ($1,$2,$3,$4,'scope control')""",
                mid,
                cid,
                sender,
                target,
            )
            if incoming:
                expected.add(str(mid))
    await db.execute("ANALYZE {{tables.messages}}")
    counts = await db.fetch_one("""SELECT count(*) AS total,
        count(*) FILTER (WHERE read_at IS NULL) AS unread FROM {{tables.messages}}""")
    assert counts["total"] >= 100000 and counts["unread"] >= 10000
    observed = RecordingDatabase(db)
    scope = await load_mail_succession_scope(db, viewer_dids=["did:aw:viewer"])
    for _ in range(2):
        result = await _current_actionable_mail(
            observed, inbox_dids=["did:aw:viewer"], mail_scope=scope
        )
        assert {r["message_id"] for r in result} == expected
        assert all(r["unread_count"] == len(expected) for r in result)
    assert not any("participant_successions" in q for q, _ in observed.calls)
    query, args = next((q, a) for q, a in observed.calls if "WITH unread AS" in q)
    rows = await db.fetch_all("EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) " + query, *args)
    plan = rows[0]["QUERY PLAN"]
    if isinstance(plan, str):
        plan = json.loads(plan)
    if directory := os.environ.get("MAIL_PLAN_REPORT_DIR"):
        Path(directory).mkdir(parents=True, exist_ok=True)
        Path(directory, f"tick-plan-{has_succession}.json").write_text(
            json.dumps(plan, indent=2)
        )
    scans = [n for n in _nodes(plan[0]["Plan"]) if n.get("Relation Name") == "messages"]
    print(
        json.dumps({"messages_scans": scans, "execution_ms": plan[0]["Execution Time"]})
    )
    assert scans and all(n["Node Type"] != "Seq Scan" for n in scans)
    assert any("to_did" in n.get("Index Cond", "") for n in _nodes(plan[0]["Plan"]))
    assert "EXISTS" not in query.upper()

    # Optional retained comparison with the exact main SQL, supplied by the
    # author harness; runtime never imports or substitutes another revision.
    if baseline_file := os.environ.get("MAIL_PLAN_BASELINE_SQL"):
        baseline = Path(baseline_file).read_text()
        rows = await db.fetch_all(
            "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) " + baseline, ["did:aw:viewer"]
        )
        baseline_plan = rows[0]["QUERY PLAN"]
        if isinstance(baseline_plan, str):
            baseline_plan = json.loads(baseline_plan)
        if directory := os.environ.get("MAIL_PLAN_REPORT_DIR"):
            Path(directory, f"baseline-plan-{has_succession}.json").write_text(
                json.dumps(baseline_plan, indent=2)
            )


@pytest.mark.asyncio
async def test_stream_scope_does_not_return_ordinary_conversation_history(
    aweb_cloud_db,
):
    db = aweb_cloud_db.aweb_db
    await db.execute("""
        INSERT INTO {{tables.conversations}}
            (conversation_id, conversation_type, created_by_did)
        SELECT md5(n::text)::uuid, 'mail', 'did:aw:viewer'
        FROM generate_series(1, 50000) n
    """)
    # 50k viewer rows in a larger server population. None carries a thread key
    # outside the viewer's identities or a recorded predecessor.
    await db.execute("""
        INSERT INTO {{tables.conversation_participants}}
            (conversation_id, did, alias, transport_hint, current_did_key)
        SELECT md5(((n - 1) % 50000 + 1)::text)::uuid,
               CASE WHEN n <= 50000 THEN 'did:aw:viewer' ELSE 'did:aw:other-' || n END,
               'participant', 'local',
               CASE WHEN n <= 50000 THEN 'did:key:viewer' ELSE 'did:key:other-' || n END
        FROM generate_series(1, 500000) n
    """)
    await db.execute("ANALYZE {{tables.conversation_participants}}")
    observed = RecordingDatabase(db)
    scope = await load_mail_succession_scope(
        observed, viewer_dids=["did:aw:viewer", "did:key:viewer"]
    )
    assert scope.identity_threads == ()
    assert len(observed.calls) == 1
    query, args = observed.calls[0]
    rows = await db.fetch_all("EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) " + query, *args)
    plan = rows[0]["QUERY PLAN"]
    if isinstance(plan, str):
        plan = json.loads(plan)
    if directory := os.environ.get("MAIL_PLAN_REPORT_DIR"):
        Path(directory).mkdir(parents=True, exist_ok=True)
        Path(directory, "scope-plan.json").write_text(json.dumps(plan, indent=2))
    scans = [
        n
        for n in _nodes(plan[0]["Plan"])
        if n.get("Relation Name") == "conversation_participants"
    ]
    assert scans and all(n["Node Type"] != "Seq Scan" for n in scans)
    assert any("did" in n.get("Index Cond", "") for n in _nodes(plan[0]["Plan"]))
    assert plan[0]["Plan"]["Actual Rows"] == 0
    assert observed.row_counts == [0]

    if baseline_file := os.environ.get("MAIL_SCOPE_BASELINE_SQL"):
        rows = await db.fetch_all(
            "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) "
            + Path(baseline_file).read_text(),
            *args,
        )
        old_plan = rows[0]["QUERY PLAN"]
        if isinstance(old_plan, str):
            old_plan = json.loads(old_plan)
        assert old_plan[0]["Plan"]["Actual Rows"] == 50000
        if directory := os.environ.get("MAIL_PLAN_REPORT_DIR"):
            Path(directory, "scope-baseline-plan.json").write_text(
                json.dumps(old_plan, indent=2)
            )

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from aweb.gc import DEAD_ROW_RULES, delete_dead_rows

QUIET = "quiet:acme.com"
BUSY = "busy:acme.com"
TEAMS = (QUIET, BUSY)

RULE_TABLES = (
    "app_events",
    "control_signals",
    "federation_mutation_outbox",
    "lifecycle_side_effect_outbox",
)


def _ago(days: int) -> datetime:
    return datetime.now(timezone.utc) - timedelta(days=days)


async def _seed(db) -> dict[str, set]:
    """Two teams, each with rows on both sides of every rule.

    Per team and table: one dead row past the rule's age, one dead row short
    of it and, where the table has a live state, one live row older than the
    age. The quiet team was created 60 days ago and holds a task, an unread
    mail and a chat message, all 60 days old. Returns the primary keys of the rows the cleanup deletes, per
    table.
    """
    dead: dict[str, set] = {table: set() for table in RULE_TABLES}
    for team_id in TEAMS:
        slug = team_id.split(":")[0]
        agent_id = uuid4()
        await db.execute(
            """
            INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key, created_at)
            VALUES ($1, 'acme.com', $2, $3, $4)
            """,
            team_id,
            slug,
            f"did:key:team-{slug}",
            _ago(60),
        )
        await db.execute(
            """
            INSERT INTO {{tables.agents}} (agent_id, team_id, did_key, alias, created_at)
            VALUES ($1, $2, $3, 'alice', $4)
            """,
            agent_id,
            team_id,
            f"did:key:agent-{slug}",
            _ago(60),
        )

        for days, is_dead in ((31, True), (29, False)):
            event_id = uuid4()
            await db.execute(
                """
                INSERT INTO {{tables.app_events}} (
                    event_id, team_id, app_id, event_type, producer_key_id,
                    producer_did_key, created_at
                )
                VALUES ($1, $2, 'tracker', 'tracker.changed', 'key-1', 'did:key:producer', $3)
                """,
                event_id,
                team_id,
                _ago(days),
            )
            if is_dead:
                dead["app_events"].add(event_id)

        # Consumed 31 and 29 days ago, and one sent 60 days ago that its
        # target has not received.
        for consumed_at, is_dead in ((_ago(31), True), (_ago(29), False), (None, False)):
            signal_id = uuid4()
            await db.execute(
                """
                INSERT INTO {{tables.control_signals}} (
                    signal_id, team_id, target_agent_id, from_agent_id,
                    signal_type, created_at, consumed_at
                )
                VALUES ($1, $2, $3, $3, 'pause', $4, $5)
                """,
                signal_id,
                team_id,
                agent_id,
                _ago(60),
                consumed_at,
            )
            if is_dead:
                dead["control_signals"].add(signal_id)

        for delivered_at, is_dead in ((_ago(31), True), (_ago(29), False), (None, False)):
            outbox_id = uuid4()
            await db.execute(
                """
                INSERT INTO {{tables.lifecycle_side_effect_outbox}} (
                    outbox_id, operation_id, effect_order, team_id, effect_kind,
                    payload_json, created_at, delivered_at
                )
                VALUES ($1, $2, 0, $3, 'presence_clear', '{}'::jsonb, $4, $5)
                """,
                outbox_id,
                uuid4(),
                team_id,
                _ago(60),
                delivered_at,
            )
            if is_dead:
                dead["lifecycle_side_effect_outbox"].add(outbox_id)

        for delivered_at, is_dead in ((_ago(31), True), (_ago(29), False), (None, False)):
            outbox_id = uuid4()
            message_id = uuid4()
            await db.execute(
                """
                INSERT INTO {{tables.message_ingress_receipts}} (
                    message_id, storage_kind, legacy_unreplayable
                )
                VALUES ($1, 'mail', TRUE)
                """,
                message_id,
            )
            await db.execute(
                """
                INSERT INTO {{tables.federation_mutation_outbox}} (
                    outbox_id, message_id, event_type, payload_json, created_at, delivered_at
                )
                VALUES ($1, $2, 'message.sent', $3::jsonb, $4, $5)
                """,
                outbox_id,
                message_id,
                json.dumps({"team_id": team_id}),
                _ago(60),
                delivered_at,
            )
            if is_dead:
                dead["federation_mutation_outbox"].add(outbox_id)

    await db.execute(
        """
        INSERT INTO {{tables.tasks}} (team_id, task_number, task_ref_suffix, title, created_at)
        VALUES ($1, 1, 'aaaa', 'task', $2)
        """,
        QUIET,
        _ago(60),
    )
    await db.execute(
        """
        INSERT INTO {{tables.messages}} (
            from_did, to_did, from_alias, to_alias, subject, body, team_id, created_at
        )
        VALUES ('did:key:agent-busy', 'did:key:agent-quiet', 'alice', 'alice', 'hi', 'unread', $1, $2)
        """,
        QUIET,
        _ago(60),
    )
    session_id = uuid4()
    await db.execute(
        "INSERT INTO {{tables.chat_sessions}} (session_id, team_id, created_by, created_at) VALUES ($1, $2, 'alice', $3)",
        session_id,
        QUIET,
        _ago(60),
    )
    await db.execute(
        """
        INSERT INTO {{tables.chat_messages}} (session_id, from_did, from_alias, body, created_at)
        VALUES ($1, 'did:key:agent-busy', 'alice', 'unread', $2)
        """,
        session_id,
        _ago(60),
    )
    return dead


async def _primary_keys(db) -> dict[str, set]:
    keys = {}
    for rule in DEAD_ROW_RULES:
        rows = await db.fetch_all(
            f"SELECT {rule.key} AS key FROM {{{{tables.{rule.table}}}}}"
        )
        keys[rule.table] = {row["key"] for row in rows}
    return keys


async def _row_counts_outside_rules(db) -> dict[str, int]:
    """Row count of every table in the schema that no rule names."""
    tables = await db.fetch_all(
        """
        SELECT table_name
        FROM information_schema.tables
        WHERE table_schema = 'aweb' AND table_type = 'BASE TABLE'
        ORDER BY table_name
        """
    )
    counts = {}
    for row in tables:
        table = row["table_name"]
        if table in RULE_TABLES:
            continue
        counts[table] = await db.fetch_value(f'SELECT COUNT(*) FROM aweb."{table}"')
    return counts


def _report(dead: dict[str, set], *, apply: bool, deleted: bool) -> dict:
    return {
        "apply": apply,
        "tables": {
            table: {
                "older_than_days": 30,
                "dead_rows": len(dead[table]),
                "deleted_rows": len(dead[table]) if deleted else 0,
            }
            for table in RULE_TABLES
        },
    }


def test_rules_name_the_expected_tables():
    assert tuple(sorted(rule.table for rule in DEAD_ROW_RULES)) == RULE_TABLES


@pytest.mark.asyncio
async def test_dry_run_counts_dead_rows_and_deletes_nothing(aweb_cloud_db):
    db = aweb_cloud_db.aweb_db
    dead = await _seed(db)
    assert all(len(keys) == 2 for keys in dead.values())
    keys_before = await _primary_keys(db)
    others_before = await _row_counts_outside_rules(db)

    report = await delete_dead_rows(db)

    assert report == _report(dead, apply=False, deleted=False)
    assert await _primary_keys(db) == keys_before
    assert await _row_counts_outside_rules(db) == others_before


@pytest.mark.asyncio
async def test_apply_deletes_dead_rows_past_the_age_in_every_team_and_nothing_else(aweb_cloud_db):
    db = aweb_cloud_db.aweb_db
    dead = await _seed(db)
    keys_before = await _primary_keys(db)
    others_before = await _row_counts_outside_rules(db)

    report = await delete_dead_rows(db, apply=True)

    assert report == _report(dead, apply=True, deleted=True)
    keys_after = await _primary_keys(db)
    for table in RULE_TABLES:
        assert keys_after[table] == keys_before[table] - dead[table], table
        # The dead row short of the age, and the live row where the table has
        # one, remain in each team.
        assert len(keys_after[table]) == (2 if table == "app_events" else 4), table
    assert await _row_counts_outside_rules(db) == others_before

    second = await delete_dead_rows(db, apply=True)

    assert second == _report({table: set() for table in RULE_TABLES}, apply=True, deleted=True)
    assert await _primary_keys(db) == keys_after


@pytest.mark.asyncio
async def test_quiet_team_keeps_its_tasks_mail_and_chat(aweb_cloud_db):
    db = aweb_cloud_db.aweb_db
    await _seed(db)

    await delete_dead_rows(db, apply=True)

    assert await db.fetch_value(
        "SELECT COUNT(*) FROM {{tables.teams}} WHERE team_id = $1", QUIET
    ) == 1
    assert await db.fetch_value(
        "SELECT COUNT(*) FROM {{tables.agents}} WHERE team_id = $1 AND deleted_at IS NULL", QUIET
    ) == 1
    assert await db.fetch_value(
        "SELECT COUNT(*) FROM {{tables.tasks}} WHERE team_id = $1 AND deleted_at IS NULL", QUIET
    ) == 1
    assert await db.fetch_value(
        "SELECT COUNT(*) FROM {{tables.messages}} WHERE team_id = $1 AND read_at IS NULL", QUIET
    ) == 1
    assert await db.fetch_value(
        """
        SELECT COUNT(*)
        FROM {{tables.chat_messages}} m
        JOIN {{tables.chat_sessions}} s ON s.session_id = m.session_id
        WHERE s.team_id = $1
        """,
        QUIET,
    ) == 1


@pytest.mark.asyncio
async def test_apply_deletes_every_dead_row_in_batches(aweb_cloud_db):
    db = aweb_cloud_db.aweb_db
    dead = await _seed(db)
    extra = [uuid4() for _ in range(5)]
    for event_id in extra:
        await db.execute(
            """
            INSERT INTO {{tables.app_events}} (
                event_id, team_id, app_id, event_type, producer_key_id,
                producer_did_key, created_at
            )
            VALUES ($1, $2, 'tracker', 'tracker.changed', 'key-1', 'did:key:producer', $3)
            """,
            event_id,
            QUIET,
            _ago(45),
        )
    dead["app_events"].update(extra)
    keys_before = await _primary_keys(db)

    # Seven dead app events: three full batches of two and a last batch of one.
    report = await delete_dead_rows(db, apply=True, batch_size=2)

    assert report == _report(dead, apply=True, deleted=True)
    keys_after = await _primary_keys(db)
    for table in RULE_TABLES:
        assert keys_after[table] == keys_before[table] - dead[table], table


@pytest.mark.asyncio
async def test_each_rule_selects_its_dead_rows_through_an_index_on_the_age_column(aweb_cloud_db):
    db = aweb_cloud_db.aweb_db
    indexes = {
        "app_events": "idx_app_events_created",
        "control_signals": "idx_control_signals_consumed",
        "federation_mutation_outbox": "idx_federation_mutation_outbox_delivered",
        "lifecycle_side_effect_outbox": "idx_lifecycle_side_effect_outbox_delivered",
    }
    for rule in DEAD_ROW_RULES:
        async with db.transaction() as tx:
            await tx.execute("SET LOCAL enable_seqscan = off")
            plan = await tx.fetch_all(
                f"""
                EXPLAIN SELECT {rule.key} FROM {{{{tables.{rule.table}}}}}
                WHERE {rule.age_column} < NOW() - INTERVAL '30 days'
                LIMIT 1000
                """
            )
        text = "\n".join(row["QUERY PLAN"] for row in plan)
        assert indexes[rule.table] in text, text


@pytest.mark.asyncio
async def test_batch_size_below_one_is_refused(aweb_cloud_db):
    with pytest.raises(ValueError):
        await delete_dead_rows(aweb_cloud_db.aweb_db, apply=True, batch_size=0)


@pytest.mark.asyncio
async def test_cli_reports_by_default_and_deletes_with_apply(test_db_factory):
    import asyncio
    import os
    import sys

    from awid.db_config import build_database_config
    from pgdbm import AsyncDatabaseManager

    from aweb.db import DatabaseInfra

    base = await test_db_factory.create_db(suffix="delete_dead_rows_cli")
    await base.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public")
    pool = await AsyncDatabaseManager.create_shared_pool(
        build_database_config(connection_string=base.config.get_dsn())
    )
    infra = DatabaseInfra()
    await infra.initialize(shared_pool=pool)
    db = infra.get_manager()
    try:
        dead = await _seed(db)
        keys_before = await _primary_keys(db)

        async def run_cli(*args: str) -> dict:
            process = await asyncio.create_subprocess_exec(
                sys.executable, "-c", "from aweb.cli import app; app()",
                "delete-dead-rows", *args,
                env={**os.environ, "AWEB_DATABASE_URL": base.config.get_dsn()},
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), 20)
            assert process.returncode == 0, stderr.decode()
            return json.loads(stdout)

        assert await run_cli() == _report(dead, apply=False, deleted=False)
        assert await _primary_keys(db) == keys_before

        assert await run_cli("--apply") == _report(dead, apply=True, deleted=True)
        keys_after = await _primary_keys(db)
        for table in RULE_TABLES:
            assert keys_after[table] == keys_before[table] - dead[table], table
    finally:
        await infra.close()
        await pool.close()

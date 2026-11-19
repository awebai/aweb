"""Broker response bytes are transient; durable outcomes contain metadata only."""

import asyncio
import json
import secrets
from pathlib import Path
from uuid import uuid4

import asyncpg
import pytest
from aweb_naapp.dispatch import (
    MIGRATIONS_MODULE,
    MIGRATIONS_PATH,
    Dispatches,
    apply_dispatch_migrations,
)
from aweb_naapp.hooks.commitment import CommitmentContext
from fastapi import Request
from fastapi.responses import JSONResponse
from pgdbm import AsyncMigrationManager

from aweb_secrets.broker_outcomes import prepare_legacy_broker_outcomes
from aweb_secrets.use_context import UseCommitments, apply_use_context_migrations, store_use_context
from tests.harness import running_upstream
from tests.test_admission import SECRET, TEAM, _admit, _grant_source_grant, _install
from tests.test_broker_audit import INSTALLATION, envelopes
from tests.test_broker_service import db as db
from tests.test_broker_service import fence as fence
from tests.test_broker_service import setup, submission


async def _is_stored(db, value: str) -> bool:
    # Inspect every table in this isolated test schema, including outbox and
    # late evidence. SQL identifiers come quoted by PostgreSQL; values remain
    # bound parameters and are never included in assertion diagnostics.
    tables = await db.fetch_all(
        "SELECT quote_ident(table_schema)||'.'||quote_ident(table_name) AS name"
        " FROM information_schema.tables WHERE table_schema=current_schema()"
        " AND table_type='BASE TABLE'"
    )
    assert tables
    for table in tables:
        if await db.fetch_value(
            f"SELECT EXISTS(SELECT 1 FROM {table['name']} AS t"
            " WHERE strpos(row_to_json(t)::text,$1)>0)",
            value,
        ):
            return True
    return False


def _create_route(upstream, document):
    @upstream.app.post("/bearer/create-server")
    async def create(request: Request):
        if request.headers.get("authorization") != f"Bearer {upstream.creds.bearer}":
            return JSONResponse({}, status_code=401)
        return JSONResponse(document, status_code=201)


async def test_provider_password_reaches_neither_the_agent_nor_any_table(db, fence, tmp_path):
    password = secrets.token_urlsafe(24)
    async with running_upstream(tmp_path) as upstream:
        _create_route(upstream, {"server": {"id": 7}, "root_password": password})
        service = await setup(db, fence, tmp_path, upstream)
        reply = await service.submit(
            secret=SECRET["ref"],
            submission=submission(upstream, url=upstream.url("/bearer/create-server")),
        )
        leaked = password in json.dumps(reply.body)
        stored = await _is_stored(db, password)
        assert (leaked, stored) == (False, False), "provider password escaped response handling"
        assert reply.body["state"] == "result_withheld"
        assert reply.body["code"] == "credential_shaped"
        assert (await envelopes(db))[-1]["payload"]["undeclared_credential"] is True
        assert upstream.paths == ["/bearer/create-server"]


async def test_even_a_harmless_live_body_is_not_persisted_or_replayed(db, fence, tmp_path):
    marker = secrets.token_hex(24)
    async with running_upstream(tmp_path) as upstream:
        _create_route(upstream, {"server": {"id": 7}, "message": marker})
        service = await setup(db, fence, tmp_path, upstream)
        original = submission(upstream, url=upstream.url("/bearer/create-server"))
        live = await service.submit(secret=SECRET["ref"], submission=original)
        assert live.body["state"] == "completed"
        assert marker in json.dumps(live.body), "the initiating request lost its live response"
        stored = await _is_stored(db, marker)
        replay = await service.submit(secret=SECRET["ref"], submission=original)
        replayed = marker in json.dumps(replay.body)
        assert (stored, replayed) == (False, False), "response bytes survived their live request"
        assert replay.body["state"] == "completed"
        assert upstream.paths == ["/bearer/create-server"]


async def test_a_recorded_dispatch_outcome_cannot_be_overwritten(db, fence, tmp_path):
    async with running_upstream(tmp_path) as upstream:
        service = await setup(db, fence, tmp_path, upstream)
        reply = await service.submit(secret=SECRET["ref"], submission=submission(upstream))
        assert reply.body["state"] == "completed"
        with pytest.raises(asyncpg.PostgresError):
            async with db.transaction() as tx:
                await tx.execute("UPDATE {{tables.dispatches}} SET result='{}'::jsonb")


async def test_a_late_live_response_is_metadata_only_and_cannot_replace_unknown(
    db, fence, tmp_path
):
    marker, header = (secrets.token_hex(24) for _ in range(2))
    entered, release = asyncio.Event(), asyncio.Event()
    async with running_upstream(tmp_path) as upstream:

        @upstream.app.post("/bearer/late-create")
        async def create(request: Request):
            if request.headers.get("authorization") != f"Bearer {upstream.creds.bearer}":
                return JSONResponse({}, status_code=401)
            entered.set()
            await release.wait()
            return JSONResponse({"message": marker}, status_code=201, headers={"ETag": header})

        service = await setup(db, fence, tmp_path, upstream)
        task = asyncio.create_task(
            service.submit(
                secret=SECRET["ref"],
                submission=submission(upstream, url=upstream.url("/bearer/late-create")),
            )
        )
        try:
            await asyncio.wait_for(entered.wait(), timeout=5)
            await db.execute(
                "UPDATE {{tables.dispatches}} SET sweep_after=clock_timestamp()-interval '1 second'"
            )
            assert await service.sweep() == 1
            release.set()
            reply = await task
        finally:
            release.set()
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        assert reply.body["state"] == "outcome_unknown"
        assert not await _is_stored(db, marker), "late response body survived"
        assert not await _is_stored(db, header), "late response header survived"
        rows = await db.fetch_all(
            "SELECT attempt,kind,state FROM {{tables.dispatch_observations}} ORDER BY observation_id"
        )
        assert [(r["attempt"], r["kind"], r["state"]) for r in rows] == [
            (1, "outcome", "outcome_unknown"),
            (1, "late", "completed"),
        ]
        assert upstream.paths == ["/bearer/late-create"]


async def test_recorded_upgrade_purges_broker_payloads_before_immutable_import(db, fence, tmp_path):
    # Apply the actual historical migrations to a real database. The fixture
    # is an old stored row, not a fake dispatch implementation or SDK.
    for source, module, count in (
        (MIGRATIONS_PATH, MIGRATIONS_MODULE, 2),
        (
            Path(__file__).parents[1] / "src/aweb_secrets/dispatch_migrations",
            "aweb_secrets_dispatch",
            4,
        ),
    ):
        old = tmp_path / module
        old.mkdir()
        for migration in sorted(source.glob("*.sql"))[:count]:
            (old / migration.name).write_bytes(migration.read_bytes())
        await AsyncMigrationManager(
            db, migrations_path=str(old), module_name=module
        ).apply_pending_migrations()
    await _install(db, installation_id=INSTALLATION)
    admitted = await _admit(db, fence, grant=_grant_source_grant(installation_id=INSTALLATION))

    async def record(tx, transition):
        await tx.execute("SELECT 1")

    from datetime import timedelta

    machine = Dispatches(
        on_transition=record, max_dispatch=timedelta(seconds=30), sweep_margin=timedelta(seconds=5)
    )
    dispatch_id, other_id = uuid4(), uuid4()
    password, header, other_output = (secrets.token_urlsafe(24) for _ in range(3))
    legacy = {
        "state": "completed",
        "request_id": "req_1",
        "request_ref": admitted.intent_id,
        "result": {
            "body": {"root_password": password},
            "headers": [["ETag", header]],
            "status": 201,
            "upstream_bytes": 100,
            "truncated": False,
        },
    }
    async with db.transaction() as tx:
        await store_use_context(
            tx,
            admission=admitted,
            dispatch_id=dispatch_id,
            commitments=UseCommitments(
                CommitmentContext(
                    "secrets", TEAM, INSTALLATION, admitted.installation.generation, "request"
                ),
                "a" * 64,
                None,
            ),
        )
        for identity in (dispatch_id, other_id):
            await machine.create(tx, dispatch_id=identity, subject=str(identity), action="fixture")
        await tx.execute(
            "UPDATE {{tables.dispatches}} SET state='completed',attempts=1,result=$2::jsonb,"
            " late_results=jsonb_build_array($2::jsonb) WHERE dispatch_id=$1",
            dispatch_id,
            json.dumps(legacy),
        )
        await tx.execute(
            "UPDATE {{tables.dispatches}} SET state='completed',attempts=1,result=$2::jsonb"
            " WHERE dispatch_id=$1",
            other_id,
            json.dumps({"sanitized_output": other_output}),
        )
    await apply_dispatch_migrations(db, before_upgrade=prepare_legacy_broker_outcomes)
    await apply_use_context_migrations(db)
    assert not await _is_stored(db, password), "historical broker body survived upgrade"
    assert not await _is_stored(db, header), "historical broker header survived upgrade"
    assert await _is_stored(db, other_output), "non-broker output was purged"
    assert await db.fetch_value("SELECT classified_rows FROM {{tables.broker_outcome_purges}}") == 1
    observations = await db.fetch_all(
        "SELECT attempt,provenance FROM {{tables.dispatch_observations}} WHERE dispatch_id=$1",
        dispatch_id,
    )
    assert len(observations) == 2
    assert all(r["attempt"] is None and r["provenance"] == "legacy_snapshot" for r in observations)
    with pytest.raises(asyncpg.PostgresError):
        async with db.transaction() as tx:
            await tx.execute(
                "INSERT INTO {{tables.dispatch_observations}}"
                " (dispatch_id,attempt,kind,state,result,provenance)"
                " VALUES ($1,1,'late','completed',$2::jsonb,'live')",
                dispatch_id,
                json.dumps(legacy),
            )

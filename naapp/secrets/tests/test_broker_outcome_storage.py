"""Broker response bytes are transient; durable outcomes contain metadata only."""

import json
import secrets

import asyncpg
import pytest
from fastapi import Request
from fastapi.responses import JSONResponse

from tests.harness import running_upstream
from tests.test_admission import SECRET
from tests.test_broker_audit import envelopes
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

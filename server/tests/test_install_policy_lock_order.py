"""Concurrent mounted routes, real TLS fetches and PostgreSQL policy reads."""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path

import aweb.installations
import httpx
import pytest
import test_install_policy_origin as policy_fixture
import test_installation_http as http_fixture
from fastapi import FastAPI

db = policy_fixture.db
origin = policy_fixture.origin
host = policy_fixture.host
pytestmark = pytest.mark.asyncio


@pytest.fixture(autouse=True)
def expected_source_tree():
    assert Path(aweb.installations.__file__).resolve() == Path(__file__).parents[1] / "src/aweb/installations.py"


async def compete(host, db, origin, calls):
    readers = []
    first_read = asyncio.Event()
    release = asyncio.Event()

    async def policy(tx, subject, *, action, app_id, verified_origin=None):
        assert subject.team_id == http_fixture.TEAM
        assert verified_origin == origin.url
        await tx.fetch_one(
            "SELECT installation_id FROM {{tables.team_app_installs}} "
            "WHERE team_id=$1 AND app_id=$2 FOR SHARE",
            subject.team_id, app_id,
        )
        readers.append(await tx.fetch_value("SELECT pg_backend_pid()"))
        first_read.set()
        await release.wait()
        return True

    host.app.state.install_admin_policy = policy
    outer = FastAPI()
    outer.mount("/api", host.app)

    @outer.middleware("http")
    async def log_server_error(request, call_next):
        try:
            return await call_next(request)
        except Exception as exc:
            logging.getLogger(__name__).exception(
                "installation route error: policy_overlap=%s sqlstate=%s",
                len(readers) == 2, getattr(exc, "sqlstate", None),
            )
            raise

    # Exercise the real HTTP refusal, rather than propagating a server exception
    # into the test. No application component or database is substituted.
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=outer, raise_app_exceptions=False), base_url="http://test",
    ) as client:
        tasks = []
        try:
            tasks.append(asyncio.create_task(http_fixture.post(client, *calls[0])))
            await asyncio.wait_for(first_read.wait(), 5)
            tasks.append(asyncio.create_task(http_fixture.post(client, *calls[1])))
            # Before the fix both policy SHARE reads enter. With correct order,
            # PostgreSQL reports the second route blocked by the first BEFORE
            # its policy read. This does not depend on an advisory-key spelling
            # or an arbitrary delay to manufacture the race.
            async with asyncio.timeout(5):
                while len(readers) < 2:
                    blocked = await db.fetch_value(
                        "SELECT EXISTS(SELECT 1 FROM pg_stat_activity "
                        "WHERE datname=current_database() AND $1::INT=ANY(pg_blocking_pids(pid)))",
                        readers[0],
                    )
                    if blocked:
                        break
                    await asyncio.sleep(0.01)
            concurrent_policy_reads = len(readers) == 2
        finally:
            release.set()
            responses = await asyncio.wait_for(asyncio.gather(*tasks), 10)
    return responses, concurrent_policy_reads


async def calls_for(host, origin, *, approval, generation=None):
    payload = http_fixture.confirmation(origin)
    if not approval:
        if generation is not None:
            payload["expected_generation"] = generation
        return [(payload, "install"), (payload, "install")]
    payload["requested_scopes"] = payload.pop("granted_scopes")
    calls = []
    for _ in range(2):
        created = await http_fixture.post(host.client, payload, "requests")
        assert created.status_code == 201, created.text
        body = {"granted_scopes": ["fixture:read"]}
        if generation is not None:
            body["expected_generation"] = generation
        calls.append((body, f"requests/{created.json()['request_id']}/approve"))
    return calls


@pytest.mark.parametrize("approval", [False, True], ids=["install", "approve"])
async def test_same_app_repins_lock_before_policy_without_deadlock(host, db, origin, approval):
    installed = await http_fixture.post(host.client, http_fixture.confirmation(origin))
    assert installed.status_code == 200, installed.text
    calls = await calls_for(host, origin, approval=approval, generation=installed.json()["generation"])
    responses, overlap = await compete(host, db, origin, calls)
    assert sorted(r.status_code for r in responses) == [200, 409], [r.text for r in responses]
    refusal = next(r for r in responses if r.status_code == 409)
    assert refusal.json()["detail"]["code"] == "generation_conflict"
    assert not overlap, "final policies read the same row before installation serialization"
    assert await db.fetch_value("SELECT count(*) FROM {{tables.team_app_installs}}") == 1
    assert await policy_fixture.successes(db) == 2


@pytest.mark.parametrize("approval", [False, True], ids=["install", "approve"])
async def test_no_row_install_is_serialized_before_policy(host, db, origin, approval):
    calls = await calls_for(host, origin, approval=approval)
    responses, overlap = await compete(host, db, origin, calls)
    assert sorted(r.status_code for r in responses) == [200, 422], [r.text for r in responses]
    refusal = next(r for r in responses if r.status_code == 422)
    assert refusal.json()["detail"]["code"] == "generation_required"
    assert not overlap, "absent installation did not serialize final policies"
    assert await db.fetch_value("SELECT count(*) FROM {{tables.team_app_installs}}") == 1
    assert await policy_fixture.successes(db) == 1

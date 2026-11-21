"""A real reconnect takes lifecycle's workspace-before-agent row-lock order."""

import asyncio
from uuid import UUID

import pytest
from asyncpg.exceptions import LockNotAvailableError

from test_dashboard_privacy import TEAM, privacy_app as privacy_app
from test_member_team_key import _connect

__all__ = ["privacy_app"]


@pytest.mark.asyncio
async def test_reconnect_locks_its_workspace_before_waiting_for_its_member(privacy_app):
    env = privacy_app
    actor = env.actors["alice"]
    member = actor.sk, actor.did, "alice"
    initial = await _connect(env, member, actor.certificate)
    assert initial.status_code == 200, initial.text
    agent_id = UUID(initial.json()["agent_id"])
    workspace_id = UUID(initial.json()["workspace_id"])
    reconnect = None
    try:
        async with env.db.transaction() as holder:
            holder_pid = await holder.fetch_value("SELECT pg_backend_pid()")
            await holder.fetch_one(
                "SELECT agent_id FROM {{tables.agents}} "
                "WHERE team_id=$1 AND agent_id=$2 FOR UPDATE",
                TEAM,
                agent_id,
            )
            reconnect = asyncio.create_task(_connect(env, member, actor.certificate))
            # Observe the actual independent request transaction waiting on the
            # held agent row; no timing guess or authentication replacement.
            async with asyncio.timeout(10):
                while True:
                    waiters = await env.db.fetch_all(
                        "SELECT pid FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid))",
                        holder_pid,
                    )
                    if waiters:
                        break
                    assert not reconnect.done()
                    await asyncio.sleep(0.01)
            assert len(waiters) == 1
            reconnect_pid = waiters[0]["pid"]
            assert reconnect_pid != holder_pid
            with pytest.raises(LockNotAvailableError) as refused:
                async with env.db.transaction() as probe:
                    probe_pid = await probe.fetch_value("SELECT pg_backend_pid()")
                    assert probe_pid not in (holder_pid, reconnect_pid)
                    await probe.fetch_one(
                        "SELECT workspace_id FROM {{tables.workspaces}} "
                        "WHERE team_id=$1 AND workspace_id=$2 FOR UPDATE NOWAIT",
                        TEAM,
                        workspace_id,
                    )
            assert refused.value.sqlstate == "55P03"
    finally:
        # Releasing the actual agent lock must let the real request finish.
        if reconnect is not None:
            finished = await asyncio.wait_for(reconnect, 10)
            assert finished.status_code == 200, finished.text

"""Real aweb/AWID/PostgreSQL/Redis coverage for agent-held reservations."""

from datetime import datetime, timedelta, timezone

import pytest

from test_dashboard_privacy import TEAM, privacy_app  # noqa: F401
from test_messages_http import _signed_team_headers


@pytest.mark.asyncio
async def test_status_reports_reservation_held_by_workspace_agent(privacy_app):
    env = privacy_app
    holder = env.actors["alice"]
    now = datetime.now(timezone.utc)
    resource = "server/src/aweb/routes/status.py"
    await env.db.execute(
        """
        INSERT INTO {{tables.reservations}}
            (team_id, resource_key, holder_agent_id, holder_alias,
             acquired_at, expires_at, metadata_json)
        VALUES ($1,$2,$3,'alice',$4,$5,'{}'::jsonb)
        """,
        TEAM, resource, holder.id, now, now + timedelta(hours=1),
    )

    # Both holder and teammate read the real team-scoped status. Reservations
    # belong to the agent, but the status projection is keyed by workspace.
    for name in ("alice", "bob"):
        actor = env.actors[name]
        headers = _signed_team_headers(actor.sk, actor.did, TEAM, actor.certificate)
        response = await env.client.get("/v1/status", headers=headers)
        assert response.status_code == 200, response.text
        body = response.json()
        assert [lock["resource_key"] for lock in body["locks"]] == [resource]
        agents = {a["workspace_id"]: a for a in body["agents"]}
        assert [lock["resource_key"] for lock in agents[str(holder.workspace)]["reservations"]] == [resource]
        assert agents[str(env.actors["bob"].workspace)]["reservations"] == []

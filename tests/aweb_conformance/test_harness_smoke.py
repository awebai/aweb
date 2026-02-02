from __future__ import annotations

import pytest

from .harness import AwebTarget


@pytest.mark.asyncio
async def test_harness_bootstrap_produces_two_agents(aweb_target: AwebTarget) -> None:
    assert aweb_target.base_url
    assert aweb_target.agent_1_api_key
    assert aweb_target.agent_2_api_key
    assert aweb_target.agent_1.agent_id
    assert aweb_target.agent_1.alias
    assert aweb_target.agent_2.agent_id
    assert aweb_target.agent_2.alias
    assert aweb_target.agent_1.alias != aweb_target.agent_2.alias


@pytest.mark.asyncio
async def test_harness_can_hit_health(aweb_client) -> None:
    # Health endpoint is not required by the aweb protocol; treat 404 as acceptable.
    resp = await aweb_client.get("/health")
    assert resp.status_code in (200, 404)

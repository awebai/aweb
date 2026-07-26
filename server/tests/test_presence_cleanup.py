from __future__ import annotations

import pytest

from aweb.presence import clear_workspace_presence, update_agent_presence


class _Pipeline:
    def __init__(self, redis: "_Redis"):
        self.redis = redis
        self.calls: list[tuple[str, tuple]] = []

    def __getattr__(self, name: str):
        def enqueue(*args):
            self.calls.append((name, args))
            return self

        return enqueue

    async def execute(self):
        results = []
        for name, args in self.calls:
            results.append(await getattr(self.redis, name)(*args))
        return results


class _Redis:
    def __init__(self):
        self.hashes: dict[str, dict[str, str]] = {}
        self.sets: dict[str, set[str]] = {}
        self.values: dict[str, str] = {}

    def pipeline(self):
        return _Pipeline(self)

    async def hset(self, key, mapping):
        self.hashes.setdefault(key, {}).update(mapping)
        return len(mapping)

    async def hgetall(self, key):
        return dict(self.hashes.get(key, {}))

    async def expire(self, key, seconds):
        return True

    async def sadd(self, key, value):
        before = len(self.sets.setdefault(key, set()))
        self.sets[key].add(value)
        return int(len(self.sets[key]) != before)

    async def srem(self, key, value):
        existed = value in self.sets.get(key, set())
        self.sets.setdefault(key, set()).discard(value)
        return int(existed)

    async def set(self, key, value, ex=None):
        self.values[key] = value
        return True

    async def delete(self, key):
        existed = key in self.hashes or key in self.values
        self.hashes.pop(key, None)
        self.values.pop(key, None)
        return int(existed)

    async def eval(self, script, number_of_keys, key, expected):
        if self.values.get(key) == expected:
            return await self.delete(key)
        return 0


@pytest.mark.asyncio
async def test_clear_workspace_presence_removes_every_production_index():
    redis = _Redis()
    workspace_id = "workspace-1"
    await update_agent_presence(
        redis,
        workspace_id=workspace_id,
        alias="worker",
        team_id="backend:acme.test",
        repo_id="repo-1",
        current_branch="main",
    )

    assert await clear_workspace_presence(redis, [workspace_id]) == 1
    assert f"presence:{workspace_id}" not in redis.hashes
    assert f"presence_coordinates:{workspace_id}" not in redis.hashes
    assert workspace_id not in redis.sets["idx:all_workspaces"]
    assert workspace_id not in redis.sets["idx:team_workspaces:backend:acme.test"]
    assert workspace_id not in redis.sets["idx:repo_workspaces:repo-1"]
    assert workspace_id not in redis.sets["idx:branch_workspaces:repo-1:main"]
    assert "idx:alias:backend%3Aacme.test:worker" not in redis.values


@pytest.mark.asyncio
async def test_clear_workspace_presence_uses_coordinates_after_primary_expires():
    redis = _Redis()
    workspace_id = "workspace-expired"
    await update_agent_presence(
        redis,
        workspace_id=workspace_id,
        alias="worker",
        team_id="backend:acme.test",
        repo_id="repo-1",
        current_branch="main",
    )
    redis.hashes.pop(f"presence:{workspace_id}")

    assert await clear_workspace_presence(redis, [workspace_id]) == 0
    assert f"presence_coordinates:{workspace_id}" not in redis.hashes
    assert workspace_id not in redis.sets["idx:all_workspaces"]
    assert workspace_id not in redis.sets["idx:team_workspaces:backend:acme.test"]
    assert workspace_id not in redis.sets["idx:repo_workspaces:repo-1"]
    assert workspace_id not in redis.sets["idx:branch_workspaces:repo-1:main"]
    assert "idx:alias:backend%3Aacme.test:worker" not in redis.values


@pytest.mark.asyncio
async def test_clear_workspace_presence_preserves_concurrently_reused_alias():
    redis = _Redis()
    await update_agent_presence(
        redis,
        workspace_id="workspace-old",
        alias="worker",
        team_id="backend:acme.test",
    )
    alias_key = "idx:alias:backend%3Aacme.test:worker"
    redis.values[alias_key] = "workspace-new"

    assert await clear_workspace_presence(redis, ["workspace-old"]) == 1
    assert redis.values[alias_key] == "workspace-new"

from __future__ import annotations

import pytest

import awid.registry as registry_module
from awid.registry import (
    CachedRegistryClient,
    RegistryClient,
    _TEAM_REVOCATIONS_CACHE_TTL_SECONDS,
)


class MemoryRedis:
    def __init__(self) -> None:
        self.values: dict[str, str] = {}

    async def get(self, key: str):
        return self.values.get(key)

    async def set(self, key: str, value: str, *, ex: int) -> None:
        self.values[key] = value

    async def delete(self, *keys: str) -> int:
        deleted = 0
        for key in keys:
            if key in self.values:
                deleted += 1
                del self.values[key]
        return deleted


@pytest.mark.asyncio
async def test_team_revocations_cache_reuses_fresh_value(monkeypatch):
    redis = MemoryRedis()
    client = CachedRegistryClient("https://registry.example", redis_client=redis)
    calls: list[int] = []

    async def fake_get_team_revocations(self, domain: str, name: str) -> set[str]:
        calls.append(1)
        return {"cert-1"}

    now = 1_700_000_000
    monkeypatch.setattr(registry_module, "_cache_now", lambda: now)
    monkeypatch.setattr(RegistryClient, "get_team_revocations", fake_get_team_revocations)

    try:
        first = await client.get_team_revocations("acme.com", "backend")
        second = await client.get_team_revocations("acme.com", "backend")
    finally:
        await client.aclose()

    assert first == {"cert-1"}
    assert second == {"cert-1"}
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_team_revocations_cache_refetches_expired_value_without_serving_stale(monkeypatch):
    redis = MemoryRedis()
    client = CachedRegistryClient("https://registry.example", redis_client=redis)
    responses = [set(), {"revoked-cert"}]

    async def fake_get_team_revocations(self, domain: str, name: str) -> set[str]:
        return responses.pop(0)

    now = 1_700_000_000
    monkeypatch.setattr(registry_module, "_cache_now", lambda: now)
    monkeypatch.setattr(RegistryClient, "get_team_revocations", fake_get_team_revocations)

    try:
        first = await client.get_team_revocations("acme.com", "backend")
        now += _TEAM_REVOCATIONS_CACHE_TTL_SECONDS + 1
        second = await client.get_team_revocations("acme.com", "backend")
    finally:
        await client.aclose()

    assert first == set()
    assert second == {"revoked-cert"}

"""An untrusted registry must finish a scan within a finite page budget."""
from __future__ import annotations

import httpx
import pytest

from awid.registry import RegistryClient, RegistryError


@pytest.mark.asyncio
@pytest.mark.parametrize("route", ["certificates", "revocations", "legacy_revocations"])
async def test_registry_scan_refuses_unending_pages(route):
    calls = 0

    def handler(request):
        nonlocal calls
        calls += 1
        # Stop the regression itself if the implementation has no budget.
        assert calls <= 500, "registry scan exceeded its 500-page budget"
        key = "certificates" if route == "certificates" else "revocations"
        if route == "legacy_revocations":
            return httpx.Response(200, json={key: [
                {"certificate_id": f"{calls}-{i}", "revoked_at": f"2026-01-01T00:{calls // 60:02}:{calls % 60:02}+00:00"}
                for i in range(1000)
            ]})
        return httpx.Response(200, json={key: [], "has_more": True, "next_cursor": str(calls)})

    client = RegistryClient("http://registry.test", transport=httpx.MockTransport(handler))
    try:
        with pytest.raises(RegistryError, match="pagination exceeded 500 pages") as caught:
            if route == "certificates":
                await client.list_team_certificates("example.com", "team")
            else:
                await client.get_team_revocations("example.com", "team")
        assert caught.value.status_code == 502
        assert calls == 500
    finally:
        await client.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("route", ["certificates", "revocations"])
async def test_registry_scan_accepts_final_page_at_budget(route):
    calls = 0

    def handler(request):
        nonlocal calls
        calls += 1
        return httpx.Response(200, json={route: [], "has_more": calls < 500, "next_cursor": str(calls)})

    client = RegistryClient("http://registry.test", transport=httpx.MockTransport(handler))
    try:
        if route == "certificates":
            assert await client.list_team_certificates("example.com", "team") == []
        else:
            assert await client.get_team_revocations("example.com", "team") == set()
        assert calls == 500
    finally:
        await client.aclose()

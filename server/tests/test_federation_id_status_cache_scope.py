"""Cache-key wiring: answering registry and admitted cohort are separate scopes."""

from contextlib import aclosing

import httpx
import pytest

from aweb.federation.id_tree_registry import _ScopedRegistry


@pytest.mark.asyncio
async def test_scoped_id_status_key_retains_answering_registry_and_cohort():
    calls = []

    def record(request):
        calls.append(request)
        return httpx.Response(500)

    # Configuration/key construction only; this stand-in supplies no authority.
    async with aclosing(
        _ScopedRegistry(
            registry_url="https://configured.test",
            redis_client=None,
            transport=httpx.MockTransport(record),
        )
    ) as client:
        object.__setattr__(client, "_authority_scope", "federation:statement:cohort:")
        request = {
            "domain": "example.test",
            "subject": {"kind": "namespace", "id": "example.test"},
        }
        key = client._id_status_cache_key(request, registry_url="https://answered.test")
        assert key.startswith("federation:statement:cohort:")
        assert "https://answered.test" in key
        assert "https://configured.test" not in key
        assert client._id_status_cache_key(request) != key
        object.__setattr__(
            client, "_authority_scope", "federation:statement:next-cohort:"
        )
        assert (
            client._id_status_cache_key(request, registry_url="https://answered.test")
            != key
        )
    assert calls == []

"""Authorization selects from a complete CRL without adding registry queries."""

import httpx
import pytest

from awid.registry import RegistryClient
from aweb.team_auth_deps import _get_revoked_certificates
from tests.test_awid_auth_dependency_fail_closed import _request_with_registry


@pytest.mark.asyncio
@pytest.mark.parametrize("fresh", [False, True])
async def test_selected_membership_still_fetches_only_the_complete_crl(fresh):
    requests = []

    def registry(request):
        requests.append(request)
        assert request.method == "GET" and request.url.path.endswith("/revocations")
        assert "certificate_ids" not in str(request.url) and not request.content
        return httpx.Response(
            200,
            json={
                "revocations": [
                    {"certificate_id": cid} for cid in ["revoked-a", "revoked-b", "unasked"]
                ],
                "has_more": False,
            },
        )

    client = RegistryClient("http://registry.test", transport=httpx.MockTransport(registry))
    try:
        assert await _get_revoked_certificates(
            _request_with_registry(client),
            "backend:acme.com",
            certificate_ids=["revoked-a", "active"],
            fresh=fresh,
        ) == {"revoked-a"}
        assert len(requests) == 1
        assert await client.get_team_revocations("acme.com", "backend") == {
            "revoked-a",
            "revoked-b",
            "unasked",
        }
    finally:
        await client.aclose()

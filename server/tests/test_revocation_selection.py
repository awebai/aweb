"""Authorization selects from a complete CRL without adding registry queries."""

import httpx
import pytest
from aweb.certificate_evidence import EvidenceMode
from aweb.team_registry import request_revoked_certificates
from awid.registry import RegistryClient
from tests.test_awid_auth_dependency_fail_closed import _request_with_registry


@pytest.mark.asyncio
@pytest.mark.parametrize("evidence", list(EvidenceMode))
async def test_selected_membership_still_fetches_only_the_complete_crl(evidence):
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
        assert await request_revoked_certificates(
            _request_with_registry(client),
            "backend:acme.com",
            certificate_ids=["revoked-a", "active"],
            evidence=evidence,
        ) == {"revoked-a"}
        assert len(requests) == 1
        assert await client.get_team_revocations("acme.com", "backend") == {
            "revoked-a",
            "revoked-b",
            "unasked",
        }
    finally:
        await client.aclose()

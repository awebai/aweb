from __future__ import annotations

import httpx
import pytest

from awid.did import did_from_public_key, generate_keypair
from awid.federation_errors import FederationAuthorityError
from test_federation_envelope import _envelope, _sign
from test_dashboard_privacy import privacy_app as privacy_app

__all__ = ["privacy_app"]


class _FirstContactBudget:
    """Observe the route's budget key, then stop before external resolution."""

    def __init__(self):
        self.sources = []

    async def authorize(self, _claim, *, source_ip):
        self.sources.append(source_ip)
        raise FederationAuthorityError("federation_rate_limited")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("configured_header", "headers", "expected"),
    [
        (
            "X-Forwarded-For",
            [{"X-Forwarded-For": "203.0.113.1"}, {"X-Forwarded-For": "198.51.100.2"}],
            ["203.0.113.1", "198.51.100.2"],
        ),
        ("X-Client-IP", [{"X-Client-IP": "spoofed, 203.0.113.3"}], ["203.0.113.3"]),
        (None, [{"X-Forwarded-For": "203.0.113.1"}], ["10.0.0.2"]),
        ("", [{"X-Forwarded-For": "203.0.113.1"}], ["10.0.0.2"]),
        ("X-Client-IP", [{}, {"X-Client-IP": "  "}], ["10.0.0.2", "10.0.0.2"]),
    ],
)
async def test_first_contact_budget_uses_only_configured_client_header(
    privacy_app,
    monkeypatch,
    configured_header,
    headers,
    expected,
):
    if configured_header is None:
        monkeypatch.delenv("AWEB_CLIENT_ADDRESS_HEADER", raising=False)
    else:
        monkeypatch.setenv("AWEB_CLIENT_ADDRESS_HEADER", configured_header)
    app = privacy_app.app
    budget = _FirstContactBudget()
    app.state.federation_authority = budget
    key, public = generate_keypair()
    transport = httpx.ASGITransport(app=app, client=("10.0.0.2", 12345))
    async with httpx.AsyncClient(
        transport=transport, base_url=app.state.public_origin
    ) as client:
        for request_headers in headers:
            envelope = _envelope(did_from_public_key(public))
            envelope["target_delivery_origin"] = app.state.public_origin
            response = await client.post(
                "/v1/federation/messages",
                headers=request_headers,
                json={"envelope": envelope, "signature": _sign(envelope, key)},
            )
            assert response.status_code == 429, response.text
            assert response.headers["Retry-After"] == "1"
    assert budget.sources == expected

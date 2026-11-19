"""The production login limiter distinguishes clients only behind a trusted proxy."""

import httpx
import pytest

from tests.test_production_bootstrap import root as root
from tests.test_production_bootstrap import signed_in_owner

HEADER = "X-Forwarded-For"
PROXY = "192.0.2.250"


@pytest.fixture(params=[True, False], ids=["trusted-header", "peer-only"], autouse=True)
def trusted_header(request, monkeypatch):
    # Autouse makes this deployment setting precede the actual root fixture's
    # settings/constructor, rather than replacing its limiter after startup.
    if request.param:
        monkeypatch.setenv("SECRETS_CLIENT_ADDRESS_HEADER", HEADER)
    else:
        monkeypatch.delenv("SECRETS_CLIENT_ADDRESS_HEADER", raising=False)
    return request.param


async def test_clients_at_one_proxy_have_only_the_configured_identity(root, trusted_header):
    service, _, settings, _, _, _, _, _ = root
    scope, _, _ = await signed_in_owner(root)
    async with (
        httpx.AsyncClient(
            transport=httpx.ASGITransport(service, client=(PROXY, 41001)),
            base_url=settings.console_origin,
            headers={HEADER: "203.0.113.1, 198.51.100.10"},
        ) as first,
        httpx.AsyncClient(
            transport=httpx.ASGITransport(service, client=(PROXY, 41002)),
            base_url=settings.console_origin,
            headers={HEADER: "203.0.113.1, 198.51.100.20"},
        ) as second,
    ):
        # Failed real B3 attempts on an enrolled scope consume the production
        # bucket. The bootstrap used another peer, so this proxy starts fresh.
        for _ in range(12):
            attempt = await first.post("/login", json={"scope": scope, "assertion": {}})
            assert attempt.status_code == 401, attempt.text
        exhausted = await first.post("/login", json={"scope": scope, "assertion": {}})
        assert exhausted.status_code == 429, exhausted.text
        assert exhausted.json()["detail"] == "login_rate_limited"

        # With the trusted header this second address has its own bucket.
        # Otherwise both forged values are ignored and the peer bucket is full.
        other = await second.post("/login/options", json={"scope": scope})
        assert other.status_code == (200 if trusted_header else 429), other.text
        if not trusted_header:
            assert other.json()["detail"] == "login_rate_limited"

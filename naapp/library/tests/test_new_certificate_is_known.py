"""A certificate the registry published after the team's facts were cached is
accepted on its first request, and unknown certificate ids cannot make the
library read the registry once per request."""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest
from aweb_naapp.runtime.team_auth import UNKNOWN_CERTIFICATE_REFRESH_SECONDS
from awid.signing import canonical_json_bytes, sign_message
from fastapi import FastAPI, Request

from library import auth
from library.auth import AWIDTeamCache, authenticate_request
from library.config import Settings

VECTORS = json.loads(
    (Path(__file__).resolve().parents[3] / "docs/vectors/team-certificate-verification-v1.json").read_text()
)
VALID = next(case for case in VECTORS["cases"] if case["name"] == "valid")
ORIGIN = "https://library.example.com"
SEEDS = {key["did_key"]: bytes.fromhex(key["seed_hex"]) for key in VECTORS["keys"].values()}


class _Registry:
    """The registry's answers for one team, and how often its certificates were read."""

    def __init__(self, published: list[str]) -> None:
        self.published = published
        self.certificate_reads = 0

    def transport(self) -> httpx.MockTransport:
        def answer(request: httpx.Request) -> httpx.Response:
            if request.url.path.endswith("/certificates"):
                self.certificate_reads += 1
                page = [{"certificate_id": certificate_id, "revoked_at": None} for certificate_id in self.published]
                return httpx.Response(200, json={"certificates": page, "has_more": False})
            return httpx.Response(200, json={"team_did_key": VALID["team_did_key"]})

        return httpx.MockTransport(answer)


def _headers() -> dict[str, str]:
    timestamp = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    payload = canonical_json_bytes(
        {
            "v": 2,
            "aud": ORIGIN,
            "method": "GET",
            "path": "/",
            "team_id": VECTORS["team_id"],
            "timestamp": timestamp,
            "body_sha256": hashlib.sha256(b"").hexdigest(),
        }
    )
    signer = VALID["request_did_key"]
    return {
        "Authorization": f"DIDKey {signer} {sign_message(SEEDS[signer], payload)}",
        "X-AWEB-Timestamp": timestamp,
        "X-AWEB-Signed-Payload": base64.urlsafe_b64encode(payload).rstrip(b"=").decode(),
        "X-AWID-Team-Certificate": VALID["certificate_header"],
    }


@pytest.mark.asyncio
async def test_a_certificate_published_after_the_facts_were_cached_is_accepted_at_once(monkeypatch) -> None:
    registry = _Registry(published=["cert-earlier"])
    cache = AWIDTeamCache(
        registry_url="https://registry.example.com", ttl_seconds=60, service_token="s" * 40,
        transport=registry.transport(),
    )
    await cache.get(VECTORS["team_id"], "cert-earlier")
    assert registry.certificate_reads == 1

    # The team's controller issues a certificate to a new member.
    registry.published.append("cert-001")

    async def record_nothing(_db, _principal) -> None:
        return None

    monkeypatch.setattr(auth, "record_observed_principal", record_nothing)
    app = FastAPI()

    @app.get("/")
    async def relying(request: Request) -> dict[str, str]:
        principal = await authenticate_request(
            request, settings=Settings(public_origin=ORIGIN), team_cache=cache, db=None
        )
        return {"certificate_id": principal.certificate_id}

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=ORIGIN) as client:
        response = await client.get("/", headers=_headers())
    assert (response.status_code, response.json()) == (200, {"certificate_id": "cert-001"}), response.text
    assert registry.certificate_reads == 2, "one refresh for the certificate the cache did not know"


@pytest.mark.asyncio
async def test_a_burst_of_unknown_certificate_ids_reads_the_registry_once(monkeypatch) -> None:
    clock = {"now": 1000 * 10**9}
    monkeypatch.setattr("aweb_naapp.runtime.team_auth.time.monotonic_ns", lambda: clock["now"])
    registry = _Registry(published=["cert-earlier"])
    cache = AWIDTeamCache(
        registry_url="https://registry.example.com", ttl_seconds=60, service_token="s" * 40,
        transport=registry.transport(),
    )
    await cache.get(VECTORS["team_id"], "cert-earlier")
    assert registry.certificate_reads == 1

    for n in range(20):
        facts = await cache.get(VECTORS["team_id"], f"cert-unknown-{n}")
        assert f"cert-unknown-{n}" not in facts.published_certificate_ids
    assert registry.certificate_reads == 2, "one refresh for the whole burst"

    clock["now"] += UNKNOWN_CERTIFICATE_REFRESH_SECONDS * 10**9
    await cache.get(VECTORS["team_id"], "cert-unknown-later")
    assert registry.certificate_reads == 3, "and one more only after the cooldown"

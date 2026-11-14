"""What the runtime verifier answers for each shared certificate case.

Each request is signed for real by the case's signer. The registry's answers
(the team key, the published and the revoked certificates) are the case's own.
"""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest
from aweb_naapp_testing import utc_timestamp
from aweb_naapp_testing.team_facts import legacy_certificate_status, legacy_team_response
from awid.signing import canonical_json_bytes, sign_message
from fastapi import FastAPI, Request

from aweb_naapp.runtime.team_auth import AWIDTeamCache, authenticate_request

VECTORS = json.loads(
    (Path(__file__).resolve().parents[3] / "docs/vectors/team-certificate-verification-v1.json").read_text()
)
ORIGIN = "https://app.example.com"
REGISTRY = "https://registry.example.com"
SEEDS = {key["did_key"]: bytes.fromhex(key["seed_hex"]) for key in VECTORS["keys"].values()}


def _registry(case: dict) -> httpx.MockTransport:
    revoked = set(case["revoked_certificate_ids"])

    def answer(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/status"):
            certificate_id = request.url.path.rsplit("/", 2)[-2]
            if certificate_id not in case["registered_certificate_ids"]:
                return httpx.Response(404)
            return httpx.Response(200, json=legacy_certificate_status(
                VECTORS["team_id"], certificate_id, team_did_key=case["team_did_key"],
                revoked_at="2026-11-02T00:00:00Z" if certificate_id in revoked else None))
        if request.url.path.endswith("/certificates"):
            page = [
                {"certificate_id": certificate_id, "revoked_at": "2026-11-02T00:00:00Z" if certificate_id in revoked else None}
                for certificate_id in case["registered_certificate_ids"]
            ]
            return httpx.Response(200, json={"certificates": page, "has_more": False})
        name, domain = VECTORS["team_id"].split(":", 1)
        return httpx.Response(200, json=legacy_team_response(domain, name, team_did_key=case["team_did_key"]))

    return httpx.MockTransport(answer)


def _headers(case: dict) -> dict[str, str]:
    timestamp = utc_timestamp(datetime.now(UTC))
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
    signer = case["request_did_key"]
    return {
        "Authorization": f"DIDKey {signer} {sign_message(SEEDS[signer], payload)}",
        "X-AWEB-Timestamp": timestamp,
        "X-AWEB-Signed-Payload": base64.urlsafe_b64encode(payload).rstrip(b"=").decode(),
        "X-AWID-Team-Certificate": case["certificate_header"],
    }


@pytest.mark.parametrize("case", VECTORS["cases"], ids=lambda case: case["name"])
async def test_the_runtime_verifier_answers_each_case_as_recorded(case: dict) -> None:
    cache = AWIDTeamCache(
        registry_url=REGISTRY, ttl_seconds=60, service_token="s" * 40, transport=_registry(case)
    )
    app = FastAPI()

    @app.get("/")
    async def relying(request: Request) -> dict[str, str]:
        principal = await authenticate_request(request, public_origin=ORIGIN, team_cache=cache)
        return {"certificate_id": principal.certificate_id}

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=ORIGIN) as client:
        response = await client.get("/", headers=_headers(case))
    answered = {200: "accepted", 401: "refused"}.get(response.status_code, f"status {response.status_code}")
    assert answered == case["today"]["naapp_runtime"], response.text
    expected = case["expected"]
    if expected is None:
        assert response.status_code == 200, response.text
    else:
        detail = expected["reason"] if "field" not in expected else f"{expected['reason']}: {expected['field']}"
        assert (response.status_code, response.json()["detail"]) == (401, detail)


def test_a_cache_cannot_be_made_to_keep_team_facts_longer_than_the_limit() -> None:
    AWIDTeamCache(registry_url=REGISTRY, ttl_seconds=60)
    with pytest.raises(ValueError, match="cached for at most 60 seconds"):
        AWIDTeamCache(registry_url=REGISTRY, ttl_seconds=61)


@pytest.mark.parametrize("fault", ["missing", "null", "malformed", "unavailable"])
async def test_vector_registry_never_turns_missing_protection_into_legacy(fault):
    from fastapi import HTTPException

    case = next(case for case in VECTORS["cases"] if case["name"] == "valid")
    original = _registry(case)

    async def answer(request):
        response = await original.handle_async_request(request)
        if request.url.path.endswith("/status") and request.url.params.get("protection") == "1":
            if fault == "unavailable":
                return httpx.Response(503)
            payload = response.json()
            if fault == "missing":
                del payload["protection"]
            else:
                payload["protection"] = None if fault == "null" else {"mode": "unknown"}
            return httpx.Response(200, json=payload)
        return response

    cache = AWIDTeamCache(registry_url=REGISTRY, ttl_seconds=60, service_token="s" * 40,
        transport=httpx.MockTransport(answer))
    certificate_id = json.loads(base64.b64decode(case["certificate_header"]))["certificate_id"]
    with pytest.raises(HTTPException) as refused:
        await cache.get(VECTORS["team_id"], certificate_id)
    assert refused.value.status_code == 503
    assert refused.value.detail == {"code": "protected_state_unavailable"}
    assert cache._cache[VECTORS["team_id"]].protection_observation is None

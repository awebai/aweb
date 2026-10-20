"""Target-bound auth and legacy usage through real aweb/AWID/PG/Redis."""
import base64
from datetime import datetime, timezone
import hashlib

import pytest

from awid.signing import canonical_json_bytes, sign_message
from test_dashboard_privacy import TEAM, privacy_app  # noqa: F401
from test_messages_http import _signed_identity_headers, _signed_team_headers


def v2_headers(env, family, *, method="GET", path="/v1/messages/inbox", body=b"", **overrides):
    actor = env.actors["alice"]
    timestamp = datetime.now(timezone.utc).isoformat()
    payload = {
        "v": 2, "aud": str(env.client.base_url).rstrip("/"), "method": method,
        "path": path, "body_sha256": hashlib.sha256(body).hexdigest(), "timestamp": timestamp,
        **({"team_id": TEAM} if family == "certificate" else {"did_aw": ""}),
    }
    payload.update(overrides)
    canonical = canonical_json_bytes(payload)
    headers = {
        "Authorization": f"DIDKey {actor.did} {sign_message(actor.sk, canonical)}",
        "X-AWEB-Timestamp": timestamp,
        "X-AWEB-Signed-Payload": base64.urlsafe_b64encode(canonical).rstrip(b"=").decode(),
        "User-Agent": "aw/1.36.44 (test/test)",
    }
    if family == "certificate":
        headers["X-AWID-Team-Certificate"] = actor.certificate
    return headers


@pytest.mark.asyncio
@pytest.mark.parametrize("family", ["identity", "certificate"])
async def test_v2_auth_accepts_correct_request_and_rejects_retargeting(privacy_app, family):
    env = privacy_app
    env.app.state.public_origin = str(env.client.base_url).rstrip("/" )
    path = "/v1/messages/inbox?limit=1&opaque=a%2Fb"
    response = await env.client.get(path, headers=v2_headers(env, family, path=path))
    assert response.status_code == 200, response.text
    for mutation in (
        {"method": "POST"}, {"path": "/v1/messages/inbox?limit=2&opaque=a%2Fb"},
        {"aud": "https://different.example.test"}, {"body_sha256": "0" * 64},
        {"team_id": "other:example.test"} if family == "certificate" else {"did_aw": "did:aw:other"},
        {"v": 1},
    ):
        response = await env.client.get(path, headers=v2_headers(env, family, **{"path": path, **mutation}))
        assert response.status_code == 401, (mutation, response.text)
    headers = v2_headers(env, family, path=path)
    response = await env.client.get(path.replace("a%2Fb", "a%2fb"), headers=headers)
    assert response.status_code == 401, response.text


@pytest.mark.asyncio
@pytest.mark.parametrize("family", ["identity", "certificate"])
async def test_only_accepted_v1_auth_counts_by_route_and_client_version(privacy_app, family):
    from aweb.auth_metrics import LEGACY_REQUEST_AUTH_ACCEPTED

    env = privacy_app
    env.app.state.public_origin = str(env.client.base_url).rstrip("/")
    actor = env.actors["alice"]
    make_headers = (
        lambda: _signed_team_headers(actor.sk, actor.did, TEAM, actor.certificate)
    ) if family == "certificate" else (
        lambda: _signed_identity_headers(actor.sk, actor.did, "")
    )
    counter = LEGACY_REQUEST_AUTH_ACCEPTED.labels(family, "GET", "/v1/messages/{message_id}", "1.36.42")
    before = counter._value.get()
    for identifier in ("11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"):
        headers = {**make_headers(), "User-Agent": "aw/1.36.42 (test/test)"}
        response = await env.client.get(f"/v1/messages/{identifier}", headers=headers)
        assert response.status_code == 404, response.text
    assert counter._value.get() == before + 2
    headers["Authorization"] = headers["Authorization"][:-8] + "AAAAAAAA"
    response = await env.client.get("/v1/messages/11111111-1111-4111-8111-111111111111", headers=headers)
    assert response.status_code == 401
    response = await env.client.get(
        "/v1/messages/11111111-1111-4111-8111-111111111111",
        headers=v2_headers(env, family, path="/v1/messages/11111111-1111-4111-8111-111111111111"),
    )
    assert response.status_code == 404, response.text
    assert counter._value.get() == before + 2

"""Team-auth v2 acceptance boundaries, each beside the valid neighbouring request.

Every request is signed for real and checked against real AWID state.
"""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta

import pytest
from awid.signing import canonical_json_bytes, sign_message
from nacl.signing import SigningKey

from tests.runtime.conftest import Member, did_key, envelope_headers, relying_app, utc_timestamp

ORIGIN = "https://app.example.com"
TEAM_ID = "backend:example.com"


@pytest.fixture
async def member(registry) -> Member:
    member = Member(team_id=TEAM_ID, extra_cert_fields={"member_did_aw": "did:aw:synthetic", "member_address": "example.com/alice"})
    await registry.add_team(TEAM_ID, member.team_did_key, visibility="private")
    await registry.add_certificate(member.certificate())
    return member


async def test_signed_request_yields_the_certified_principal(registry, member):
    async with relying_app(registry, public_origin=ORIGIN) as (client, _):
        body = b'{"title":"x"}'
        response = await client.post(
            "/v1/items?draft=1", content=body,
            headers=member.headers(aud=ORIGIN, method="POST", path="/v1/items?draft=1", body=body),
        )
    assert response.status_code == 200, response.text
    assert response.json() == {
        "team_id": TEAM_ID,
        "did_key": member.did_key,
        "did_aw": "did:aw:synthetic",
        "address": "example.com/alice",
        "alias": "alice",
        "certificate_id": "cert-1",
        "team_did_key": member.team_did_key,
        "cached_body": '{"title":"x"}',
    }


@pytest.mark.parametrize("offset,accepted", [(299, True), (-299, True), (301, False), (-301, False)])
async def test_timestamp_window_is_five_minutes(registry, member, offset, accepted):
    signed_at = datetime(2026, 10, 19, 12, 0, 0, tzinfo=UTC)
    async with relying_app(registry, public_origin=ORIGIN, now=lambda: signed_at + timedelta(seconds=offset)) as (client, _):
        response = await client.get(
            "/v1/items", headers=member.headers(aud=ORIGIN, method="GET", path="/v1/items", timestamp=utc_timestamp(signed_at)),
        )
    assert response.status_code == (200 if accepted else 401), response.text


@pytest.mark.parametrize("timestamp", ["2026-10-19T12:00:00", "not-a-time"])
async def test_timestamp_without_zone_or_unparseable_is_refused(registry, member, timestamp):
    async with relying_app(registry, public_origin=ORIGIN) as (client, _):
        response = await client.get(
            "/v1/items", headers=member.headers(aud=ORIGIN, method="GET", path="/v1/items", timestamp=timestamp),
        )
    assert response.status_code == 401


@pytest.mark.parametrize("authorization", [
    "Bearer abc", "DIDKey only-two", "DIDKey did:web:example.com sig", "DIDKey did:key:z6Mk sig extra",
])
async def test_authorization_header_must_be_didkey(registry, member, authorization):
    headers = member.headers(aud=ORIGIN, method="GET", path="/v1/items")
    headers["Authorization"] = authorization
    async with relying_app(registry, public_origin=ORIGIN) as (client, _):
        response = await client.get("/v1/items", headers=headers)
    assert response.status_code == 401


@pytest.mark.parametrize("missing", ["Authorization", "X-AWEB-Timestamp", "X-AWEB-Signed-Payload", "X-AWID-Team-Certificate"])
async def test_every_envelope_header_is_required(registry, member, missing):
    headers = member.headers(aud=ORIGIN, method="GET", path="/v1/items")
    headers.pop(missing)
    async with relying_app(registry, public_origin=ORIGIN) as (client, _):
        response = await client.get("/v1/items", headers=headers)
    assert response.status_code == 401


@pytest.mark.parametrize("change", [
    {"method": "POST"}, {"path": "/v1/other"}, {"path": "/v1/items?draft=1"},
    {"team_id": "other:example.com"}, {"body_sha256": "0" * 64}, {"v": 1}, {"v": None},
    {"timestamp": "2026-01-01T00:00:00Z"}, {"aud": "https://other.example.com"},
])
async def test_signed_claims_bind_the_actual_request(registry, member, change):
    async with relying_app(registry, public_origin=ORIGIN) as (client, _):
        response = await client.get(
            "/v1/items", headers=member.headers(aud=ORIGIN, method="GET", path="/v1/items", payload_changes=change),
        )
    assert response.status_code == 401


async def test_audience_compares_canonical_origins(registry, member):
    async with relying_app(registry, public_origin=ORIGIN + "/") as (client, _):
        response = await client.get(
            "/v1/items", headers=member.headers(aud="HTTPS://APP.EXAMPLE.COM", method="GET", path="/v1/items"),
        )
    assert response.status_code == 200, response.text


@pytest.mark.parametrize("encoding", ["padded", "standard_alphabet", "non_canonical_json"])
async def test_signed_payload_must_be_unpadded_base64url_canonical_json(registry, member, encoding):
    timestamp = utc_timestamp(datetime.now(UTC))
    shows_encoding = {
        "padded": lambda raw: base64.urlsafe_b64encode(raw).endswith(b"="),
        "standard_alphabet": lambda raw: bool(set(b"+/") & set(base64.b64encode(raw))),
        "non_canonical_json": lambda raw: True,
    }[encoding]
    for size in range(64):
        # The informational operation field only sizes the payload so the encoding under test shows.
        payload = {"v": 2, "aud": ORIGIN, "method": "GET", "path": "/v1/items?q=%3F%3E", "team_id": TEAM_ID,
                   "timestamp": timestamp, "operation": "o" * size,
                   "body_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}
        raw = json.dumps(payload).encode() if encoding == "non_canonical_json" else canonical_json_bytes(payload)
        if shows_encoding(raw):
            break
    headers = envelope_headers(
        did_key=member.did_key, signature=sign_message(bytes(member.member_key), raw),
        timestamp=timestamp, signed_payload=raw, cert=member.certificate(),
    )
    if encoding == "padded":
        headers["X-AWEB-Signed-Payload"] = base64.urlsafe_b64encode(raw).decode()
        assert headers["X-AWEB-Signed-Payload"].endswith("=")
    elif encoding == "standard_alphabet":
        headers["X-AWEB-Signed-Payload"] = base64.b64encode(raw).rstrip(b"=").decode()
        assert set("+/") & set(headers["X-AWEB-Signed-Payload"])
    async with relying_app(registry, public_origin=ORIGIN) as (client, _):
        response = await client.get("/v1/items?q=%3F%3E", headers=headers)
    assert response.status_code == 401


async def test_signature_must_be_the_members(registry, member):
    headers = member.headers(aud=ORIGIN, method="GET", path="/v1/items")
    other = Member(team_id=TEAM_ID).headers(aud=ORIGIN, method="GET", path="/v1/items", timestamp=headers["X-AWEB-Timestamp"])
    headers["Authorization"] = f"DIDKey {member.did_key} {other['Authorization'].split()[2]}"
    async with relying_app(registry, public_origin=ORIGIN) as (client, _):
        response = await client.get("/v1/items", headers=headers)
    assert response.status_code == 401


async def test_certificate_must_name_the_signer(registry, member):
    impostor = Member(team_id=TEAM_ID, team_key=member.team_key, certificate_id="cert-2", alias="bob")
    await registry.add_certificate(impostor.certificate())
    headers = impostor.headers(aud=ORIGIN, method="GET", path="/v1/items", cert=member.certificate())
    async with relying_app(registry, public_origin=ORIGIN) as (client, _):
        assert (await client.get("/v1/items", headers=headers)).status_code == 401
        neighbour = impostor.headers(aud=ORIGIN, method="GET", path="/v1/items")
        assert (await client.get("/v1/items", headers=neighbour)).status_code == 200


@pytest.mark.parametrize("field", ["team_id", "certificate_id", "member_did_key", "alias"])
async def test_certificate_requires_its_identifying_fields(registry, member, field):
    cert = member.certificate()
    cert.pop(field)
    async with relying_app(registry, public_origin=ORIGIN) as (client, _):
        response = await client.get("/v1/items", headers=member.headers(aud=ORIGIN, method="GET", path="/v1/items", cert=cert))
    assert response.status_code == 401


@pytest.mark.parametrize("header", ["not base64!", base64.b64encode(b"[]").decode(), base64.b64encode(b"{").decode()])
async def test_malformed_certificate_is_refused(registry, member, header):
    headers = member.headers(aud=ORIGIN, method="GET", path="/v1/items")
    headers["X-AWID-Team-Certificate"] = header
    async with relying_app(registry, public_origin=ORIGIN) as (client, _):
        assert (await client.get("/v1/items", headers=headers)).status_code == 401


async def test_certificate_signature_must_be_the_current_team_key(registry, member):
    altered = member.certificate()
    altered["alias"] = "mallory"
    forged = Member(team_id=TEAM_ID, member_key=member.member_key)  # signed by a key that is not the team's
    async with relying_app(registry, public_origin=ORIGIN) as (client, _):
        for cert in (altered, forged.certificate()):
            headers = member.headers(aud=ORIGIN, method="GET", path="/v1/items", cert=cert)
            assert (await client.get("/v1/items", headers=headers)).status_code == 401


async def test_team_key_rotation_invalidates_old_certificates(registry, member):
    await registry.rotate_team_key(TEAM_ID, did_key(SigningKey.generate()))
    async with relying_app(registry, public_origin=ORIGIN) as (client, _):
        response = await client.get("/v1/items", headers=member.headers(aud=ORIGIN, method="GET", path="/v1/items"))
    assert response.status_code == 401


async def test_revoked_certificate_is_refused_once_the_cache_expires(registry, member):
    async with relying_app(registry, public_origin=ORIGIN) as (client, cache):
        headers = member.headers(aud=ORIGIN, method="GET", path="/v1/items")
        assert (await client.get("/v1/items", headers=headers)).status_code == 200
        await registry.revoke("cert-1")
        cache._certificate_cache.clear()
        assert (await client.get("/v1/items", headers=headers)).status_code == 401


async def test_mounted_app_verifies_the_external_path(registry, member):
    async with relying_app(registry, public_origin=ORIGIN, root_path="/api") as (client, _):
        external = member.headers(aud=ORIGIN, method="GET", path="/api/v1/items")
        assert (await client.get("/api/v1/items", headers=external)).status_code == 200
        internal = member.headers(aud=ORIGIN, method="GET", path="/v1/items")
        assert (await client.get("/api/v1/items", headers=internal)).status_code == 401


async def test_raw_percent_encoding_is_what_is_signed(registry, member):
    async with relying_app(registry, public_origin=ORIGIN) as (client, _):
        raw = member.headers(aud=ORIGIN, method="GET", path="/v1/items/a%2Fb")
        assert (await client.get("/v1/items/a%2Fb", headers=raw)).status_code == 200
        decoded = member.headers(aud=ORIGIN, method="GET", path="/v1/items/a/b")
        assert (await client.get("/v1/items/a%2Fb", headers=decoded)).status_code == 401

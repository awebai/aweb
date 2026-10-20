"""AWID team facts: the service-token history path and the anonymous status path.

Real AWID routes on real PostgreSQL answer every lookup. A fault, when a test sets
one, alters a response only after the real handler produced it.
"""

from __future__ import annotations

import json
import time
from dataclasses import replace

import httpx
import pytest
from awid.pagination import decode_cursor, encode_cursor
from fastapi import HTTPException

from aweb_naapp.runtime.team_auth import AWIDTeamCache
from tests.runtime.conftest import REGISTRY_URL, SERVICE_TOKEN, Member, relying_app

ORIGIN = "https://app.example.com"
TEAM_ID = "backend:example.com"


def history_cache(registry, token=SERVICE_TOKEN) -> AWIDTeamCache:
    return AWIDTeamCache(registry_url=REGISTRY_URL, ttl_seconds=60, service_token=token, transport=registry.transport)


def status_cache(registry) -> AWIDTeamCache:
    return AWIDTeamCache(registry_url=REGISTRY_URL, ttl_seconds=600, transport=registry.transport)


def certificate_pages(registry) -> list[httpx.Request]:
    return [r for r in registry.transport.calls if r.url.path.endswith("/certificates")]


async def add_filler_certificates(registry, member, first, last):
    await registry.db.execute(
        "INSERT INTO {{tables.team_certificates}} (team_uuid, certificate_id, member_did_key, alias, issued_at) "
        "SELECT team_uuid, 'filler-' || n, $1, 'filler-' || n, '2026-01-01'::timestamptz + n * interval '1 second' "
        "FROM {{tables.teams}} CROSS JOIN generate_series($2::int, $3::int) AS n",
        member.did_key, first, last,
    )


@pytest.fixture(params=["public", "private"])
async def team(registry, request) -> Member:
    """201 certificates precede the target, so it sits beyond AWID's and the client's first page."""
    member = Member(team_id=TEAM_ID, certificate_id="target", alias="target")
    await registry.add_team(TEAM_ID, member.team_did_key, visibility=request.param)
    await add_filler_certificates(registry, member, 1, 200)
    await registry.db.execute(
        "INSERT INTO {{tables.team_certificates}} (team_uuid, certificate_id, member_did_key, alias, issued_at) "
        "SELECT team_uuid, 'target', $1, 'target', '2026-01-02' FROM {{tables.teams}}", member.did_key,
    )
    return member


def get_items(member):
    return member.headers(aud=ORIGIN, method="GET", path="/v1/items")


# --- Service-token history path ---------------------------------------------------


@pytest.mark.parametrize("revoked", [False, True])
async def test_history_finds_the_certificate_beyond_the_first_page(registry, team, revoked):
    if revoked:
        await registry.revoke("target")
    cache = history_cache(registry)
    async with relying_app(registry, public_origin=ORIGIN, cache=cache) as (client, _):
        response = await client.get("/v1/items", headers=get_items(team))
    assert response.status_code == (401 if revoked else 200), response.text
    pages = certificate_pages(registry)
    assert len(pages) == 2 and pages[1].url.params["cursor"]
    assert all(r.headers.get("X-AWID-Service-Token") == SERVICE_TOKEN for r in registry.transport.calls)
    assert cache._cache[TEAM_ID].revoked_certificate_ids == (frozenset({"target"}) if revoked else frozenset())


async def test_history_refuses_a_certificate_awid_never_published(registry, team):
    unpublished = Member(team_id=TEAM_ID, team_key=team.team_key, certificate_id="unpublished", alias="ghost")
    async with relying_app(registry, public_origin=ORIGIN, cache=history_cache(registry)) as (client, _):
        assert (await client.get("/v1/items", headers=get_items(unpublished))).status_code == 401
        assert (await client.get("/v1/items", headers=get_items(team))).status_code == 200


async def test_history_facts_are_reused_for_at_most_a_minute(registry, team):
    cache = AWIDTeamCache(registry_url=REGISTRY_URL, ttl_seconds=600, service_token=SERVICE_TOKEN,
                          transport=registry.transport)
    await cache.get(TEAM_ID, "target")
    assert 0 < cache._cache[TEAM_ID].expires_at - time.monotonic() <= 60


async def test_history_page_bound_fails_closed_without_caching_partial_facts(registry, team):
    cache = history_cache(registry)
    await add_filler_certificates(registry, team, 201, 20000)
    async with relying_app(registry, public_origin=ORIGIN, cache=cache) as (client, _):
        assert (await client.get("/v1/items", headers=get_items(team))).status_code == 503
        assert not cache._cache
        assert len(certificate_pages(registry)) == 100
        # The last permitted page is accepted when it completes the history.
        await registry.db.execute("DELETE FROM {{tables.team_certificates}} WHERE certificate_id = 'filler-1'")
        assert (await client.get("/v1/items", headers=get_items(team))).status_code == 200
    assert TEAM_ID in cache._cache


async def test_history_refresh_failure_never_reuses_expired_facts(registry, team, caplog):
    cache = history_cache(registry)
    async with relying_app(registry, public_origin=ORIGIN, cache=cache) as (client, _):
        assert (await client.get("/v1/items", headers=get_items(team))).status_code == 200
        expired = replace(cache._cache[TEAM_ID], expires_at=-1)
        cache._cache[TEAM_ID] = expired
        await add_filler_certificates(registry, team, 201, 20000)
        assert (await client.get("/v1/items", headers=get_items(team))).status_code == 503
    assert cache._cache[TEAM_ID] is expired
    assert "AWID team facts refresh failed" in caplog.text


def later_page_fault(kind: str, first_cursor: dict):
    def fault(request: httpx.Request, response: httpx.Response) -> None:
        if not request.url.path.endswith("/certificates"):
            return
        payload = response.json()
        if not request.url.params.get("cursor"):
            first_cursor["value"] = payload.get("next_cursor")
            return
        if kind == "transport":
            raise httpx.ReadTimeout("injected later-page timeout", request=request)
        if kind == "http":
            response.status_code = 503
            return
        if kind == "json":
            response._content = b"{"
            return
        if kind == "payload":
            payload = []
        elif kind == "missing_has_more":
            payload.pop("has_more")
        elif kind == "has_more":
            payload["has_more"] = "false"
        elif kind == "certificates":
            payload["certificates"] = {}
        elif kind == "row":
            payload["certificates"] = [None]
        elif kind == "missing_revoked_at":
            payload["certificates"][0].pop("revoked_at")
        elif kind == "missing_certificate_id":
            payload["certificates"][0].pop("certificate_id")
        elif kind == "oversized_page":
            payload["certificates"] = payload["certificates"] * 300
        elif kind == "private":
            response.status_code = 403
            payload = {"detail": {"code": "team_private"}}
        else:
            payload["has_more"] = True
            if kind == "cycling_cursor" and request.url.params["cursor"] == first_cursor["value"]:
                prior = decode_cursor(first_cursor["value"])
                prior["issued_at"] = "2025-12-31T00:00:00+00:00"
                payload["next_cursor"] = encode_cursor(prior)
            else:
                payload["next_cursor"] = {"missing_cursor": None, "blank_cursor": " ", "invalid_cursor": 1}.get(
                    kind, first_cursor["value"]
                )
        response._content = json.dumps(payload).encode()

    return fault


@pytest.mark.parametrize("kind", [
    "payload", "json", "missing_has_more", "has_more", "certificates", "row", "missing_revoked_at",
    "missing_certificate_id", "oversized_page", "missing_cursor", "repeated_cursor", "blank_cursor",
    "invalid_cursor", "cycling_cursor", "http", "transport",
])
async def test_history_later_page_fault_fails_closed_then_recovers(registry, team, kind, caplog):
    cache = history_cache(registry)
    first_cursor: dict = {}
    registry.transport.fault = later_page_fault(kind, first_cursor)
    async with relying_app(registry, public_origin=ORIGIN, cache=cache) as (client, _):
        assert (await client.get("/v1/items", headers=get_items(team))).status_code == 503
        assert not cache._cache
        pages = certificate_pages(registry)
        assert len(pages) == (3 if kind == "cycling_cursor" else 2)
        assert pages[1].url.params["cursor"] == first_cursor["value"]
        assert "AWID team facts refresh failed" in caplog.text
        registry.transport.fault = None
        assert (await client.get("/v1/items", headers=get_items(team))).status_code == 200
    assert TEAM_ID in cache._cache


async def test_history_private_denial_is_classified(registry, team):
    cache = history_cache(registry)
    registry.transport.fault = later_page_fault("private", {})
    with pytest.raises(HTTPException) as caught:
        await cache.get(TEAM_ID, "target")
    assert caught.value.status_code == 403
    assert caught.value.detail["code"] == "team_private_unreadable"
    assert not cache._cache


async def test_history_with_a_wrong_token_reads_public_but_not_private_teams(registry, team):
    cache = history_cache(registry, token="not-the-registry-service-token")
    visibility = (await registry.db.fetch_one("SELECT visibility FROM {{tables.teams}}"))["visibility"]
    if visibility == "public":
        assert (await cache.get(TEAM_ID, "target")).team_did_key == team.team_did_key
        return
    with pytest.raises(HTTPException) as caught:
        await cache.get(TEAM_ID, "target")
    assert caught.value.status_code == 403
    assert caught.value.detail["code"] == "team_private_unreadable"


@pytest.mark.parametrize("status,body,expected", [
    (403, {"detail": {"code": "other"}}, 503),
    (403, {"detail": "team_private"}, 503),
    (403, None, 503),
    (500, {"detail": {"code": "team_private"}}, 503),
    (404, {"detail": "not found"}, 401),
])
async def test_history_team_lookup_refusals_map_to_distinct_outcomes(registry, team, status, body, expected):
    def fault(request, response):
        if request.url.path.endswith("/teams/backend"):
            response.status_code = status
            response._content = json.dumps(body).encode()

    registry.transport.fault = fault
    cache = history_cache(registry)
    with pytest.raises(HTTPException) as caught:
        await cache.get(TEAM_ID, "target")
    assert caught.value.status_code == expected
    assert not cache._cache


# --- Anonymous certificate-status path ---------------------------------------------


async def test_status_path_verifies_without_a_token_and_reuses_for_at_most_a_minute(registry, team):
    cache = status_cache(registry)
    async with relying_app(registry, public_origin=ORIGIN, cache=cache) as (client, _):
        assert (await client.get("/v1/items", headers=get_items(team))).status_code == 200
        assert [r.url.path for r in registry.transport.calls] == [
            "/v1/namespaces/example.com/teams/backend/certificates/target/status"
        ]
        assert "X-AWID-Service-Token" not in registry.transport.calls[0].headers
        cached = cache._certificate_cache[(TEAM_ID, "target")]
        assert 0 < cached.expires_at - time.monotonic() <= 60
        await registry.revoke("target")
        assert (await client.get("/v1/items", headers=get_items(team))).status_code == 200
        cache._certificate_cache[(TEAM_ID, "target")] = replace(cached, expires_at=-1)
        assert (await client.get("/v1/items", headers=get_items(team))).status_code == 401


async def test_status_path_refuses_an_unpublished_certificate(registry, team):
    unpublished = Member(team_id=TEAM_ID, team_key=team.team_key, certificate_id="unpublished", alias="ghost")
    cache = status_cache(registry)
    async with relying_app(registry, public_origin=ORIGIN, cache=cache) as (client, _):
        assert (await client.get("/v1/items", headers=get_items(unpublished))).status_code == 401
        assert (await client.get("/v1/items", headers=get_items(team))).status_code == 200
    assert (TEAM_ID, "unpublished") not in cache._certificate_cache


async def test_status_cache_is_per_certificate(registry, team):
    cache = status_cache(registry)
    await cache.get(TEAM_ID, "target")
    with pytest.raises(HTTPException) as caught:
        await cache.get(TEAM_ID, "unpublished")
    assert caught.value.status_code == 401
    assert len(registry.transport.calls) == 2


async def test_status_path_requires_a_certificate_id(registry, team):
    with pytest.raises(HTTPException) as caught:
        await status_cache(registry).get(TEAM_ID)
    assert caught.value.status_code == 401
    assert registry.transport.calls == []


@pytest.mark.parametrize("kind", [404, 429, 503, "timeout", "json"])
async def test_status_refresh_failure_has_no_stale_fallback(registry, team, kind):
    cache = status_cache(registry)
    await cache.get(TEAM_ID, "target")
    expired = replace(cache._certificate_cache[(TEAM_ID, "target")], expires_at=-1)
    cache._certificate_cache[(TEAM_ID, "target")] = expired

    def fault(request, response):
        if kind == "timeout":
            raise httpx.ReadTimeout("injected status timeout", request=request)
        if kind == "json":
            response._content = b"{"
        else:
            response.status_code = kind

    registry.transport.fault = fault
    with pytest.raises(HTTPException) as caught:
        await cache.get(TEAM_ID, "target")
    assert caught.value.status_code == (401 if kind == 404 else 503)
    assert cache._certificate_cache[(TEAM_ID, "target")] is expired
    registry.transport.fault = None
    assert (await cache.get(TEAM_ID, "target")).team_did_key == team.team_did_key


@pytest.mark.parametrize("change", [
    "nonobject", "missing_key", "invalid_key", "wrong_team", "missing_status", "bad_status",
    "missing_revoked_at", "active_with_revocation", "revoked_without_time", "bad_time", "naive_time", "extra",
])
async def test_malformed_status_is_unavailable_and_not_cached(registry, team, change):
    def fault(request, response):
        payload = response.json()
        if change == "nonobject":
            payload = []
        elif change.startswith("missing_"):
            payload.pop({"missing_key": "team_did_key"}.get(change, change[len("missing_"):]))
        elif change == "invalid_key":
            payload["team_did_key"] = "garbage"
        elif change == "wrong_team":
            payload["team_id"] = "other:example.com"
        elif change == "bad_status":
            payload["status"] = "unknown"
        elif change == "active_with_revocation":
            payload["revoked_at"] = "2026-01-01T00:00:00Z"
        elif change in ("revoked_without_time", "bad_time", "naive_time"):
            payload["status"] = "revoked"
            payload["revoked_at"] = {"revoked_without_time": None, "bad_time": "yesterday",
                                     "naive_time": "2026-01-01T00:00:00"}[change]
        else:
            payload["alias"] = "private-member"
        response._content = json.dumps(payload).encode()

    registry.transport.fault = fault
    cache = status_cache(registry)
    with pytest.raises(HTTPException) as caught:
        await cache.get(TEAM_ID, "target")
    assert caught.value.status_code == 503
    assert not cache._certificate_cache

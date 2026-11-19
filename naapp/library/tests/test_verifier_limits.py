"""The verifier's own limits: a deployment cannot configure past them.

A revoked certificate is accepted for as long as the team's facts stay cached,
and a captured request for as long as the clock skew allows. A value past
either limit stops the service from starting.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from fastapi import HTTPException
from pydantic import ValidationError
from starlette.requests import Request

from library.auth import AWIDTeamCache, authenticate_request
from library.config import MAX_TEAM_FACTS_TTL_SECONDS, MAX_TIMESTAMP_SKEW_SECONDS, Settings

TOKEN = "library-e2e-service-token-with-at-least-32-bytes"


class _Response:
    def __init__(self, payload: dict) -> None:
        self.status_code = 200
        self._payload = payload

    def json(self) -> dict:
        return self._payload


@pytest.mark.asyncio
async def test_a_revocation_is_seen_within_a_minute(
    monkeypatch,
) -> None:
    registry = {"revoked": False}

    class _Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args) -> None:
            return None

        async def get(self, url: str, **_kwargs) -> _Response:
            if not url.endswith("/certificates"):
                return _Response({"team_did_key": "did:key:z6Mkhx"})
            revoked_at = "2026-08-18T00:00:00Z" if registry["revoked"] else None
            return _Response(
                {
                    "certificates": [{"certificate_id": "member", "revoked_at": revoked_at}],
                    "has_more": False,
                }
            )

    clock = {"now": 1000.0}
    monkeypatch.setattr("library.auth.httpx.AsyncClient", lambda **_kwargs: _Client())
    monkeypatch.setattr("library.auth.time.monotonic", lambda: clock["now"])

    cache = AWIDTeamCache(
        registry_url="https://awid.test",
        ttl_seconds=Settings().auth_cache_ttl_seconds,
        service_token=TOKEN,
    )
    assert (await cache.get("team:example.test")).revoked_certificate_ids == frozenset()

    registry["revoked"] = True
    clock["now"] += MAX_TEAM_FACTS_TTL_SECONDS - 1
    assert (await cache.get("team:example.test")).revoked_certificate_ids == frozenset()

    clock["now"] += 1
    assert (await cache.get("team:example.test")).revoked_certificate_ids == frozenset({"member"})
    assert MAX_TEAM_FACTS_TTL_SECONDS == 60


def _request(sent: datetime) -> Request:
    headers = [
        (b"authorization", b"DIDKey did:key:z6Mkhx c2lnbmF0dXJl"),
        (b"x-aweb-timestamp", sent.strftime("%Y-%m-%dT%H:%M:%SZ").encode()),
    ]
    return Request({"type": "http", "method": "GET", "path": "/", "query_string": b"", "headers": headers})


@pytest.mark.asyncio
async def test_a_request_older_than_five_minutes_is_refused() -> None:
    settings = Settings()
    cache = AWIDTeamCache(registry_url="https://awid.test", ttl_seconds=60, service_token=TOKEN)

    late = datetime.now(UTC) - timedelta(seconds=MAX_TIMESTAMP_SKEW_SECONDS + 5)
    with pytest.raises(HTTPException) as refused:
        await authenticate_request(_request(late), settings=settings, team_cache=cache, db=None)
    assert (refused.value.status_code, refused.value.detail) == (
        401,
        "X-AWEB-Timestamp outside allowed clock skew",
    )

    # Inside the limit the timestamp passes, and the next check answers.
    recent = datetime.now(UTC) - timedelta(seconds=MAX_TIMESTAMP_SKEW_SECONDS - 30)
    with pytest.raises(HTTPException) as next_check:
        await authenticate_request(_request(recent), settings=settings, team_cache=cache, db=None)
    assert next_check.value.detail != "X-AWEB-Timestamp outside allowed clock skew"
    assert MAX_TIMESTAMP_SKEW_SECONDS == 300


@pytest.mark.parametrize(
    ("setting", "limit"),
    [
        ("auth_cache_ttl_seconds", MAX_TEAM_FACTS_TTL_SECONDS),
        ("timestamp_skew_seconds", MAX_TIMESTAMP_SKEW_SECONDS),
    ],
)
def test_a_setting_past_its_limit_stops_the_service_from_starting(
    monkeypatch, setting: str, limit: int
) -> None:
    assert getattr(Settings(**{setting: limit}), setting) == limit
    assert getattr(Settings(), setting) == limit

    with pytest.raises(ValidationError) as refused:
        Settings(**{setting: limit + 1})
    said = str(refused.value)
    assert setting in said and f"less than or equal to {limit}" in said

    # As a deployment sets it: through the environment.
    monkeypatch.setenv(f"LIBRARY_{setting.upper()}", str(limit * 10))
    with pytest.raises(ValidationError) as from_env:
        Settings()
    assert setting in str(from_env.value) and f"less than or equal to {limit}" in str(from_env.value)


def test_a_cache_cannot_be_made_to_keep_team_facts_longer_than_the_limit() -> None:
    AWIDTeamCache(registry_url="https://awid.test", ttl_seconds=MAX_TEAM_FACTS_TTL_SECONDS)
    with pytest.raises(ValueError, match="cached for at most 60 seconds"):
        AWIDTeamCache(registry_url="https://awid.test", ttl_seconds=MAX_TEAM_FACTS_TTL_SECONDS + 1)

"""Real AWID routes on real PostgreSQL (aweb_naapp_testing), and a relying app
that authenticates every request through the shared verifier."""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any

import httpx
import pytest_asyncio
from aweb_naapp_testing import REGISTRY_URL, Registry, awid_registry
from fastapi import FastAPI, Request

from aweb_naapp.runtime.team_auth import (
    AWIDTeamCache,
    DidAwProfile,
    Principal,
    authenticate_request,
)


@pytest_asyncio.fixture
async def registry(test_db_factory) -> AsyncIterator[Registry]:
    registry_db = await test_db_factory.create_db(suffix="naapp_awid")
    async with awid_registry(registry_db.config.get_dsn()) as running:
        yield running


@asynccontextmanager
async def relying_app(
    registry: Registry,
    *,
    public_origin: str,
    cache: AWIDTeamCache | None = None,
    now: Callable[[], datetime] | None = None,
    timestamp_skew_seconds: int | None = None,
    root_path: str = "",
    did_aw_profile: DidAwProfile | None = None,
    on_principal: Callable[[Request, Principal], Any] | None = None,
) -> AsyncIterator[tuple[httpx.AsyncClient, AWIDTeamCache]]:
    """A naapp whose every route authenticates the request and echoes the principal."""
    cache = cache or AWIDTeamCache(registry_url=REGISTRY_URL, ttl_seconds=60, transport=registry.transport)
    app = FastAPI()

    @app.api_route("/{route:path}", methods=["GET", "POST", "PUT", "DELETE"])
    async def relying(request: Request):
        kwargs: dict[str, Any] = {"now": now} if now is not None else {}
        if timestamp_skew_seconds is not None:
            kwargs["timestamp_skew_seconds"] = timestamp_skew_seconds
        if did_aw_profile is not None:
            kwargs["did_aw_profile"] = did_aw_profile
        principal = await authenticate_request(request, public_origin=public_origin, team_cache=cache, **kwargs)
        if on_principal is not None:
            return await on_principal(request, principal)
        return {
            "team_id": principal.team_id,
            "did_key": principal.did_key,
            "did_aw": principal.did_aw,
            "did_aw_registry_verified": principal.did_aw_registry_verified,
            "address": principal.address,
            "alias": principal.alias,
            "certificate_id": principal.certificate_id,
            "team_did_key": principal.team_did_key,
            "cached_body": request.state.cached_body.decode(),
        }

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app, root_path=root_path), base_url=public_origin) as client:
        yield client, cache
